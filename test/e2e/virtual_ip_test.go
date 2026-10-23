//go:build e2e_ebpf

package e2e

import (
	"context"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestVirtualIPAllocation checks the experimental virtual IP host
// resolution (--host-resolution=virtual-ip, spinningfactory/kloak#327): the
// controller gives the host of a host-scoped secret a fake IP from the
// virtual IP range, keeps it across a controller restart (the maps are
// pinned in bpffs), and retires it once no secret uses the host. Runs only
// when the controller is deployed in that mode (the virtual-ip CI leg).
func TestVirtualIPAllocation(t *testing.T) {
	vipRange := controllerVirtualIPRange(t)
	const host = "vip-e2e.example.com"

	createEnabledSecret(t, "secret-vip", map[string][]byte{"api-key": []byte("REAL-VIP-E2E-KEY-12345")}, nil,
		map[string]string{"getkloak.io/hosts": host})

	// Pins outlive an uninstall, so on a node an earlier run used the host
	// gets its retired IP back instead of a new one.
	oldPod := controllerPod(t)
	ip := waitForVirtualIPLog(t, oldPod, host, vipRange, "allocated virtual IP", "reactivated virtual IP")
	if !vipRange.Contains(ip) {
		t.Fatalf("%s got %s, outside the virtual IP range %s", host, ip, vipRange)
	}

	// A new controller finds the same fake IP in the pinned maps.
	if out, err := kubectl("delete", "pod", "-n", kloakNamespace, oldPod, "--wait=false"); err != nil {
		t.Fatalf("deleting controller pod: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if err := waitForPodAbsent(ctx, kloakNamespace, oldPod); err != nil {
		t.Fatal(err)
	}
	if err := waitForDaemonSetReady(ctx, kloakNamespace, "kloak-controller"); err != nil {
		t.Fatal(err)
	}
	newPod := controllerPod(t)
	if restored := waitForVirtualIPLog(t, newPod, host, vipRange, "restored virtual IP"); restored != ip {
		t.Fatalf("after a controller restart %s has %s, was %s", host, restored, ip)
	}

	// No secret uses the host any more: its IP is retired, not reused.
	if err := clientset.CoreV1().Secrets(testNamespace).Delete(context.Background(), "secret-vip", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting secret: %v", err)
	}
	if retired := waitForVirtualIPLog(t, newPod, host, vipRange, "retired virtual IP"); retired != ip {
		t.Fatalf("retired %s for %s, want %s", retired, host, ip)
	}
}

// TestVirtualIPRedirect checks the virtual IP data plane on the raw TLS demo:
// the pod resolves the echo server's host to its fake IP, its connects to
// the fake IP reach the server (the secret is rewritten end to end, still
// attributed by DNS snooping) and getpeername() reports the fake IP, while a
// connect to a fake IP no host has is refused.
func TestVirtualIPRedirect(t *testing.T) {
	vipRange := controllerVirtualIPRange(t)
	echoHostFQDN := "tls." + testNamespace + ".svc.cluster.local"

	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	for _, name := range []string{"secret-allowed", "secret-blocked", "secret-allowed-kloak", "secret-blocked-kloak"} {
		_ = waitForSecretAbsent(gcCtx, testNamespace, name)
	}

	allowedData := map[string][]byte{"api-key": []byte("REAL-VIP-ALLOWED-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-VIP-BLOCKED-KEY-67890")}
	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{"getkloak.io/hosts": echoHostFQDN})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{"getkloak.io/hosts": "example.com"})
	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-raw-tls", "deployment.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-python-raw-tls: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-raw-tls"); err != nil {
		t.Fatalf("demo-python-raw-tls not ready: %v", err)
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-python-raw-tls", "demo-python-raw-tls",
		"timed out waiting for the allowed secret through the virtual IP",
		func(s string) bool { return strings.Contains(s, "REAL-VIP-ALLOWED-KEY-12345") })
	if strings.Contains(out, "REAL-VIP-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret rewritten (host mismatch)")
	}

	// The range's first address is never allocated (planVirtualIPs).
	unallocated := vipRange.Masked().Addr()
	const probe = `import socket, sys
host, unallocated = sys.argv[1], sys.argv[2]
s = socket.create_connection((host, 8443), timeout=5)
print("resolved", socket.gethostbyname(host), "peer", s.getpeername()[0])
s.close()
try:
    socket.create_connection((unallocated, 8443), timeout=5)
    print("unallocated connected")
except OSError as e:
    print("unallocated errno", e.errno)
`
	res, err := kubectl("exec", "-n", testNamespace, "deploy/demo-python-raw-tls", "-c", "demo-app", "--",
		"python", "-c", probe, echoHostFQDN, unallocated.String())
	if err != nil {
		t.Fatalf("probe in the demo pod: %v", err)
	}
	t.Logf("probe: %s", strings.TrimSpace(res))
	var resolved, peer string
	for _, line := range strings.Split(res, "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[0] == "resolved" && f[2] == "peer" {
			resolved, peer = f[1], f[3]
		}
	}
	ip, err := netip.ParseAddr(resolved)
	if err != nil || !vipRange.Contains(ip) {
		t.Errorf("%s resolved to %q in the pod, want an address in %s", echoHostFQDN, resolved, vipRange)
	}
	if peer != resolved {
		t.Errorf("getpeername() = %q, want the fake IP %q", peer, resolved)
	}
	if !strings.Contains(res, "unallocated errno 1\n") { // EPERM
		t.Errorf("connect to the unallocated fake IP %s was not refused with EPERM", unallocated)
	}
}

// TestVirtualIPPodScope checks which pods get a host's fake IP: a pod that
// references a secret restricted to the host does, already in its init
// container, and a kloak pod without such a secret gets the real address.
// With NRI the container runtime waits for the controller to attach the DNS
// rewrite while it creates the sandbox, so the init container's first
// lookup gets the fake IP; without it (the polling CI leg) the controller
// polls the Pending pod, and an early lookup may still get the real
// address.
func TestVirtualIPPodScope(t *testing.T) {
	vipRange := controllerVirtualIPRange(t)
	// Resolvable in every cluster.
	const host = "kubernetes.default.svc.cluster.local"
	data := map[string][]byte{"api-key": []byte("REAL-VIP-SCOPE-KEY-12345")}
	createEnabledSecret(t, "secret-vip-scope", data, nil, map[string]string{"getkloak.io/hosts": host})
	assertShadowSecret(t, "secret-vip-scope", data)
	// The secret is synced and the host has its fake IP, so the pods' first
	// lookups only wait for the DNS rewrite to attach. Not "restored": a
	// host retired by an earlier run is restored at startup but only
	// reactivated by the sync.
	waitForVirtualIPLog(t, controllerPod(t), host, vipRange, "allocated virtual IP", "reactivated virtual IP")

	// The init container exits once the host resolves to a fake IP, so the
	// pod only starts if the rewrite was attached before it ran.
	const waitForFakeIP = `import ipaddress, socket, sys, time
host, net = sys.argv[1], ipaddress.ip_network(sys.argv[2])
deadline = time.monotonic() + 90
while True:
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        ip = "error-%d" % e.errno
    print("lookup", ip, flush=True)
    try:
        if ipaddress.ip_address(ip) in net:
            sys.exit(0)
    except ValueError:
        pass
    if time.monotonic() > deadline:
        sys.exit(1)
    time.sleep(0.2)
`
	bound := vipProbePod("vip-scope-bound", "secret-vip-scope")
	bound.Spec.InitContainers = []corev1.Container{{
		Name:            "wait-for-fake-ip",
		Image:           bound.Spec.Containers[0].Image,
		ImagePullPolicy: corev1.PullNever,
		Command:         []string{"python", "-c", waitForFakeIP, host, vipRange.String()},
	}}
	createVIPProbePod(t, bound)
	createVIPProbePod(t, vipProbePod("vip-scope-unbound"))

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	for _, name := range []string{"vip-scope-bound", "vip-scope-unbound"} {
		if err := waitForPodReady(ctx, testNamespace, name); err != nil {
			logs, _ := kubectl("logs", "-n", testNamespace, name, "--all-containers", "--tail=20")
			t.Fatalf("%v\n%s", err, logs)
		}
	}
	initLogs, _ := kubectl("logs", "-n", testNamespace, "vip-scope-bound", "-c", "wait-for-fake-ip")
	early := strings.Count(initLogs, "lookup ") - 1
	controller := controllerPod(t)
	nri := controllerUsesNRI(t, controller)
	t.Logf("init container lookups before the fake IP: %d (NRI: %v)", early, nri)
	if nri {
		if early != 0 {
			t.Errorf("with NRI, the init container's first %d lookups got the real address:\n%s", early, initLogs)
		}
		// Attached by the runtime's call, not by the reconciler's polling,
		// which would hide a broken NRI path.
		logs, _ := kubectl("logs", "-n", kloakNamespace, controller, "-c", "controller", "--tail=-1")
		if !slices.ContainsFunc(strings.Split(logs, "\n"), func(l string) bool {
			return strings.Contains(l, "DNS rewrite in place at sandbox creation (NRI)") &&
				strings.Contains(l, testNamespace+"/vip-scope-bound")
		}) {
			t.Errorf("the DNS rewrite of vip-scope-bound was not attached at sandbox creation (NRI)")
		}
	}

	resolve := func(pod string) netip.Addr {
		t.Helper()
		out, err := kubectl("exec", "-n", testNamespace, pod, "-c", "app", "--",
			"python", "-c", "import socket, sys; print(socket.gethostbyname(sys.argv[1]))", host)
		if err != nil {
			t.Fatalf("resolving %s in %s: %v\n%s", host, pod, err, out)
		}
		// The last line: kubectl may print warnings before it.
		lines := strings.Split(strings.TrimSpace(out), "\n")
		ip, err := netip.ParseAddr(strings.TrimSpace(lines[len(lines)-1]))
		if err != nil {
			t.Fatalf("%s resolved %s to %q", pod, host, out)
		}
		return ip
	}
	if ip := resolve("vip-scope-bound"); !vipRange.Contains(ip) {
		t.Errorf("pod with a secret for %s resolved it to %s, want an address in %s", host, ip, vipRange)
	}
	if ip := resolve("vip-scope-unbound"); vipRange.Contains(ip) {
		t.Errorf("pod without a secret for %s got its fake IP %s", host, ip)
	}
}

// TestVirtualIPSocketHost checks that, in virtual-ip mode, a secret's host
// is the socket's: the host of the fake IP it connected to. The echo server
// has two names leading to the same IP, its Service and an ExternalName
// alias of it, which DNS snooping can't tell apart; here each gets its own
// fake IP. A secret restricted to one name is rewritten on a connection to
// that name, and not on a connection to the other name even with the right
// SNI. A secret restricted to the server's IP is rewritten on a connection
// made through a fake IP, which reaches that IP.
func TestVirtualIPSocketHost(t *testing.T) {
	vipRange := controllerVirtualIPRange(t)
	hostA := "tls." + testNamespace + ".svc.cluster.local"
	hostB := "tls-alias." + testNamespace + ".svc.cluster.local"

	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	for _, name := range []string{"secret-allowed", "secret-blocked", "secret-allowed-kloak", "secret-blocked-kloak"} {
		_ = waitForSecretAbsent(gcCtx, testNamespace, name)
	}
	// The demo's two secrets, restricted to each name.
	dataA := map[string][]byte{"api-key": []byte("REAL-SOCKHOST-A-KEY-12345")}
	dataB := map[string][]byte{"api-key": []byte("REAL-SOCKHOST-B-KEY-67890")}
	createEnabledSecret(t, "secret-allowed", dataA, nil, map[string]string{"getkloak.io/hosts": hostA})
	createEnabledSecret(t, "secret-blocked", dataB, nil, map[string]string{"getkloak.io/hosts": hostB})
	assertShadowSecret(t, "secret-allowed", dataA)
	assertShadowSecret(t, "secret-blocked", dataB)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-raw-tls", "deployment.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-python-raw-tls: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})
	alias := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "tls-alias", Namespace: testNamespace},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: hostA},
	}
	if _, err := clientset.CoreV1().Services(testNamespace).Create(context.Background(), alias, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the ExternalName alias: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Services(testNamespace).Delete(context.Background(), "tls-alias", metav1.DeleteOptions{})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-raw-tls"); err != nil {
		t.Fatalf("demo-python-raw-tls not ready: %v", err)
	}
	svc, err := clientset.CoreV1().Services(testNamespace).Get(context.Background(), "tls", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting the echo Service: %v", err)
	}
	dataIP := map[string][]byte{"api-key": []byte("REAL-SOCKHOST-IP-KEY-24680")}
	createEnabledSecret(t, "secret-sockhost-ip", dataIP, nil, map[string]string{"getkloak.io/hosts": svc.Spec.ClusterIP})
	assertShadowSecret(t, "secret-sockhost-ip", dataIP)

	controller := controllerPod(t)
	for _, host := range []string{hostA, hostB} {
		waitForVirtualIPLog(t, controller, host, vipRange, "allocated virtual IP", "reactivated virtual IP")
	}
	createVIPProbePod(t, vipProbePod("vip-sockhost-probe", "secret-allowed", "secret-blocked", "secret-sockhost-ip"))
	if err := waitForPodReady(ctx, testNamespace, "vip-sockhost-probe"); err != nil {
		t.Fatal(err)
	}

	// Each line: <case> <first line of the echo>. The process is only
	// traced once kloak has seen its exec, so it first waits for a rewrite
	// that must happen.
	const probe = `import socket, ssl, sys, time
a, b, ip = sys.argv[1:4]
def send(host, sni, secret):
    value = open("/etc/secrets/%s/api-key" % secret).read().strip()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 8443), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            tls.sendall(("S=%s\n" % value).encode())
            return tls.recv(16384).decode(errors="replace").strip().splitlines()[0]
deadline = time.monotonic() + 60
while True:
    out = send(a, a, "secret-allowed")
    if "REAL-" in out or time.monotonic() > deadline:
        break
    time.sleep(0.5)
print("a-via-a", out)
print("a-via-b", send(b, a, "secret-allowed"))
print("b-via-b", send(b, b, "secret-blocked"))
print("ip-via-a", send(a, a, "secret-sockhost-ip"))
`
	res, err := kubectl("exec", "-n", testNamespace, "vip-sockhost-probe", "-c", "app", "--",
		"python", "-c", probe, hostA, hostB, svc.Spec.ClusterIP)
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, res)
	}
	t.Logf("probe:\n%s", strings.TrimSpace(res))
	got := make(map[string]string)
	for _, line := range strings.Split(res, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			got[k] = v
		}
	}
	for _, c := range []struct {
		name, real string
		rewritten  bool
	}{
		{"a-via-a", "REAL-SOCKHOST-A-KEY-12345", true},
		// The socket's host is the alias: refused, though the SNI names A
		// and the connection reaches A's server.
		{"a-via-b", "REAL-SOCKHOST-A-KEY-12345", false},
		{"b-via-b", "REAL-SOCKHOST-B-KEY-67890", true},
		// The socket's real address is the ClusterIP; the app connected to
		// A's fake IP.
		{"ip-via-a", "REAL-SOCKHOST-IP-KEY-24680", true},
	} {
		echo, ok := got[c.name]
		if !ok {
			t.Errorf("%s: no result", c.name)
			continue
		}
		if strings.Contains(echo, c.real) != c.rewritten {
			t.Errorf("%s: echo %q, rewritten %v, want %v", c.name, echo, !c.rewritten, c.rewritten)
		}
	}
}

// TestVirtualIPv6 checks virtual IP host resolution over IPv6 in a
// dual-stack cluster. The echo server gets an IPv6-only Service; a pod with
// a secret restricted to its name gets the name's fake IPv6 in AAAA answers,
// its IPv6 connect to it is redirected to the Service's address
// (getpeername still reports the fake IPv6), and the secret is rewritten on
// that connection: an IPv6 TLS connection, patched at tc. A secret
// restricted to the Service's IPv6 address is rewritten on a connection
// through the fake IPv6, whose socket reaches that address; a connection
// made straight to the address gets no secret restricted to the name.
// Skipped unless the controller runs in virtual-ip mode with an IPv6 range,
// on a cluster with an IPv6 pod network (the virtual-ip CI leg).
func TestVirtualIPv6(t *testing.T) {
	_, vipRange6 := controllerVirtualIPRanges(t)
	if !vipRange6.IsValid() {
		t.Skip("controller has no IPv6 virtual IP range")
	}
	if !clusterHasIPv6(t) {
		t.Skip("cluster has no IPv6 pod network")
	}
	host := "tls6." + testNamespace + ".svc.cluster.local"

	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	for _, name := range []string{"secret-allowed", "secret-blocked", "secret-allowed-kloak", "secret-blocked-kloak"} {
		_ = waitForSecretAbsent(gcCtx, testNamespace, name)
	}
	// The demo's own secrets, unused here.
	demoAllowed := map[string][]byte{"api-key": []byte("REAL-VIP6-DEMO-KEY-11111")}
	demoBlocked := map[string][]byte{"api-key": []byte("REAL-VIP6-DEMO-KEY-22222")}
	createEnabledSecret(t, "secret-allowed", demoAllowed, nil,
		map[string]string{"getkloak.io/hosts": "tls." + testNamespace + ".svc.cluster.local"})
	createEnabledSecret(t, "secret-blocked", demoBlocked, nil, map[string]string{"getkloak.io/hosts": "example.com"})
	assertShadowSecret(t, "secret-allowed", demoAllowed)
	assertShadowSecret(t, "secret-blocked", demoBlocked)
	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-raw-tls", "deployment.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-python-raw-tls: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})
	single := corev1.IPFamilyPolicySingleStack
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "tls6", Namespace: testNamespace},
		Spec: corev1.ServiceSpec{
			Selector:       map[string]string{"app": "demo-python-raw-tls-echo"},
			Ports:          []corev1.ServicePort{{Port: 8443}},
			IPFamilies:     []corev1.IPFamily{corev1.IPv6Protocol},
			IPFamilyPolicy: &single,
		},
	}
	svc, err := clientset.CoreV1().Services(testNamespace).Create(context.Background(), svc, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating the IPv6 Service: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Services(testNamespace).Delete(context.Background(), "tls6", metav1.DeleteOptions{})
	})
	clusterIP := svc.Spec.ClusterIP
	if ip, err := netip.ParseAddr(clusterIP); err != nil || !ip.Is6() {
		t.Fatalf("IPv6 Service got ClusterIP %q", clusterIP)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-raw-tls"); err != nil {
		t.Fatalf("demo-python-raw-tls not ready: %v", err)
	}

	dataHost := map[string][]byte{"api-key": []byte("REAL-VIP6-HOST-KEY-12345")}
	dataIP := map[string][]byte{"api-key": []byte("REAL-VIP6-IP-KEY-67890")}
	createEnabledSecret(t, "secret-vip6-host", dataHost, nil, map[string]string{"getkloak.io/hosts": host})
	createEnabledSecret(t, "secret-vip6-ip", dataIP, nil, map[string]string{"getkloak.io/hosts": clusterIP})
	assertShadowSecret(t, "secret-vip6-host", dataHost)
	assertShadowSecret(t, "secret-vip6-ip", dataIP)
	fake6 := waitForVirtualIPLog(t, controllerPod(t), host, vipRange6, "allocated virtual IP", "reactivated virtual IP")
	createVIPProbePod(t, vipProbePod("vip6-probe", "secret-vip6-host", "secret-vip6-ip"))
	if err := waitForPodReady(ctx, testNamespace, "vip6-probe"); err != nil {
		t.Fatal(err)
	}

	// Each line: <case> <address connected to> <getpeername> <first line
	// of the echo>. The process is only traced once kloak has seen its
	// exec, so it first waits for a rewrite that must happen.
	const probe = `import socket, ssl, sys, time
host, cip = sys.argv[1:3]
def send(target, secret):
    value = open("/etc/secrets/%s/api-key" % secret).read().strip()
    addr = socket.getaddrinfo(target, 8443, socket.AF_INET6, socket.SOCK_STREAM)[0][4]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(addr)
        peer = sock.getpeername()[0]
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            tls.sendall(("S=%s\n" % value).encode())
            echo = tls.recv(16384).decode(errors="replace").strip().splitlines()[0]
    return "%s %s %s" % (addr[0], peer, echo)
deadline = time.monotonic() + 60
while True:
    out = send(host, "secret-vip6-host")
    if "REAL-" in out or time.monotonic() > deadline:
        break
    time.sleep(0.5)
print("name", out)
print("ip-via-name", send(host, "secret-vip6-ip"))
print("name-via-ip", send(cip, "secret-vip6-host"))
`
	res, err := kubectl("exec", "-n", testNamespace, "vip6-probe", "-c", "app", "--", "python", "-c", probe, host, clusterIP)
	if err != nil {
		t.Fatalf("probe: %v\n%s", err, res)
	}
	t.Logf("probe:\n%s", strings.TrimSpace(res))
	got := make(map[string][]string)
	for _, line := range strings.Split(res, "\n") {
		if f := strings.Fields(line); len(f) >= 4 {
			got[f[0]] = f[1:]
		}
	}
	for _, c := range []struct {
		name, target, real string
		rewritten          bool
	}{
		{"name", fake6.String(), "REAL-VIP6-HOST-KEY-12345", true},
		// The socket's real address is the ClusterIP; the app connected to
		// the name's fake IPv6.
		{"ip-via-name", fake6.String(), "REAL-VIP6-IP-KEY-67890", true},
		// No fake IPv6: the socket has no host.
		{"name-via-ip", clusterIP, "REAL-VIP6-HOST-KEY-12345", false},
	} {
		f, ok := got[c.name]
		if !ok {
			t.Errorf("%s: no result", c.name)
			continue
		}
		if f[0] != c.target || f[1] != c.target {
			t.Errorf("%s: connected to %s, getpeername %s; want %s for both", c.name, f[0], f[1], c.target)
		}
		if echo := strings.Join(f[2:], " "); strings.Contains(echo, c.real) != c.rewritten {
			t.Errorf("%s: echo %q, rewritten %v, want %v", c.name, echo, !c.rewritten, c.rewritten)
		}
	}
}

// clusterHasIPv6 reports whether a node of the cluster has an IPv6 pod CIDR.
func clusterHasIPv6(t *testing.T) bool {
	t.Helper()
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	for _, n := range nodes.Items {
		for _, c := range n.Spec.PodCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is6() {
				return true
			}
		}
	}
	return false
}

// vipProbePod returns a kloak pod running the raw TLS demo's image (for its
// Python), mounting each of secrets at /etc/secrets/<secret>.
func vipProbePod(name string, secrets ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    map[string]string{"getkloak.io/enabled": "true"},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:            "app",
				Image:           "kloak-demo-python-raw-tls:latest",
				ImagePullPolicy: corev1.PullNever,
				Command:         []string{"python", "-c", "import time; time.sleep(3600)"},
			}},
		},
	}
	for _, secret := range secrets {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name:         secret,
			VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret}},
		})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{Name: secret, MountPath: "/etc/secrets/" + secret, ReadOnly: true})
	}
	return pod
}

func createVIPProbePod(t *testing.T, pod *corev1.Pod) {
	t.Helper()
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating pod %s: %v", pod.Name, err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
	})
}

// controllerVirtualIPRange returns the IPv4 virtual IP range the controller
// is deployed with, and skips the test unless it runs in virtual-ip mode.
func controllerVirtualIPRange(t *testing.T) netip.Prefix {
	t.Helper()
	v4, _ := controllerVirtualIPRanges(t)
	return v4
}

// controllerVirtualIPRanges returns the IPv4 and IPv6 virtual IP ranges the
// controller is deployed with (v6 is the zero Prefix without one), and skips
// the test unless it runs in virtual-ip mode.
func controllerVirtualIPRanges(t *testing.T) (v4, v6 netip.Prefix) {
	t.Helper()
	ds, err := clientset.AppsV1().DaemonSets(kloakNamespace).Get(context.Background(), "kloak-controller", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting controller DaemonSet: %v", err)
	}
	mode, vipRange := "dns-snoop", "198.18.0.0/15,2001:2::/48"
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name != "controller" {
			continue
		}
		for _, a := range c.Args {
			if v, ok := strings.CutPrefix(a, "--host-resolution="); ok {
				mode = v
			}
			if v, ok := strings.CutPrefix(a, "--virtual-ip-range="); ok {
				vipRange = v
			}
		}
	}
	if mode != "virtual-ip" {
		t.Skipf("controller runs with --host-resolution=%s", mode)
	}
	for _, part := range strings.Split(vipRange, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			t.Fatalf("controller --virtual-ip-range=%s: %v", vipRange, err)
		}
		if p.Addr().Is4() {
			v4 = p
		} else {
			v6 = p
		}
	}
	return v4, v6
}

// controllerPod returns the name of the (single-node) cluster's running
// controller pod.
func controllerPod(t *testing.T) string {
	t.Helper()
	pods, err := clientset.CoreV1().Pods(kloakNamespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=controller",
	})
	if err != nil {
		t.Fatalf("listing controller pods: %v", err)
	}
	for _, p := range pods.Items {
		if p.DeletionTimestamp == nil && p.Status.Phase == "Running" {
			return p.Name
		}
	}
	t.Fatalf("no running controller pod among %d", len(pods.Items))
	return ""
}

// controllerUsesNRI reports whether the controller pod connected to the
// container runtime through NRI.
func controllerUsesNRI(t *testing.T, pod string) bool {
	t.Helper()
	logs, err := kubectl("logs", "-n", kloakNamespace, pod, "-c", "controller", "--tail=-1")
	if err != nil {
		t.Fatalf("controller logs: %v", err)
	}
	return strings.Contains(logs, "connected to the container runtime through NRI")
}

var virtualIPLogIP = regexp.MustCompile(`"ip":\s*"([0-9a-fA-F.:]+)"`)

// waitForVirtualIPLog waits for pod's controller log to have a line with one
// of msgs for host and an IP in r (a host has one fake IP per family), and
// returns the IP of the last such line.
func waitForVirtualIPLog(t *testing.T, pod, host string, r netip.Prefix, msgs ...string) netip.Addr {
	t.Helper()
	hostField := regexp.MustCompile(`"host":\s*"` + regexp.QuoteMeta(host) + `"`)
	deadline := time.Now().Add(90 * time.Second)
	var logs string
	for time.Now().Before(deadline) {
		logs, _ = kubectl("logs", "-n", kloakNamespace, pod, "-c", "controller", "--tail=-1")
		var found netip.Addr
		for _, line := range strings.Split(logs, "\n") {
			if !hostField.MatchString(line) || !slices.ContainsFunc(msgs, func(m string) bool { return strings.Contains(line, m) }) {
				continue
			}
			if m := virtualIPLogIP.FindStringSubmatch(line); m != nil {
				if ip, err := netip.ParseAddr(m[1]); err == nil && r.Contains(ip) {
					found = ip
				}
			}
		}
		if found.IsValid() {
			return found
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("controller %s did not log %q for %s in %s; last logs:\n%s", pod, msgs, host, r, lastLines(logs, 40))
	return netip.Addr{}
}
