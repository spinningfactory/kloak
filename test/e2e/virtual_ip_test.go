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
	ip := waitForVirtualIPLog(t, oldPod, host, "allocated virtual IP", "reactivated virtual IP")
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
	if restored := waitForVirtualIPLog(t, newPod, host, "restored virtual IP"); restored != ip {
		t.Fatalf("after a controller restart %s has %s, was %s", host, restored, ip)
	}

	// No secret uses the host any more: its IP is retired, not reused.
	if err := clientset.CoreV1().Secrets(testNamespace).Delete(context.Background(), "secret-vip", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting secret: %v", err)
	}
	if retired := waitForVirtualIPLog(t, newPod, host, "retired virtual IP"); retired != ip {
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

// controllerVirtualIPRange returns the virtual IP range the controller is
// deployed with, and skips the test unless it runs in virtual-ip mode.
func controllerVirtualIPRange(t *testing.T) netip.Prefix {
	t.Helper()
	ds, err := clientset.AppsV1().DaemonSets(kloakNamespace).Get(context.Background(), "kloak-controller", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting controller DaemonSet: %v", err)
	}
	mode, vipRange := "dns-snoop", "198.18.0.0/15"
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
	p, err := netip.ParsePrefix(vipRange)
	if err != nil {
		t.Fatalf("controller --virtual-ip-range=%s: %v", vipRange, err)
	}
	return p
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

var virtualIPLogIP = regexp.MustCompile(`"ip":\s*"([0-9a-fA-F.:]+)"`)

// waitForVirtualIPLog waits for pod's controller log to have a line with one
// of msgs for host, and returns the IP of the last such line.
func waitForVirtualIPLog(t *testing.T, pod, host string, msgs ...string) netip.Addr {
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
				if ip, err := netip.ParseAddr(m[1]); err == nil {
					found = ip
				}
			}
		}
		if found.IsValid() {
			return found
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("controller %s did not log %q for %s; last logs:\n%s", pod, msgs, host, lastLines(logs, 40))
	return netip.Addr{}
}
