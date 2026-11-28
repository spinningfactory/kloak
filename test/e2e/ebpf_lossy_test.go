//go:build e2e_ebpf

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TestEBPFLossyNetwork runs the network conditions under which a record
// leaves in several skbs, or a patched segment is lost and retransmitted,
// on a real stack: the end-to-end form of the tc gaps kloak#383 found
// (pkg/ebpf/tc_patch_gaps_bpf_test.go rows c, d, e), and the target of its
// phase 2 (the tc ledger). It counts, per scenario, how many requests came
// back rewritten, unrewritten (the shadow), or failed (bad_record_mac,
// reset, timeout).
//
// kloak patches at tc ingress on the host side of the client pod's veth.
//   - Loss: netem on the echo server pod's host-side veth, egress: the
//     segments it drops have been patched, and TCP retransmits them from its
//     own queue, which tc's patches never reach, through tc again.
//   - Segments: the client pod's eth0 with TSO/GSO off and a 1000-byte MTU,
//     so that tc sees each MSS-sized segment instead of a GSO packet that
//     holds the whole record.
//
// Both are set from the node, by a privileged helper pod (busybox, hostPID)
// that runs the node's own ip, tc and ethtool (nsenter -t 1): the test needs
// E2E_NETEM=1, a node with those and sch_netem, and one node for the
// helper, the server and the clients (they are pinned to the server's).
//
// Today it asserts what must hold whatever the network does: no request
// gets a wrong secret back, and the blocked secret's real value never
// reaches a host it is not for; on a clean network, every request is
// rewritten. E2E_EXPECT_LEDGER=1 (phase 2) asserts every request of every
// scenario is. E2E_LOSSY_REPORT=<file> writes the results as JSON lines.
func TestEBPFLossyNetwork(t *testing.T) {
	if os.Getenv("E2E_NETEM") != "1" {
		t.Skip("E2E_NETEM=1 runs the lossy network scenarios (privileged helper pod, netem)")
	}
	expectLedger := os.Getenv("E2E_EXPECT_LEDGER") == "1"

	echo, node := deployLossyEcho(t)
	shell := newNodeShell(t, node)
	if out, err := shell.run("command -v ip && command -v tc && command -v ethtool && modprobe sch_netem"); err != nil {
		t.Skipf("the node lacks ip, tc, ethtool or sch_netem: %v\n%s", err, out)
	}

	// Two allowed secrets for the echo host: 128 bytes, today's maximum,
	// and 100 bytes; and one for another host, which must never be
	// rewritten towards the echo.
	reals := map[string]string{
		"lossy-128":     secretOfLen("LOSSY", 128),
		"lossy-100":     secretOfLen("LOSSY", 100),
		"lossy-blocked": secretOfLen("BLOCKE", 100),
	}
	for name, real := range reals {
		host := echo.fqdn
		if name == "lossy-blocked" {
			host = "example.com"
		}
		data := map[string][]byte{"api-key": []byte(real)}
		createEnabledSecret(t, name, data, nil, map[string]string{"getkloak.io/hosts": host})
		assertShadowSecret(t, name, data)
	}

	scenarios := []lossyScenario{
		{name: "clean network, 128-byte secret", secret: "lossy-128", requests: 100, control: true},
		{name: "1% loss, 128-byte secret", secret: "lossy-128", loss: "1%", requests: 400},
		{name: "5% loss, 128-byte secret", secret: "lossy-128", loss: "5%", requests: 400},
		// One ~4.1 KiB record, the secret at its end: ~5 segments.
		{name: "4 KiB record, 1000-byte MTU", secret: "lossy-100", mtu: 1000, oneRecord: true, before: 4000, requests: 100},
		{name: "4 KiB record, 1000-byte MTU, 5% loss", secret: "lossy-100", mtu: 1000, oneRecord: true, before: 4000, loss: "5%", requests: 200},
		// The secret at the start: patched in the first segment, the tag
		// deferred to the last. The record's size varies over an MSS (948
		// bytes at this MTU), so that ~16 in 948 records have their tag
		// split across two segments; with loss, the patched first segment
		// is retransmitted unpatched.
		{name: "4 KiB record, secret at its start, 1000-byte MTU", secret: "lossy-100", mtu: 1000, oneRecord: true, after: 4000, spread: 948, requests: 400},
		{name: "4 KiB record, secret at its start, 1000-byte MTU, 5% loss", secret: "lossy-100", mtu: 1000, oneRecord: true, after: 4000, spread: 948, loss: "5%", requests: 400},
		// A new connection's first record holds ~1.2 KB (Go's dynamic
		// record sizing): the secret is in its second record.
		{name: "new Go connections, 1.3 KiB before the secret", secret: "lossy-100", fresh: true, before: 1300, requests: 100},
		{name: "new Go connections, 1.3 KiB before the secret, 1000-byte MTU", secret: "lossy-100", fresh: true, before: 1300, mtu: 1000, requests: 100},
	}
	var results []lossyResult
	for i, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			if err := echo.setLoss(shell, sc.loss); err != nil {
				t.Fatal(err)
			}
			res := runLossyClient(t, shell, node, echo, sc, i, reals)
			results = append(results, res)
			t.Logf("%s", res)
			if n := res.Counts["wrong"]; n > 0 {
				t.Errorf("%d requests got a wrong secret back", n)
			}
			if n := res.Counts["blocked_leak"]; n > 0 {
				t.Errorf("%d requests carried the blocked secret's real value to the echo host", n)
			}
			if (sc.control || expectLedger) && res.Counts["correct"] != res.Requests {
				t.Errorf("%d of %d requests rewritten, want all", res.Counts["correct"], res.Requests)
			}
		})
	}
	_ = echo.setLoss(shell, "")

	t.Logf("%-62s %8s %8s %8s %8s %8s %8s", "scenario", "correct", "shadow", "bad MAC", "reset", "timeout", "other")
	for _, r := range results {
		t.Logf("%-62s %8s %8s %8s %8s %8s %8s", r.Scenario, r.pct("correct"), r.pct("shadow"), r.pct("bad_record_mac"),
			r.pct("reset"), r.pct("timeout"), r.pct("other_error", "wrong", "blocked_leak"))
	}
	if path := os.Getenv("E2E_LOSSY_REPORT"); path != "" {
		var lines []string
		for _, r := range results {
			b, _ := json.Marshal(r)
			lines = append(lines, string(b))
		}
		if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			t.Errorf("writing %s: %v", path, err)
		}
	}
}

// lossyScenario is one network condition and request shape.
type lossyScenario struct {
	name      string
	secret    string // the allowed secret's name
	loss      string // netem loss on the server's veth ("5%"), or none
	mtu       int    // the client pod's MTU, with TSO/GSO off; 0: unchanged
	oneRecord bool   // dynamic record sizing off: each message is one record
	fresh     bool   // a new connection for each request
	before    int    // filler bytes before the secret
	after     int    // filler bytes after the secrets
	spread    int    // vary after over this many bytes, request to request
	requests  int
	control   bool // a clean network: every request must be rewritten
}

// lossyResult is the client's RESULT line (test/e2e/lossy-tls).
type lossyResult struct {
	Scenario     string         `json:"scenario"`
	Requests     int            `json:"requests"`
	Counts       map[string]int `json:"counts"`
	Errors       []string       `json:"errors,omitempty"`
	WarmupMillis int64          `json:"warmup_ms"`
}

func (r lossyResult) pct(outcomes ...string) string {
	n := 0
	for _, o := range outcomes {
		n += r.Counts[o]
	}
	if r.Requests == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", float64(n)*100/float64(r.Requests))
}

func (r lossyResult) String() string {
	keys := make([]string, 0, len(r.Counts))
	for k := range r.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, r.Counts[k]))
	}
	s := fmt.Sprintf("%s: %d requests: %s", r.Scenario, r.Requests, strings.Join(parts, ", "))
	if len(r.Errors) > 0 {
		s += "; errors: " + strings.Join(r.Errors, " | ")
	}
	return s
}

// nodeShell runs shell scripts on a node, as root in the node's own
// namespaces, through a privileged hostPID pod.
type nodeShell struct{ pod string }

func newNodeShell(t *testing.T, node string) nodeShell {
	t.Helper()
	privileged := true
	grace := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "lossy-node-shell",
			Namespace: testNamespace,
			// Test infrastructure, not a workload under test.
			Labels: map[string]string{"getkloak.io/enabled": "false"},
		},
		Spec: corev1.PodSpec{
			NodeName:                      node,
			HostPID:                       true,
			TerminationGracePeriodSeconds: &grace,
			Containers: []corev1.Container{{
				Name:            "shell",
				Image:           "busybox:latest",
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command:         []string{"sleep", "3600"},
				SecurityContext: &corev1.SecurityContext{Privileged: &privileged},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the node shell pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, pod.Name); err != nil {
		t.Skipf("the node shell pod (busybox, privileged, hostPID) did not start: %v", err)
	}
	return nodeShell{pod: pod.Name}
}

// nodeShellLib finds a pod's network namespace on the node by its IP.
const nodeShellLib = `
podns() {
  for n in $(ip netns list | awk '{print $1}'); do
    if ip -n "$n" -o addr show 2>/dev/null | grep -q " $1/"; then echo "$n"; return 0; fi
  done
  echo "no network namespace has $1" >&2
  return 1
}
`

func (s nodeShell) run(script string) (string, error) {
	return kubectl("exec", "-n", testNamespace, s.pod, "--",
		"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "sh", "-c", "set -e\n"+nodeShellLib+script)
}

// lossyEcho is the echo server: its Service's name, and its pod's IP.
type lossyEcho struct{ fqdn, podIP string }

func deployLossyEcho(t *testing.T) (lossyEcho, string) {
	t.Helper()
	const name = "lossy-echo"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			Labels:    map[string]string{"app": name, "getkloak.io/enabled": "false"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "echo",
				Image:           e2eImage("kloak-lossy-tls", "latest"),
				ImagePullPolicy: e2ePullPolicy(),
				Args:            []string{"server"},
				Ports:           []corev1.ContainerPort{{ContainerPort: 8443}},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler:  corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(8443)}},
					PeriodSeconds: 1,
				},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the echo pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": name},
			Ports:    []corev1.ServicePort{{Port: 8443, TargetPort: intstr.FromInt32(8443)}},
		},
	}
	if _, err := clientset.CoreV1().Services(testNamespace).Create(context.Background(), svc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the echo service: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Services(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, name); err != nil {
		t.Fatalf("echo server not ready: %v", err)
	}
	p, err := clientset.CoreV1().Pods(testNamespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return lossyEcho{fqdn: fmt.Sprintf("%s.%s.svc.cluster.local", name, testNamespace), podIP: p.Status.PodIP}, p.Spec.NodeName
}

// setLoss puts netem (loss and a 5 ms delay) on the egress of the echo pod's
// host-side veth, or removes it.
func (e lossyEcho) setLoss(s nodeShell, loss string) error {
	qdisc := "tc qdisc del dev \"$veth\" root 2>/dev/null || true"
	if loss != "" {
		qdisc = fmt.Sprintf("tc qdisc replace dev \"$veth\" root netem loss %s delay 5ms", loss)
	}
	out, err := s.run(fmt.Sprintf(`
ns=$(podns %s)
idx=$(ip -n "$ns" -o link show dev eth0 | sed -n 's/^[0-9]*: eth0@if\([0-9]*\):.*/\1/p')
veth=$(ip -o link show | awk -F': ' -v i="$idx" '$1 == i { sub(/@.*/, "", $2); print $2 }')
[ -n "$veth" ] || { echo "no host-side veth for the echo pod (index $idx)" >&2; exit 1; }
%s
tc qdisc show dev "$veth"
`, e.podIP, qdisc))
	if err != nil {
		return fmt.Errorf("netem %q on the echo's veth: %v\n%s", loss, err, out)
	}
	return nil
}

// runLossyClient runs one scenario's client pod to completion and returns
// its result.
func runLossyClient(t *testing.T, shell nodeShell, node string, echo lossyEcho, sc lossyScenario, i int, reals map[string]string) lossyResult {
	t.Helper()
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	envs := map[string]string{
		"SECRET_FILE":         "/etc/secrets/allowed/api-key",
		"BLOCKED_FILE":        "/etc/secrets/blocked/api-key",
		"TARGET":              echo.fqdn + ":8443",
		"SERVER_NAME":         echo.fqdn,
		"REAL_SHA256":         sum(reals[sc.secret]),
		"BLOCKED_REAL_SHA256": sum(reals["lossy-blocked"]),
		"REQUESTS":            strconv.Itoa(sc.requests),
		"FILLER_BEFORE":       strconv.Itoa(sc.before),
		"FILLER_AFTER":        strconv.Itoa(sc.after),
		"AFTER_SPREAD":        strconv.Itoa(sc.spread),
	}
	if sc.fresh {
		envs["FRESH_CONN"] = "1"
	}
	if sc.oneRecord {
		envs["DYNAMIC_RECORDS"] = "0"
	}
	if sc.mtu > 0 {
		envs["WAIT_MTU"] = strconv.Itoa(sc.mtu)
	}
	var env []corev1.EnvVar
	for k, v := range envs {
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}
	name := fmt.Sprintf("lossy-client-%d", i)
	secretVolume := func(vol, secret string) corev1.Volume {
		return corev1.Volume{Name: vol, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secret}}}
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace, Labels: map[string]string{"app": "lossy-client"}},
		Spec: corev1.PodSpec{
			NodeName:      node,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{{
				Name:            "client",
				Image:           e2eImage("kloak-lossy-tls", "latest"),
				ImagePullPolicy: e2ePullPolicy(),
				Args:            []string{"client"},
				Env:             env,
				VolumeMounts: []corev1.VolumeMount{
					{Name: "allowed", MountPath: "/etc/secrets/allowed", ReadOnly: true},
					{Name: "blocked", MountPath: "/etc/secrets/blocked", ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{secretVolume("allowed", sc.secret), secretVolume("blocked", "lossy-blocked")},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the client pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	segmented := sc.mtu == 0
	for {
		p, err := clientset.CoreV1().Pods(testNamespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("client pod: %v", err)
		}
		if !segmented && p.Status.PodIP != "" && p.Status.Phase == corev1.PodRunning {
			// TSO/GSO off first: the client starts when it sees the MTU.
			out, err := shell.run(fmt.Sprintf(`
ns=$(podns %s)
ip netns exec "$ns" ethtool -K eth0 tso off gso off
ip -n "$ns" link set dev eth0 mtu %d
ip netns exec "$ns" ethtool -k eth0 | grep -E '^(tcp|generic)-segmentation-offload'
`, p.Status.PodIP, sc.mtu))
			if err != nil {
				t.Fatalf("segmenting the client pod's traffic: %v\n%s", err, out)
			}
			t.Logf("client eth0: mtu %d\n%s", sc.mtu, out)
			segmented = true
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			break
		}
		select {
		case <-ctx.Done():
			out, _ := kubectl("logs", "-n", testNamespace, name, "--tail=50")
			t.Fatalf("client pod still %s after 6 minutes:\n%s", p.Status.Phase, out)
		case <-time.After(pollInterval):
		}
	}
	out, err := kubectl("logs", "-n", testNamespace, name)
	if err != nil {
		t.Fatalf("client logs: %v", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if j, ok := strings.CutPrefix(line, "RESULT "); ok {
			r := lossyResult{Scenario: sc.name}
			if err := json.Unmarshal([]byte(j), &r); err != nil {
				t.Fatalf("client result %q: %v", j, err)
			}
			r.Scenario = sc.name
			return r
		}
	}
	t.Logf("=== Controller logs ===\n%s", controllerLogs())
	t.Fatalf("the client printed no result:\n%s", clipLog(out))
	return lossyResult{}
}
