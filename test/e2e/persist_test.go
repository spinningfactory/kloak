//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rawTLSEverySecond is the raw TLS demo writing once a second.
func rawTLSEverySecond(manifest string) string {
	return strings.Replace(manifest,
		"- name: REQUEST_INTERVAL\n              value: \"5\"",
		"- name: REQUEST_INTERVAL\n              value: \"1\"", 1)
}

// echoLines returns the demo's request outcomes logged since since: its
// "Echo:" and "Error:" lines, with kubectl's timestamps.
func echoLines(t *testing.T, appLabel string, since time.Time) []string {
	t.Helper()
	out, err := kubectl("logs", "-n", testNamespace, "-l", appLabel, "--timestamps",
		"--since-time="+since.UTC().Format(time.RFC3339), "--tail=-1")
	if err != nil {
		t.Fatalf("reading the demo's logs: %v: %s", err, out)
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Echo:") || strings.Contains(l, "Error:") {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestControllerRestartKeepsRewriting restarts the controller while a pod
// writes a secret every second, and checks that every write in the window
// was rewritten (spinningfactory/kloak#107): the old controller keeps its
// eBPF data plane attached, and the new one adopts it.
func TestControllerRestartKeepsRewriting(t *testing.T) {
	echoHostFQDN := "tls." + testNamespace + ".svc.cluster.local"
	const real = "REAL-RESTART-KEY-0001"
	// An earlier test's shadows must be gone: the demo would mount them.
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")
	allowed := map[string][]byte{"api-key": []byte(real)}
	blocked := map[string][]byte{"api-key": []byte("REAL-RESTART-BLOCKED-01")}
	createEnabledSecret(t, "secret-allowed", allowed, nil, map[string]string{"getkloak.io/hosts": echoHostFQDN})
	createEnabledSecret(t, "secret-blocked", blocked, nil, map[string]string{"getkloak.io/hosts": "example.com"})
	assertShadowSecret(t, "secret-allowed", allowed)
	assertShadowSecret(t, "secret-blocked", blocked)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-raw-tls", "deployment.yaml")
	if err := applyManifestTransformed(t, demoManifest, rawTLSEverySecond); err != nil {
		t.Fatalf("deploying demo-python-raw-tls: %v", err)
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
	pollDemoLogs(t, pollCtx, "app=demo-python-raw-tls", "restart",
		"the secret was never rewritten before the restart",
		func(s string) bool { return strings.Contains(s, "ALLOWED="+real) })

	start := time.Now()
	if out, err := kubectl("rollout", "restart", "daemonset/kloak-controller", "-n", kloakNamespace); err != nil {
		t.Fatalf("restarting the controller: %v: %s", err, out)
	}
	if out, err := kubectl("rollout", "status", "daemonset/kloak-controller", "-n", kloakNamespace, "--timeout=180s"); err != nil {
		t.Fatalf("waiting for the controller's rollout: %v: %s", err, out)
	}
	// Writes made after the new controller is ready, while it reconciles.
	time.Sleep(15 * time.Second)

	lines := echoLines(t, "app=demo-python-raw-tls", start)
	elapsed := time.Since(start)
	if len(lines) < int(elapsed/time.Second)/2 {
		t.Fatalf("only %d requests in the %s window: the demo stalled\n%s", len(lines), elapsed.Round(time.Second), strings.Join(lines, "\n"))
	}
	var bad []string
	for _, l := range lines {
		if !strings.Contains(l, "ALLOWED="+real) {
			bad = append(bad, l)
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d of %d requests in the %s window were not rewritten:\n%s\n=== Controller logs ===\n%s",
			len(bad), len(lines), elapsed.Round(time.Second), strings.Join(bad, "\n"), controllerLogs())
	}
	t.Logf("%d requests in the %s window, all rewritten", len(lines), elapsed.Round(time.Second))

	// The new controller adopted the pinned data plane, rather than
	// attaching it again quickly. Its whole log: the line is at its start.
	logs, err := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller",
		"-c", "controller", "--tail=-1")
	if err != nil {
		t.Fatalf("reading the controller's logs: %v", err)
	}
	var pinned string
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, "BPF programs are pinned") {
			pinned = l
		}
	}
	if !strings.Contains(pinned, `"adopted": true`) && !strings.Contains(pinned, `"adopted":true`) {
		t.Errorf("the new controller did not adopt the pinned eBPF objects: %q\n=== Controller logs ===\n%s", pinned, controllerLogs())
	}
}
