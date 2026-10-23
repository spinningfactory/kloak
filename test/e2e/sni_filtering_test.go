//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEBPFSNIFiltering checks the SNI check (spinningfactory/kloak#328): a
// secret restricted to a hostname is only rewritten on a connection whose
// TLS ClientHello names that host.
//
// The raw TLS demo first connects to the echo Service by its full name with
// a matching SNI (positive control: the allowed secret is rewritten). It is
// then patched to send SNI "evil.example" on the same connection, made to
// the name's virtual IP, which is what a compromised pod would do to reach
// another tenant behind a shared front end: the connection still passes the
// host check, but the rewrite must be refused and the controller must log it.
func TestEBPFSNIFiltering(t *testing.T) {
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")

	echoHostFQDN := "tls." + testNamespace + ".svc.cluster.local"
	const (
		realAllowed = "REAL-SNI-ALLOWED-KEY-12345"
		realBlocked = "REAL-SNI-BLOCKED-KEY-67890"
		evilSNI     = "evil.example"
	)
	allowedData := map[string][]byte{"api-key": []byte(realAllowed)}
	blockedData := map[string][]byte{"api-key": []byte(realBlocked)}
	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": echoHostFQDN,
	})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
		"getkloak.io/hosts": "example.com",
	})
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

	// Positive control: SNI == host, so the allowed secret is rewritten.
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-python-raw-tls", "sni-match",
		"timed out waiting for the allowed secret with a matching SNI",
		func(s string) bool { return strings.Contains(s, realAllowed) })
	if strings.Contains(out, realBlocked) {
		t.Errorf("blocked secret should NOT be rewritten (host mismatch)")
	}

	// Same destination, different SNI. Changing the pod template rolls the
	// deployment.
	patch := `{"spec":{"template":{"spec":{"containers":[{"name":"demo-app","env":[{"name":"TLS_SERVER_NAME","value":"` + evilSNI + `"}]}]}}}}`
	if out, err := kubectl("patch", "deployment", "demo-python-raw-tls", "-n", testNamespace, "-p", patch); err != nil {
		t.Fatalf("failed to patch TLS_SERVER_NAME: %v\n%s", err, out)
	}
	if out, err := kubectl("rollout", "status", "deployment/demo-python-raw-tls", "-n", testNamespace, "--timeout=120s"); err != nil {
		t.Fatalf("demo-python-raw-tls rollout failed: %v\n%s", err, out)
	}

	// Requests sent with the evil SNI must echo the placeholder, never the
	// real value. Wait for a few of them so the uprobe and tc had their chance.
	const wantRequests = 3
	evilCtx, evilCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer evilCancel()
	var evilBlocks []string
	pollDemoLogs(t, evilCtx, "app=demo-python-raw-tls", "sni-mismatch",
		"timed out waiting for requests sent with a mismatched SNI",
		func(s string) bool {
			evilBlocks = requestBlocksWithSNI(s, evilSNI)
			return len(evilBlocks) >= wantRequests
		})
	for _, b := range evilBlocks {
		if strings.Contains(b, realAllowed) {
			t.Errorf("allowed secret was rewritten on a connection with SNI %q:\n%s", evilSNI, b)
		}
		if !strings.Contains(b, "ALLOWED=kl::") {
			t.Errorf("expected the allowed secret's placeholder in the echo:\n%s", b)
		}
	}

	// The refusal is reported by the controller.
	logCtx, logCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer logCancel()
	for {
		logs := controllerLogs()
		if strings.Contains(logs, "SNI check violation (rewrite refused)") && strings.Contains(logs, evilSNI) {
			break
		}
		select {
		case <-logCtx.Done():
			t.Fatalf("controller did not log the SNI check violation:\n%s", logs)
		case <-time.After(pollInterval):
		}
	}
}

// requestBlocksWithSNI splits raw TLS demo logs into per-request blocks
// ("--- Request #N (target=..., sni=...) ---" plus the echo) and returns the
// ones sent with the given SNI that got an echo back.
func requestBlocksWithSNI(logs, sni string) []string {
	var blocks []string
	for _, b := range strings.Split(logs, "--- Request #")[1:] {
		header, _, _ := strings.Cut(b, "\n")
		if strings.Contains(header, "sni="+sni+")") && strings.Contains(b, "Echo: ") {
			blocks = append(blocks, b)
		}
	}
	return blocks
}
