//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEBPFSecretRewrite(t *testing.T) {
	// This test requires --enable-ebpf=true and a demo app that makes HTTPS requests.
	// It verifies that the eBPF uprobe replaces kloak:UUID with the real secret value.

	// Create secrets with host restrictions.
	// Key must be "api-key" to match the demo-go deployment's volume mount paths.
	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-67890")}

	createEnabledSecret(t, "secret-allowed", allowedData, map[string]string{
		"getkloak.io/hosts": "httpbin.org",
	})
	createEnabledSecret(t, "secret-blocked", blockedData, map[string]string{
		"getkloak.io/hosts": "example.com",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	// Deploy the demo-go app
	demoManifest := filepath.Join(repoRoot, "examples", "demo-go", "deployment.yaml")
	_, err := kubectl("apply", "-f", demoManifest, "-n", testNamespace)
	if err != nil {
		t.Fatalf("failed to deploy demo-go: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	// Wait for demo app to start and make requests
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-go"); err != nil {
		t.Fatalf("demo-go not ready: %v", err)
	}

	// Dump controller logs to see eBPF status (uprobe attachment, errors, etc.)
	ctrlLogs, _ := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=100")
	t.Logf("=== Controller logs ===\n%s", ctrlLogs)

	// Wait for demo-go startup delay (15s) + a few request cycles (5s each).
	// Also give the controller time to sync secrets to the BPF map and
	// attach uprobes after the pod is detected.
	time.Sleep(45 * time.Second)

	// Dump controller logs AFTER requests have been made to see rewrite events
	ctrlLogsAfter, _ := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=200")
	t.Logf("=== Controller logs (after requests) ===\n%s", ctrlLogsAfter)

	// Read demo app logs
	out, err := kubectl("logs", "-n", testNamespace, "-l", "app=demo-go", "--tail=50")
	if err != nil {
		t.Fatalf("failed to read demo-go logs: %v", err)
	}
	t.Logf("=== Demo app logs ===\n%s", out)

	// The allowed secret should be rewritten to the real value
	if !strings.Contains(out, "REAL-ALLOWED-KEY-12345") {
		t.Errorf("demo-go logs should contain the real allowed secret (eBPF should have replaced it)")
	}

	// The blocked secret should NOT be rewritten (wrong host restriction)
	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("demo-go logs should NOT contain the real blocked secret (host restriction should prevent replacement)")
	}
}
