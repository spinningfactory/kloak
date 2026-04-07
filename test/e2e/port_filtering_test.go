//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEBPFRawTLSPortFiltering tests that port-based filtering works with
// raw TLS sockets. A TLS echo server runs as a sidecar behind a K8s Service.
// The client connects on a specific port, and the port is verified at
// connect() time to enable port-based secret filtering.
func TestEBPFRawTLSPortFiltering(t *testing.T) {
	echoHostFQDN := "tls." + testNamespace + ".svc.cluster.local"
	// The echo server runs on port 8443
	echoPort := "8443"
	wrongPort := "443"

	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-PORT-KEY")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-PORT-KEY")}

	createEnabledSecret(t, "secret-port-allowed", allowedData, map[string]string{
		"getkloak.io/hosts": echoHostFQDN,
		"getkloak.io/port": echoPort,
	})
	createEnabledSecret(t, "secret-port-blocked", blockedData, map[string]string{
		"getkloak.io/hosts": echoHostFQDN,
		"getkloak.io/port": wrongPort,
	})

	assertShadowSecret(t, "secret-port-allowed", allowedData)
	assertShadowSecret(t, "secret-port-blocked", blockedData)

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

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer pollCancel()
	var out string
	for {
		select {
		case <-pollCtx.Done():
			t.Logf("=== demo-python-raw-tls final logs ===\n%s", out)
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("timed out waiting for allowed secret in raw TLS demo logs")
		default:
		}
		out, _ = kubectl("logs", "-n", testNamespace, "-l", "app=demo-python-raw-tls", "--tail=200")
		if strings.Contains(out, "REAL-ALLOWED-PORT-KEY") {
			break
		}
		time.Sleep(pollInterval)
	}
	t.Logf("=== demo-python-raw-tls logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-PORT-KEY") {
		t.Errorf("blocked secret should NOT be rewritten (port mismatch)")
	}

	// Also verify the blocked secret's placeholder appears in the output
	// This confirms it was NOT rewritten (if it was, we'd see the real value)
	if !strings.Contains(out, "BLOCKED=") {
		t.Logf("output: %s", out)
		t.Errorf("blocked secret should have its placeholder value in the echo output")
	}
}
