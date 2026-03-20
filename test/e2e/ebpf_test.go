//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// controllerLogs fetches the latest controller log output.
func controllerLogs() string {
	out, _ := kubectl("logs", "-n", kloakNamespace, "-l",
		"app.kubernetes.io/component=controller", "--tail=200")
	return out
}

// ebpfRewriteTest describes a single eBPF rewrite test case for a specific runtime.
type ebpfRewriteTest struct {
	name           string
	demoDir        string
	deploymentName string
	appLabel       string
}

var ebpfTests = []ebpfRewriteTest{
	{
		name:           "go",
		demoDir:        "demo-go",
		deploymentName: "demo-go",
		appLabel:       "app=demo-go",
	},
	{
		name:           "python",
		demoDir:        "demo-python",
		deploymentName: "demo-python",
		appLabel:       "app=demo-python",
	},
	{
		name:           "js",
		demoDir:        "demo-js",
		deploymentName: "demo-js",
		appLabel:       "app=demo-js",
	},
	{
		name:           "go-boringssl",
		demoDir:        "demo-go-boring",
		deploymentName: "demo-go-boring",
		appLabel:       "app=demo-go-boring",
	},
}

// TestEBPFSNIHostFiltering tests that SNI-based host filtering works for
// non-HTTP TLS protocols. The demo app uses raw TLS sockets (no HTTP)
// with a local echo server. The only hostname source is SSL_set_tlsext_host_name.
func TestEBPFSNIHostFiltering(t *testing.T) {
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

	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-sni", "deployment.yaml")
	_, err := kubectl("apply", "-f", demoManifest, "-n", testNamespace)
	if err != nil {
		t.Fatalf("failed to deploy demo-python-sni: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-sni"); err != nil {
		t.Fatalf("demo-python-sni not ready: %v", err)
	}

	// Poll app logs for the real secret value
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer pollCancel()
	var out string
	for {
		select {
		case <-pollCtx.Done():
			t.Logf("=== demo-python-sni final logs ===\n%s", out)
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("timed out waiting for allowed secret in SNI demo logs")
		default:
		}
		out, _ = kubectl("logs", "-n", testNamespace, "-l", "app=demo-python-sni", "--tail=200")
		if strings.Contains(out, "REAL-ALLOWED-KEY-12345") {
			break
		}
		time.Sleep(pollInterval)
	}
	t.Logf("=== demo-python-sni logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret should NOT be rewritten (host mismatch)")
	}
}

func TestEBPFSecretRewrite(t *testing.T) {
	// Wait for stale shadows from previous tests to be garbage-collected
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")

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

	for _, tc := range ebpfTests {
		t.Run(tc.name, func(t *testing.T) {
			runEBPFRewriteTest(t, tc)
		})
	}
}

func runEBPFRewriteTest(t *testing.T, tc ebpfRewriteTest) {
	demoManifest := filepath.Join(repoRoot, "examples", tc.demoDir, "deployment.yaml")
	_, err := kubectl("apply", "-f", demoManifest, "-n", testNamespace)
	if err != nil {
		t.Fatalf("failed to deploy %s: %v", tc.demoDir, err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, tc.deploymentName); err != nil {
		demoDesc, _ := kubectl("describe", "deployment", "-n", testNamespace, tc.deploymentName)
		t.Logf("deployment describe:\n%s", demoDesc)
		t.Fatalf("%s not ready: %v", tc.deploymentName, err)
	}

	// Poll app logs for the real secret value (definitive per-app check).
	// This replaces the old arbitrary sleep — we poll until the app has
	// made at least one request and the eBPF rewrite is visible in output.
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer pollCancel()
	var out string
	for {
		select {
		case <-pollCtx.Done():
			t.Logf("=== %s final logs ===\n%s", tc.name, out)
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("[%s] timed out waiting for allowed secret in app logs", tc.name)
		default:
		}
		out, _ = kubectl("logs", "-n", testNamespace, "-l", tc.appLabel, "--tail=200")
		if strings.Contains(out, "REAL-ALLOWED-KEY-12345") {
			break
		}
		time.Sleep(pollInterval)
	}
	t.Logf("=== %s demo app logs ===\n%s", tc.name, out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("[%s] logs should NOT contain the real blocked secret", tc.name)
	}

	// Clean up deployment before next subtest
	_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	time.Sleep(2 * time.Second)
}

// TestEBPFSecretLengths verifies that secrets of different lengths (8 to 100 bytes)
// are correctly rewritten. Runs last to avoid secret name collisions.
func TestEBPFSecretLengths(t *testing.T) {
	type lengthCase struct {
		name    string
		allowed string
		blocked string
	}
	cases := []lengthCase{
		{"8bytes", "SECRET-8", "BLOCKED8"},
		{"16bytes", "SECRET-16B-ABCDE", "BLOCKE-16B-FGHIJ"},
		{"21bytes", "SECRET-21B-ABCDEFGHIJ", "BLOCKE-21B-KLMNOPQRST"},
		{"42bytes", "SECRET-42B-ABCDEFGHIJKLMNOPQRSTUVWXYZABCDE", "BLOCKE-42B-FGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ"},
		{"100bytes", "SECRET-100B-ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ", "BLOCKE-100B-KLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRST"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Wait for stale secrets and shadows from previous tests to be cleaned up
			gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer gcCancel()
			_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed")
			_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked")
			_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
			_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")

			allowedData := map[string][]byte{"api-key": []byte(tc.allowed)}
			blockedData := map[string][]byte{"api-key": []byte(tc.blocked)}

			createEnabledSecret(t, "secret-allowed", allowedData, map[string]string{
				"getkloak.io/hosts": "httpbin.org",
			})
			createEnabledSecret(t, "secret-blocked", blockedData, map[string]string{
				"getkloak.io/hosts": "example.com",
			})

			assertShadowSecret(t, "secret-allowed", allowedData)
			assertShadowSecret(t, "secret-blocked", blockedData)

			demoManifest := filepath.Join(repoRoot, "examples", "demo-python-sni", "deployment.yaml")
			_, err := kubectl("apply", "-f", demoManifest, "-n", testNamespace)
			if err != nil {
				t.Fatalf("failed to deploy: %v", err)
			}
			t.Cleanup(func() {
				_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
				time.Sleep(2 * time.Second)
			})

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-sni"); err != nil {
				t.Fatalf("deployment not ready: %v", err)
			}

			// Check prefix to poll for (use first 20 chars for long secrets)
			allowedCheck := tc.allowed
			if len(allowedCheck) > 20 {
				allowedCheck = allowedCheck[:20]
			}
			blockedCheck := tc.blocked
			if len(blockedCheck) > 20 {
				blockedCheck = blockedCheck[:20]
			}

			// Poll app logs for the allowed secret prefix
			pollCtx, pollCancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer pollCancel()
			var out string
			for {
				select {
				case <-pollCtx.Done():
					t.Logf("=== python-sni-%s final logs ===\n%s", tc.name, out)
					t.Logf("=== Controller logs ===\n%s", controllerLogs())
					t.Fatalf("allowed secret (%d bytes) not rewritten — prefix %q not found", len(tc.allowed), allowedCheck)
				default:
				}
				out, _ = kubectl("logs", "-n", testNamespace, "-l", "app=demo-python-sni", "--tail=200")
				if strings.Contains(out, allowedCheck) {
					break
				}
				time.Sleep(pollInterval)
			}
			t.Logf("=== python-sni-%s logs ===\n%s", tc.name, out)

			if strings.Contains(out, blockedCheck) {
				t.Errorf("blocked secret (%d bytes) should NOT be rewritten — prefix %q found in logs", len(tc.blocked), blockedCheck)
			}
		})
	}
}
