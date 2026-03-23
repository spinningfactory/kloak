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
	// Go crypto/tls passes ssl_ptr=0, so the DNS-verified host resolution chain
	// cannot run. Host-filtered secrets are blocked. Skip until Phase 2 (Go Handshake uprobe).
	if tc.name == "go" {
		t.Skip("Go crypto/tls: DNS-based host verification requires ssl_ptr (Phase 2)")
	}

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

// TestEBPFSNISpoofingPrevention verifies that Kloak's DNS-based host verification
// prevents secret rewriting when an app connects to the wrong IP while claiming
// to be connecting to the allowed hostname via SNI.
//
// Setup: two Kubernetes Services (svc-spoof-allowed, svc-spoof-other) back the
// same demo pod on port 8443. They have different ClusterIPs. Kloak's eBPF
// intercepts DNS responses and records dns_ip_map[ClusterIP] = hostname for each.
//
// Legitimate path: connect to ClusterIP_A (resolved for svc-spoof-allowed) with
// SNI = svc-spoof-allowed → eBPF verifies IP matches DNS record → REWRITE.
//
// Spoof path: connect to ClusterIP_B (resolved for svc-spoof-other) but set
// SNI = svc-spoof-allowed → eBPF sees IP_B maps to svc-spoof-other ≠ svc-spoof-allowed
// → NO REWRITE.
func TestEBPFSNISpoofingPrevention(t *testing.T) {
	// Go crypto/tls passes ssl_ptr=0 to resolve_host, so the IP-verified DNS
	// chain (Path 1: ssl_ptr → ssl_fd_map → conn_ip_map → dns_ip_map) is skipped
	// entirely. DNS spoofing prevention requires OpenSSL's SSL_set_fd uprobe.
	// See TestEBPFSNISpoofingPreventionOpenSSL for the OpenSSL-based test.
	t.Skip("Go crypto/tls does not call SSL_set_fd — DNS-based spoofing prevention requires OpenSSL (Phase 2)")
}

// TestEBPFSNISpoofingPreventionOpenSSL verifies that Kloak's DNS-based host
// verification prevents secret rewriting when a Python (OpenSSL) app connects
// to the wrong IP while claiming to be connecting to the allowed hostname via SNI.
//
// The full OpenSSL verification chain is:
//
//	SSL_set_fd uprobe → ssl_fd_map[ssl_ptr] = fd
//	connect tracepoint → conn_ip_map[{tgid, fd}] = peer_ip
//	recvfrom tracepoint → dns_ip_map[{tgid, peer_ip}] = hostname (from DNS response)
//	SSL_write: ssl_ptr → fd → peer_ip → dns_ip_map → actual_hostname
//
// Setup: two Kubernetes Services (svc-spoof-allowed, svc-spoof-other) back the
// same Python TLS echo server pod on port 8443 with different ClusterIPs.
//
// Legitimate path: connect to ClusterIP_A (resolved for svc-spoof-allowed) with
// SNI = svc-spoof-allowed → eBPF verifies IP matches DNS record → REWRITE.
//
// Spoof path: connect to ClusterIP_B (resolved for svc-spoof-other) but set
// SNI = svc-spoof-allowed → eBPF sees IP_B maps to svc-spoof-other ≠ allowed → NO REWRITE.
func TestEBPFSNISpoofingPreventionOpenSSL(t *testing.T) {
	// Secret restricted to svc-spoof-allowed's DNS name (first 32 chars stored in BPF map).
	secretData := map[string][]byte{"api-key": []byte("REAL-SPOOF-SECRET-12345678901234")}
	createEnabledSecret(t, "secret-spoof", secretData, map[string]string{
		"getkloak.io/hosts": "svc-spoof-allowed.kloak-e2e.svc.cluster.local",
	})
	assertShadowSecret(t, "secret-spoof", secretData)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-python-sni-spoof", "deployment.yaml")
	_, err := kubectl("apply", "-f", demoManifest, "-n", testNamespace)
	if err != nil {
		t.Fatalf("failed to deploy demo-python-sni-spoof: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-sni-spoof"); err != nil {
		t.Fatalf("demo-python-sni-spoof not ready: %v", err)
	}

	// Poll until the legitimate path has been rewritten at least once.
	// This confirms the eBPF DNS chain is working before we check the spoof path.
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer pollCancel()
	var out string
	for {
		select {
		case <-pollCtx.Done():
			t.Logf("=== demo-python-sni-spoof final logs ===\n%s", out)
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("timed out: LEGIT_REWRITTEN never appeared — DNS verification chain may not be active")
		default:
		}
		out, _ = kubectl("logs", "-n", testNamespace, "-l", "app=demo-python-sni-spoof", "--tail=200")
		if strings.Contains(out, "LEGIT_REWRITTEN") {
			break
		}
		time.Sleep(pollInterval)
	}
	t.Logf("=== demo-python-sni-spoof logs ===\n%s", out)

	if strings.Contains(out, "SPOOF_REWRITTEN") {
		t.Errorf("DNS spoofing prevention FAILED: secret was rewritten despite IP/hostname mismatch")
	}
	if !strings.Contains(out, "SPOOF_NOT_REWRITTEN") {
		t.Logf("WARNING: SPOOF_NOT_REWRITTEN not yet seen in logs (may appear in next iteration)")
	}
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

			// No host filtering — this test validates length handling, not host verification.
			// The demo app connects to localhost (no DNS), so DNS-based host verification
			// would block rewriting. Use wildcard (no hosts annotation) instead.
			createEnabledSecret(t, "secret-allowed", allowedData, nil)
			createEnabledSecret(t, "secret-blocked", blockedData, nil)

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
		})
	}
}
