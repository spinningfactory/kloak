//go:build e2e_ebpf

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// e2eImage returns the full image reference, prefixed by E2E_REGISTRY if set.
func e2eImage(name, tag string) string {
	if imageRegistry != "" {
		return imageRegistry + "/" + name + ":" + tag
	}
	return name + ":" + tag
}

// e2ePullPolicy returns Never for local images, IfNotPresent for registry images.
func e2ePullPolicy() corev1.PullPolicy {
	if imageRegistry != "" {
		return corev1.PullAlways
	}
	return corev1.PullNever
}

// applyManifest applies a k8s manifest YAML, rewriting image references
// if E2E_REGISTRY is set.
func applyManifest(t *testing.T, path string) error {
	return applyManifestTransformed(t, path, nil)
}

// applyManifestTransformed is applyManifest with an optional post-read
// transform applied to the raw YAML before the E2E_REGISTRY image rewrite.
// It lets a test retarget a shared demo manifest (e.g. swap the demo's
// TARGET_URL from the public internet to an in-cluster echo) without
// forking the manifest file, which is also consumed by setup-demo.sh.
func applyManifestTransformed(t *testing.T, path string, transform func(string) string) error {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading manifest %s: %w", path, err)
	}
	manifest := string(data)

	if transform != nil {
		manifest = transform(manifest)
	}

	if imageRegistry != "" {
		manifest = strings.ReplaceAll(manifest, "image: kloak-", "image: "+imageRegistry+"/kloak-")
		manifest = strings.ReplaceAll(manifest, "imagePullPolicy: Never", "imagePullPolicy: Always")
	}

	cmd := exec.Command("kubectl", "apply", "-f", "-", "-n", testNamespace)
	cmd.Stdin = strings.NewReader(manifest)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply: %s: %w", string(out), err)
	}
	return nil
}

// httpEchoServerName is the in-cluster HTTPS echo server that stands in for
// httpbin.org in the Go e2e path. See test/e2e/http-echo-server for why.
const httpEchoServerName = "httpbin-echo"

// httpEchoTargetURL retargets a demo manifest's TARGET_URL at the in-cluster
// echo and enables the demo's opt-in InsecureSkipVerify (the echo presents a
// self-signed cert). fqdn is the echo Service FQDN returned by
// deployHTTPEchoServer.
func httpEchoTargetURL(fqdn string) func(string) string {
	return func(manifest string) string {
		manifest = strings.ReplaceAll(manifest,
			`value: "https://httpbin.org/headers"`,
			`value: "https://`+fqdn+`:8443/headers"`)
		// Inject the skip-verify env right after the (now-rewritten) TARGET_URL
		// value line so the demo trusts the echo's self-signed cert.
		manifest = strings.ReplaceAll(manifest,
			`value: "https://`+fqdn+`:8443/headers"`,
			`value: "https://`+fqdn+`:8443/headers"`+"\n"+
				`            - name: INSECURE_SKIP_VERIFY`+"\n"+
				`              value: "true"`)
		return manifest
	}
}

// deployHTTPEchoServer creates the in-cluster HTTPS header-echo server (an
// httpbin.org replacement) as a pod behind a Service, and returns its FQDN.
// It mirrors deployTLSEchoServer but speaks HTTP/1.1 + HTTP/2 on :8443.
func deployHTTPEchoServer(t *testing.T) string {
	t.Helper()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      httpEchoServerName,
			Namespace: testNamespace,
			// Opt the echo out of kloak interception — it is test
			// infrastructure, not a workload under test.
			Labels: map[string]string{
				"app":                 httpEchoServerName,
				"getkloak.io/enabled": "false",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:            "echo",
				Image:           e2eImage("kloak-http-echo", "latest"),
				ImagePullPolicy: e2ePullPolicy(),
				Ports:           []corev1.ContainerPort{{ContainerPort: 8443}},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/health",
							Port:   intstr.FromInt32(8443),
							Scheme: corev1.URISchemeHTTPS,
						},
					},
					InitialDelaySeconds: 2,
					PeriodSeconds:       2,
				},
			}},
		},
	}
	if _, err := clientset.CoreV1().Pods(testNamespace).Create(
		context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create http echo pod: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Pods(testNamespace).Delete(
			context.Background(), httpEchoServerName, metav1.DeleteOptions{})
	})

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      httpEchoServerName,
			Namespace: testNamespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": httpEchoServerName},
			Ports: []corev1.ServicePort{{
				Port:       8443,
				TargetPort: intstr.FromInt32(8443),
			}},
		},
	}
	if _, err := clientset.CoreV1().Services(testNamespace).Create(
		context.Background(), svc, metav1.CreateOptions{}); err != nil {
		t.Fatalf("failed to create http echo service: %v", err)
	}
	t.Cleanup(func() {
		_ = clientset.CoreV1().Services(testNamespace).Delete(
			context.Background(), httpEchoServerName, metav1.DeleteOptions{})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := waitForPodReady(ctx, testNamespace, httpEchoServerName); err != nil {
		t.Fatalf("http echo server not ready: %v", err)
	}

	return fmt.Sprintf("%s.%s.svc.cluster.local", httpEchoServerName, testNamespace)
}

// retargetAllowedSecretToEcho replaces the shared httpbin-scoped secret-allowed
// with one scoped to the in-cluster echo host, so kloak's DNS-verified host
// filter matches the hermetic target. It recreates (rather than relabels) to
// force a clean shadow + BPF map resync. The value is unchanged, so the
// negative assertions elsewhere still hold.
func retargetAllowedSecretToEcho(t *testing.T, host string) {
	t.Helper()
	_ = clientset.CoreV1().Secrets(testNamespace).Delete(
		context.Background(), "secret-allowed", metav1.DeleteOptions{})
	gcCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Wait for both the original and its shadow to clear so the recreate
	// below can't lose an AlreadyExists race with a still-terminating secret.
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")

	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-KEY-12345")}
	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": host,
	})
	assertShadowSecret(t, "secret-allowed", allowedData)
}

// controllerLogs fetches the latest controller log output.
func controllerLogs() string {
	out, _ := kubectl("logs", "-n", kloakNamespace, "-l",
		"app.kubernetes.io/component=controller", "--tail=200")
	return out
}

// pollDemoLogs polls `kubectl logs -l <appLabel>` every pollInterval
// until match(out) returns true or ctx expires. On expiry the most
// recent tail and the kloak controller logs are tagged onto t.Fatalf
// for postmortem; failTag identifies which subtest fired (e.g. "js"
// vs "demo-python-raw-tls") so a cascade is debuggable.
//
// Returns the final log output so the caller can run negative
// assertions on it (e.g. blocked-secret leakage).
//
// `--tail=500` matches the per-cycle log volume of the slowest demo
// (js, REQUEST_INTERVAL=1s) — gives ~70-100 cycles of headroom before
// the marker the caller is looking for can scroll out of the window.
func pollDemoLogs(t *testing.T, ctx context.Context, appLabel, failTag, failMsg string, match func(string) bool) string {
	t.Helper()
	var out string
	for {
		select {
		case <-ctx.Done():
			t.Logf("=== %s final logs ===\n%s", failTag, out)
			t.Logf("=== Controller logs ===\n%s", controllerLogs())
			t.Fatalf("[%s] %s", failTag, failMsg)
		default:
		}
		out, _ = kubectl("logs", "-n", testNamespace, "-l", appLabel, "--tail=500")
		if match(out) {
			return out
		}
		time.Sleep(pollInterval)
	}
}

// ebpfRewriteTest describes a single eBPF rewrite test case for a specific runtime.
type ebpfRewriteTest struct {
	name           string
	demoDir        string
	deploymentName string
	appLabel       string
	skip           string // if non-empty, test is skipped with this reason
	// hermetic retargets the demo at the in-cluster HTTPS echo server instead
	// of the public httpbin.org, so the test doesn't depend on the internet.
	// The shared allowed secret is re-scoped to the echo's FQDN for this case.
	hermetic bool
}

var ebpfTests = []ebpfRewriteTest{
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
		name:           "go",
		demoDir:        "demo-go",
		deploymentName: "demo-go",
		appLabel:       "app=demo-go",
		// The Go demo negotiates HTTP/2 and was the flakiest cell in the Go
		// nightly because it hit the public httpbin.org. Run it against the
		// in-cluster echo instead.
		hermetic: true,
	},
	{
		name:           "go-boringssl",
		demoDir:        "demo-go-boring",
		deploymentName: "demo-go-boring",
		appLabel:       "app=demo-go-boring",
		skip:           "BoringSSL H extraction not yet implemented",
	},
	{
		name:           "gnutls",
		demoDir:        "demo-gnutls",
		deploymentName: "demo-gnutls",
		appLabel:       "app=demo-gnutls",
		skip:           "GnuTLS H extraction not yet implemented",
	},
}

// TestEBPFRawTLSHostFiltering tests that DNS-verified host filtering works with
// raw TLS sockets (non-HTTP). A TLS echo server runs as a sidecar behind a K8s
// Service. The client resolves the Service name via DNS, which populates dns_ip_map,
// enabling host-based secret filtering at the TCP level.
func TestEBPFRawTLSHostFiltering(t *testing.T) {
	// The Service FQDN as it appears in DNS responses from CoreDNS.
	echoHostFQDN := "tls." + testNamespace + ".svc.cluster.local"

	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-67890")}

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

	// Same flake class as TestEBPFSecretRewrite — bumped to 180s + 500-line
	// tail for parity with `runEBPFRewriteTest`. This test was at the same
	// 95s edge in recent CI cascades.
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-python-raw-tls", "demo-python-raw-tls",
		"timed out waiting for allowed secret in raw TLS demo logs",
		func(s string) bool { return strings.Contains(s, "REAL-ALLOWED-KEY-12345") })
	t.Logf("=== demo-python-raw-tls logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret should NOT be rewritten (host mismatch)")
	}
}

// TestEBPFBoringSSLHostFiltering is the BoringSSL analogue of
// TestEBPFRawTLSHostFiltering: a C client linked against a symbol-bearing
// BoringSSL shared library sends ALLOWED=/BLOCKED= secrets over raw TLS via
// SSL_write to an in-cluster echo server. Exercises the BoringSSL H-extraction
// path (SSL→s3→aead_write_ctx→AES_KEY, H recomputed as AES_encrypt(0)), which
// is distinct from the OpenSSL provider chain.
func TestEBPFBoringSSLHostFiltering(t *testing.T) {
	echoHostFQDN := "tls-boring." + testNamespace + ".svc.cluster.local"

	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-67890")}

	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": echoHostFQDN,
	})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
		"getkloak.io/hosts": "example.com",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-boringssl", "deployment.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-boringssl: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-boringssl"); err != nil {
		t.Fatalf("demo-boringssl not ready: %v", err)
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-boringssl", "demo-boringssl",
		"timed out waiting for allowed secret in BoringSSL demo logs",
		func(s string) bool { return strings.Contains(s, "REAL-ALLOWED-KEY-12345") })
	t.Logf("=== demo-boringssl logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret should NOT be rewritten (host mismatch)")
	}
}

// TestEBPFBunHostFiltering is the Bun analogue of TestEBPFBoringSSLHostFiltering:
// a TypeScript client running on a Bun single-executable (BoringSSL statically
// linked, symbols stripped) sends ALLOWED=/BLOCKED= secrets over raw TLS to an
// in-cluster echo server. Exercises the file-offset-based uprobe attach path and
// the BoringSSL H-extraction chain (SSL→s3→aead_write_ctx→AES_KEY).
func TestEBPFBunHostFiltering(t *testing.T) {
	echoHostFQDN := "tls-bun." + testNamespace + ".svc.cluster.local"

	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-BUN-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-BUN-KEY-67890")}

	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": echoHostFQDN,
	})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
		"getkloak.io/hosts": "example.com",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-bun", "deployment.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-bun: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-bun"); err != nil {
		t.Fatalf("demo-bun not ready: %v", err)
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-bun", "demo-bun",
		"timed out waiting for allowed secret in Bun demo logs",
		func(s string) bool { return strings.Contains(s, "REAL-ALLOWED-BUN-KEY-12345") })
	t.Logf("=== demo-bun logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-BUN-KEY-67890") {
		t.Errorf("blocked secret should NOT be rewritten (host mismatch)")
	}
}

// TestEBPFBunClaudeCode exercises the exact pattern that Claude Code uses:
// a Bun single-executable sends HTTPS requests using fetch() with the secret
// in an "Authorization: Bearer <key>" header. This is the primary real-world
// motivation for the Bun file-offset uprobe path.
//
// The echo server (kloak-tls-echo) responds to GET /echo with a JSON object
// containing the full request headers, so the rewritten Authorization value is
// visible in the demo-app pod logs and assertable here.
func TestEBPFBunClaudeCode(t *testing.T) {
	echoHostFQDN := "tls-bun-claude." + testNamespace + ".svc.cluster.local"

	allowedData := map[string][]byte{"api-key": []byte("REAL-API-KEY-CLAUDE-ABCDEF")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-CLAUDE-XYZ")}

	// Allowed secret: scoped to the echo service — kloak should rewrite the
	// shadow in the Authorization header before it leaves the TLS stack.
	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": echoHostFQDN,
	})
	// Blocked secret: scoped to a host the client never contacts — should NOT
	// be rewritten, so the shadow value stays on the wire.
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
		"getkloak.io/hosts": "api.anthropic.com",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-bun", "deployment-claude.yaml")
	if err := applyManifest(t, demoManifest); err != nil {
		t.Fatalf("failed to deploy demo-bun-claude: %v", err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-bun-claude"); err != nil {
		t.Fatalf("demo-bun-claude not ready: %v", err)
	}

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	// The echo server returns headers as JSON; the rewritten Authorization value
	// appears as "Authorization":"Bearer REAL-API-KEY-CLAUDE-ABCDEF".
	out := pollDemoLogs(t, pollCtx, "app=demo-bun-claude", "demo-bun-claude",
		"timed out waiting for rewritten API key in demo-bun-claude logs",
		func(s string) bool { return strings.Contains(s, "REAL-API-KEY-CLAUDE-ABCDEF") })
	t.Logf("=== demo-bun-claude logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-CLAUDE-XYZ") {
		t.Errorf("blocked API key should NOT appear in echo (host mismatch — api.anthropic.com != %s)", echoHostFQDN)
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

	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": "httpbin.org",
	})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
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
	if tc.skip != "" {
		t.Skip(tc.skip)
	}
	demoManifest := filepath.Join(repoRoot, "examples", tc.demoDir, "deployment.yaml")

	// Hermetic cases retarget the demo at the in-cluster HTTPS echo so the
	// test never depends on httpbin.org (the dominant Go-nightly flake). This
	// re-scopes the shared allowed secret to the echo's FQDN and rewrites the
	// manifest's TARGET_URL + skip-verify at apply time.
	var transform func(string) string
	if tc.hermetic {
		echoFQDN := deployHTTPEchoServer(t)
		retargetAllowedSecretToEcho(t, echoFQDN)
		transform = httpEchoTargetURL(echoFQDN)
	}

	if err := applyManifestTransformed(t, demoManifest, transform); err != nil {
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

	// Two-phase wait. The 90s single-budget approach was flaky on slow CI
	// runners because it conflated three distinct delays (Node.js cold-
	// start / TLS module init, DNS+RTT to the target, and the uprobe
	// attach race) into one ceiling. Splitting them gives a clearer signal
	// when something does break:
	//
	//   Phase 1 — wait until the demo has issued at least two requests.
	//   All three demos use the same `--- Request #N ---` prefix; counting
	//   occurrences (rather than matching `Request #2` literally) stays
	//   correct after `Request #1` scrolls out of the kubectl --tail
	//   window on long phase-1 waits. Two requests means the runtime is
	//   alive AND the uprobe-attach race window has closed at least once,
	//   so any subsequent rewrite failure points at the eBPF path rather
	//   than at startup. 120s budget covers Node.js cold-start; the Go
	//   case now hits an in-cluster echo (sub-ms RTT) rather than the
	//   public internet, so its own budget is comfortably slack.
	//
	//   Phase 2 — poll for the rewritten secret in the demo logs. 180s
	//   budget; the original 90s sat exactly at the failure edge for JS
	//   on stressed runners.
	//
	demoActiveCtx, demoActiveCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer demoActiveCancel()
	pollDemoLogs(t, demoActiveCtx, tc.appLabel, tc.name,
		"demo runtime never reached its second request — image, network, or scheduling problem (not an eBPF rewrite issue)",
		func(s string) bool { return strings.Count(s, "Request #") >= 2 })

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, tc.appLabel, tc.name,
		"timed out waiting for allowed secret in app logs (demo runtime is healthy — uprobe path failed to rewrite)",
		func(s string) bool { return strings.Contains(s, "REAL-ALLOWED-KEY-12345") })
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
	echoHostFQDN := "tls." + testNamespace + ".svc.cluster.local"

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
				t.Fatalf("failed to deploy: %v", err)
			}
			t.Cleanup(func() {
				_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
				time.Sleep(2 * time.Second)
			})

			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			if err := waitForDeploymentReady(ctx, testNamespace, "demo-python-raw-tls"); err != nil {
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
					t.Logf("=== python-raw-tls-%s final logs ===\n%s", tc.name, out)
					t.Logf("=== Controller logs ===\n%s", controllerLogs())
					t.Fatalf("allowed secret (%d bytes) not rewritten — prefix %q not found", len(tc.allowed), allowedCheck)
				default:
				}
				out, _ = kubectl("logs", "-n", testNamespace, "-l", "app=demo-python-raw-tls", "--tail=200")
				if strings.Contains(out, allowedCheck) {
					break
				}
				time.Sleep(pollInterval)
			}
			t.Logf("=== python-raw-tls-%s logs ===\n%s", tc.name, out)

			if strings.Contains(out, blockedCheck) {
				t.Errorf("blocked secret (%d bytes) should NOT be rewritten — prefix %q found in logs", len(tc.blocked), blockedCheck)
			}
		})
	}
}
