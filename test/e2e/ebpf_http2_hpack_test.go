//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// TestEBPFHttp2HpackOverPadding exercises the HTTP/2 HPACK rewrite path
// with a deliberately low-Huffman-density real value. The shadow secret
// kloak generates (Crockford Base32 uppercase + digits) has noticeably
// higher Huffman density than this lowercase-only real, producing a
// >7-bit gap that pkg/ebpf/sync.go fills with HPACK EOS (0xFF) bits.
//
// Per RFC 7541 §5.2: "A padding strictly longer than 7 bits MUST be
// treated as a decoding error." Strict HPACK decoders (nghttp2, the
// AWS ALB fronting httpbin.org) therefore reject the header block and
// drop the stream. The Go demo's http.Client logs an HTTP error rather
// than the rewritten secret — the test fails by timing out without
// ever observing the real value in the response echo.
//
// Why existing tests miss this:
//   - TestEBPFSecretRewrite uses real="REAL-ALLOWED-KEY-12345"
//     (HuffmanEncodeLength=18) with a ULID shadow ~22 chars
//     (HuffmanEncodeLength=19). The 1-byte gap fits in the 7-bit
//     allowance so the bug stays latent.
//   - demo-python (requests) and demo-js (Node http) both default to
//     HTTP/1.1, which doesn't HPACK-encode headers at all.
//   - examples/demo-go-boring/main.go:70 explicitly sets
//     ForceAttemptHTTP2=false — almost certainly to dodge this exact
//     bug; the workaround leaves no HTTP/2 + non-Go-stdlib coverage.
//
// Repro shape (verified via golang.org/x/net/http2/hpack):
//
//	real   = "lowercase-secret-triggering-hpack-bug" (37 chars, HuffmanLen=26)
//	shadow ≈ "kl::<31 chars of Crockford Base32>"  (37 chars, HuffmanLen=31)
//	gap    = 5 bytes (40 bits) of trailing 0xFF — illegal under §5.2.
//
// The fix lands in the same PR: pkg/secrets/shadow.go is rewritten as
// byte-by-byte construction against an exact (originalLen,
// realHuffmanBits) budget, so every shadow's Huffman bit length equals
// the real's bit-exactly. The BPF sync path then rewrites the wire
// slot byte-for-byte with zero EOS padding, independent of any
// character-class mismatch between real and shadow. This test
// transitions from "regression demonstrator" to "regression guard
// against any future change that reintroduces the over-padding".
func TestEBPFHttp2HpackOverPadding(t *testing.T) {
	// GC stale shadows so this test doesn't pick up a shadow created by
	// a prior TestEBPFSecretRewrite run for the same secret name.
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")

	// 37 chars of lowercase + dashes. Huffman-encodes to 26 bytes.
	// The kloak-generated shadow (Crockford Base32 tail) encodes to
	// ~31 bytes — a 5-byte gap, well past the 7-bit RFC allowance.
	const realLowDensity = "lowercase-secret-triggering-hpack-bug"
	allowedData := map[string][]byte{"api-key": []byte(realLowDensity)}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-67890")}

	// Hermetic HTTP/2 target. The in-cluster echo serves h2 via Go's stdlib
	// server, whose HPACK decoder is strict about EOS padding (RFC 7541 §5.2)
	// exactly like the AWS ALB that used to front httpbin.org — so this stays
	// a real over-padding regression guard while dropping the internet
	// dependency that made the Go nightly flaky.
	echoFQDN := deployHTTPEchoServer(t)

	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": echoFQDN,
	})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
		"getkloak.io/hosts": "example.com",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	// demo-go specifically: its http.Client negotiates HTTP/2 over ALPN
	// against the in-cluster echo. demo-python (requests) and demo-js (node
	// http) default to HTTP/1.1 and so don't exercise HPACK at all.
	demoManifest := filepath.Join(repoRoot, "examples", "demo-go", "deployment.yaml")
	if err := applyManifestTransformed(t, demoManifest, httpEchoTargetURL(echoFQDN)); err != nil {
		t.Fatalf("failed to deploy demo-go: %v", err)
	}
	t.Cleanup(func() {
		// Cleanup is best-effort but we surface failures via t.Logf so a
		// leaked deployment doesn't silently affect the next test run.
		if out, err := kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found"); err != nil {
			t.Logf("demo-go cleanup failed: %v\n%s", err, out)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-go"); err != nil {
		// describe is for the postmortem; if it also fails, surface the
		// reason rather than logging an empty string and losing the signal.
		if demoDesc, descErr := kubectl("describe", "deployment", "-n", testNamespace, "demo-go"); descErr == nil {
			t.Logf("deployment describe:\n%s", demoDesc)
		} else {
			t.Logf("kubectl describe failed: %v", descErr)
		}
		t.Fatalf("demo-go not ready: %v", err)
	}

	// Two-phase wait mirrors TestEBPFSecretRewrite. Phase 1 confirms the
	// runtime is alive AND the uprobe attach race has closed at least
	// once, so any subsequent rewrite failure points at the eBPF path
	// rather than at startup. Phase 2 polls for the rewritten secret.
	demoActiveCtx, demoActiveCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer demoActiveCancel()
	pollDemoLogs(t, demoActiveCtx, "app=demo-go", "http2-hpack-overpad",
		"demo-go never issued a second request — image, network, or scheduling problem (not the HPACK path)",
		func(s string) bool { return strings.Count(s, "Request #") >= 2 })

	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-go", "http2-hpack-overpad",
		"timed out waiting for the low-Huffman-density secret in demo-go's response echo — HPACK over-padding bug fired (the echo's strict HPACK decoder rejected the stream or the rewritten value didn't decode to the real secret)",
		func(s string) bool { return strings.Contains(s, realLowDensity) })
	t.Logf("=== demo-go (HTTP/2 HPACK over-pad) logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret leaked despite host mismatch — host filtering regressed")
	}
}

// TestEBPFHttp2HpackTrailingText checks that text after a placeholder in the
// same HTTP/2 header value arrives intact (spinningfactory/kloak#228, 1.7).
//
// HPACK Huffman-codes the whole value, so the placeholder's code shares its
// last byte with the first bits of the next character unless it ends on a
// byte boundary. The patch used to make that byte Huffman(real) followed by
// EOS 1-bits, overwriting those bits. The real is chosen so that its code
// (and so its shadow's) is 1 bit past a byte boundary: 7 bits of the ';'
// after it are in the placeholder's last byte, and ';' (11111011) does not
// start with 7 1-bits, so the old patch corrupted it. demo-go sends the
// placeholder followed by ";tail" in X-Secret-Suffixed (SECRET_ALLOWED_SUFFIX).
func TestEBPFHttp2HpackTrailingText(t *testing.T) {
	gcCtx, gcCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer gcCancel()
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-allowed-kloak")
	_ = waitForSecretAbsent(gcCtx, testNamespace, "secret-blocked-kloak")

	const (
		realValue = "real-trailing-key-10"
		suffix    = ";tail"
	)
	if bits := secrets.HuffmanBits(realValue); bits%8 != 1 {
		t.Fatalf("%q is %d Huffman bits; the test needs 1 mod 8 to overwrite the next character's first 7 bits", realValue, bits)
	}
	allowedData := map[string][]byte{"api-key": []byte(realValue)}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-67890")}

	echoFQDN := deployHTTPEchoServer(t)
	createEnabledSecret(t, "secret-allowed", allowedData, nil, map[string]string{
		"getkloak.io/hosts": echoFQDN,
	})
	createEnabledSecret(t, "secret-blocked", blockedData, nil, map[string]string{
		"getkloak.io/hosts": "example.com",
	})
	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	demoManifest := filepath.Join(repoRoot, "examples", "demo-go", "deployment.yaml")
	toEcho := httpEchoTargetURL(echoFQDN)
	withSuffix := addDemoEnv("SECRET_ALLOWED_SUFFIX", suffix)
	if err := applyManifestTransformed(t, demoManifest, func(m string) string { return withSuffix(toEcho(m)) }); err != nil {
		t.Fatalf("failed to deploy demo-go: %v", err)
	}
	t.Cleanup(func() {
		if out, err := kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found"); err != nil {
			t.Logf("demo-go cleanup failed: %v\n%s", err, out)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, "demo-go"); err != nil {
		if demoDesc, descErr := kubectl("describe", "deployment", "-n", testNamespace, "demo-go"); descErr == nil {
			t.Logf("deployment describe:\n%s", demoDesc)
		} else {
			t.Logf("kubectl describe failed: %v", descErr)
		}
		t.Fatalf("demo-go not ready: %v", err)
	}

	demoActiveCtx, demoActiveCancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer demoActiveCancel()
	pollDemoLogs(t, demoActiveCtx, "app=demo-go", "http2-hpack-trailing",
		"demo-go never issued a second request — image, network, or scheduling problem (not the HPACK path)",
		func(s string) bool { return strings.Count(s, "Request #") >= 2 })

	// The echo returns the headers as JSON: the suffixed one must hold the
	// real value followed by the suffix, byte for byte.
	want := `"X-Secret-Suffixed":"` + realValue + suffix + `"`
	pollCtx, pollCancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer pollCancel()
	out := pollDemoLogs(t, pollCtx, "app=demo-go", "http2-hpack-trailing",
		"timed out waiting for "+want+" in demo-go's response echo — the rewrite corrupted the text after the placeholder, or the echo's HPACK decoder rejected the header block",
		func(s string) bool { return strings.Contains(s, want) })
	t.Logf("=== demo-go (HTTP/2 HPACK trailing text) logs ===\n%s", out)

	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("blocked secret leaked despite host mismatch — host filtering regressed")
	}
}

// addDemoEnv adds name=value to a demo manifest's container env, as the
// entry before TARGET_URL (whose indentation it copies).
func addDemoEnv(name, value string) func(string) string {
	return func(manifest string) string {
		const anchor = "- name: TARGET_URL\n"
		idx := strings.Index(manifest, anchor)
		if idx == -1 {
			return manifest
		}
		lineStart := strings.LastIndexByte(manifest[:idx], '\n') + 1
		indent := manifest[lineStart:idx]
		entry := indent + "- name: " + name + "\n" + indent + "  value: " + strconv.Quote(value) + "\n"
		return manifest[:lineStart] + entry + manifest[lineStart:]
	}
}
