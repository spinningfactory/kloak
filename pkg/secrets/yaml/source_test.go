package yaml

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempYAML drops a YAML blob into a temp file scoped to t and
// returns its path. Cheap fixture pattern that keeps the YAML literal
// next to the test that uses it.
func writeTempYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func TestSource_GoldenValid(t *testing.T) {
	// Realistic mixed config: literal value, valueFrom env, env+file
	// injection, host + port filter, port-with-protocol.
	t.Setenv("KLOAK_TEST_REAL", "from-env-real")
	path := writeTempYAML(t, `secrets:
  - name: stripe-key
    value: sk-live-abcdef123
    host: api.stripe.com
    port: 443
    inject:
      env: STRIPE_KEY
  - name: openai-key
    valueFrom:
      env: KLOAK_TEST_REAL
    host: api.openai.com
    inject:
      env: OPENAI_KEY
      file: /run/kloak/openai-key
  - name: dns-secret
    value: dns-real-value
    port: 53/udp
    inject:
      env: DNS_KEY
`)

	src, err := NewSource(path)
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	snap, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snap) != 3 {
		t.Fatalf("len(snap)=%d, want 3", len(snap))
	}
	// Confirm valueFrom resolution flowed through.
	if snap[1].Real != "from-env-real" {
		t.Errorf("snap[1].Real=%q, want from-env-real", snap[1].Real)
	}
	// Confirm both inject targets set on the second entry.
	if snap[1].Inject.Env != "OPENAI_KEY" || snap[1].Inject.File != "/run/kloak/openai-key" {
		t.Errorf("snap[1].Inject=%+v, want env+file both set", snap[1].Inject)
	}
}

func TestSource_FileNotFound(t *testing.T) {
	_, err := NewSource("/no/such/path/secrets.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "read secrets file") {
		t.Errorf("expected `read secrets file` in error, got: %v", err)
	}
}

func TestSource_InvalidYAML(t *testing.T) {
	path := writeTempYAML(t, ": not yaml :::\n")
	_, err := NewSource(path)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "parse secrets file") {
		t.Errorf("expected `parse secrets file` in error, got: %v", err)
	}
}

func TestSource_ValidatorErrorsBubbleUp(t *testing.T) {
	// Confirms that translator errors propagate through NewSource with
	// the entry context preserved.
	path := writeTempYAML(t, `secrets:
  - name: bad
    value: v
    port: not-a-port
    inject:
      env: X
`)
	_, err := NewSource(path)
	if err == nil {
		t.Fatal("expected validator error")
	}
	if !strings.Contains(err.Error(), `entry 0 ("bad")`) {
		t.Errorf("error should include entry context, got: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid port") {
		t.Errorf("error should describe the failure, got: %v", err)
	}
}

func TestSource_SnapshotIsStable(t *testing.T) {
	// Snapshot must return the same slice on every call (per the
	// secrets.Source contract — no I/O on the hot path).
	path := writeTempYAML(t, `secrets:
  - name: a
    value: src-snapshot-real
    inject:
      env: A
`)
	src, err := NewSource(path)
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	a, _ := src.Snapshot(context.Background())
	b, _ := src.Snapshot(context.Background())
	if len(a) != len(b) || a[0].Shadow != b[0].Shadow {
		t.Error("Snapshot should be cached + stable across calls")
	}
}
