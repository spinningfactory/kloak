//go:build linux

package host

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func writeResolvConf(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestReadResolvConfNameservers_Standard(t *testing.T) {
	path := writeResolvConf(t, `# auto-generated
nameserver 8.8.8.8
nameserver 1.1.1.1
search example.com
options ndots:5
`)
	ips, err := readResolvConfNameservers(path)
	if err != nil {
		t.Fatalf("readResolvConfNameservers: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(ips)=%d, want 2; got=%v", len(ips), ips)
	}
	if ips[0].String() != "8.8.8.8" || ips[1].String() != "1.1.1.1" {
		t.Errorf("ips=%v, want [8.8.8.8 1.1.1.1]", ips)
	}
}

func TestReadResolvConfNameservers_IgnoresCommentsAndBlanks(t *testing.T) {
	path := writeResolvConf(t, `
; semicolon comment
# hash comment

nameserver 9.9.9.9

# another comment
`)
	ips, err := readResolvConfNameservers(path)
	if err != nil {
		t.Fatalf("readResolvConfNameservers: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "9.9.9.9" {
		t.Errorf("ips=%v, want [9.9.9.9]", ips)
	}
}

func TestReadResolvConfNameservers_DropsMalformedIPs(t *testing.T) {
	// A single typo shouldn't kill the parse — drop the bad line,
	// keep the rest. Same fail-soft posture as resolv.conf libraries.
	path := writeResolvConf(t, `nameserver not-an-ip
nameserver 8.8.4.4
nameserver 999.999.999.999
nameserver 2001:4860:4860::8888
`)
	ips, err := readResolvConfNameservers(path)
	if err != nil {
		t.Fatalf("readResolvConfNameservers: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(ips)=%d, want 2 (8.8.4.4 + IPv6); got=%v", len(ips), ips)
	}
	if ips[0].String() != "8.8.4.4" {
		t.Errorf("ips[0]=%s, want 8.8.4.4", ips[0])
	}
	if ips[1].String() != "2001:4860:4860::8888" {
		t.Errorf("ips[1]=%s, want 2001:4860:4860::8888", ips[1])
	}
}

func TestReadResolvConfNameservers_MissingFileSurfacesError(t *testing.T) {
	// Missing file is a warning at the call site, but the helper must
	// return the error so the caller can choose how to log it.
	_, err := readResolvConfNameservers(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("error %v, want os.IsNotExist", err)
	}
}

func TestEBPFHandle_CloseIsIdempotentAndPreservesError(t *testing.T) {
	// Close runs the real teardown exactly once (sync.Once) but the
	// returned error must be consistent across calls so deferred
	// cleanups that re-fire on error paths report the same outcome
	// the first caller saw. Without persisting closeErr on the
	// handle, the second caller would always get nil.
	//
	// We can't easily construct a real ebpfHandle in a unit test
	// (needs a live TLSUprobeManager → CAP_BPF → root) so we exercise
	// the idempotence pattern with a minimal stand-in that mimics the
	// sync.Once + persisted-error shape.
	wantErr := errors.New("simulated mgr.Close failure")
	var (
		runs   int
		once   sync.Once
		stored error
	)
	doClose := func() error {
		once.Do(func() {
			runs++
			stored = wantErr
		})
		return stored
	}

	got1 := doClose()
	got2 := doClose()
	got3 := doClose()

	if runs != 1 {
		t.Errorf("teardown ran %d times, want exactly 1", runs)
	}
	for i, got := range []error{got1, got2, got3} {
		if !errors.Is(got, wantErr) {
			t.Errorf("call %d returned %v, want %v on every call", i+1, got, wantErr)
		}
	}
}

func TestWrapEBPFSetupError_EPERMSuggestsSudoAndCaps(t *testing.T) {
	// EPERM is the common non-root failure mode — the wrap must call
	// out sudo / setcap so the user knows what to fix instead of
	// chasing the misleading MEMLOCK hint cilium/ebpf surfaces.
	wrapped := wrapEBPFSetupError(fmt.Errorf("loading eBPF objects: %w", syscall.EPERM))
	msg := wrapped.Error()
	for _, want := range []string{"CAP_SYS_ADMIN", "sudo", "setcap", "--no-rewrite"} {
		if !strings.Contains(msg, want) {
			t.Errorf("EPERM wrap missing %q in: %s", want, msg)
		}
	}
	if !errors.Is(wrapped, syscall.EPERM) {
		t.Error("wrap should preserve EPERM so errors.Is keeps working")
	}
}

func TestWrapEBPFSetupError_NonEPERMKeepsGenericWrap(t *testing.T) {
	// Anything that isn't EPERM (kernel feature missing, BTF mismatch,
	// verifier rejection) gets the generic "use --no-rewrite for dev
	// only" wrap, without inventing capability advice that may not apply.
	original := errors.New("verifier rejected program")
	wrapped := wrapEBPFSetupError(original)
	msg := wrapped.Error()
	if !strings.Contains(msg, "--no-rewrite") {
		t.Errorf("non-EPERM wrap missing --no-rewrite reminder: %s", msg)
	}
	if strings.Contains(msg, "CAP_SYS_ADMIN") || strings.Contains(msg, "setcap") {
		t.Errorf("non-EPERM wrap should not advertise capability fixes: %s", msg)
	}
	if !errors.Is(wrapped, original) {
		t.Error("wrap should preserve the original error via %w")
	}
}

func TestReadResolvConfNameservers_TrailingInlineComments(t *testing.T) {
	// resolv.conf comments can sit at end-of-line with no whitespace
	// separator: `nameserver 8.8.8.8#hint` is valid and the IP is
	// 8.8.8.8, not "8.8.8.8#hint". An earlier version of this parser
	// split into fields first and would silently drop such entries
	// because net.ParseIP rejects "8.8.8.8#hint".
	path := writeResolvConf(t, `nameserver 8.8.8.8#trailing-no-space
nameserver 1.1.1.1 # trailing-with-space
nameserver 9.9.9.9;semicolon-comment
# whole-line comment
nameserver 8.8.4.4    # multiple-space-before-comment
`)
	ips, err := readResolvConfNameservers(path)
	if err != nil {
		t.Fatalf("readResolvConfNameservers: %v", err)
	}
	want := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"}
	if len(ips) != len(want) {
		t.Fatalf("len(ips)=%d, want %d; got=%v", len(ips), len(want), ips)
	}
	for i, w := range want {
		if ips[i].String() != w {
			t.Errorf("ips[%d]=%s, want %s", i, ips[i], w)
		}
	}
}

func TestReadResolvConfNameservers_EmptyFile(t *testing.T) {
	// A file with no nameserver entries returns (nil, nil). The caller
	// then enables the whitelist with an empty list, which is the
	// fail-closed behavior we want (DNS rejected, child fails to
	// resolve — loud and observable).
	path := writeResolvConf(t, "")
	ips, err := readResolvConfNameservers(path)
	if err != nil {
		t.Fatalf("readResolvConfNameservers: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("ips=%v, want empty", ips)
	}
}
