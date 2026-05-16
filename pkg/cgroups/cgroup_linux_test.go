//go:build linux

package cgroups

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCreateTransient_HappyPath exercises mkdir + inode read + cleanup
// against a t.TempDir() acting as the cgroup root. Real cgroupfs isn't
// required because the operation is plain mkdir/rmdir at the syscall
// layer; the inode we get back is just a normal directory inode, which
// is fine for verifying the contract.
func TestCreateTransient_HappyPath(t *testing.T) {
	root := t.TempDir()
	path, id, cleanup, err := CreateTransient(root, "abc123")
	if err != nil {
		t.Fatalf("CreateTransient: %v", err)
	}
	if path == "" {
		t.Error("path is empty")
	}
	if id == 0 {
		t.Error("inode id is zero")
	}
	wantPath := filepath.Join(root, KloakSliceName, "abc123")
	if path != wantPath {
		t.Errorf("path=%q, want %q", path, wantPath)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected transient dir to exist: %v", err)
	}
	if cleanup == nil {
		t.Fatal("cleanup is nil")
	}
	if err := cleanup(); err != nil {
		t.Errorf("cleanup: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("transient dir should be gone after cleanup, got: %v", err)
	}
	// kloak.slice parent should remain — concurrent invocations share it.
	if _, err := os.Stat(filepath.Join(root, KloakSliceName)); err != nil {
		t.Errorf("kloak.slice parent should outlive cleanup: %v", err)
	}
}

func TestCreateTransient_CleanupIdempotent(t *testing.T) {
	root := t.TempDir()
	_, _, cleanup, err := CreateTransient(root, "idempotent")
	if err != nil {
		t.Fatalf("CreateTransient: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	// Calling cleanup again must succeed silently — runtime defer
	// chains often invoke cleanup more than once on the error path.
	if err := cleanup(); err != nil {
		t.Errorf("second cleanup should be a no-op, got: %v", err)
	}
}

func TestCreateTransient_NonEmptyDirRejected(t *testing.T) {
	// If the transient cgroup still has files inside (in real life, a
	// child process whose pid is in cgroup.procs), cleanup must return
	// an error rather than swallow the failure — the runtime then knows
	// to kill survivors first.
	root := t.TempDir()
	path, _, cleanup, err := CreateTransient(root, "nonempty")
	if err != nil {
		t.Fatalf("CreateTransient: %v", err)
	}
	// Drop a file in the dir so rmdir fails with ENOTEMPTY.
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte("12345"), 0o644); err != nil {
		t.Fatalf("seed non-empty: %v", err)
	}
	if err := cleanup(); err == nil {
		t.Error("expected error rmdir'ing non-empty cgroup, got nil")
	}
}

func TestCreateTransient_DefaultCgroupRoot(t *testing.T) {
	// Empty cgroupRoot should fall back to DefaultCgroupRoot. As a
	// non-root test we usually can't mkdir under /sys/fs/cgroup, so we
	// confirm the call attempts that root by checking the error
	// message. When the test DOES have permission (CI as root), the
	// call succeeds — we must call cleanup() before returning or we
	// leak `/sys/fs/cgroup/kloak.slice/<name>` on the host.
	_, _, cleanup, err := CreateTransient("", "kloak-test-default-root")
	if err == nil {
		if cleanup != nil {
			if cerr := cleanup(); cerr != nil {
				t.Errorf("cleanup of root-created dir failed: %v", cerr)
			}
		}
		return
	}
	if !strings.Contains(err.Error(), DefaultCgroupRoot) {
		t.Errorf("error should reference default root %q, got: %v", DefaultCgroupRoot, err)
	}
}

func TestCreateTransient_NameValidation(t *testing.T) {
	cases := []struct {
		name, wantSub string
	}{
		{"", "must not be empty"},
		{"with/slash", "must not contain `/`"},
		{"..", "must not contain"},
		{".", "must not contain"},
		{"trailing/..", "must not contain `/`"},
		{"sneaky..name", "must not contain"},
	}
	root := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := CreateTransient(root, tc.name)
			if err == nil {
				t.Fatalf("expected error containing %q for name %q, got nil", tc.wantSub, tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not contain %q", err, tc.wantSub)
			}
		})
	}
}

func TestCreateTransient_DuplicateNameRejected(t *testing.T) {
	root := t.TempDir()
	if _, _, _, err := CreateTransient(root, "dup"); err != nil {
		t.Fatalf("first CreateTransient: %v", err)
	}
	_, _, _, err := CreateTransient(root, "dup")
	if err == nil {
		t.Fatal("expected error on duplicate name, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention `already exists`, got: %v", err)
	}
}

func TestCreateTransient_ReadOnlyParent(t *testing.T) {
	// When the cgroupfs (or our test stand-in) is mounted read-only,
	// MkdirAll on the kloak.slice parent must fail with an actionable
	// error. We approximate this by chmod'ing the test root to 0500
	// (read+execute, no write). Running as root would bypass that
	// permission check, so skip when we are uid 0.
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permission bits")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	_, _, _, err := CreateTransient(root, "ro")
	if err == nil {
		t.Fatal("expected error against read-only parent, got nil")
	}
	if !strings.Contains(err.Error(), "cgroupfs writable?") {
		t.Errorf("error should hint at cgroupfs writability, got: %v", err)
	}
}
