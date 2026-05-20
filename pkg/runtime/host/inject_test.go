//go:build linux

package host

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

func TestMaterializeInjection_EnvOnly(t *testing.T) {
	snap := []secrets.Secret{
		{Key: "a", Shadow: "kl::shadowA", Inject: secrets.Inject{Env: "A"}},
		{Key: "b", Shadow: "kl::shadowB", Inject: secrets.Inject{Env: "B"}},
	}
	env, cleanup, err := materializeInjection(snap, filepath.Join(t.TempDir(), "stage"))
	if err != nil {
		t.Fatalf("materializeInjection: %v", err)
	}
	defer func() { _ = cleanup() }()

	// Order matches snapshot order so the child sees a predictable view.
	if got, want := env, []string{"A=kl::shadowA", "B=kl::shadowB"}; !equalEnv(got, want) {
		t.Errorf("env=%v, want %v", got, want)
	}
}

func TestMaterializeInjection_FileOnly(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "stage")
	target := filepath.Join(t.TempDir(), "secret-file")
	snap := []secrets.Secret{
		{Key: "k", Shadow: "kl::shadowK", Inject: secrets.Inject{File: target}},
	}
	env, cleanup, err := materializeInjection(snap, stage)
	if err != nil {
		t.Fatalf("materializeInjection: %v", err)
	}
	defer func() { _ = cleanup() }()

	if len(env) != 0 {
		t.Errorf("env=%v, want empty when only file injection is used", env)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "kl::shadowK" {
		t.Errorf("file contents=%q, want kl::shadowK", got)
	}
	// The runtime stages a sentinel inside the per-invocation dir so
	// post-crash debugging can correlate stale files with the
	// invocation that wrote them.
	if entries, err := os.ReadDir(stage); err == nil {
		var found bool
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				found = true
			}
		}
		if !found {
			t.Errorf("expected sentinel file inside %s, got entries: %v", stage, entries)
		}
	}
}

func TestMaterializeInjection_BothEnvAndFile(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "stage")
	target := filepath.Join(t.TempDir(), "secret-file")
	snap := []secrets.Secret{
		{Key: "k", Shadow: "kl::both", Inject: secrets.Inject{Env: "K", File: target}},
	}
	env, cleanup, err := materializeInjection(snap, stage)
	if err != nil {
		t.Fatalf("materializeInjection: %v", err)
	}
	defer func() { _ = cleanup() }()

	if len(env) != 1 || env[0] != "K=kl::both" {
		t.Errorf("env=%v, want [K=kl::both]", env)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "kl::both" {
		t.Errorf("file contents=%q, want kl::both", got)
	}
}

func TestMaterializeInjection_RelativePathRejected(t *testing.T) {
	// inject.file MUST be absolute — relative paths land in the
	// runtime's cwd, not the child's, which is almost never what the
	// user intended. Translator could reject this at YAML load time
	// too; the runtime guards defensively in case a future Source
	// produces a relative path.
	stage := filepath.Join(t.TempDir(), "stage")
	snap := []secrets.Secret{
		{Key: "k", Shadow: "kl::rel", Inject: secrets.Inject{File: "relative/path"}},
	}
	_, _, err := materializeInjection(snap, stage)
	if err == nil {
		t.Fatal("expected error for relative inject.file")
	}
	if !strings.Contains(err.Error(), "must be absolute") {
		t.Errorf("error %q should explain the absolute-path requirement", err)
	}
	// Cleanup runs in the error path; the staging dir should be gone.
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging dir should be cleaned up on error, got: %v", err)
	}
}

func TestMaterializeInjection_NoInjectIsZeroState(t *testing.T) {
	// A snapshot of secrets with empty Inject (e.g. the k8s adapter's
	// output) must produce no env and no staging dir creation.
	snap := []secrets.Secret{
		{Key: "k8s", Shadow: "kl::k", Real: "r"},
	}
	stage := filepath.Join(t.TempDir(), "stage")
	env, cleanup, err := materializeInjection(snap, stage)
	if err != nil {
		t.Fatalf("materializeInjection: %v", err)
	}
	defer func() { _ = cleanup() }()

	if len(env) != 0 {
		t.Errorf("env=%v, want empty", env)
	}
	// Staging dir was never created — cleanup should still be a no-op.
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging dir should not exist when no injection happened, got: %v", err)
	}
}

func TestMaterializeInjection_CleanupIdempotent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "secret-file")
	snap := []secrets.Secret{
		{Key: "k", Shadow: "kl::idempotent", Inject: secrets.Inject{File: target}},
	}
	stage := filepath.Join(t.TempDir(), "stage")
	_, cleanup, err := materializeInjection(snap, stage)
	if err != nil {
		t.Fatalf("materializeInjection: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	// Second call must be a no-op — defer chains often invoke
	// cleanup more than once on error paths.
	if err := cleanup(); err != nil {
		t.Errorf("second cleanup should be silent, got: %v", err)
	}
}

// equalEnv compares two env slices ignoring order — runtime materializes
// in snapshot iteration order, which is stable today, but the assertion
// shouldn't break if that changes.
func equalEnv(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
