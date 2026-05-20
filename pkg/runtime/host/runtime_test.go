//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/runtime"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// errSource is a secrets.Source whose Snapshot always fails. Useful to
// drive the snapshot error path in Run without needing a malformed
// YAML on disk.
type errSource struct{ err error }

func (e errSource) Snapshot(context.Context) ([]secrets.Secret, error) { return nil, e.err }

// staticSource returns a fixed snapshot every call.
type staticSource struct{ snap []secrets.Secret }

func (s staticSource) Snapshot(context.Context) ([]secrets.Secret, error) { return s.snap, nil }

func TestNew_DefaultsInjectRootAndLogger(t *testing.T) {
	// nil logger must default to a no-op — Run dereferences r.log
	// unconditionally on debug/warn paths.
	rt := New("", "", nil)
	if rt == nil {
		t.Fatal("New returned nil")
	}
	hr, ok := rt.(*hostRuntime)
	if !ok {
		t.Fatalf("type=%T, want *hostRuntime", rt)
	}
	if hr.log == nil {
		t.Error("logger should default to no-op, got nil")
	}
	// injectRoot default depends on privilege: /run/kloak for root,
	// $XDG_RUNTIME_DIR/kloak for unprivileged users (the per-user
	// systemd-managed tmpfs), /tmp/kloak as last resort.
	wantInject := expectedDefaultInjectRoot(t)
	if hr.injectRoot != wantInject {
		t.Errorf("injectRoot=%q, want %q (euid=%d, XDG_RUNTIME_DIR=%q)",
			hr.injectRoot, wantInject, os.Geteuid(), os.Getenv("XDG_RUNTIME_DIR"))
	}
}

// expectedDefaultInjectRoot mirrors chooseInjectRoot's branch logic so
// the test asserts the same default the runtime computes. Keeps the
// assertion robust to whatever the test environment is (root in
// docker-based CI, non-root with XDG_RUNTIME_DIR in dev/Lima, non-root
// without it in some kind clusters).
func expectedDefaultInjectRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		return "/run/kloak"
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "kloak")
	}
	return "/tmp/kloak"
}

func TestRun_NilSpecRejected(t *testing.T) {
	rt := New(t.TempDir(), t.TempDir(), nil)
	code, err := rt.Run(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil spec")
	}
	if code != -1 {
		t.Errorf("code=%d, want -1", code)
	}
	if !strings.Contains(err.Error(), "spec is nil") {
		t.Errorf("error %q should mention nil spec", err)
	}
}

func TestRun_EmptyCmdRejected(t *testing.T) {
	rt := New(t.TempDir(), t.TempDir(), nil)
	code, err := rt.Run(context.Background(), &runtime.Spec{Cmd: nil})
	if err == nil {
		t.Fatal("expected error for empty Cmd")
	}
	if code != -1 {
		t.Errorf("code=%d, want -1", code)
	}
	if !strings.Contains(err.Error(), "spec.Cmd is empty") {
		t.Errorf("error %q should mention empty Cmd", err)
	}
}

func TestRun_SnapshotErrorPropagates(t *testing.T) {
	rt := New(t.TempDir(), t.TempDir(), nil)
	want := errors.New("snapshot blew up")
	_, err := rt.Run(context.Background(), &runtime.Spec{
		Cmd:     []string{"echo", "x"},
		Secrets: errSource{err: want},
	})
	if err == nil {
		t.Fatal("expected snapshot error to propagate")
	}
	if !errors.Is(err, want) {
		t.Errorf("error %q should wrap the source error", err)
	}
	if !strings.Contains(err.Error(), "snapshot secrets") {
		t.Errorf("error %q should be wrapped with 'snapshot secrets'", err)
	}
}

// TestRun_HappyPath exercises the full Run flow with a tempdir as the
// cgroupRoot. The runtime mkdirs the slice + transient dir under that
// temp path; the cgroup.procs write succeeds because os.WriteFile
// creates the file when missing (the path is just a regular tmpfs entry,
// not a real cgroupfs). What we're asserting:
//   - the snapshot drives env injection
//   - the child actually exec's and its stdout is captured
//   - the exit code is propagated as 0 on success
//   - the cgroup parent dir was created
//
// The follow-up PR wires real BPF programs; until then this test
// covers everything *except* the in-kernel rewrite, which is exactly
// the surface we own in this PR.
func TestRun_HappyPath(t *testing.T) {
	cgroupRoot := t.TempDir()
	injectRoot := t.TempDir()
	rt := New(cgroupRoot, injectRoot, zap.NewNop().Sugar())

	var stdout, stderr bytes.Buffer
	src := staticSource{snap: []secrets.Secret{
		{Key: "k1", Real: "real-1", Shadow: "kl::shadow-1", Inject: secrets.Inject{Env: "KLOAK_TEST"}},
	}}

	// Use sh -c so we can echo $KLOAK_TEST and prove the env injection
	// reached the child. /bin/sh is required by POSIX so this works on
	// any Linux CI runner without further deps.
	spec := &runtime.Spec{
		Cmd:     []string{"sh", "-c", "echo got=$KLOAK_TEST"},
		Secrets: src,
		Stdout:  &stdout,
		Stderr:  &stderr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := rt.Run(ctx, spec)
	if err != nil {
		t.Fatalf("Run: %v\nstderr=%s", err, stderr.String())
	}
	if code != 0 {
		t.Errorf("exit code=%d, want 0; stderr=%s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != "got=kl::shadow-1" {
		t.Errorf("child stdout=%q, want 'got=kl::shadow-1'", got)
	}

	// The transient cgroup directory survives cleanup because the
	// tmpdir-as-cgroup leaves cgroup.procs as a regular file inside
	// it, and os.Remove refuses to rmdir a non-empty directory. That
	// failure is logged but doesn't fail the run — verify the slice
	// parent exists, which confirms CreateTransient ran.
	if _, err := os.Stat(filepath.Join(cgroupRoot, "kloak.slice")); err != nil {
		t.Errorf("kloak.slice was not created: %v", err)
	}
}

func TestRun_PropagatesNonZeroExitCode(t *testing.T) {
	rt := New(t.TempDir(), t.TempDir(), zap.NewNop().Sugar())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := rt.Run(ctx, &runtime.Spec{Cmd: []string{"sh", "-c", "exit 42"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != 42 {
		t.Errorf("exit code=%d, want 42", code)
	}
}

func TestRun_BadStartReturnsError(t *testing.T) {
	rt := New(t.TempDir(), t.TempDir(), zap.NewNop().Sugar())
	// A binary that definitely won't exist on any runner.
	code, err := rt.Run(context.Background(), &runtime.Spec{
		Cmd: []string{"/this/binary/does/not/exist-kloak-test"},
	})
	if err == nil {
		t.Fatal("expected error for non-existent binary")
	}
	if code != -1 {
		t.Errorf("code=%d on Start failure, want -1", code)
	}
	if !strings.Contains(err.Error(), "start child") {
		t.Errorf("error %q should be wrapped with 'start child'", err)
	}
}

func TestSnapshotOrEmpty_NilSource(t *testing.T) {
	got, err := snapshotOrEmpty(context.Background(), nil)
	if err != nil {
		t.Fatalf("snapshotOrEmpty(nil): %v", err)
	}
	if got != nil {
		t.Errorf("got=%v, want nil", got)
	}
}

func TestSnapshotOrEmpty_Delegates(t *testing.T) {
	want := []secrets.Secret{{Key: "k", Real: "r", Shadow: "kl::s"}}
	got, err := snapshotOrEmpty(context.Background(), staticSource{snap: want})
	if err != nil {
		t.Fatalf("snapshotOrEmpty: %v", err)
	}
	if len(got) != 1 || got[0].Key != "k" {
		t.Errorf("got=%v, want %v", got, want)
	}
}

func TestComposeEnv_OrderingAndOverride(t *testing.T) {
	// composeEnv = os.Environ() ++ extra ++ inject. Later entries
	// override earlier ones via os/exec semantics (last-write-wins on
	// duplicate keys). We assert ordering rather than the resolved
	// value so this test is independent of the host's env.
	env := composeEnv([]string{"FOO=extra"}, []string{"FOO=inject", "BAR=inject"})
	if len(env) < 3 {
		t.Fatalf("env len=%d, want >=3 (os.Environ + extra + inject)", len(env))
	}
	// Last three entries must be ours in the order: extras, then inject.
	tail := env[len(env)-3:]
	want := []string{"FOO=extra", "FOO=inject", "BAR=inject"}
	for i := range want {
		if tail[i] != want[i] {
			t.Errorf("env[%d]=%q, want %q (tail=%v)", i, tail[i], want[i], tail)
		}
	}
}

func TestOrDefault(t *testing.T) {
	// Non-nil reader passes through; nil reader uses fallback.
	r := bytes.NewReader([]byte("hi"))
	if got := orDefault(r, os.Stdin); got != r {
		t.Errorf("non-nil reader was replaced (got %T, want %T)", got, r)
	}
	if got := orDefault(nil, os.Stdin); got != os.Stdin {
		t.Errorf("nil reader did not fall back to os.Stdin (got %T)", got)
	}
}

func TestOrWriter(t *testing.T) {
	w := &bytes.Buffer{}
	if got := orWriter(w, os.Stdout); got != w {
		t.Errorf("non-nil writer was replaced (got %T, want %T)", got, w)
	}
	if got := orWriter(nil, os.Stdout); got != os.Stdout {
		t.Errorf("nil writer did not fall back to os.Stdout (got %T)", got)
	}
}

func TestForwardSignals_StopIsIdempotent(t *testing.T) {
	// Use our own pid; we never send signals to it, we only verify the
	// start+stop cycle completes and stop is safe to call twice. The
	// goroutine inside forwardSignals would only call syscall.Kill if
	// the os/signal package delivered to its channel — we deliver
	// nothing.
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	stop := forwardSignals(proc, zap.NewNop().Sugar())

	done := make(chan struct{})
	go func() {
		stop()
		stop() // must be a no-op the second time
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwardSignals stop did not return within 2s")
	}
}
