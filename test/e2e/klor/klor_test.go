//go:build e2e_klor

// Package klor_e2e exercises the standalone `klor` binary against a real
// filesystem and a real child process. It is intentionally NOT part of
// the k8s e2e suite (`//go:build e2e_ebpf`) — klor's design point is
// "no Kubernetes required", and that property would be undermined by
// gating its e2e on a k3s cluster.
//
// What this suite covers today (this PR):
//   - klor builds and exits cleanly
//   - --secrets is required and validated
//   - unsupported extension surfaces a clear error
//   - a real child is exec'd inside the transient cgroup dir, env
//     injection reaches it, and the child's exit code propagates
//
// What it does NOT cover yet:
//   - the in-kernel TLS rewrite — wired by a follow-up PR per
//     pkg/runtime/host/runtime.go's TODO(phase-3b-followup). Once that
//     lands, this suite gains a tls-echo-server flow that asserts the
//     echoed body contains the *real* secret, not the placeholder.
//
// Run it with:
//
//	go test -v -tags=e2e_klor ./test/e2e/klor/
package klor_e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// klorBinary is built once per package run and reused across tests.
// The build happens in TestMain so failures fail the whole suite fast
// instead of silently skipping every test.
var klorBinary string

func TestMain(m *testing.M) {
	if runtime.GOOS != "linux" {
		// klor compiles cross-platform but only the linux host runtime
		// can exec a child inside a cgroup. The macOS path returns
		// ErrNotSupported, which is its own (smaller) test surface.
		// Skipping the whole suite here keeps the dev-on-mac story sane.
		_, _ = fmt.Fprintf(os.Stdout, "e2e_klor: skipping on %s (linux-only)\n", runtime.GOOS)
		os.Exit(0)
	}
	repoRoot, err := findRepoRoot()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2e_klor: %v\n", err)
		os.Exit(1)
	}
	tmp, err := os.MkdirTemp("", "klor-e2e-bin-")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2e_klor: mkdir tmp: %v\n", err)
		os.Exit(1)
	}
	klorBinary = filepath.Join(tmp, "klor")
	build := exec.Command("go", "build", "-o", klorBinary, "./cmd/klor")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2e_klor: build failed:\n%s\n", out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// findRepoRoot walks up until it finds go.mod. We can't lean on `go
// list -m` because that would invoke the build system from inside a
// test that's already running under it; the parent-walk is independent
// of any go invocation.
func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// runKlor invokes the built klor binary with the given args + a fresh
// context. Returns stdout, stderr, and the exit code (or -1 on a
// start-error). Times out at 30 s — every flow this suite tests
// completes in milliseconds, so any hang means a real bug.
func runKlor(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(klorBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("klor start: %v", err)
	}
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var code int
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("klor wait: %v", err)
		}
		return stdout.String(), stderr.String(), code
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("klor timed out\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
		return "", "", -1
	}
}

// writeYAML drops a fixture secrets.yaml in t.TempDir() and returns its
// path. Keeps every test's fixtures hermetic.
func writeYAML(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestKlor_VersionlessHelpExits(t *testing.T) {
	// `klor --help` must exit 0 with usage text on stdout. Catches any
	// regression where the cobra wiring breaks at link time.
	stdout, _, code := runKlor(t, "--help")
	if code != 0 {
		t.Errorf("exit code=%d, want 0", code)
	}
	if !strings.Contains(stdout, "klor") || !strings.Contains(stdout, "run") {
		t.Errorf("help output missing 'klor' / 'run' command: %s", stdout)
	}
}

func TestKlor_RunMissingSecretsFlag(t *testing.T) {
	// `klor run -- echo hi` without --secrets is invalid; klor must
	// reject it cleanly (exit 1) with a clear error.
	_, stderr, code := runKlor(t, "run", "--", "echo", "hi")
	if code != 1 {
		t.Errorf("exit code=%d, want 1", code)
	}
	if !strings.Contains(stderr, "--secrets is required") {
		t.Errorf("stderr should explain missing flag, got: %s", stderr)
	}
}

func TestKlor_RunUnsupportedExtension(t *testing.T) {
	// .txt is not a supported secrets file format; the dispatcher must
	// reject it before any runtime work happens.
	path := filepath.Join(t.TempDir(), "secrets.txt")
	if err := os.WriteFile(path, []byte("irrelevant"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, stderr, code := runKlor(t, "run", "--secrets", path, "--", "true")
	if code != 1 {
		t.Errorf("exit code=%d, want 1", code)
	}
	if !strings.Contains(stderr, "unsupported secrets file extension") {
		t.Errorf("stderr should explain bad extension, got: %s", stderr)
	}
}

// TestKlor_RunExecsChildWithEnvInjection is the headline test: build
// the binary, point it at a tempdir cgroup root (so we don't need root
// or a real cgroupfs), and verify the child sees the shadow env var
// AND its stdout makes it back through klor's pipe.
func TestKlor_RunExecsChildWithEnvInjection(t *testing.T) {
	yaml := writeYAML(t, `secrets:
  - name: testkey
    value: my-real-value-1234
    inject:
      env: TEST_KEY
`)
	cgroupRoot := t.TempDir()
	injectRoot := t.TempDir()

	stdout, stderr, code := runKlor(t,
		"run",
		"--secrets", yaml,
		"--cgroup-root", cgroupRoot,
		"--inject-root", injectRoot,
		// --no-rewrite: this test validates the injection + cgroup +
		// child-exec plumbing without the eBPF data plane. Loading BPF
		// programs needs root + a real cgroupfs; the rooted e2e
		// (added separately) covers the rewrite end-to-end.
		"--no-rewrite",
		"--",
		"sh", "-c", "echo got=$TEST_KEY",
	)
	if code != 0 {
		t.Fatalf("exit code=%d, want 0\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	// Child should have seen the shadow placeholder (kl::<UUID>),
	// NOT the real value — the in-kernel rewrite (follow-up PR) is
	// what turns the placeholder back into the real value on the wire.
	if !strings.Contains(stdout, "got=kl::") {
		t.Errorf("child stdout should contain shadow placeholder 'kl::...', got: %s", stdout)
	}
	if strings.Contains(stdout, "my-real-value-1234") {
		t.Errorf("child saw the real secret value in env — that's a regression. stdout: %s", stdout)
	}
	// The transient cgroup slice parent must have been mkdir'd.
	if _, err := os.Stat(filepath.Join(cgroupRoot, "kloak.slice")); err != nil {
		t.Errorf("kloak.slice not created under cgroup-root: %v", err)
	}
}

// TestKlor_RunPropagatesChildExitCode proves the exit-code path from
// runRun through *exitCodeError to main.go's os.Exit translation
// works end-to-end against a real child.
func TestKlor_RunPropagatesChildExitCode(t *testing.T) {
	yaml := writeYAML(t, `secrets:
  - name: testkey
    value: src-snapshot-real
    inject:
      env: TEST_KEY
`)
	_, _, code := runKlor(t,
		"run",
		"--secrets", yaml,
		"--cgroup-root", t.TempDir(),
		"--inject-root", t.TempDir(),
		"--no-rewrite", // same reasoning as TestKlor_RunExecsChildWithEnvInjection
		"--",
		"sh", "-c", "exit 17",
	)
	if code != 17 {
		t.Errorf("exit code=%d, want 17 (child's exit code propagated)", code)
	}
}
