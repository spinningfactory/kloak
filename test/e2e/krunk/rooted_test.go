//go:build e2e_krunk_rooted

// Package krunk_e2e_rooted exercises the install.sh + cap-on-binary
// rootless install path end-to-end.
//
// What this validates today (PR #221 base, no eBPF wiring yet):
//   - install.sh runs (with sudo-detect, with checkout-local build)
//   - the binary lands at PREFIX/krunk with the kernel-version-appropriate
//     capability set
//   - getcap confirms the caps actually stuck (catches AppArmor /
//     SELinux / NFS-acl strip regressions)
//   - krunk, invoked as the same user (no sudo prefix), exits 0 — proves
//     the cgroup operations work via cap delegation
//
// What this does NOT validate yet:
//   - the in-kernel TLS rewrite, because the eBPF wiring is on
//     feat/runtime-host-ebpf and hasn't merged. A follow-up extends
//     this file with an in-process TLS echo server + a real-value
//     assertion in the wire body.
//
// The test does NOT touch /usr/local/bin — it uses a temp INSTALL_PREFIX
// so re-runs are safe on dev machines.
package krunk_e2e

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

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// requireRootedEnv gates every rooted test on (Linux + root). Lifted
// into a helper instead of a package-level TestMain because the
// `e2e_krunk` and `e2e_krunk_rooted` build tags can be active
// simultaneously (golangci-lint typechecks across all tags), and
// having two TestMains in the same package fails to link.
func requireRootedEnv(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("Linux-only (got %s)", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to run install.sh + setcap")
	}
}

func TestInstallScript_FromCheckout(t *testing.T) {
	requireRootedEnv(t)
	repoRoot, err := findRepoRootForRootedTest()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	prefix := t.TempDir()
	installSh := filepath.Join(repoRoot, "install.sh")
	if _, err := os.Stat(installSh); err != nil {
		t.Fatalf("install.sh not present at %s: %v", installSh, err)
	}

	// Run install.sh against a sandbox prefix so we don't clobber a real
	// /usr/local/bin/krunk on the test host.
	cmd := exec.Command(installSh, "--prefix", prefix)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install.sh failed: %v\n%s", err, out)
	}

	krunkPath := filepath.Join(prefix, "krunk")
	st, err := os.Stat(krunkPath)
	if err != nil {
		t.Fatalf("krunk not at %s after install.sh: %v\n%s", krunkPath, err, out)
	}
	if mode := st.Mode().Perm(); mode&0o111 == 0 {
		t.Errorf("installed krunk at %s is not executable (mode %v)", krunkPath, mode)
	}

	// Verify the caps stuck. The kernel-version-aware capset chosen by
	// install.sh is harder to assert exactly (depends on the runner's
	// kernel), so we verify the bare-minimum subset that every supported
	// kernel should produce: cap_sys_admin + cap_dac_override. If either
	// is missing the rest of the suite would fail anyway.
	caps, err := exec.Command("getcap", krunkPath).CombinedOutput()
	if err != nil {
		t.Fatalf("getcap failed: %v\n%s", err, caps)
	}
	for _, want := range []string{"cap_sys_admin", "cap_dac_override"} {
		if !bytes.Contains(caps, []byte(want)) {
			t.Errorf("getcap output missing required cap %q: %s", want, caps)
		}
	}
}

func TestKrunkRunsWithoutSudoAfterInstall(t *testing.T) {
	requireRootedEnv(t)
	repoRoot, err := findRepoRootForRootedTest()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	// Install krunk into the sandbox prefix.
	prefix := t.TempDir()
	installCmd := exec.Command(filepath.Join(repoRoot, "install.sh"), "--prefix", prefix)
	installCmd.Dir = repoRoot
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh failed: %v\n%s", err, out)
	}
	krunkPath := filepath.Join(prefix, "krunk")

	// Drop privileges via setpriv to prove the cap-on-binary path
	// actually works for unprivileged users. We need a non-root uid to
	// drop to; SUDO_UID is set when the test was invoked via sudo (the
	// expected CI / dev path). If neither SUDO_UID nor a usable
	// alternate uid is in env, fall back to uid 1000 (typical for
	// ubuntu-latest's `ubuntu` user). The test then trusts setpriv to
	// fail clearly if that uid doesn't exist.
	dropUID := dropTargetUID(t)
	if dropUID == 0 {
		// Already non-root somehow (shouldn't happen given TestMain
		// gates on root, but be explicit).
		t.Skip("can't drop to a non-zero uid")
	}

	yaml := writeYAMLForRootedTest(t, `secrets:
  - name: k
    value: rooted-e2e-real-value
    inject:
      env: K
`)

	cmd := exec.Command(
		"setpriv", "--reuid", fmt.Sprintf("%d", dropUID), "--regid", fmt.Sprintf("%d", dropUID), "--init-groups",
		// Clear PATH-from-root so krunk isn't tempted to find some other
		// build via the test invoker's $PATH; pass it explicitly via
		// absolute path.
		krunkPath, "run",
		"--secrets", yaml,
		"--", "sh", "-c", "echo got=$K",
	)
	cmd.Env = append(os.Environ(), krunkCoverEnv(t)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("krunk (post-install, uid %d) failed: %v\n%s", dropUID, err, out)
	}

	// Child should have seen the shadow placeholder in its env. The
	// real value never reaches the child until the eBPF rewrite
	// follow-up lands — for now we assert the structural plumbing:
	// krunk exec'd the child, env injection happened, exit code 0.
	got := strings.TrimSpace(string(out))
	if !strings.Contains(got, "got=kl::") {
		t.Errorf("expected shadow 'got=kl::...' in output, got: %q", got)
	}
	if strings.Contains(got, "rooted-e2e-real-value") {
		t.Errorf("real value leaked to child env (bug regression?): %q", got)
	}
}

// TestKrunkRewritesShadowOnTheWire is the end-to-end assertion this
// whole stack exists to enable: a non-root krunk invocation reaches a
// TLS server with the *real* secret in the request body, while the
// child process only ever saw the shadow placeholder.
//
// What it catches (in one shot):
//   - eBPF program load regressions (PR #223 ARCH substitution bug)
//   - libssl offset regressions across kernel/OpenSSL versions
//     (PR #222 wbio offset bug)
//   - cgroup migration race fixes (krunk's cgroup.procs write must land
//     before curl issues SSL_write)
//   - the kubepods-on-non-k8s downgrade landing here (without it the
//     ERROR log would fire and arguably the cgroup_ancestor path
//     could refuse to set up)
//   - install.sh's setcap (without it, the BPF program load EPERMs
//     and the whole pipeline never starts)
//
// What it can NOT catch yet:
//   - DNS-chain breakage on hosts running systemd-resolved — the
//     wildcard-secret path bypasses the dns_ip_map gate for now, so
//     the test works on hosts where DNS interception is broken. A
//     stronger variant that uses host: filter and asserts the
//     systemd-resolved fallback would be a separate test, currently
//     gated on a fix for that issue.
func TestKrunkRewritesShadowOnTheWire(t *testing.T) {
	requireRootedEnv(t)
	repoRoot, err := findRepoRootForRootedTest()
	if err != nil {
		t.Fatalf("find repo root: %v", err)
	}

	// Install krunk with caps into a sandbox prefix so we don't disturb
	// a real install on the test host.
	prefix := t.TempDir()
	installCmd := exec.Command(filepath.Join(repoRoot, "install.sh"), "--prefix", prefix)
	installCmd.Dir = repoRoot
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh failed: %v\n%s", err, out)
	}
	krunkPath := filepath.Join(prefix, "krunk")

	// In-process TLS echo server on a random loopback port. The cert
	// is self-signed and only valid for 127.0.0.1/::1, so curl needs
	// --insecure (the wire bytes are still TLS-encrypted — the
	// rewrite happens at the SSL_write boundary, before encryption).
	echo, stop := startEchoServer(t)
	t.Cleanup(stop)

	const real = "rewrite-real-value-for-rooted-e2e-1234567890"
	yaml := writeYAMLForRootedTest(t, fmt.Sprintf(`secrets:
  - name: k
    value: %s
    inject:
      file: %s
`, real, filepath.Join("/tmp", "kloak-rewrite-payload")))

	// The injection file path is chosen at /tmp/ rather than
	// $XDG_RUNTIME_DIR/kloak/* so curl, running as a different uid
	// post-setpriv, can definitely read it (XDG_RUNTIME_DIR is
	// 0700 owned by SUDO_UID's user, which may not match our drop
	// target). The shadow placeholder is the only thing written
	// there — value confidentiality is provided by the rewrite.
	payloadPath := filepath.Join("/tmp", "kloak-rewrite-payload")
	t.Cleanup(func() { _ = os.Remove(payloadPath) })

	dropUID := dropTargetUID(t)
	if dropUID == 0 {
		t.Skip("can't drop to a non-zero uid")
	}

	// `curl --insecure` to accept the self-signed cert, --data-binary
	// to send the file contents verbatim (the shadow), -s to silence
	// progress noise. The whole point: curl is the cap'd krunk's
	// direct child, so krunk.cgroup.procs migration races neither bash
	// nor a re-exec — the cleanest possible attach window.
	// Direct curl exec — no sleep, no shell wrapper. krunk's sync-pipe
	// gate (see runtime.go) guarantees uprobes are attached BEFORE
	// the user's curl can call SSL_write, so the loopback-curl-
	// completes-in-1ms race that previously needed a sleep workaround
	// is closed at the runtime layer instead of papered over in the
	// test.
	cmd := exec.Command(
		"setpriv", "--reuid", fmt.Sprintf("%d", dropUID), "--regid", fmt.Sprintf("%d", dropUID), "--init-groups",
		krunkPath, "run",
		"--secrets", yaml,
		"--",
		"/usr/bin/curl", "-sk", "--data-binary", "@"+payloadPath, echo.URL+"/",
	)
	cmd.Env = append(os.Environ(), krunkCoverEnv(t)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("krunk + curl failed: %v\n%s", err, out)
	}

	// Server-side assertion: the bytes the TLS endpoint saw must
	// contain the real value, not the shadow. If the rewrite didn't
	// fire, the body is `kl::<random-tail>` of matching length.
	body := echo.waitForRequest(5 * time.Second)
	if body == nil {
		t.Fatalf("echo server did not receive the request — krunk/curl output:\n%s", out)
	}
	got := string(body)
	if !strings.Contains(got, real) {
		t.Errorf("echo server did NOT see real value — rewrite failed.\n  wanted body to contain: %q\n  got body:               %q", real, got)
	}
	if strings.Contains(got, secrets.ValuePrefix) {
		t.Errorf("echo server saw the SHADOW on the wire — rewrite did not fire:\n  body: %q", got)
	}
}

// krunkCoverEnv returns the env entries to pass when invoking the cap'd
// krunk binary so that any `-cover`-instrumented runs flush covcounters
// into a directory the CI's Krunk E2E job can later pick up and merge
// into the combined coverage profile.
//
// The mechanism: CI sets `KRUNK_COVDATA_DIR=/tmp/krunk-covdata` (host
// path) and `KRUNK_COVER=1` (consumed by install.sh to add
// `-cover -covermode=atomic -tags cover` to `go build`). Each rooted
// test then forwards `GOCOVERDIR=<that dir>` into krunk's env. Krunk's
// `flushCoverage` (cmd/krunk/coverage_flush_cover.go, compiled in via
// `-tags cover`) writes covcounters into that dir before os.Exit
// fires. CI converts the binary covdata to text format via
// `go tool covdata textfmt` and merges into combined-coverage.
//
// chmod 1777 because the dir is created as root (the test runs as
// root via TestMain's gate) but krunk runs under setpriv as the
// dropped uid — without a permissive mode the writer would EACCES.
func krunkCoverEnv(t *testing.T) []string {
	t.Helper()
	dir := os.Getenv("KRUNK_COVDATA_DIR")
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o1777); err != nil {
		t.Fatalf("mkdir KRUNK_COVDATA_DIR=%s: %v", dir, err)
	}
	// MkdirAll may not apply the sticky bit when the dir already
	// exists — re-chmod to be explicit.
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatalf("chmod KRUNK_COVDATA_DIR=%s: %v", dir, err)
	}
	return []string{"GOCOVERDIR=" + dir}
}

// dropTargetUID picks a non-root uid to drop privilege to. Preference
// order: SUDO_UID (set by sudo, points at the actual invoking user),
// then a hardcoded fallback. We don't probe /etc/passwd here — setpriv
// will give a clear error if the chosen uid doesn't exist.
func dropTargetUID(t *testing.T) int {
	t.Helper()
	if s := os.Getenv("SUDO_UID"); s != "" {
		var u int
		if _, err := fmt.Sscanf(s, "%d", &u); err == nil && u > 0 {
			return u
		}
	}
	// Fallback: 1000 (ubuntu/debian default) — present on every CI image
	// we run on and most dev boxes. setpriv fails loud if it isn't there.
	return 1000
}

func findRepoRootForRootedTest() (string, error) {
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
			return "", fmt.Errorf("no go.mod found walking up from %s", wd)
		}
		dir = parent
	}
}

func writeYAMLForRootedTest(t *testing.T, body string) string {
	t.Helper()
	// The test runs as root (via TestMain gate), but krunk will run as
	// the dropped uid via setpriv. The fixture file needs to be
	// readable by that uid; t.TempDir() gives us a 0700 dir owned by
	// root that the dropped uid can't read. Use /tmp + a unique
	// sub-dir we open up to all.
	dir, err := os.MkdirTemp("/tmp", "krunk-rooted-fixture-")
	if err != nil {
		t.Fatalf("mkdir tmp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod fixture dir: %v", err)
	}
	path := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
