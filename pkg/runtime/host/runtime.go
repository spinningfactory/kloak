//go:build linux

// Package host implements runtime.Runtime as a host-process backend:
// the child runs as a normal Linux process inside a transient cgroup,
// and kloak's eBPF programs run in the host kernel for the duration
// of the invocation.
//
// This is the smallest path to a working `kloak run` — no VM, no
// guest agent, no image distribution, and every byte of the existing
// `pkg/ebpf.TLSUprobeManager` is reused directly. The trade-off is
// operational surface: kloak's BPF programs touch the host kernel and
// the runtime requires CAP_SYS_ADMIN (or root) — same operational
// profile as the controller DaemonSet today.
//
// What lands here (PR #221 + the eBPF wiring on top):
//   - the Runtime interface surface (`New() Runtime`, `WithEBPF()`)
//   - cgroup primitive integration (CreateTransient from #220)
//   - injection materialization (env + file per Secret.Inject)
//   - child exec inside the cgroup with stdio inheritance
//   - eBPF data plane: TLSUprobeManager load, TrackCgroup,
//     RecordCgroupNetns, AttachTLS, trusted-DNS population, and the
//     PollEvents/PollExecEvents goroutines that drain the ring buffers
//   - signal forwarding (SIGINT / SIGTERM / SIGHUP) to the child
//   - exit-code propagation
//   - deterministic cleanup of cgroup + tmpfs injection dir + BPF
//     program detach
//
// Open follow-ups (intentionally deferred):
//   - sync-pipe gate to close the cmd.Start → AttachChild race window
//   - rootless mode via cgroup-v2 delegation + CAP_BPF/CAP_PERFMON
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/runtime"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// Option configures a hostRuntime at construction. Options are
// composable so the caller picks the policy that matches its context
// (CLI invocation vs unit test vs future microvm-agent re-use).
type Option func(*hostRuntime)

// WithEBPF enables the in-kernel TLS rewrite for invocations made
// through this Runtime. The CLI sets this by default; tests omit it
// because loading BPF programs needs CAP_BPF / CAP_SYS_ADMIN — readily
// available after install.sh runs setcap, or via sudo, but absent from
// a vanilla `go test` invocation.
//
// When unset (the zero-value default) Run exec's the child correctly
// but the rewrite is a no-op — the child's shadow placeholders go on
// the wire verbatim. This is useful for testing the injection
// plumbing without privileges; it is NOT a secure mode and must not
// be the production default. cmd/krunk wraps this behind the explicit
// `--no-rewrite` flag with a loud startup warning.
func WithEBPF() Option {
	return func(r *hostRuntime) { r.ebpfEnabled = true }
}

// New returns a host-cgroup Runtime.
//
// cgroupRoot defaults to `/sys/fs/cgroup` (cgroups.DefaultCgroupRoot)
// when empty. Privilege to mkdir under that path comes from one of:
//
//   - `sudo krunk …` — CAP_SYS_ADMIN via the sudo session.
//   - File capabilities applied by install.sh: the binary carries
//     `cap_dac_override,cap_sys_admin,…+ep` so the process has the
//     right caps without sudo. See install.sh in the repo root.
//
// injectRoot is the tmpfs base for `inject.file` materialization. When
// empty, defaults to `/run/kloak` for root and `$XDG_RUNTIME_DIR/kloak`
// (typically `/run/user/$UID/kloak`) for unprivileged callers, since
// `/run` is not writable to them. Falls back to `/tmp/kloak` if
// XDG_RUNTIME_DIR isn't set — better than failing outright.
//
// opts is a variadic of Option-returning helpers (currently only
// WithEBPF); callers pass them to opt into the in-kernel TLS rewrite.
func New(cgroupRoot, injectRoot string, log *zap.SugaredLogger, opts ...Option) runtime.Runtime {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	if injectRoot == "" {
		injectRoot = chooseInjectRoot()
	}
	if cgroupRoot == "" {
		cgroupRoot = cgroups.DefaultCgroupRoot
	}
	r := &hostRuntime{
		cgroupRoot: cgroupRoot,
		injectRoot: injectRoot,
		log:        log,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// annotateCgroupError wraps a CreateTransient error with a one-line
// remediation hint. EPERM as a non-root user always means we don't
// have the caps needed for cgroup-v2 mkdir + the cgroup.procs write
// that follows; we point at the required cap set and let the operator
// decide between `sudo`, file capabilities, or another path.
func annotateCgroupError(err error) error {
	if os.Geteuid() == 0 || !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("create cgroup: %w", err)
	}
	return fmt.Errorf("create cgroup: %w\n"+
		"krunk needs CAP_SYS_ADMIN + CAP_DAC_OVERRIDE to mkdir under /sys/fs/cgroup and write cgroup.procs",
		err)
}

// chooseInjectRoot returns the staging root for `inject.file` writes.
// `/run` requires CAP_DAC_OVERRIDE to create subdirectories under
// without being root, so for non-root callers we prefer the per-user
// tmpfs systemd-logind provisions at session start (XDG_RUNTIME_DIR).
// `/tmp/kloak` is the last resort — writable to anyone but
// world-readable, so the `inject.file` 0o400 mode + per-invocation
// UUID path are the actual confidentiality protection there.
func chooseInjectRoot() string {
	if os.Geteuid() == 0 {
		return "/run/kloak"
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		return filepath.Join(x, "kloak")
	}
	return "/tmp/kloak"
}

type hostRuntime struct {
	cgroupRoot  string
	injectRoot  string
	log         *zap.SugaredLogger
	ebpfEnabled bool
}

func (r *hostRuntime) Run(ctx context.Context, spec *runtime.Spec) (int, error) {
	if spec == nil {
		return -1, errors.New("spec is nil")
	}
	if len(spec.Cmd) == 0 {
		return -1, errors.New("spec.Cmd is empty")
	}

	// 1. Snapshot the secrets so the same view drives both the
	//    injection materialization and (in the follow-up PR) the BPF
	//    map sync. The Source contract says Snapshot may be called
	//    multiple times, but pinning it once here keeps the runtime's
	//    behavior deterministic.
	snap, err := snapshotOrEmpty(ctx, spec.Secrets)
	if err != nil {
		return -1, fmt.Errorf("snapshot secrets: %w", err)
	}

	// 2. Allocate a per-invocation UUID. Used as both the cgroup
	//    directory name and the injection-tmpfs subdir name so the
	//    two halves are co-located for postmortem.
	invID := uuid.NewString()

	// 3. Create the transient cgroup. The cleanup func runs on every
	//    exit path via defer.
	cgPath, cgID, cgCleanup, err := cgroups.CreateTransient(r.cgroupRoot, invID)
	if err != nil {
		return -1, annotateCgroupError(err)
	}
	defer func() {
		if err := cgCleanup(); err != nil {
			r.log.Warnw("transient cgroup cleanup failed", "err", err, "path", cgPath)
		}
	}()
	r.log.Debugw("created transient cgroup", "path", cgPath, "id", cgID, "invocation", invID)

	// 4. Materialize injection. Env vars come back as a []string the
	//    child inherits; file injections are written into a
	//    per-invocation tmpfs dir whose path is captured for cleanup.
	injectDir := filepath.Join(r.injectRoot, invID)
	injEnv, injectCleanup, err := materializeInjection(snap, injectDir)
	if err != nil {
		return -1, fmt.Errorf("materialize injection: %w", err)
	}
	defer func() {
		if err := injectCleanup(); err != nil {
			r.log.Warnw("injection cleanup failed", "err", err, "dir", injectDir)
		}
	}()

	// 4b. Construct the eBPF data plane *before* the child starts so
	//     TLS uprobes are ready to attach the moment we have a PID.
	//     With WithEBPF() off (unit tests, dev no-rewrite mode) this
	//     is a no-op and the child sees shadow placeholders verbatim
	//     on the wire.
	//
	//     TODO(phase-3b-followup): the window between cmd.Start and
	//     AttachChild remains unguarded. A sync pipe will let the
	//     parent gate the child's exec until uprobes are attached.
	var ebpf *ebpfHandle
	if r.ebpfEnabled {
		var setupErr error
		ebpf, setupErr = setupEBPF(ctx, spec.Secrets, r.cgroupRoot, cgPath, cgID, r.log)
		if setupErr != nil {
			return -1, wrapEBPFSetupError(setupErr)
		}
		defer func() {
			if err := ebpf.Close(); err != nil {
				r.log.Warnw("eBPF close failed", "err", err)
			}
		}()
	}

	// 5. Build the child command. We don't exec the user's command
	//    directly — instead a tiny `sh -c 'read <&3; exec "$@"'` shim
	//    sits between krunk and the user's command. The shim's only job
	//    is to block on a sync pipe (FD 3, the read end of a pipe whose
	//    write end krunk holds) until krunk explicitly releases it.
	//
	//    This is THE fix for the AttachTLS-vs-short-lived-child race:
	//    krunk previously had no way to guarantee that uprobes were
	//    attached BEFORE the user's TLS code ran. A loopback `curl`
	//    completes in ~1 ms — faster than AttachTLS can open
	//    /proc/<pid>/exe, parse its ELF, and load uprobes — so the
	//    real value would have already gone over the wire before any
	//    rewrite hook existed. With the gate, krunk finishes all setup
	//    (cgroup migration, AttachTLS, BPF map updates) and only THEN
	//    closes the pipe, letting the shim's `read` return EOF and the
	//    `exec` replace the shim with the user's command in-place
	//    (same PID, same cgroup, same tracked-tgid state).
	//
	//    The shim adds one extra `exec` step in the kernel but no
	//    extra process — the shell `exec` replaces itself, so cmd.Wait
	//    still returns the user command's exit code unchanged. Signal
	//    forwarding still targets the original Process.Pid because
	//    exec-replacement preserves it.
	syncRead, syncWrite, err := os.Pipe()
	if err != nil {
		return -1, fmt.Errorf("sync pipe: %w", err)
	}
	defer func() { _ = syncWrite.Close() }()

	// The shim script: `read _ <&3` waits until we close FD 3's write
	// end (returns EOF). `_` is a placeholder variable — required by
	// POSIX `read`, which `dash` (Ubuntu's /bin/sh) enforces strictly
	// even though `bash` accepts a bare `read`. Without the placeholder
	// dash prints `read: arg count` and falls through with an error,
	// defeating the whole point of the gate. Then `exec "$@"` replaces
	// the shell with the user's command in-place. `--` passes the
	// remaining args as positional $1, $2, … so `$@` re-assembles them.
	const shimScript = `read _ <&3; exec "$@"`
	shimArgs := append([]string{"-c", shimScript, "--"}, spec.Cmd...)
	cmd := exec.CommandContext(ctx, "/bin/sh", shimArgs...)
	cmd.Env = composeEnv(spec.ExtraEnv, injEnv)
	cmd.Dir = spec.WorkDir
	cmd.Stdin = orDefault(spec.Stdin, os.Stdin)
	cmd.Stdout = orWriter(spec.Stdout, os.Stdout)
	cmd.Stderr = orWriter(spec.Stderr, os.Stderr)
	// ExtraFiles starts mapping at FD 3 in the child — must match the
	// `<&3` in shimScript above.
	cmd.ExtraFiles = []*os.File{syncRead}
	// Put the child in its own process group so a parent SIGINT
	// doesn't propagate twice (once to us, once to the child) — we
	// forward it explicitly below.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		_ = syncRead.Close()
		return -1, fmt.Errorf("start child: %w", err)
	}
	// krunk doesn't read from the sync pipe — only writes (specifically
	// closing the write end to signal EOF). Close the read end after
	// fork so krunk isn't the second holder; otherwise sh's `read` would
	// never see EOF when we close `syncWrite`.
	_ = syncRead.Close()

	// 6. Move the shim's PID into the transient cgroup BEFORE releasing
	//    the gate. Failing this is fatal: if the shim runs outside our
	//    cgroup, the eBPF data plane will not intercept its TLS writes
	//    — the user would think their traffic is being rewritten when
	//    it isn't, and a real secret would leak unredacted. Kill the
	//    shim and surface the error rather than silently degrade to
	//    "running but un-intercepted".
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return -1, fmt.Errorf("attach child pid %d to cgroup %s: %w (TLS rewrite would not apply — refusing to run unprotected)",
			cmd.Process.Pid, cgPath, err)
	}

	// Debug-log to verify the move actually took. Useful when triaging
	// "rewrite never fires" reports — silent migration failures look
	// like rewrite failures from the user's perspective.
	if procBytes, perr := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", cmd.Process.Pid)); perr == nil {
		r.log.Debugw("post-cgroup-move verification",
			"pid", cmd.Process.Pid,
			"expected_cgroup_path", cgPath,
			"actual_proc_cgroup", strings.TrimSpace(string(procBytes)))
	}

	// 6b. Attach TLS uprobes against the shim — still gated, hasn't
	//     exec'd the user's command yet. AttachTLS opens /proc/<pid>/exe
	//     to read the ELF; that's /bin/sh right now and won't have TLS
	//     symbols, but TrackTGID still runs so DNS / connect filtering
	//     for the upcoming exec is wired. PollExecEvents picks up the
	//     subsequent sh→user_command exec and re-attaches uprobes
	//     against the user binary's libssl (uprobes attach to library
	//     files system-wide, so the second attach is fast).
	if ebpf != nil {
		if err := ebpf.AttachChild(cmd.Process.Pid); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return -1, fmt.Errorf("%w (TLS rewrite would not apply — refusing to run unprotected)", err)
		}
	}

	// 6c. Everything's in place: cgroup membership locked in, BPF
	//     programs loaded, uprobes attached, polling goroutines
	//     running. Close the sync pipe's write end → shim's
	//     `read <&3` returns EOF → shim exec's the user's command
	//     in-place. From this moment forward the user's command is
	//     running with full rewrite coverage.
	_ = syncWrite.Close()

	// 7. Forward signals to the child. Stop the signal handler before
	//    Wait returns so the goroutine doesn't outlive the runtime.
	stopSignals := forwardSignals(cmd.Process, r.log)
	defer stopSignals()

	// 8. Wait for the child to exit and translate to an exit code.
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return -1, fmt.Errorf("child wait: %w", err)
	}
	return 0, nil
}

// snapshotOrEmpty returns an empty snapshot when Secrets is nil, so
// callers can pass `Spec{Secrets: nil}` for "run a command in a cgroup
// with no secrets attached" — useful for tests and for runtime smoke
// checks that don't need TLS rewriting.
func snapshotOrEmpty(ctx context.Context, src secrets.Source) ([]secrets.Secret, error) {
	if src == nil {
		return nil, nil
	}
	return src.Snapshot(ctx)
}

// composeEnv merges the caller's ExtraEnv with the runtime's injected
// env vars. Inject values override ExtraEnv keys; both override the
// inherited process env via the standard os/exec semantics (cmd.Env
// replaces, doesn't append). We always prepend os.Environ() so the
// child sees PATH, HOME, etc.
func composeEnv(extra, inject []string) []string {
	out := append([]string{}, os.Environ()...)
	out = append(out, extra...)
	out = append(out, inject...)
	return out
}

// orDefault returns r when non-nil, else fallback. Tiny helper to
// keep the Run body readable.
func orDefault(r interface{ Read([]byte) (int, error) }, fallback *os.File) interface {
	Read([]byte) (int, error)
} {
	if r != nil {
		return r
	}
	return fallback
}

func orWriter(w interface{ Write([]byte) (int, error) }, fallback *os.File) interface {
	Write([]byte) (int, error)
} {
	if w != nil {
		return w
	}
	return fallback
}

// forwardSignals listens for SIGINT/SIGTERM/SIGHUP and forwards them
// to the child's process group. Returns a stop function the caller
// defers; stop is safe to call multiple times.
func forwardSignals(proc *os.Process, log *zap.SugaredLogger) func() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	var stopOnce sync.Once
	done := make(chan struct{})
	go func() {
		for sig := range ch {
			// Negative pid signals the entire process group, which is
			// what we want because cmd.SysProcAttr.Setpgid=true put
			// the child at the head of its own group.
			if err := syscall.Kill(-proc.Pid, sig.(syscall.Signal)); err != nil {
				log.Debugw("forward signal", "err", err, "signal", sig)
			}
		}
		close(done)
	}()
	return func() {
		stopOnce.Do(func() {
			signal.Stop(ch)
			close(ch)
			<-done
		})
	}
}
