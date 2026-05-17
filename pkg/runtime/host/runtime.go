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
// eBPF wiring (TLSUprobeManager construction, TrackCgroup / AttachTLS /
// PollEvents goroutines, trusted DNS population) is a follow-up PR.
// What lands here:
//   - the Runtime interface surface (`New() Runtime`)
//   - cgroup primitive integration (CreateTransient from #220)
//   - injection materialization (env + file per Secret.Inject)
//   - child exec inside the cgroup with stdio inheritance
//   - signal forwarding (SIGINT / SIGTERM / SIGHUP) to the child
//   - exit-code propagation
//   - deterministic cleanup of cgroup + tmpfs injection dir
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
	"sync"
	"syscall"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/runtime"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// New returns a host-cgroup Runtime.
//
// cgroupRoot defaults to `/sys/fs/cgroup` (cgroups.DefaultCgroupRoot)
// when empty. Privilege to mkdir under that path comes from one of:
//
//   - `sudo klor …` — CAP_SYS_ADMIN via the sudo session.
//   - File capabilities applied by install.sh: the binary carries
//     `cap_dac_override,cap_sys_admin,…+ep` so the process has the
//     right caps without sudo. See install.sh in the repo root.
//
// injectRoot is the tmpfs base for `inject.file` materialization. When
// empty, defaults to `/run/kloak` for root and `$XDG_RUNTIME_DIR/kloak`
// (typically `/run/user/$UID/kloak`) for unprivileged callers, since
// `/run` is not writable to them. Falls back to `/tmp/kloak` if
// XDG_RUNTIME_DIR isn't set — better than failing outright.
func New(cgroupRoot, injectRoot string, log *zap.SugaredLogger) runtime.Runtime {
	if log == nil {
		log = zap.NewNop().Sugar()
	}
	if injectRoot == "" {
		injectRoot = chooseInjectRoot()
	}
	if cgroupRoot == "" {
		cgroupRoot = cgroups.DefaultCgroupRoot
	}
	return &hostRuntime{
		cgroupRoot: cgroupRoot,
		injectRoot: injectRoot,
		log:        log,
	}
}

// annotateCgroupError wraps a CreateTransient error with a remediation
// hint pointing at install.sh (or sudo as the always-works fallback).
// EPERM as a non-root user always means we don't have the caps needed
// for cgroup-v2 mkdir + the cgroup.procs write that follows. The
// in-tree install.sh fixes this by setting file capabilities on the
// binary; sudo is the per-invocation alternative.
func annotateCgroupError(err error) error {
	if os.Geteuid() == 0 || !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("create cgroup: %w", err)
	}
	return fmt.Errorf("create cgroup: %w\n\n"+
		"klor needs CAP_SYS_ADMIN + CAP_DAC_OVERRIDE for cgroup-v2 mkdir + process migration. Two fixes:\n"+
		"  1. Reinstall klor so the binary carries the caps:\n"+
		"     curl -fsSL https://github.com/spinningfactory/kloak/raw/main/install.sh | bash\n"+
		"     (one-time, then klor runs as your user with no prefix)\n"+
		"  2. sudo klor run …\n"+
		"     (per-invocation; same caps, granted via the sudo session)",
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
	cgroupRoot string
	injectRoot string
	log        *zap.SugaredLogger
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

	// TODO(phase-3b-followup): construct pkg/ebpf.TLSUprobeManager
	// here, call TrackCgroup(cgID, cgPath), RecordCgroupNetns(cgID,
	// child PID once available), AttachTLS(child PID, cgID),
	// PopulateTrustedDNSServers from /etc/resolv.conf, and spawn
	// PollEvents / PollExecEvents goroutines. Until that lands the
	// runtime executes the child correctly but the in-kernel rewrite
	// is a no-op — the child sees shadow placeholders in its env and
	// sends them over the wire verbatim.
	_ = snap // referenced by the BPF map sync in the follow-up

	// 5. Build the child command and start it inside the cgroup.
	cmd := exec.CommandContext(ctx, spec.Cmd[0], spec.Cmd[1:]...) //nolint:gosec // user-supplied cmd is the whole point of `kloak run`
	cmd.Env = composeEnv(spec.ExtraEnv, injEnv)
	cmd.Dir = spec.WorkDir
	cmd.Stdin = orDefault(spec.Stdin, os.Stdin)
	cmd.Stdout = orWriter(spec.Stdout, os.Stdout)
	cmd.Stderr = orWriter(spec.Stderr, os.Stderr)
	// Put the child in its own process group so a parent SIGINT
	// doesn't propagate twice (once to us, once to the child) — we
	// forward it explicitly below.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start child: %w", err)
	}

	// 6. Move the child's PID into the transient cgroup. Failing this
	//    is fatal: if the child runs outside our cgroup, the eBPF data
	//    plane (wired in the follow-up PR) will not intercept its TLS
	//    writes — the user would think their traffic is being rewritten
	//    when it isn't, and a real secret would leak unredacted. Kill
	//    the child immediately and surface the error rather than
	//    silently degrade to "running but un-intercepted".
	//
	//    There's still a tiny race window between Start and this write
	//    where the child can issue syscalls outside the cgroup. A
	//    follow-up will gate exec behind a sync pipe so the move
	//    completes before any user-visible work runs in the child.
	if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"),
		[]byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		// Best-effort kill — the child may already be dead, in which
		// case Kill returns ESRCH. Wait reaps either way; we ignore
		// its error since we're returning a more interesting one.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return -1, fmt.Errorf("attach child pid %d to cgroup %s: %w (TLS rewrite would not apply — refusing to run unprotected)",
			cmd.Process.Pid, cgPath, err)
	}

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
