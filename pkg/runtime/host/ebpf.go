//go:build linux

package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/zap"

	"github.com/spinningfactory/kloak/pkg/ebpf"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// ebpfHandle owns the lifecycle of a TLSUprobeManager for one Run
// invocation: BPF programs load on setup, polling goroutines run for
// the duration of the run, and Close drains them + detaches programs
// before the cgroup directory is rmdir'd.
//
// We deliberately treat this as a per-invocation construct rather than
// reusing a long-lived manager across runs. The data plane is cheap to
// load (a few hundred ms) and per-invocation isolation eliminates a
// whole class of cross-invocation collisions (prefix collisions in
// secret_map, pollster leak from one run into the next).
type ebpfHandle struct {
	mgr        *ebpf.TLSUprobeManager
	cgroupID   uint64
	log        *zap.SugaredLogger
	pollCtx    context.Context
	pollCancel context.CancelFunc
	pollWG     sync.WaitGroup
	closeOnce  sync.Once
	// closeErr persists the result of the one real Close call so
	// idempotent retries (deferred cleanups firing multiple times on
	// error paths) report the same outcome instead of returning nil
	// the second time. Without this, "did the BPF program detach
	// cleanly?" loses fidelity on the second caller.
	closeErr error
}

// setupEBPF constructs a TLSUprobeManager and gets it to the state where
// AttachChild can be called: programs loaded, trusted DNS populated,
// cgroup tracked, pollers running. Cleanup on partial-setup error is
// in-function so the caller only owns the success-path handle.
func setupEBPF(
	ctx context.Context,
	src secrets.Source,
	cgroupRoot, cgroupPath string,
	cgroupID uint64,
	log *zap.SugaredLogger,
) (*ebpfHandle, error) {
	mgr, err := ebpf.NewTLSUprobeManager(src, cgroupRoot, log)
	if err != nil {
		return nil, fmt.Errorf("load eBPF programs: %w", err)
	}

	// /etc/resolv.conf is the source of trust for the DNS chain. A
	// missing file is unusual (every linux distro ships one) but
	// shouldn't be fatal — we surface it as a warning and let the
	// child run. The whitelist still gets enabled with the empty list
	// upstream, which means DNS responses get rejected — that surfaces
	// loudly enough on the next user request to be a useful signal.
	dnsIPs, err := readResolvConfNameservers("/etc/resolv.conf")
	if err != nil {
		log.Warnw("could not read /etc/resolv.conf — DNS whitelist will reject all responses", "err", err)
	}
	if err := mgr.PopulateTrustedDNSServers(dnsIPs); err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("populate trusted DNS servers: %w", err)
	}

	if err := mgr.TrackCgroup(cgroupID, cgroupPath); err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("track cgroup %d %s: %w", cgroupID, cgroupPath, err)
	}

	pollCtx, pollCancel := context.WithCancel(ctx)
	h := &ebpfHandle{
		mgr:        mgr,
		cgroupID:   cgroupID,
		log:        log,
		pollCtx:    pollCtx,
		pollCancel: pollCancel,
	}
	// Pollers run for the duration of the invocation. They exit when
	// pollCtx is cancelled by Close. Each one logs its own error path,
	// but we suppress the "context cancelled" tail since that's the
	// normal exit path and would be noise.
	h.pollWG.Add(2)
	go func() {
		defer h.pollWG.Done()
		if perr := mgr.PollEvents(pollCtx); perr != nil && pollCtx.Err() == nil {
			log.Errorw("PollEvents returned unexpectedly", "err", perr)
		}
	}()
	go func() {
		defer h.pollWG.Done()
		if perr := mgr.PollExecEvents(pollCtx); perr != nil && pollCtx.Err() == nil {
			log.Errorw("PollExecEvents returned unexpectedly", "err", perr)
		}
	}()

	return h, nil
}

// AttachChild wires a started child pid into the data plane: records
// the cgroup→netns mapping (so untrack can release the netns fd) and
// attaches TLS uprobes against /proc/<pid>/exe.
//
// There's a tiny race window between cmd.Start and this call where the
// child can make TLS syscalls before uprobes are attached. For typical
// CLI tools (curl, kubectl, etc.) the boot path is long enough that
// the race is unobservable in practice. A follow-up will gate child
// exec behind a sync pipe so AttachChild completes before any
// user-visible work in the child.
func (h *ebpfHandle) AttachChild(pid int) error {
	h.mgr.RecordCgroupNetns(h.cgroupID, pid)
	if err := h.mgr.AttachTLS(pid, h.cgroupID); err != nil {
		return fmt.Errorf("attach TLS uprobes to pid %d: %w", pid, err)
	}
	return nil
}

// Close stops the polling goroutines, untracks the cgroup (releasing
// the pinned netns fd), and detaches the BPF programs. Idempotent so
// the runtime's defer chain can call it safely on multiple paths.
func (h *ebpfHandle) Close() error {
	h.closeOnce.Do(func() {
		h.pollCancel()
		h.pollWG.Wait()
		// UntrackCgroup before Close so the tcAttached netns fd cleanup
		// happens while the manager is still live.
		if err := h.mgr.UntrackCgroup(h.cgroupID); err != nil {
			h.log.Warnw("untrack cgroup failed during close", "err", err, "cgroupID", h.cgroupID)
		}
		h.closeErr = h.mgr.Close()
	})
	return h.closeErr
}

// wrapEBPFSetupError annotates a setupEBPF failure with the most likely
// remediation. The cilium/ebpf "operation not permitted (MEMLOCK may be
// too low)" string is misleading on modern kernels — the actual issue
// is almost always missing capabilities, and the MEMLOCK hint sends
// users down the wrong path. We catch EPERM specifically and surface a
// clear action; other errors get a generic safety reminder.
func wrapEBPFSetupError(err error) error {
	if errors.Is(err, syscall.EPERM) {
		return fmt.Errorf("eBPF requires CAP_SYS_ADMIN (rerun with sudo) "+
			"or CAP_BPF+CAP_PERFMON+CAP_NET_ADMIN via setcap. "+
			"Pass --no-rewrite to test the injection plumbing without it, "+
			"but shadow placeholders WILL leak unredacted in that mode. "+
			"Underlying error: %w", err)
	}
	return fmt.Errorf("setup eBPF: %w "+
		"(use --no-rewrite for dev only — secrets WILL leak unredacted)", err)
}

// readResolvConfNameservers parses /etc/resolv.conf and returns the
// `nameserver` entries. Comments (#/;), blank lines, and non-nameserver
// directives (search, options, …) are silently ignored. Malformed IP
// addresses are dropped rather than failing the whole parse — a single
// typo shouldn't prevent krunk from running.
func readResolvConfNameservers(path string) ([]net.IP, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var ips []net.IP
	s := bufio.NewScanner(f)
	for s.Scan() {
		// resolv.conf treats anything from the first `#` or `;` to
		// end-of-line as a comment, regardless of preceding whitespace.
		// `nameserver 8.8.8.8#hint` is a valid line: the `8.8.8.8` is
		// the address, `#hint` is a trailing comment, NOT part of the
		// IP. Strip first, split into fields second — the reverse order
		// (the old implementation) would treat the entire `8.8.8.8#hint`
		// as the address field and ParseIP would drop it silently.
		line := s.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, s.Err()
}
