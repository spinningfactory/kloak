//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/cgroups"
	"github.com/spinningfactory/kloak/pkg/logging"
	"github.com/spinningfactory/kloak/pkg/secrets"
)

// tlsEvent must match the C struct tls_event (lightweight, no data payload)
type tlsEvent struct {
	Pid         uint32
	Tgid        uint32
	Len         uint32
	IsRewritten uint8
	_           [3]byte // padding for alignment
}

// procEvent must match the C struct kloak_proc_event
type procEvent struct {
	Tgid     uint32
	Type     uint8 // 1 = exec, 2 = exit
	_        [3]byte
	CgroupID uint64
}

// secretKey matches C struct secret_key (SECRET_KEY_LEN = 8)
type secretKey struct {
	Prefix [8]byte
}

// secretValue matches C struct secret_value
type secretValue struct {
	Len         uint32
	RealSecret  [128]byte
	HostLen     uint32
	AllowedHost [64]byte
	IpLen       uint32
	AllowedIp   [16]byte // IPv4-mapped-IPv6
	Port        uint16   // 0 = wildcard, otherwise port number (host byte order)
	Protocol    uint8    // IPPROTO_TCP (6) = TCP, IPPROTO_UDP (17) = UDP
	_           [1]byte  // padding to align PrefixLen (uint32)
	PrefixLen   uint32
	FullPrefix  [42]byte // SECRET_PREFIX_MAX
	_           [2]byte  // trailing padding to match C struct alignment
}

// watchedHostKey matches C struct watched_host_key
type watchedHostKey struct {
	Host [64]byte
}

// Generate eBPF bindings. KLOAK_TARGET_ARCH (set by the Makefile or by CI)
// selects the `__TARGET_ARCH_xxx` define handed to clang. Defaults to arm64
// for local development on macOS/Lima.
//
// The actual command runs out of `generate.sh` rather than inline here — Go's
// directive substitution mangles `${VAR:-default}` (matches greedily, doesn't
// understand the shell `:-default` form, drops the whole token to empty),
// which silently dead-strips the arch-specific register-read code in every
// uprobe. See generate.sh for the full story.
//
// `bash ./generate.sh` (rather than just `./generate.sh`) avoids depending
// on the file mode bit surviving every clone / tarball / CI checkout — some
// fetch paths drop the executable bit and we'd get "permission denied" with
// no obvious cause.
//go:generate bash ./generate.sh

// TLSUprobeManager manages the loading and attaching of eBPF uprobes for TLS interception.
type TLSUprobeManager struct {
	objs       *tlsuprobeObjects
	reader     *ringbuf.Reader
	procReader *ringbuf.Reader
	log        *zap.SugaredLogger
	// linksMu guards links — AttachTLS runs concurrently from the reconciler
	// goroutine and PollExecEvents (incl. its retry goroutine), so unsynchronized
	// appends could lose entries, double-write the backing array, or race Close().
	linksMu sync.Mutex
	links   []link.Link

	// secretSource produces snapshots of the secrets the BPF map should
	// hold. The k8s controller wires a pkg/secrets/k8s.Source here; tests
	// or non-k8s callers may pass nil (sync becomes a no-op) or a
	// different implementation.
	secretSource secrets.Source
	// cgroupRoot is the path to the cgroup v2 filesystem (e.g. /sys/fs/cgroup)
	cgroupRoot string
	// egressInterface selects which NIC inside the target's netns gets the
	// tc-egress patch program attached:
	//
	//	"" or "auto"     — read /proc/net/route inside the netns and pick
	//	                   the interface backing the default IPv4 route.
	//	                   Works for the standard CNI veth-named-"eth0"
	//	                   convention AND for host-mode netns where the
	//	                   default route exits via e.g. enp0s3 / wlp3s0.
	//	"none","lo-only" — explicit opt-out of external interface
	//	                   attachment; lo only. Useful for tests and
	//	                   loopback-only workloads.
	//	any other value  — exact interface name (e.g., "eth0", "wlp3s0").
	//	                   Fail closed if the named interface is not found
	//	                   in the netns.
	//
	// `lo` is always attached in addition to whichever external interface
	// the above resolves — covers intra-pod loopback (e.g., sidecar →
	// sidecar via a ClusterIP Service that DNATs back to the same pod).
	egressInterface string
	// cgroupPaths maps cgroup inode ID -> filesystem path.
	// Populated by TrackCgroup.
	cgroupPaths sync.Map // uint64 -> string
	// tcAttached tracks network namespace inodes where tc egress is already
	// attached. Stores an open fd to the netns — keeping it open prevents the
	// kernel from freeing the inode, so a new pod's netns always gets a
	// different inode. This avoids false "already attached" dedup hits from
	// inode reuse after pod deletion. The fd is closed in UntrackCgroup.
	tcAttached sync.Map // uint64 (netns inode) -> *tcAttachEntry
	// cgroupToNetns maps cgroup ID → netns inode for cleanup on UntrackCgroup.
	cgroupToNetns sync.Map // uint64 (cgroup ID) -> uint64 (netns inode)
	// retryWG tracks the deferred-attach goroutines spawned by PollExecEvents.
	// Close() waits on it (with a bounded timeout) before tearing down BPF
	// objects, so a sleeping retry can't fire AttachTLS against a freed map fd.
	retryWG sync.WaitGroup
}

// tcAttachEntry holds an open fd to a network namespace to prevent inode reuse.
type tcAttachEntry struct {
	netnsFd *os.File // kept open to pin the inode
}

// setupCgroupAncestor finds the kubepods cgroup directory and stores its fd
// in the BPF cgroup_ancestor map. This enables bpf_current_task_under_cgroup()
// in the exec tracepoint to catch all container execs without per-container
// cgroup tracking.
func setupCgroupAncestor(objs *tlsuprobeObjects, cgroupRoot string, log *zap.SugaredLogger) error {
	// Find the kubepods cgroup directory. Strategy:
	// 1. Derive from the controller's own cgroup path (/proc/self/cgroup)
	//    since the controller runs under kubepods — most reliable because
	//    the ancestor is guaranteed to be on our task's cgroup chain.
	// 2. Fall back to well-known direct paths.
	// 3. Walk the cgroup tree.
	// Matching is fuzzy: any path component whose name contains "kubepods"
	// is accepted, which covers the vanilla "kubepods.slice" / "kubepods"
	// as well as kind's "kubelet-kubepods.slice" layout.
	var candidates []string

	// Derive from controller's own cgroup. The controller itself runs under
	// kubepods, so scanning its cgroup path upward for a kubepods-named
	// component yields a usable ancestor that's guaranteed to be on our
	// task's hierarchy.
	if selfCgroup, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(selfCgroup), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[0] == "0" {
				cgPath := parts[2]
				// Walk left-to-right through segments; pick the first
				// (shallowest) segment whose name contains "kubepods".
				segments := strings.Split(cgPath, "/")
				var acc []string
				for _, seg := range segments {
					acc = append(acc, seg)
					if strings.Contains(seg, "kubepods") {
						candidates = append(candidates,
							filepath.Join(cgroupRoot, strings.Join(acc, "/")))
						break
					}
				}
			}
		}
	}

	// Well-known direct paths (vanilla k8s, k3s).
	candidates = append(candidates,
		filepath.Join(cgroupRoot, "kubepods.slice"),
		filepath.Join(cgroupRoot, "kubepods"),
	)

	// Walk the tree as a last resort (nested cgroups on k3d/Docker etc.).
	// Match by substring so kind's "kubelet-kubepods.slice" is found.
	_ = filepath.WalkDir(cgroupRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Contains(d.Name(), "kubepods") {
			candidates = append(candidates, path)
			return filepath.SkipDir
		}
		return nil
	})

	for _, path := range candidates {
		f, err := os.Open(path)
		if err != nil {
			continue
		}

		key := uint32(0)
		val := uint32(f.Fd())
		err = objs.CgroupAncestor.Update(key, val, 0)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("updating cgroup_ancestor map: %w", err)
		}
		log.Infow("Configured cgroup ancestor for exec tracepoint", "path", path)
		return nil
	}

	// List top-level entries to help diagnose cgroup layout
	var topLevel []string
	if entries, err := os.ReadDir(cgroupRoot); err == nil {
		for _, e := range entries {
			topLevel = append(topLevel, e.Name())
		}
	}
	log.Errorw("kubepods cgroup not found — exec tracepoint will not detect container processes",
		"cgroupRoot", cgroupRoot, "candidates", candidates, "topLevelDirs", topLevel)
	return fmt.Errorf("kubepods cgroup not found in %s", cgroupRoot)
}

// parseBPFLogLevel maps a string from the KLOAK_BPF_LOG_LEVEL env var (or the
// helm value log.ebpfLevel) to the corresponding ebpf.LogLevel. Empty / "off"
// / "disabled" returns 0, which suppresses proactive verifier-log buffer
// allocation; cilium/ebpf still retries with branch-level logging on verifier
// rejection so failures remain debuggable. Comma-separated values are OR'd
// together (e.g. "branch,stats").
func parseBPFLogLevel(s string) ebpf.LogLevel {
	if s == "" {
		return 0
	}
	var lvl ebpf.LogLevel
	for _, part := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "", "off", "disabled", "none":
			// no-op
		case "branch":
			lvl |= ebpf.LogLevelBranch
		case "instruction", "instructions":
			lvl |= ebpf.LogLevelInstruction
		case "stats":
			lvl |= ebpf.LogLevelStats
		}
	}
	return lvl
}

// NewTLSUprobeManager initializes a new uprobe manager.
//
// egressInterface selects which interface(s) inside each target netns get the
// tc-egress patch program attached. Pass "auto" (or empty) to detect from
// the default route, an explicit name (e.g., "eth0", "wlp3s0") to pin, or
// "none"/"lo-only" to attach only to loopback. See the field comment on
// TLSUprobeManager.egressInterface for the full semantics.
func NewTLSUprobeManager(secretSource secrets.Source, cgroupRoot, egressInterface string, log *zap.SugaredLogger) (*TLSUprobeManager, error) {
	log = log.Named("ebpf-uprobe")

	objs := &tlsuprobeObjects{}
	// Verifier-log level for BPF program loads. Defaults to disabled (0) so the
	// 1 MB-per-program log buffers aren't allocated proactively. cilium/ebpf
	// still retries with LogLevelBranch automatically on verifier failure, so
	// the diagnostic remains available on the only path that needs it.
	// Set KLOAK_BPF_LOG_LEVEL=branch / instruction / stats to opt in.
	progOpts := ebpf.ProgramOptions{
		LogSizeStart: 1 << 20, // 1 MB
		LogLevel:     parseBPFLogLevel(os.Getenv("KLOAK_BPF_LOG_LEVEL")),
	}
	if err := loadTlsuprobeObjects(objs, &ebpf.CollectionOptions{
		Programs: progOpts,
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Print only the error summary (includes rejection reason).
			// The full verifier log can be 100K+ lines and overflows container log buffers.
			log.Errorw("eBPF verifier rejected program", "error", err)
		} else {
			log.Errorw("eBPF loading failed (not a verifier error, check dmesg)",
				"error", err, "error_type", fmt.Sprintf("%T", err))
		}
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Wire up tail call map: index 1 -> bpf_xor_path (AES-GCM ciphertext patching)
	xorFd := uint32(objs.BpfXorPath.FD())
	if err := objs.ProgArray.Put(uint32(1), xorFd); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("configuring tail call map index 1: %w", err)
	}

	// Wire up tail call: index 2 -> bpf_h_extract (GHASH key H extraction)
	hExtFd := uint32(objs.BpfH_extract.FD())
	if err := objs.ProgArray.Put(uint32(2), hExtFd); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("configuring tail call map index 2: %w", err)
	}

	// Wire up tc tail call: index 0 -> tc_ghash_update
	tcGhashFd := uint32(objs.TcGhashUpdate.FD())
	if err := objs.TcProgArray.Put(uint32(0), tcGhashFd); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("configuring tc tail call map: %w", err)
	}

	// Populate the cgroup ancestor map so the exec tracepoint can catch
	// ALL container execs. Find the kubepods cgroup and store its fd.
	if err := setupCgroupAncestor(objs, cgroupRoot, log); err != nil {
		log.Errorw("failed to setup cgroup ancestor — exec tracepoint will not catch initial container processes", "error", err)
		// Non-fatal: exec tracepoint falls back to tracked_cgroups
	}

	reader, err := ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}

	procReader, err := ringbuf.NewReader(objs.ProcEvents)
	if err != nil {
		_ = reader.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("creating proc events ringbuf reader: %w", err)
	}

	mgr := &TLSUprobeManager{
		objs:            objs,
		reader:          reader,
		procReader:      procReader,
		log:             log,
		secretSource:    secretSource,
		cgroupRoot:      cgroupRoot,
		egressInterface: egressInterface,
	}

	// Attach tracepoints for DNS interception and connect tracking.
	// These are system-wide but filtered per-process via tracked_tgids map.
	if err := mgr.attachTracepoints(); err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("attaching tracepoints: %w", err)
	}

	return mgr, nil
}

// attachTracepoints attaches the syscall tracepoints and kprobes for DNS and connect tracking.
func (m *TLSUprobeManager) attachTracepoints() error {
	type tp struct {
		group string
		name  string
		prog  *ebpf.Program
	}

	tracepoints := []tp{
		{"syscalls", "sys_enter_connect", m.objs.TpEnterConnect},
		{"syscalls", "sys_exit_connect", m.objs.TpExitConnect},
		{"syscalls", "sys_enter_close", m.objs.TpEnterClose},
		{"sched", "sched_process_exec", m.objs.TpSchedProcessExec},
		{"sched", "sched_process_exit", m.objs.TpSchedProcessExit},
	}

	for _, t := range tracepoints {
		l, err := link.Tracepoint(t.group, t.name, t.prog, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s/%s: %w", t.group, t.name, err)
		}
		m.linksMu.Lock()
		m.links = append(m.links, l)
		m.linksMu.Unlock()
		m.log.Debugw("Attached tracepoint", "group", t.group, "name", t.name)
	}

	// Attach kprobe/kretprobe on udp_recvmsg for language-agnostic DNS interception.
	kp, err := link.Kprobe("udp_recvmsg", m.objs.KprobeUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe udp_recvmsg: %w", err)
	}
	m.linksMu.Lock()
	m.links = append(m.links, kp)
	m.linksMu.Unlock()
	m.log.Debugw("Attached kprobe", "function", "udp_recvmsg")

	krp, err := link.Kretprobe("udp_recvmsg", m.objs.KretprobeUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe udp_recvmsg: %w", err)
	}
	m.linksMu.Lock()
	m.links = append(m.links, krp)
	m.linksMu.Unlock()
	m.log.Debugw("Attached kretprobe", "function", "udp_recvmsg")

	// Attach kprobe on tcp_sendmsg to bridge xor_pending → tc_pending.
	// This runs after SSL_write encrypts and calls write/send, giving us
	// access to the struct sock (source port) for per-connection keying.
	tkp, err := link.Kprobe("tcp_sendmsg", m.objs.BpfKprobeTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe tcp_sendmsg: %w", err)
	}
	m.linksMu.Lock()
	m.links = append(m.links, tkp)
	m.linksMu.Unlock()
	m.log.Debugw("Attached kprobe", "function", "tcp_sendmsg")

	return nil
}

// attachTCEgress attaches the tc egress BPF program to eth0 and lo inside a
// container's network namespace. eth0 covers external traffic; lo covers
// intra-pod traffic (e.g. sidecar → sidecar via a ClusterIP Service that
// DNATs back to the same pod, routing through loopback).
//
// The controller enters the container's netns via /proc/<pid>/ns/net
// (requires hostPID: true), attaches tc, then returns to its own netns.
func (m *TLSUprobeManager) attachTCEgress(pid int) error {
	// Check if this network namespace already has tc attached by reading
	// the netns inode. We keep an open fd to the netns file — this prevents
	// the kernel from freeing the inode, so a new pod's netns always gets a
	// different inode (no false dedup from inode reuse).
	//
	// To avoid a TOCTOU race between this check and the final Store (two
	// goroutines could both miss the Load and both attach tc, doubling the
	// patch program on each interface and corrupting GHASH), we reserve the
	// inode atomically with LoadOrStore using a zero-value placeholder. The
	// winner proceeds with the attach; losers bail out. On any failure the
	// winner MUST Delete the placeholder so a future retry can succeed.
	//
	// Placeholder semantics on a hit:
	//   netnsFd == nil → attach is in-flight by another goroutine. Return
	//     an error so the caller retries; returning nil would mask an
	//     in-flight failure (if that goroutine deletes its placeholder, the
	//     caller who got nil won't retry and the pod stays unpatched).
	//   netnsFd != nil → a previous attach completed successfully. Return
	//     nil; no work to do.
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	var netnsIno uint64
	var haveIno bool
	var placeholder *tcAttachEntry
	if fi, err := os.Stat(netnsPath); err == nil {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			netnsIno = stat.Ino
			haveIno = true
			placeholder = &tcAttachEntry{} // zero value, no fd yet
			if existing, loaded := m.tcAttached.LoadOrStore(netnsIno, placeholder); loaded {
				placeholder = nil // we didn't reserve a slot; nothing to roll back
				if e, ok := existing.(*tcAttachEntry); ok && e.netnsFd != nil {
					m.log.Debugw("tc egress already attached for this netns", "pid", pid, "netns_ino", netnsIno)
					return nil
				}
				return fmt.Errorf("tc egress attach in progress for pid %d netns %d; retry", pid, netnsIno)
			}
		}
	}

	// rollback releases the placeholder on any error path so a later retry
	// can re-attempt the attach. CompareAndDelete (not plain Delete) so a
	// real entry that some pathological reorder placed into the slot can't
	// be accidentally removed. Cleared (set nil) on success.
	rollback := func() {
		if haveIno && placeholder != nil {
			m.tcAttached.CompareAndDelete(netnsIno, placeholder)
		}
	}
	defer func() {
		if rollback != nil {
			rollback()
		}
	}()

	// Open the netns fd for two purposes:
	// 1. setns to enter the container's network namespace
	// 2. Keep it open (stored in tcAttached) to pin the inode
	containerNS, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("opening container netns %s: %w", netnsPath, err)
	}
	// NOTE: containerNS is NOT closed here on success — it's stored in
	// tcAttachEntry to pin the netns inode. Closed in UntrackCgroup when
	// the pod is deleted.

	// Save our current network namespace.
	selfNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		_ = containerNS.Close()
		return fmt.Errorf("opening self netns: %w", err)
	}
	defer func() { _ = selfNS.Close() }()

	// Run the netns-entered work in a dedicated worker goroutine, NOT on
	// the caller's goroutine. Per Go runtime contract
	// (https://pkg.go.dev/runtime#LockOSThread), if a goroutine exits
	// without unlocking its OS thread, the runtime retires the thread
	// instead of returning it to the worker pool. So if setns-restore
	// fails, we want the goroutine holding the wrong-netns thread to
	// exit, taking the poisoned thread with it.
	//
	// Doing this on the caller's goroutine (the reconciler loop or
	// PollExecEvents — both long-lived) would leave the poisoned thread
	// pinned to a caller that keeps running, so subsequent BPF syscalls
	// / net.Dial / k8s client-go HTTP calls in that caller would silently
	// route through the container's netns. A short-lived worker
	// goroutine isolates the failure to the worker alone.
	//
	// Do NOT "simplify" this back to inline LockOSThread on the caller.
	type tcResult struct {
		links []link.Link
		err   error
	}
	resultCh := make(chan tcResult, 1)
	go func() {
		runtime.LockOSThread()
		threadUsable := true
		defer func() {
			if threadUsable {
				runtime.UnlockOSThread()
			}
			// else: goroutine returns with thread still locked; the Go
			// runtime retires that OS thread and never returns it to
			// the worker pool. The caller is unaffected.
		}()

		// Switch to the container's network namespace.
		if err := unix.Setns(int(containerNS.Fd()), unix.CLONE_NEWNET); err != nil {
			resultCh <- tcResult{err: fmt.Errorf("setns to container netns: %w", err)}
			return
		}
		// Ensure we return to our original netns. Registered AFTER the
		// unlock defer so it runs FIRST (LIFO): restore is attempted,
		// and on failure threadUsable is flipped before the unlock
		// defer reads it.
		defer func() {
			if err := unix.Setns(int(selfNS.Fd()), unix.CLONE_NEWNET); err != nil {
				m.log.Errorw("CRITICAL: failed to restore netns; retiring this worker goroutine's OS thread",
					"error", err, "pid", pid)
				threadUsable = false
			}
		}()

		// Resolve which external interface to attach tc egress on. We're
		// now inside the target netns (setns above), so net.InterfaceByName
		// and /proc/net/route both see the netns-local view.
		ifNames := m.resolveEgressInterfaces(pid)

		// Pre-validate every interface before attaching any. If we
		// attached the first interface and then failed on the second, the
		// kernel-side TCX attachment would stay live but the CAS below
		// would never run, so the reconciler's next retry would miss the
		// dedup and re-attach the same TCX program a second time.
		// link.AttachTCX stacks attachments → wrong GHASH.
		ifaces := make([]*net.Interface, 0, len(ifNames))
		for _, ifName := range ifNames {
			iface, err := net.InterfaceByName(ifName)
			if err != nil {
				if ifName == "lo" {
					resultCh <- tcResult{err: fmt.Errorf("finding %s in container netns: %w", ifName, err)}
					return
				}
				resultCh <- tcResult{err: fmt.Errorf("egress interface %q not found in pid %d netns (configured via --egress-interface or controller.ebpf.egressInterface): %w", ifName, pid, err)}
				return
			}
			ifaces = append(ifaces, iface)
		}

		// Track links attached during this call locally. On a partial
		// failure close them all and return; the caller won't splice
		// them into m.links so a retry doesn't see a half-attached netns.
		attachedHere := make([]link.Link, 0, len(ifaces))
		for i, iface := range ifaces {
			tcLink, err := link.AttachTCX(link.TCXOptions{
				Interface: iface.Index,
				Program:   m.objs.TcEgressPatch,
				Attach:    ebpf.AttachTCXEgress,
			})
			if err != nil {
				for _, prior := range attachedHere {
					if cerr := prior.Close(); cerr != nil {
						m.log.Warnw("rollback: failed to close partially-attached tc egress link", "error", cerr, "pid", pid)
					}
				}
				resultCh <- tcResult{err: fmt.Errorf("attaching tc egress to %s (ifindex %d) in pid %d netns: %w", ifNames[i], iface.Index, pid, err)}
				return
			}
			attachedHere = append(attachedHere, tcLink)
			m.log.Debugw("Attached tc egress to container", "pid", pid, "interface", ifNames[i], "ifindex", iface.Index)
		}
		resultCh <- tcResult{links: attachedHere}
	}()

	res := <-resultCh
	if res.err != nil {
		_ = containerNS.Close()
		return res.err
	}

	m.linksMu.Lock()
	m.links = append(m.links, res.links...)
	m.linksMu.Unlock()

	// Replace the placeholder with the real entry holding the pinned netns fd.
	// CompareAndSwap (not Store) guards against a concurrent UntrackCgroup
	// (pod deleted mid-attach) that already removed our placeholder —
	// unconditional Store would re-insert the entry and leak containerNS,
	// since UntrackCgroup is the only place that closes the pinned netns fd.
	// On a lost CAS, close containerNS directly and let Close() take down
	// the TCX links via m.links at controller shutdown.
	if haveIno {
		finalEntry := &tcAttachEntry{netnsFd: containerNS}
		if !m.tcAttached.CompareAndSwap(netnsIno, placeholder, finalEntry) {
			_ = containerNS.Close()
			m.log.Debugw("tcAttached entry removed mid-attach (pod likely deleted); not reinserting", "pid", pid, "netns_ino", netnsIno)
		}
		rollback = nil // success — don't run the rollback defer
	} else {
		// Defensive: we never reserved a placeholder (initial Stat failed),
		// so there's nothing to roll back. Close the open fd to avoid a leak
		// since it won't be tracked for cleanup.
		_ = containerNS.Close()
	}
	return nil
}

// resolveEgressInterfaces returns the ordered interface names tc egress
// should attach to inside the current netns. Must be called AFTER setns
// to the target netns, since the resolution reads /proc/net/route and
// performs netns-local interface lookups.
//
// Always includes "lo" at the end (intra-pod loopback + local-echo-server
// test fixtures rely on it). The leading external interface is chosen by:
//
//   - empty / "auto": parse /proc/net/route inside the netns and pick
//     the interface whose Destination is 0.0.0.0 (the default IPv4
//     route). Returns no external interface if no default route exists
//     and logs a warning — external TLS rewrites will NOT apply until
//     a route is configured (typical for a netns mid-CNI-setup).
//   - "none" / "lo-only": opt out of external interface attachment.
//   - any other value: trust it as an explicit interface name.
//
// pid is informational, used only for log messages.
//
// Doesn't return an error: every "failure" (auto-detection couldn't
// find a default route, etc.) is recoverable by falling back to
// lo-only attachment with a warning logged at the call site. The
// hard-failure cases (explicit interface name that's missing from the
// netns) surface later in attachTCEgress via the net.InterfaceByName
// lookup, which has the full netns context for the error message.
func (m *TLSUprobeManager) resolveEgressInterfaces(pid int) []string {
	var external string
	switch strings.ToLower(m.egressInterface) {
	case "", "auto":
		got, err := findDefaultRouteInterface()
		switch {
		case err != nil:
			m.log.Warnw("default-route auto-detection failed; attaching only to lo — external TLS rewrites will NOT apply",
				"pid", pid, "error", err)
		case got == "":
			m.log.Warnw("no default IPv4 route in target netns; attaching only to lo — external TLS rewrites will NOT apply (set --egress-interface explicitly if a default route exists under a non-standard name)",
				"pid", pid)
		default:
			external = got
			m.log.Debugw("auto-detected egress interface from default route",
				"pid", pid, "interface", external)
		}
	case "none", "lo-only":
		// explicit opt-out
	default:
		external = m.egressInterface
	}

	if external == "" {
		return []string{"lo"}
	}
	return []string{external, "lo"}
}

// findDefaultRouteInterface reads /proc/net/route in the current netns
// and returns the interface name backing the default IPv4 route, or ""
// if no default route exists.
func findDefaultRouteInterface() (string, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("reading /proc/net/route: %w", err)
	}
	return parseDefaultRouteInterface(data), nil
}

// parseDefaultRouteInterface walks a /proc/net/route body and returns
// the interface name on the row whose Destination column is 00000000
// (the default IPv4 route). Returns "" if no such row exists.
//
// Format reference: kernel Documentation/networking/proc_net.rst —
// /proc/net/route is a fixed hex-encoded table with one row per route;
// header line first, then Iface, Destination, Gateway, Flags, …
// separated by whitespace. Extracted into its own function so the
// parser can be exercised without reading from the kernel.
func parseDefaultRouteInterface(data []byte) string {
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			// header row
			continue
		}
		fields := strings.Fields(line)
		// Need at least Iface + Destination. Anything shorter is a
		// blank line or a future format extension we don't grok —
		// skip rather than fail.
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

// TrackTGID adds a process TGID to the tracked_tgids map, enabling
// DNS/connect tracepoint processing for that process.
func (m *TLSUprobeManager) TrackTGID(tgid uint32) error {
	val := uint8(1)
	return m.objs.TrackedTgids.Update(tgid, &val, 0)
}

// UntrackTGID removes a process TGID from the tracked_tgids map.
// go_tls_offset_config is keyed by cgroup_id, not tgid, and is cleaned up
// via UntrackCgroup when the container is removed.
func (m *TLSUprobeManager) UntrackTGID(tgid uint32) error {
	// Best-effort: delete the strategy entry so it doesn't accumulate. Either
	// map may legitimately have no entry (BoringSSL/static binaries never had
	// strategy=LIBCRYPTO_HOOK), so ignore not-found errors.
	_ = m.objs.TlsStrategy.Delete(&tgid)
	return m.objs.TrackedTgids.Delete(tgid)
}

// TrackCgroup adds a container cgroup ID to the tracked_cgroups map,
// enabling exec/exit tracepoint processing for processes in that cgroup.
func (m *TLSUprobeManager) TrackCgroup(cgroupID uint64, cgroupPath string) error {
	val := uint8(1)
	if err := m.objs.TrackedCgroups.Update(cgroupID, &val, 0); err != nil {
		return err
	}
	m.cgroupPaths.Store(cgroupID, cgroupPath)
	return nil
}

// RecordCgroupNetns records the cgroup → netns inode mapping for a container
// process. This enables cleanup of the tcAttached entry (which pins the netns
// fd) when the cgroup is untracked on pod deletion.
func (m *TLSUprobeManager) RecordCgroupNetns(cgroupID uint64, pid int) {
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	fi, err := os.Stat(netnsPath)
	if err != nil {
		return
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	m.cgroupToNetns.Store(cgroupID, stat.Ino)
}

// UntrackCgroup removes a container cgroup ID from the tracked_cgroups map
// and cleans up the associated tc attachment state. When the last cgroup
// referencing a netns is untracked, the pinned netns fd is closed, allowing
// the kernel to free the inode for reuse.
func (m *TLSUprobeManager) UntrackCgroup(cgroupID uint64) error {
	m.cgroupPaths.Delete(cgroupID)

	// Clean up tcAttached: close the pinned netns fd so the kernel can
	// reclaim the inode. Check if any other cgroup still maps to the same
	// netns before closing (multi-container pods share a netns).
	if inoVal, ok := m.cgroupToNetns.LoadAndDelete(cgroupID); ok {
		ino := inoVal.(uint64)
		// Check if any other cgroup still references this netns.
		otherRefs := false
		m.cgroupToNetns.Range(func(_, v any) bool {
			if v.(uint64) == ino {
				otherRefs = true
				return false // stop iteration
			}
			return true
		})
		if !otherRefs {
			if entry, ok := m.tcAttached.LoadAndDelete(ino); ok {
				if e, ok := entry.(*tcAttachEntry); ok && e.netnsFd != nil {
					_ = e.netnsFd.Close()
				}
			}
		}
	}

	// Remove TLS offset entries belonging to this cgroup. Both go_tls_offset_config
	// and tls_offset_config are keyed by (cgroup_id, exe_inode) via the shared
	// tls_binary_key struct — iterate each and delete keys whose cgroup_id
	// matches. Best-effort: failures here only leak map entries.
	{
		var k tlsuprobeTlsBinaryKey
		var v tlsuprobeGoTlsOffsets
		var stale []tlsuprobeTlsBinaryKey
		iter := m.objs.GoTlsOffsetConfig.Iterate()
		for iter.Next(&k, &v) {
			if k.CgroupId == cgroupID {
				stale = append(stale, k)
			}
		}
		for i := range stale {
			_ = m.objs.GoTlsOffsetConfig.Delete(&stale[i])
		}
	}
	{
		var k tlsuprobeTlsBinaryKey
		var v tlsuprobeTlsOffsets
		var stale []tlsuprobeTlsBinaryKey
		iter := m.objs.TlsOffsetConfig.Iterate()
		for iter.Next(&k, &v) {
			if k.CgroupId == cgroupID {
				stale = append(stale, k)
			}
		}
		for i := range stale {
			_ = m.objs.TlsOffsetConfig.Delete(&stale[i])
		}
	}

	return m.objs.TrackedCgroups.Delete(cgroupID)
}

// AttachTLS attaches system-wide eBPF uprobes to all TLS libraries in a
// container. The uprobes fire for ALL processes in the container (same overlay
// mount = same inode). The BPF cgroup filter restricts interception to tracked
// containers only.
func (m *TLSUprobeManager) AttachTLS(pid int, cgroupID uint64) error {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Register the process for DNS/connect tracking.
	if err := m.TrackTGID(uint32(pid)); err != nil {
		m.log.Errorw("failed to track TGID for DNS/connect", "error", err, "pid", pid)
	} else {
		logging.Tracew(m.log, "tracking TGID for DNS/connect verification", "pid", pid)
	}

	// H extraction now happens in the entry uprobe via 4-step pointer chain.
	// The offsets are pushed to the BPF config map by pushTLSOffsets below.

	// Open the executable to check for statically linked TLS
	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", exePath, err)
	}

	// 1. Try Go crypto/tls (statically linked into the binary).
	// Use PID-scoped attachment because Go binaries are unique per container
	// and system-wide uprobes via overlay don't fire for the same binary.
	goWriteSym := "crypto/tls.(*Conn).Write"
	if up, err := ex.Uprobe(goWriteSym, m.objs.BpfUprobeGoTlsWrite, &link.UprobeOptions{PID: pid}); err == nil {
		m.log.Debugw("Attached Go uprobe", "pid", pid, "symbol", goWriteSym)
		m.linksMu.Lock()
		m.links = append(m.links, up)
		m.linksMu.Unlock()

		// Push Go-specific struct offsets for H extraction and attach tc egress
		// for ciphertext patching. Both are required for the XOR-patch path.
		// Key by cgroup_id, not PID — the BPF kprobe sees root-NS PIDs and
		// can't look up by our local-NS PID in nested deployments (kind/k3d).
		m.pushGoTLSOffsets(pid, cgroupID)
		if err := m.attachTCEgress(pid); err != nil {
			m.log.Errorw("Failed to attach tc egress for Go TLS — secrets will not be rewritten", "error", err, "pid", pid)
		}
		return nil
	}

	// 2. Bun single-executable (e.g. Claude Code): detect by version string
	// embedded in the binary ("bun/X.Y.Z") and attach at the pre-computed
	// SSL_write file offset. The binary is symbol-stripped, so the normal
	// symbol-scan below would fail. UprobeOptions.Address bypasses symbol
	// resolution in cilium/ebpf when non-zero (link/uprobe.go:167-169).
	if bunOff, bunVer, ok := DetectBun(exePath); ok && bunOff.SSLWriteOffset > 0 {
		m.log.Infow("Bun single-executable detected — attaching at SSL_write file offset",
			"pid", pid, "version", bunVer,
			"ssl_write_offset", fmt.Sprintf("0x%x", bunOff.SSLWriteOffset))
		if up, err := ex.Uprobe("", m.objs.BpfUprobeSslWrite, &link.UprobeOptions{
			Address: bunOff.SSLWriteOffset,
			PID:     pid,
		}); err == nil {
			m.linksMu.Lock()
			m.links = append(m.links, up)
			m.linksMu.Unlock()

			// Push BoringSSL chain offsets — Bun statically links BoringSSL and
			// uses the same SSL→s3→aead_write_ctx→AES_KEY walk.
			var st syscall.Stat_t
			if serr := syscall.Stat(exePath, &st); serr == nil {
				val := bpfTLSOffsets{
					SSLToVersion:     0xFFFFFFFF,
					SSLToWBIO:        bunOff.BoringSSL.SSLToWBIO,
					TLSLib:           bpfTLSLibBoringSSL,
					BsslSSLToS3:      bunOff.BoringSSL.SSLToS3,
					BsslS3ToAEAD:     bunOff.BoringSSL.S3ToAEAD,
					BsslAEADToAESKey: bunOff.BoringSSL.AEADToAESKey,
				}
				m.pushOffsetVal(val, cgroupID, st.Ino)
				m.log.Debugw("Pushed BoringSSL offsets for Bun process",
					"pid", pid, "cgroupID", cgroupID, "offsets", fmt.Sprintf("%+v", bunOff.BoringSSL))
			}
			if err := m.attachTCEgress(pid); err != nil {
				m.log.Errorw("Failed to attach tc egress for Bun — secrets will not be rewritten",
					"error", err, "pid", pid)
			}
			return nil
		} else {
			m.log.Warnw("Bun detected but SSL_write uprobe failed — falling through to symbol scan",
				"pid", pid, "error", err)
		}
	}

	// 3. Scan all TLS shared libraries in the container filesystem and attach
	// system-wide uprobes. Uses /proc/<pid>/root to access the container's
	// overlay mount — all processes in the same container share the same
	// overlay inode, so the uprobe fires for any of them.
	sslSymbols := []string{"SSL_write", "SSL_write_ex"}
	gnutlsSymbols := []string{"gnutls_record_send", "gnutls_record_send2"}
	attached := false

	// Try main executable first (statically linked OpenSSL/BoringSSL/GnuTLS).
	// Use PID-scoped because the main exe is unique per container.
	for _, sym := range append(sslSymbols, gnutlsSymbols...) {
		up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslWrite, &link.UprobeOptions{PID: pid})
		if err != nil {
			continue
		}
		m.log.Debugw("Attached uprobe to main exe", "pid", pid, "symbol", sym)
		m.linksMu.Lock()
		m.links = append(m.links, up)
		m.linksMu.Unlock()
		attached = true
	}

	// Scan container filesystem for all TLS shared libraries
	containerLibs := findContainerTLSLibraries(pid)
	logging.Tracew(m.log, "found container TLS libraries", "pid", pid, "count", len(containerLibs), "libs", containerLibs)

	for _, containerPath := range containerLibs {
		hostPath := fmt.Sprintf("/proc/%d/root%s", pid, containerPath)
		libEx, err := link.OpenExecutable(hostPath)
		if err != nil {
			continue
		}
		for _, sym := range append(sslSymbols, gnutlsSymbols...) {
			up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslWrite, nil)
			if err != nil {
				continue
			}
			m.log.Debugw("Attached uprobe (system-wide)", "pid", pid, "symbol", sym, "lib", containerPath)
			m.linksMu.Lock()
			m.links = append(m.links, up)
			m.linksMu.Unlock()
			attached = true
		}
	}

	if attached {
		// Try to detect the OpenSSL version and push struct offsets for the
		// XOR-patch path. Non-fatal: if detection fails, the XOR path simply
		// won't activate and the shadow secret is sent as-is (fail-secure).
		m.pushTLSOffsets(pid, cgroupID, containerLibs)

		// Attach the libcrypto EVP_CipherInit_ex hooks for the libcrypto-hook
		// H-extraction strategy. If libcrypto.so is found and at least one of
		// EVP_CipherInit_ex2 / EVP_CipherInit_ex resolves, write
		// tls_strategy[tgid] = STRATEGY_LIBCRYPTO_HOOK so SSL_write routes
		// through h_extract → cache lookup. Otherwise (BoringSSL, statically
		// linked) leave strategy at 0 (default) — process stays on the legacy
		// kprobe-walks-chain path that's been on main since launch.
		if m.attachLibcryptoCipherInit(pid, containerLibs) {
			tgid := uint32(pid)
			strategyVal := strategyLibcryptoHook
			if err := m.objs.TlsStrategy.Update(&tgid, &strategyVal, 0); err != nil {
				m.log.Errorw("Failed to set tls_strategy for libcrypto hook",
					"error", err, "pid", pid)
			} else {
				m.log.Debugw("Process on libcrypto-hook H-extraction path",
					"pid", pid)
			}
		}

		// Attach tc egress to the container's eth0 for kernel-only ciphertext
		// patching. Required for secret rewriting.
		if err := m.attachTCEgress(pid); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				m.log.Debugw("Process exited before tc egress could attach", "error", err, "pid", pid)
			} else {
				m.log.Errorw("Failed to attach tc egress to container — secrets will not be rewritten", "error", err, "pid", pid)
			}
		}

		return nil
	}
	return fmt.Errorf("could not find compatible TLS symbols for PID %d", pid)
}

// Strategy values must match #defines in pkg/ebpf/bpf/tls_uprobe.c.
const (
	strategyKprobeWalk    uint8 = 0
	strategyLibcryptoHook uint8 = 1
)

// processUsesBoringSSL reports whether the process's main exe or any of its
// TLS libraries is BoringSSL. Used to keep BoringSSL on the kprobe-walk H
// strategy (it must not take the OpenSSL libcrypto-hook path).
func (m *TLSUprobeManager) processUsesBoringSSL(pid int, containerLibs []string) bool {
	paths := append([]string{fmt.Sprintf("/proc/%d/exe", pid)}, containerLibs...)
	for _, p := range paths {
		base := filepath.Base(p)
		// Only the exe and libssl/libcrypto objects can be BoringSSL; skip the
		// rest (gnutls, etc.) to avoid needless ELF opens.
		if !strings.HasPrefix(base, "libssl.so") &&
			!strings.HasPrefix(base, "libcrypto.so") &&
			!strings.HasSuffix(p, "/exe") {
			continue
		}
		if _, _, err := DetectBoringSSL(pid, p); err == nil {
			return true
		}
	}
	return false
}

// attachLibcryptoCipherInit attaches the EVP_CipherInit_ex entry+uretprobe
// pair so the libcrypto-hook H-extraction path activates for this process.
// Returns true if any attach point succeeded, in which case the caller marks
// the process as STRATEGY_LIBCRYPTO_HOOK.
//
// Tries two attach points:
//
//  1. The main executable (/proc/<pid>/exe), PID-scoped. This catches apps
//     that statically link OpenSSL into the binary — most notably Node.js,
//     which bundles OpenSSL 3.x inside the `node` ELF and exports
//     EVP_CipherInit_ex / _ex2 directly. PID-scoped because the exe is
//     unique per container and we don't want the hook firing for unrelated
//     copies on the host.
//
//  2. Each libcrypto.so found in containerLibs, system-wide. This catches
//     apps that dynamically link to system libcrypto (curl, python, ruby,
//     ...). System-wide because the BPF cgroup filter narrows it to tracked
//     containers and one attach covers every process linking the same .so
//     copy.
//
// Order matters only for log clarity — both attach points fire independently
// and double-attach for the same EVP_CIPHER_CTX is idempotent at the cache.
//
// BoringSSL apps that don't expose EVP_CipherInit_ex anywhere (rare in
// practice — Node.js publishes as OpenSSL despite the historical "uses
// BoringSSL" reputation) stay on STRATEGY_KPROBE_WALK.
func (m *TLSUprobeManager) attachLibcryptoCipherInit(pid int, containerLibs []string) bool {
	// BoringSSL must stay on STRATEGY_KPROBE_WALK. Its libcrypto also exports
	// EVP_CipherInit_ex, but BoringSSL's cipher init does NOT populate the
	// OpenSSL evp_h_cache that h_extract reads, and the OpenSSL provider chain
	// h_extract walks doesn't exist in BoringSSL. Hooking it would set
	// STRATEGY_LIBCRYPTO_HOOK and route SSL_write to h_extract, which bails on
	// ssl_to_wrl==0 — bypassing the kprobe BoringSSL H-walk entirely (the path
	// that recomputes H from the AES round keys). So skip the hook for BoringSSL.
	if m.processUsesBoringSSL(pid, containerLibs) {
		m.log.Debugw("BoringSSL process — skipping EVP_CipherInit hook, staying on kprobe-walk",
			"pid", pid)
		return false
	}

	// OpenSSL 3.x exposes two independent cipher-init entry points:
	//   - EVP_CipherInit_ex  (1.1+ compat): calls evp_cipher_init_internal directly
	//   - EVP_CipherInit_ex2 (3.0+):        calls evp_cipher_init_internal directly
	// Neither wraps the other. OpenSSL's own TLS layer (t1_enc.c, tls13_enc.c)
	// uses EVP_CipherInit_ex when keying the per-record cipher; new application
	// code may use _ex2. Hooking both catches any caller path. Double-attach is
	// safe because the cache write is idempotent for the same EVP_CIPHER_CTX *.
	cipherInitSymbols := []string{"EVP_CipherInit_ex", "EVP_CipherInit_ex2"}
	attached := false

	// 1. Main executable, PID-scoped — for statically-linked OpenSSL (Node.js).
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	if exeEx, err := link.OpenExecutable(exePath); err == nil {
		exeAttached := false
		for _, sym := range cipherInitSymbols {
			up, errEntry := exeEx.Uprobe(sym, m.objs.BpfUprobeEvpCipherInit,
				&link.UprobeOptions{PID: pid})
			if errEntry != nil {
				continue
			}
			ret, errRet := exeEx.Uretprobe(sym, m.objs.BpfUretprobeEvpCipherInit,
				&link.UprobeOptions{PID: pid})
			if errRet != nil {
				_ = up.Close()
				continue
			}
			m.linksMu.Lock()
			m.links = append(m.links, up, ret)
			m.linksMu.Unlock()
			m.log.Debugw("Attached EVP_CipherInit hooks (main exe, PID-scoped)",
				"pid", pid, "symbol", sym)
			attached = true
			exeAttached = true
		}
		if !exeAttached {
			m.log.Debugw("Main exe has no EVP_CipherInit symbols — likely dynamically links libcrypto",
				"pid", pid)
		}
	} else {
		m.log.Debugw("Failed to open main exe for cipher_init attach",
			"pid", pid, "error", err)
	}

	// 2. libcrypto.so libraries, system-wide — for dynamically-linked apps.
	libcryptoFound := false
	for _, containerPath := range containerLibs {
		base := filepath.Base(containerPath)
		if !strings.HasPrefix(base, "libcrypto.so") {
			continue
		}
		libcryptoFound = true
		hostPath := fmt.Sprintf("/proc/%d/root%s", pid, containerPath)
		libEx, err := link.OpenExecutable(hostPath)
		if err != nil {
			m.log.Debugw("Failed to open libcrypto for cipher_init attach",
				"pid", pid, "lib", containerPath, "error", err)
			continue
		}
		libAttached := false
		for _, sym := range cipherInitSymbols {
			up, errEntry := libEx.Uprobe(sym, m.objs.BpfUprobeEvpCipherInit, nil)
			if errEntry != nil {
				m.log.Debugw("EVP_CipherInit entry uprobe attach failed",
					"pid", pid, "symbol", sym, "lib", containerPath, "error", errEntry)
				continue
			}
			ret, errRet := libEx.Uretprobe(sym, m.objs.BpfUretprobeEvpCipherInit, nil)
			if errRet != nil {
				_ = up.Close()
				m.log.Debugw("EVP_CipherInit uretprobe attach failed",
					"pid", pid, "symbol", sym, "lib", containerPath, "error", errRet)
				continue
			}
			m.linksMu.Lock()
			m.links = append(m.links, up, ret)
			m.linksMu.Unlock()
			m.log.Debugw("Attached EVP_CipherInit hooks (libcrypto.so, system-wide)",
				"pid", pid, "symbol", sym, "lib", containerPath)
			attached = true
			libAttached = true
		}
		if !libAttached {
			m.log.Debugw("No EVP_CipherInit symbol attached for libcrypto",
				"pid", pid, "lib", containerPath, "tried", cipherInitSymbols)
		}
	}

	if !attached && !libcryptoFound {
		m.log.Debugw("No libcrypto.so and no exe symbols — staying on KPROBE_WALK",
			"pid", pid, "containerLibs", containerLibs)
	}

	return attached
}

// pushTLSOffsets detects the OpenSSL version from the container's TLS libraries
// or the main executable (for statically linked OpenSSL) and pushes struct
// offsets to the tls_offset_config BPF map, keyed by (cgroup_id, exe_inode).
// See the tls_binary_key commentary in tls_uprobe.c for why the composite key.
func (m *TLSUprobeManager) pushTLSOffsets(pid int, cgroupID uint64, containerLibs []string) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Resolve the exe's inode — stat follows the /proc/<pid>/exe symlink to
	// the actual on-disk binary.
	var st syscall.Stat_t
	if err := syscall.Stat(exePath, &st); err != nil {
		m.log.Errorw("Failed to stat exe for TLS offset push", "error", err, "pid", pid)
		return
	}
	exeInode := st.Ino

	// Try the main executable FIRST — if the binary statically links OpenSSL
	// (e.g., Node.js bundles OpenSSL 3.5), its struct offsets differ from the
	// system libssl. The main exe's version takes precedence because the
	// PID-scoped uprobe fires for its SSL_write, not the shared library's.
	// Fall back to shared libraries for dynamically linked apps.
	paths := make([]string, 1+len(containerLibs))
	paths[0] = exePath
	copy(paths[1:], containerLibs)

	for _, libPath := range paths {
		// OpenSSL: read the version string, look up the 3-/4-hop chain offsets.
		if version, offsets, err := DetectOpenSSLVersion(pid, libPath); err == nil {
			val := bpfTLSOffsets{
				SSLToWRL:              offsets.SSLToWRL,
				WRLToEncCtx:           offsets.WRLToEncCtx,
				EncCtxToAlgctx:        offsets.EncCtxToAlgctx,
				AlgctxToH:             offsets.AlgctxToH,
				SSLToVersion:          offsets.SSLToVersion,
				SSLToWBIO:             offsets.SSLToWBIO,
				TLSLib:                bpfTLSLibOpenSSL,
				OpenSSLAlgctxToAESKey: offsets.AlgctxToAESKey,
			}
			m.pushOffsetVal(val, cgroupID, exeInode)
			m.log.Debugw("Pushed TLS offsets for XOR-patch path",
				"lib", libPath, "tls", "openssl", "version", version,
				"pid", pid, "cgroupID", cgroupID, "exeInode", exeInode,
				"offsets", fmt.Sprintf("%+v", offsets))
			return
		}

		// BoringSSL: no resolvable version and no persisted raw H. Push the
		// SSL→s3→aead_write_ctx→AES_KEY chain; the BPF kprobe recomputes
		// H = AES_encrypt(0) from the round-key schedule. SSLToVersion is left
		// as 0xFFFFFFFF (BoringSSL keeps the TLS version in SSL3_STATE, not at a
		// fixed SSL offset), so the data plane falls back to its nonce_len
		// heuristic.
		if key, boff, err := DetectBoringSSL(pid, libPath); err == nil {
			val := bpfTLSOffsets{
				SSLToVersion:     0xFFFFFFFF,
				SSLToWBIO:        boff.SSLToWBIO,
				TLSLib:           bpfTLSLibBoringSSL,
				BsslSSLToS3:      boff.SSLToS3,
				BsslS3ToAEAD:     boff.S3ToAEAD,
				BsslAEADToAESKey: boff.AEADToAESKey,
			}
			m.pushOffsetVal(val, cgroupID, exeInode)
			m.log.Debugw("Pushed TLS offsets for XOR-patch path",
				"lib", libPath, "tls", "boringssl", "version", key,
				"pid", pid, "cgroupID", cgroupID, "exeInode", exeInode,
				"offsets", fmt.Sprintf("%+v", boff))
			return
		}

		m.log.Debugw("TLS offset detection skipped", "lib", libPath)
	}
}

// bpfTLSLib* mirror the TLS_LIB_* constants in tls_uprobe.c.
const (
	bpfTLSLibOpenSSL   uint32 = 0
	bpfTLSLibBoringSSL uint32 = 1
)

// bpfTLSOffsets must match struct tls_offsets in tls_uprobe.c byte-for-byte.
// Field order is load-bearing — the BPF program reads this struct by offset.
type bpfTLSOffsets struct {
	SSLToWRL       uint32
	WRLToEncCtx    uint32
	EncCtxToAlgctx uint32
	AlgctxToH      uint32
	SSLToVersion   uint32
	SSLToWBIO      uint32
	// BoringSSL chain (unused when TLSLib == bpfTLSLibOpenSSL).
	TLSLib           uint32
	BsslSSLToS3      uint32
	BsslS3ToAEAD     uint32
	BsslAEADToAESKey uint32
	// OpenSSL AES-round-key H fallback (issue #275). Appended last to match the
	// C struct, which appends it after the BoringSSL fields.
	OpenSSLAlgctxToAESKey uint32
}

// pushOffsetVal writes the offsets for this binary (keyed by exe inode) plus a
// per-cgroup fallback entry (ExeInode=0) for short-lived processes spawned into
// the cgroup that fire SSL_write before their inode-specific push runs.
func (m *TLSUprobeManager) pushOffsetVal(val bpfTLSOffsets, cgroupID, exeInode uint64) {
	key := tlsuprobeTlsBinaryKey{CgroupId: cgroupID, ExeInode: exeInode}
	if err := m.objs.TlsOffsetConfig.Update(&key, &val, 0); err != nil {
		m.log.Errorw("Failed to push TLS offsets to BPF map",
			"error", err, "cgroupID", cgroupID, "exeInode", exeInode)
		return
	}
	fallbackKey := tlsuprobeTlsBinaryKey{CgroupId: cgroupID, ExeInode: 0}
	_ = m.objs.TlsOffsetConfig.Update(&fallbackKey, &val, 0)
}

// pushGoTLSOffsets detects Go struct offsets from the binary's DWARF or
// buildinfo and pushes them to the go_tls_offset_config BPF map, keyed by
// (cgroup_id, exe_inode). See goTLSKey for why this composite key is used.
func (m *TLSUprobeManager) pushGoTLSOffsets(pid int, cgroupID uint64) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Resolve the exe's inode — stat follows the /proc/<pid>/exe symlink to
	// the actual on-disk binary.
	var st syscall.Stat_t
	if err := syscall.Stat(exePath, &st); err != nil {
		m.log.Errorw("Failed to stat exe for Go TLS offset push", "error", err, "pid", pid)
		return
	}
	exeInode := st.Ino

	// DetectGoTLSOffsets tries DWARF first, then falls back to version-based lookup.
	version, offsets, err := DetectGoTLSOffsets(exePath)
	if err != nil {
		m.log.Errorw("Go TLS offset detection failed — Go secrets will NOT be rewritten", "error", err, "pid", pid)
		return
	}

	m.log.Debugw("Detected Go TLS offsets",
		"pid", pid, "cgroupID", cgroupID, "exeInode", exeInode, "goVersion", version,
		"connToCipher", offsets.ConnToCipher,
		"aeadIfaceOff", offsets.AEADIfaceOff,
		"h2HiOff", offsets.H2HiOff,
		"h2LoOff", offsets.H2LoOff)

	key := tlsuprobeTlsBinaryKey{CgroupId: cgroupID, ExeInode: exeInode}
	if err := m.objs.GoTlsOffsetConfig.Update(&key, &offsets, 0); err != nil {
		m.log.Errorw("Failed to push Go TLS offsets to BPF map",
			"error", err, "pid", pid, "cgroupID", cgroupID, "exeInode", exeInode)
		return
	}

	m.log.Debugw("Pushed Go TLS offsets for XOR-patch path",
		"pid", pid, "cgroupID", cgroupID, "exeInode", exeInode, "goVersion", version)
}

// findContainerTLSLibraries scans well-known library directories in the
// container's root filesystem for all TLS libraries. Returns container-
// relative paths (e.g., "/usr/lib/aarch64-linux-gnu/libssl.so.3",
// "/usr/lib64/libssl.so.3").
//
// Walks recursively under a set of root library directories so any distro
// that nests TLS libs under arch-specific or vendor-named subdirectories
// is covered. The roots intentionally include both /usr/lib* and
// /usr/local/lib* plus the /lib* legacy aliases — different distros put
// libssl in different places:
//
//	Debian/Ubuntu:  /usr/lib/x86_64-linux-gnu/libssl.so.3
//	Fedora/RHEL:    /usr/lib64/libssl.so.3  (← what the original 3-dir
//	                                          + one-level scan missed)
//	Alpine/Arch:    /usr/lib/libssl.so.3
//
// filepath.WalkDir does not follow internal symlinks (avoids cycles) but
// does resolve the root if the root itself is a symlink — which means
// Fedora's UsrMove pattern (/lib → /usr/lib, /lib64 → /usr/lib64) works
// without manual EvalSymlinks calls.
func findContainerTLSLibraries(pid int) []string {
	return walkTLSLibrariesUnder(fmt.Sprintf("/proc/%d/root", pid))
}

// tlsLibScanRoots are the directory prefixes (relative to the target's
// root filesystem) inside which we look for TLS shared libraries. Ordered
// from most-common-distro convention to legacy aliases.
var tlsLibScanRoots = []string{
	"/usr/lib",       // Debian/Ubuntu primary + Alpine/Arch
	"/usr/lib64",     // Fedora/RHEL/CentOS/openSUSE 64-bit
	"/lib",           // legacy FHS root; symlink on modern distros
	"/lib64",         // legacy FHS 64-bit alias
	"/usr/local/lib", // operator/admin-installed
}

// walkTLSLibrariesUnder is the recursive scan that backs
// findContainerTLSLibraries. Extracted with a configurable rootPrefix so
// tests can exercise it against a synthetic filesystem laid out under a
// tmpdir, exercising the exact same walker + isTLSLibrary filter the
// production path uses.
//
// Dedup is by (device, inode), not by path string. Two distinct paths
// can resolve to the same physical file in two common ways:
//
//  1. UsrMove distros (Fedora/Arch/etc.): /lib is a symlink to /usr/lib.
//     filepath.WalkDir follows the root if the root itself is a symlink,
//     so walking both /usr/lib AND /lib produces the same files under
//     different path prefixes (e.g. /usr/lib/libssl.so.3 AND
//     /lib/libssl.so.3, same inode).
//  2. Library aliases: libssl.so → libssl.so.3 are typically symlinks
//     to the same .so file in the same directory. WalkDir does NOT
//     follow internal symlinks, so both names are visited as separate
//     DirEntries, but they refer to the same inode.
//
// Attaching uprobes twice to the same inode wastes a verifier slot and
// produces duplicate ringbuf events. Inode-dedup eliminates both.
//
// On stat failure we conservatively skip the entry (rather than fall
// back to path-dedup) so a flaky filesystem can't double-register a
// uprobe and corrupt event accounting.
func walkTLSLibrariesUnder(rootPrefix string) []string {
	type fileID struct {
		dev uint64
		ino uint64
	}
	seen := make(map[fileID]bool)
	var libs []string

	for _, dir := range tlsLibScanRoots {
		hostDir := rootPrefix + dir
		_ = filepath.WalkDir(hostDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				// Unreadable subtree (perm denied, missing dir) — skip
				// silently and keep going. Returning SkipDir on a
				// directory avoids WalkDir re-reporting the same error.
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !isTLSLibrary(d.Name()) {
				return nil
			}
			// os.Stat (not d.Info() / lstat) so we follow symlinks
			// to the underlying file. This matters for the
			// libssl.so → libssl.so.3 alias case: both DirEntries
			// pass isTLSLibrary, but lstat would give us each
			// symlink's own inode and miss the dedup. Following
			// the symlink gives us the real .so file's inode, so
			// the second visit short-circuits on `seen[id]`.
			info, err := os.Stat(path)
			if err != nil {
				return nil
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			id := fileID{dev: stat.Dev, ino: stat.Ino}
			if seen[id] {
				return nil
			}
			seen[id] = true
			libs = append(libs, strings.TrimPrefix(path, rootPrefix))
			return nil
		})
	}
	return libs
}

// isTLSLibrary returns true if the filename looks like an SSL/TLS shared library.
func isTLSLibrary(name string) bool {
	return strings.HasPrefix(name, "libssl.so") ||
		strings.HasPrefix(name, "libboringssl.so") ||
		strings.HasPrefix(name, "libcrypto.so") ||
		strings.HasPrefix(name, "libgnutls.so")
}

// Close releases all links and the eBPF manager.
//
// Each link.Close on a uprobe is a kernel syscall that takes ~50-100 ms,
// and m.links accumulates one entry per uprobe attachment over the
// daemonset's lifetime. On a long-running cluster with churning pods this
// reaches into the thousands; closing serially blows past kubelet's
// terminationGracePeriodSeconds and the pod is SIGKILL'd before the Go
// runtime gets to flush exit hooks (which lost us the e2e covcounters
// flush, among other things). Close concurrently with a bounded worker
// pool so wall time stays inside the grace period regardless of how
// long the controller has been running.
func (m *TLSUprobeManager) Close() error {
	t0 := time.Now()
	// Drain in-flight retry goroutines first. PollExecEvents is expected to
	// be cancelled before Close() is called (its ctx fires the retry's
	// select case), so the wait is normally instantaneous. The 5 s cap
	// prevents a stuck retry from holding shutdown past kubelet's grace
	// period. Must happen BEFORE we snapshot m.links — a retry can append
	// to it via AttachTLS, and we'd race the snapshot otherwise.
	waited := make(chan struct{})
	go func() {
		m.retryWG.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		m.log.Warnw("timed out waiting for retry goroutines on shutdown; proceeding with teardown")
	}

	// Snapshot + nil out the slice under the lock, then release before doing
	// the (slow, ~50-100ms each) kernel syscalls. Holding linksMu across the
	// parallel Close would serialize any in-flight AttachTLS calls against
	// the full shutdown — and the syscalls themselves don't need the lock
	// since the slice is already detached.
	m.linksMu.Lock()
	links := m.links
	m.links = nil
	m.linksMu.Unlock()

	linkCount := len(links)
	var errs []error
	var errsMu sync.Mutex

	// Cap workers at the number of links — no point spinning up 64
	// goroutines just to close 5 tracepoints at startup teardown.
	const maxWorkers = 64
	workers := maxWorkers
	if linkCount < workers {
		workers = linkCount
	}
	jobs := make(chan link.Link, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for l := range jobs {
				if err := l.Close(); err != nil {
					errsMu.Lock()
					errs = append(errs, err)
					errsMu.Unlock()
				}
			}
		}()
	}
	for _, l := range links {
		jobs <- l
	}
	close(jobs)
	wg.Wait()

	if m.reader != nil {
		if err := m.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.procReader != nil {
		if err := m.procReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if m.objs != nil {
		if err := m.objs.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.log.Infow("Close: done", "links", linkCount, "duration", time.Since(t0).String())
	if len(errs) > 0 {
		return fmt.Errorf("errors closing uprobe manager: %v", errs)
	}
	return nil
}

// PollExecEvents reads process exec events from the proc_events ring buffer
// and attaches TLS uprobes to newly exec'd processes in tracked containers.
func (m *TLSUprobeManager) PollExecEvents(ctx context.Context) error {
	m.log.Infow("Starting process exec event poller")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		m.procReader.SetDeadline(time.Now().Add(1 * time.Second))
		record, err := m.procReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			m.log.Errorw("reading from proc events ringbuf", "error", err)
			continue
		}

		var event procEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			m.log.Errorw("failed to parse proc event", "error", err)
			continue
		}

		if event.Type == 1 { // exec
			// Only attach to processes whose cgroup was explicitly registered by
			// the controller via TrackCgroup (i.e. kloak-enabled pods).
			// sched_process_exec fires for ALL kubepods containers; without this
			// guard, AttachTLS would attach tc egress to non-kloak pods and
			// corrupt their outbound TLS (wrong H key → bad GHASH tag).
			pathVal, ok := m.cgroupPaths.Load(event.CgroupID)
			if !ok {
				m.log.Debugw("exec in untracked cgroup, skipping", "tgid", event.Tgid, "cgroupID", event.CgroupID)
				continue
			}
			cgroupPath, _ := pathVal.(string)

			// event.Tgid is the root-NS PID — on nested deployments (kind,
			// k3d) the controller's /proc is in a child namespace and can't
			// open /proc/<root-NS-pid>/exe. Resolve current PIDs via
			// cgroup.procs (which lists PIDs in the controller's own NS),
			// then let AttachTLS pick up whichever ones load TLS symbols.
			pids, err := cgroups.ReadCgroupProcs(cgroupPath)
			if err != nil {
				m.log.Debugw("failed reading cgroup.procs on exec", "error", err, "cgroup", event.CgroupID)
				continue
			}
			logging.Tracew(m.log, "detected exec in tracked container, attaching uprobes",
				"rootNsTgid", event.Tgid, "cgroupID", event.CgroupID, "localPids", pids)
			for _, p := range pids {
				pid := p
				if err := m.AttachTLS(pid, event.CgroupID); err != nil {
					// libssl may not be loaded yet (e.g. Python hasn't imported ssl).
					// Retry after a delay to catch lazy-loaded libraries.
					m.log.Debugw("first attach attempt failed, scheduling retry", "pid", pid, "err", err)
					m.retryWG.Add(1)
					go func(p int, cg uint64) {
						defer m.retryWG.Done()
						// Respect shutdown: a bare time.Sleep would call
						// AttachTLS against freed BPF map fds if Close()
						// runs during the 2 s window. Use time.NewTimer so
						// that ctx.Done winning the select releases the
						// underlying runtime timer immediately instead of
						// leaving it in the heap until it fires — under
						// pod churn we'd otherwise accumulate one live
						// timer per failed attach.
						timer := time.NewTimer(2 * time.Second)
						select {
						case <-timer.C:
						case <-ctx.Done():
							timer.Stop()
							return
						}
						// Skip if the cgroup was untracked while we slept —
						// the pod was deleted and the PID may have been
						// reused by an unrelated host process.
						if _, stillTracked := m.cgroupPaths.Load(cg); !stillTracked {
							m.log.Debugw("cgroup untracked before retry; skipping", "pid", p, "cgroupID", cg)
							return
						}
						if err := m.AttachTLS(p, cg); err != nil {
							m.log.Debugw("retry attach also failed", "pid", p, "err", err)
						}
					}(pid, event.CgroupID)
				}
			}
		}
	}
}

// PollEvents reads TLS events from the ring buffer and periodically syncs secrets to the eBPF map.
func (m *TLSUprobeManager) PollEvents(ctx context.Context) error {
	m.log.Infow("Starting eBPF TLS event poller and secret syncer")

	// Trigger an initial sync
	m.syncSecretsToBPF(ctx)

	// Periodic re-sync ticker. The initial sync may have found an empty store
	// (secret reconciler hasn't run yet), so we must keep re-syncing.
	syncTicker := time.NewTicker(5 * time.Second)
	defer syncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-syncTicker.C:
			m.syncSecretsToBPF(ctx)
			m.DumpDebugCounters()
		default:
		}

		// Use a short deadline so we don't block forever and miss sync ticks
		m.reader.SetDeadline(time.Now().Add(1 * time.Second))
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			m.log.Errorw("reading from ringbuf", "error", err)
			continue
		}

		var event tlsEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			m.log.Errorw("failed to parse ringbuf event", "error", err)
			continue
		}

		if event.IsRewritten == 1 {
			m.log.Debugw("REWRITE SUCCESS: eBPF synchronously rewrote a secret", "pid", event.Pid)
		} else {
			m.log.Debugw("Intercepted TLS packet (no rewrite)", "pid", event.Pid, "len", event.Len)
		}
	}
}

// dnsIPKey matches C struct dns_ip_key (16-byte IPv4-mapped-IPv6).
type dnsIPKey struct {
	IP [16]byte
}

// PopulateTrustedDNSServers adds trusted DNS server IPs to the BPF map and
// enables the whitelist. If ips is empty, the whitelist is not enabled and
// all DNS responses are accepted.
func (m *TLSUprobeManager) PopulateTrustedDNSServers(ips []net.IP) error {
	if len(ips) == 0 {
		m.log.Errorw("No trusted DNS servers — all DNS responses will be rejected")
	}

	val := uint8(1)

	// Always enable the whitelist — we never want untrusted DNS
	flagKey := uint32(0)
	if err := m.objs.DnsWhitelistEnabled.Update(flagKey, val, 0); err != nil {
		return fmt.Errorf("enabling DNS whitelist: %w", err)
	}

	for _, ip := range ips {
		var key dnsIPKey
		ip4 := ip.To4()
		if ip4 != nil {
			// IPv4-mapped-IPv6
			key.IP[10] = 0xff
			key.IP[11] = 0xff
			copy(key.IP[12:], ip4)
		} else {
			copy(key.IP[:], ip.To16())
		}
		if err := m.objs.TrustedDnsServers.Update(&key, &val, 0); err != nil {
			return fmt.Errorf("adding trusted DNS server %s: %w", ip, err)
		}
		m.log.Infow("Added trusted DNS server", "ip", ip.String())
	}

	m.log.Infow("DNS server whitelist enabled", "count", len(ips))
	return nil
}

// syncSecretsToBPF updates the eBPF map with the latest shadow secret values
// and the watched_hosts map with hostnames from secret entries.
func (m *TLSUprobeManager) syncSecretsToBPF(ctx context.Context) {
	if err := syncSecrets(ctx, m.objs.SecretMap, m.objs.WatchedHosts, m.secretSource, m.log); err != nil {
		m.log.Errorw("failed to sync secrets to BPF map", "error", err)
	}
}

// debugCounterNames maps index to human-readable name (must match C enum in
// pkg/ebpf/bpf/tls_uprobe.c — DBG_* constants).
var debugCounterNames = []string{
	"kprobe_entry", "kprobe_tracked", "kprobe_dport53", "kprobe_dport0",
	"kprobe_dport_other", "kprobe_iov_ok", "kretprobe_entry", "kretprobe_ret_small",
	"kretprobe_read_fail", "kretprobe_read_ok", "dns_parse_entry", "dns_not_response",
	"dns_no_answers", "dns_qname_fail", "dns_not_watched", "dns_watched_hit",
	"dns_answer_stored",
	"resolve_ssl_fd_hit", "resolve_last_vfd_hit", "resolve_fd_scan_hit",
	"resolve_no_fd", "resolve_no_conn", "resolve_no_dns", "resolve_host_ok",
	"xor_conn_check", "xor_conn_hit", "xor_prescan_match", "xor_tailcall",
	"xor_path_entered", "xor_secret_found", "xor_delta_done",
	"tc_entry", "tc_match", "tc_patched",
	"kprobe_bridge", "kprobe_bridge_no_entry", "kprobe_bridge_h_fail",
	"evp_init_entry", "evp_init_h_ok", "evp_init_h_zero", "evp_init_chain_fail",
	"h_extract_cache_hit", "h_extract_cache_miss",
	"kprobe_bridge_from_pending", "kprobe_walk_legacy",
	"h_extract_live_walk",
	"bssl_reached", "bssl_h_ok",
	"bssl_s3_null", "bssl_aead_null", "bssl_rdkey_fail", "bssl_rounds_bad", "bssl_hzero",
}

// DumpDebugCounters reads and logs all debug counters from the BPF map.
func (m *TLSUprobeManager) DumpDebugCounters() {
	if m.objs.DebugCounters == nil {
		return
	}
	for i, name := range debugCounterNames {
		var vals []uint64
		key := uint32(i)
		if err := m.objs.DebugCounters.Lookup(key, &vals); err != nil {
			continue
		}
		var total uint64
		for _, v := range vals {
			total += v
		}
		if total > 0 {
			logging.Tracew(m.log, "eBPF debug counter", "name", name, "count", total)
		}
	}

	// BoringSSL H-walk diagnostic capture (last walk + offset scan).
	if m.objs.BsslProbe != nil {
		var pv struct {
			SSL, S3, AEAD                       uint64
			CfgOff, RawRounds, GoodOff, GoodRds uint32
		}
		if err := m.objs.BsslProbe.Lookup(uint32(0), &pv); err == nil && pv.AEAD != 0 {
			logging.Tracew(m.log, "bssl probe",
				"aead", fmt.Sprintf("0x%x", pv.AEAD),
				"cfg_off", pv.CfgOff, "raw_rounds", pv.RawRounds,
				"good_off", pv.GoodOff, "good_rounds", pv.GoodRds)
		}
	}
}
