//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
	// linksMu guards links, the node-wide links (tracepoints, kprobes, the
	// virtual IP cgroup hooks), held until Close.
	linksMu sync.Mutex
	links   []io.Closer
	// registry holds the uprobes attached for containers (links.go).
	registry linkRegistry

	// secretSource produces snapshots of the secrets the BPF map should
	// hold. The k8s controller wires a pkg/secrets/k8s.Source here; tests
	// or non-k8s callers may pass nil (sync becomes a no-op) or a
	// different implementation.
	secretSource secrets.Source
	// cgroupRoot is the path to the cgroup v2 filesystem (e.g. /sys/fs/cgroup)
	cgroupRoot string
	// kubepods is the cgroup directory every container cgroup is under
	// (setupCgroupAncestor), "" when it was not found.
	kubepods string
	// egressInterface selects which container-netns NIC is used to locate
	// the tc patch attach point (the host side of its veth pair):
	//
	//	"" or "auto"     — read the netns's routes and pick the interface
	//	                   backing the default IPv4 route, or the default
	//	                   IPv6 route without one (IPv6-only pods).
	//	                   Works for the standard CNI veth-named-"eth0"
	//	                   convention AND for host-mode netns where the
	//	                   default route exits via e.g. enp0s3 / wlp3s0.
	//	"none","lo-only" — explicit opt-out of external interface
	//	                   attachment. Useful for tests.
	//	any other value  — exact interface name (e.g., "eth0", "wlp3s0").
	//	                   Fail closed if the named interface is not found
	//	                   in the netns.
	//
	// Loopback is never attached: lo traffic cannot be patched from the
	// host side, and patching it in-pod would expose the rewritten
	// ciphertext to in-pod AF_PACKET capture (see attachTCEgress).
	egressInterface string
	// tcMode decides between TCX and the clsact fallback (tc_attach.go).
	tcMode *tcModeResolver
	// cgroupPaths maps cgroup inode ID -> filesystem path.
	// Populated by TrackCgroup.
	cgroupPaths sync.Map // uint64 -> string
	// tcMu guards podTC.
	tcMu sync.Mutex
	// podTC maps a pod network namespace's inode to the tc patch program
	// attached for it, released (detached) with the last cgroup recorded
	// for the netns (ReleaseCgroupNetns).
	podTC map[uint64]*podTC
	// tcProgID is the kernel ID of the tc patch program (tcLinkKey).
	tcProgID ebpf.ProgramID
	// cgroupToNetns maps cgroup ID → netns inode, for the pod's release.
	cgroupToNetns sync.Map // uint64 (cgroup ID) -> uint64 (netns inode)
	// retryWG tracks the deferred-attach goroutines spawned by PollExecEvents.
	// Close() waits on it (with a bounded timeout) before tearing down BPF
	// objects, so a sleeping retry can't fire AttachTLS against a freed map fd.
	retryWG sync.WaitGroup

	// bindMu guards bindings, bindingMode and lastSnapshot, and serializes
	// every secret_acl and vip_pod_host write, so a secret sync can't
	// prune entries a concurrent BindPodSecrets just granted.
	bindMu sync.Mutex
	// bindings maps pod UID → the secrets that pod may redeem (secret_binding.go).
	bindings map[string]podBinding
	// bindingMode is the --secret-binding mode (SetSecretBindingMode).
	bindingMode SecretBindingMode
	// lastSnapshot is the most recent secrets snapshot, used to grant a new
	// pod's bindings immediately instead of at the next secret sync.
	lastSnapshot []secrets.Secret
	// bindingLogged rate-limits violation logs per (cgroup, placeholder,
	// reason).
	bindingLogged map[bindingLogKey]time.Time

	// virtualIPs allocates the watched hosts' fake IPs (nil only in tests
	// that build a manager without one).
	virtualIPs *virtualIPAllocator
	// dnsRewriteMu guards dnsRewrite and dnsRewriteFailed, and serializes
	// AttachPodDNSRewrite.
	dnsRewriteMu sync.Mutex
	// dnsRewrite maps pod UID → tc_dns_rewrite attached in the pod's netns.
	dnsRewrite map[string]*dnsRewriteAttach
	// dnsRewriteFailed records the pods whose attach failure was logged.
	dnsRewriteFailed map[string]bool

	// detachWG tracks the goroutines detaching links that are no longer
	// needed (detachAsync).
	detachWG sync.WaitGroup
}

// bindingLogKey identifies a logged binding or SNI violation.
type bindingLogKey struct {
	acl       secretACLKey
	reason    uint8
	sniStatus uint8
}

// podTC is the tc patch program attached for a pod's network namespace:
// tc ingress on the host side of its veth pairs, or tc egress on an
// interface without a peer. Its mutex serializes the attaches and the
// release for the netns.
type podTC struct {
	mu sync.Mutex
	// netnsFd is an open fd to the netns: it keeps the kernel from reusing
	// the inode for another pod's netns while the entry is recorded.
	netnsFd *os.File
	// links are the attachments, by what they are attached to.
	links map[tcLinkKey]io.Closer
	// attached: the last attach completed (possibly without any link, with
	// --egress-interface none).
	attached bool
	// released: ReleaseCgroupNetns detached it (the pod went).
	released bool
}

// detachAsync closes links in the background: a uprobe detach can wait for
// an RCU grace period, which must not hold up an attach or the
// reconciliation. Close waits for it.
func (m *TLSUprobeManager) detachAsync(links []io.Closer, what string, keysAndValues ...any) {
	if len(links) == 0 {
		return
	}
	m.detachWG.Add(1)
	go func() {
		defer m.detachWG.Done()
		for _, l := range links {
			if err := l.Close(); err != nil {
				m.log.Debugw("failed to detach "+what, append([]any{"error", err}, keysAndValues...)...)
			}
		}
		logging.Tracew(m.log, "detached "+what, append([]any{"links", len(links)}, keysAndValues...)...)
	}()
}

// setupCgroupAncestor finds the kubepods cgroup directory, stores its fd in
// the BPF cgroup_ancestor map and returns its path. This enables
// bpf_current_task_under_cgroup() in the exec tracepoint to catch all
// container execs without per-container cgroup tracking.
func setupCgroupAncestor(objs *tlsuprobeObjects, cgroupRoot string, log *zap.SugaredLogger) (string, error) {
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
			return "", fmt.Errorf("updating cgroup_ancestor map: %w", err)
		}
		log.Infow("Configured cgroup ancestor for exec tracepoint", "path", path)
		return path, nil
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
	return "", fmt.Errorf("kubepods cgroup not found in %s", cgroupRoot)
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
//
// hostRes holds the virtual IP ranges; the virtual IP maps are pinned under
// hostRes.PinPath, which must be on bpffs.
func NewTLSUprobeManager(secretSource secrets.Source, cgroupRoot, egressInterface string, hostRes *HostResolutionConfig, log *zap.SugaredLogger) (*TLSUprobeManager, error) {
	if hostRes == nil {
		return nil, errors.New("no host resolution config")
	}
	log = log.Named("ebpf-uprobe")

	if err := hostRes.validate(); err != nil {
		return nil, err
	}
	spec, err := loadTlsuprobe()
	if err != nil {
		return nil, fmt.Errorf("loading eBPF collection spec: %w", err)
	}
	if err := prepareVirtualIPPins(spec, hostRes.pinPath(), log); err != nil {
		return nil, fmt.Errorf("preparing virtual IP map pins: %w", err)
	}
	mapOpts := ebpf.MapOptions{PinPath: hostRes.pinPath()}

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
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Maps:     mapOpts,
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
	kubepods, err := setupCgroupAncestor(objs, cgroupRoot, log)
	if err != nil {
		log.Errorw("failed to setup cgroup ancestor — exec tracepoint will not catch initial container processes", "error", err)
		// Non-fatal: exec tracepoint falls back to tracked_cgroups
	}

	reader, err := ringbuf.NewReader(objs.SecretBindingEvents)
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
		objs:             objs,
		reader:           reader,
		procReader:       procReader,
		log:              log,
		secretSource:     secretSource,
		cgroupRoot:       cgroupRoot,
		kubepods:         kubepods,
		egressInterface:  egressInterface,
		tcMode:           newTCModeResolver(TCAttachAuto),
		tcProgID:         programID(objs.TcEgressPatch),
		bindings:         make(map[string]podBinding),
		bindingLogged:    make(map[bindingLogKey]time.Time),
		dnsRewrite:       make(map[string]*dnsRewriteAttach),
		dnsRewriteFailed: make(map[string]bool),
	}
	mgr.virtualIPs = newVirtualIPAllocator(objs, hostRes.VirtualIPRanges, log)
	mgr.virtualIPs.logRestored()
	// Without the redirect, a pod handed a fake IP could not connect.
	if err := mgr.attachVirtualIPRedirect(hostRes.VirtualIPRanges, kubepods); err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("attaching the virtual IP connect redirect: %w", err)
	}
	log.Infow("virtual IP host resolution: kloak pods get fake IPs for watched hosts, connects to them are redirected",
		"range", hostRes.VirtualIPRanges.String(), "pinPath", hostRes.pinPath(), "cgroup", kubepods)

	// Attach the connect, process and socket tracepoints and the tcp_sendmsg
	// kprobes. These are node-wide, filtered in BPF by tracked_tgids and
	// tracked_cgroups.
	if err := mgr.attachTracepoints(); err != nil {
		_ = mgr.Close()
		return nil, fmt.Errorf("attaching tracepoints: %w", err)
	}

	return mgr, nil
}

// attachTracepoints attaches the syscall tracepoints and kprobes for connect tracking and the tcp_sendmsg bridge.
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

	// SNI check: record each connection's ClientHello SNI (a second kprobe
	// on tcp_sendmsg) and forget it when the socket reconnects or closes.
	skp, err := link.Kprobe("tcp_sendmsg", m.objs.BpfKprobeTcpSendmsgSni, nil)
	if err != nil {
		return fmt.Errorf("attaching SNI kprobe tcp_sendmsg: %w", err)
	}
	m.linksMu.Lock()
	m.links = append(m.links, skp)
	m.linksMu.Unlock()
	stp, err := link.Tracepoint("sock", "inet_sock_set_state", m.objs.TpInetSockSetState, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint sock/inet_sock_set_state: %w", err)
	}
	m.linksMu.Lock()
	m.links = append(m.links, stp)
	m.linksMu.Unlock()
	m.log.Debugw("Attached SNI capture", "kprobe", "tcp_sendmsg", "tracepoint", "sock/inet_sock_set_state")

	return nil
}

// SetTCAttachMode selects how the tc patch program is attached (see
// TCAttachMode). Call it before any pod is tracked; the default is
// TCAttachAuto.
func (m *TLSUprobeManager) SetTCAttachMode(mode TCAttachMode) {
	m.tcMode = newTCModeResolver(mode)
}

// attachTCEgress attaches the tc patch program where a container's outbound
// traffic leaves the pod: tc INGRESS on the host side of the pod's veth pair.
//
// Why host-side and not tc egress inside the pod netns (the previous design):
// in the pod netns the tc egress hook runs before the AF_PACKET tap
// (dev_queue_xmit_nit fires in xmit_one, after sch_handle_egress), so a
// compromised container with CAP_NET_RAW — in the default Docker/containerd
// capability set — could capture its own patched ciphertext and decrypt it
// with its own TLS session keys, recovering the real secret. Patching on the
// host side of the veth puts the rewrite out of reach of in-pod capture.
//
// Pod attribution is preserved: the skb keeps its socket across the veth
// boundary (veth_forward_skb does not orphan it), so bpf_skb_cgroup_id() at
// host-veth ingress still returns the container's cgroup ID and the
// (dst_ip, src_port, cgroup_id) tc_pending key built by the tcp_sendmsg
// kprobe matches unchanged. The host-veth ingress point is also pre-NAT, so
// dst_ip/src_port still hold the values the kprobe recorded.
//
// Loopback is intentionally no longer patched: lo traffic never crosses the
// veth, and injecting real secrets into same-pod traffic would make them
// readable by any process in the pod — contradicting the isolation model.
// Same-pod localhost destinations receive the placeholder.
//
// Interfaces without a veth peer (hostNetwork pods, physical NICs in
// host-mode netns) have no host side to attach to; those keep the legacy
// in-netns egress attach and remain exposed to in-pod capture (drop NET_RAW
// for such workloads).
//
// The controller enters the container's netns via /proc/<pid>/ns/net to
// resolve the veth peer ifindex, then switches to the root netns
// (/proc/1/ns/net — requires hostPID: true) to attach.
//
// It is attached once per pod network namespace (podTC), which cgroupID's
// container is recorded in, for the pod's release to detach it
// (ReleaseCgroupNetns). A later call finds it attached, after checking with
// the kernel that every attachment is still there (tcLinkLive): one whose
// interface went (the pod's veth recreated) is attached again, on the
// interfaces the netns has now. Attaching the program twice on one hook
// would patch each record twice and corrupt it, so an attachment kloak has
// is never attached again.
func (m *TLSUprobeManager) attachTCEgress(pid int, cgroupID uint64) error {
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	podNetns, err := netnsInode(netnsPath)
	if err != nil {
		return fmt.Errorf("reading the netns of pid %d: %w", pid, err)
	}
	// Record the container's netns first: the pod's release then finds
	// what this attaches, whatever the caller does with the result.
	m.cgroupToNetns.Store(cgroupID, podNetns)

	e := m.podTCEntry(podNetns)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.released {
		return fmt.Errorf("tc patch program of pid %d's netns released during the attach; retry", pid)
	}
	if e.attached && m.podTCLive(e) {
		m.log.Debugw("tc egress already attached for this netns", "pid", pid, "netns_ino", podNetns)
		return nil
	}

	// Open the netns fd for two purposes:
	// 1. setns to enter the container's network namespace
	// 2. Keep it open (in the podTC entry) to pin the inode
	containerNS, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("opening container netns %s: %w", netnsPath, err)
	}
	if ino, err := netnsInode(netnsPath); err != nil || ino != podNetns {
		// The process exited and its PID was reused, between the two opens.
		_ = containerNS.Close()
		return fmt.Errorf("pid %d's netns changed during the attach; retry", pid)
	}
	keepNS := false
	defer func() {
		if !keepNS {
			_ = containerNS.Close()
		}
	}()

	// The host-side veth peer lives in the root network namespace. With
	// hostPID: true, /proc/1/ns/net is the node init's netns (in kind/k3d,
	// the node container's netns — which is where the CNI places pod veth
	// peers there too).
	const rootNetnsPath = "/proc/1/ns/net"
	rootNS, err := os.Open(rootNetnsPath)
	if err != nil {
		return fmt.Errorf("opening root netns %s: %w", rootNetnsPath, err)
	}
	defer func() { _ = rootNS.Close() }()
	rootNetns, err := netnsInode(rootNetnsPath)
	if err != nil {
		return fmt.Errorf("reading the root netns: %w", err)
	}

	// The attachments kloak has for the netns and that the kernel still
	// has: those are kept, the others are attached.
	have := make(map[tcLinkKey]io.Closer, len(e.links))
	var dead []io.Closer
	for k, l := range e.links {
		if tcLinkLive(l) {
			have[k] = l
		} else {
			dead = append(dead, l)
		}
	}

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
		links map[tcLinkKey]io.Closer // the netns's attachments, kept and new
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

		// Save this thread's network namespace (see threadNetnsPath).
		selfNS, err := os.Open(threadNetnsPath)
		if err != nil {
			resultCh <- tcResult{err: fmt.Errorf("opening self netns: %w", err)}
			return
		}
		defer func() { _ = selfNS.Close() }()

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

		// Phase 1: inside the container netns, resolve the egress
		// interface(s) and their host-side veth peers. net.InterfaceByName
		// (netlink) and /proc/thread-self/net/route (procfs) follow the
		// thread's current netns; the iflink read goes through
		// /proc/<pid>/root instead —
		// /sys/class/net is scoped to the sysfs mount's netns and does NOT
		// follow setns (see vethPeerIfindex).
		ifNames := m.resolveEgressInterfaces(fmt.Sprintf("pid %d", pid))

		// hostPeer is a container interface whose veth peer gets the tc
		// ingress attach in the root netns.
		type hostPeer struct {
			ifName    string // container-side name (for logs)
			podIfidx  int    // container-side ifindex (peer validation)
			hostIfidx int    // peer ifindex in the root netns
		}
		var peers []hostPeer
		// legacy holds interfaces without a veth peer (hostNetwork pods,
		// physical NICs): no host side exists, so they keep the in-netns
		// egress attach.
		var legacy []*net.Interface

		// Resolve and validate everything before attaching anything, so
		// that a failure leaves the netns as it was.
		for _, ifName := range ifNames {
			if ifName == "lo" {
				// Loopback is deliberately not patched — see the
				// attachTCEgress doc comment.
				continue
			}
			iface, err := net.InterfaceByName(ifName)
			if err != nil {
				resultCh <- tcResult{err: fmt.Errorf("egress interface %q not found in pid %d netns (configured via --egress-interface or controller.ebpf.egressInterface): %w", ifName, pid, err)}
				return
			}
			peerIdx, err := vethPeerIfindex(fmt.Sprintf("/proc/%d/root", pid), ifName)
			if err != nil {
				resultCh <- tcResult{err: fmt.Errorf("resolving host-side peer of %s in pid %d netns: %w", ifName, pid, err)}
				return
			}
			if peerIdx == 0 || peerIdx == iface.Index {
				// No peer: physical NIC, host-mode netns, or tunnel.
				legacy = append(legacy, iface)
				continue
			}
			peers = append(peers, hostPeer{ifName: ifName, podIfidx: iface.Index, hostIfidx: peerIdx})
		}

		// The netns's attachments after this call: those it keeps and those
		// it attaches. On a partial failure the ones it attached are closed
		// and the netns keeps what it had, for a retry to complete.
		out := make(map[tcLinkKey]io.Closer, len(peers)+len(legacy))
		var attachedHere []io.Closer
		closeOnFail := func() {
			for _, prior := range attachedHere {
				if cerr := prior.Close(); cerr != nil {
					m.log.Warnw("rollback: failed to close partially-attached tc link", "error", cerr, "pid", pid)
				}
			}
		}
		// ensure attaches the program on (netns, ifindex, ingress) unless
		// the netns has it there already.
		ensure := func(netnsIno uint64, ifindex int, ingress bool, nsFd *os.File) (bool, error) {
			key := tcLinkKey{netns: netnsIno, ifindex: ifindex, ingress: ingress, prog: m.tcProgID}
			if l, ok := have[key]; ok {
				out[key] = l
				return false, nil
			}
			l, err := m.attachTCProgram(m.objs.TcEgressPatch, ifindex, ingress, nsFd)
			if err != nil {
				return false, err
			}
			attachedHere = append(attachedHere, l)
			out[key] = l
			return true, nil
		}

		// Legacy fallback first, while still inside the container netns.
		for _, iface := range legacy {
			created, err := ensure(podNetns, iface.Index, false, containerNS)
			if err != nil {
				closeOnFail()
				resultCh <- tcResult{err: fmt.Errorf("attaching tc egress to %s (ifindex %d) in pid %d netns: %w", iface.Name, iface.Index, pid, err)}
				return
			}
			if created {
				m.log.Warnw("interface has no veth peer — attached tc egress inside the pod netns; "+
					"patched traffic remains capturable by in-pod AF_PACKET (drop NET_RAW)",
					"pid", pid, "interface", iface.Name, "ifindex", iface.Index)
			}
		}

		// Phase 2: switch to the root netns and attach tc ingress on each
		// host-side veth peer.
		if len(peers) > 0 {
			if err := unix.Setns(int(rootNS.Fd()), unix.CLONE_NEWNET); err != nil {
				closeOnFail()
				resultCh <- tcResult{err: fmt.Errorf("setns to root netns: %w", err)}
				return
			}
			// Pre-validate every peer before attaching any: the peer must
			// exist and point back at the pod interface. The back-pointer
			// check guards against ifindex reuse and against non-veth
			// interfaces whose iflink references a lower device (tunnels).
			for _, p := range peers {
				peerIface, err := net.InterfaceByIndex(p.hostIfidx)
				if err != nil {
					closeOnFail()
					resultCh <- tcResult{err: fmt.Errorf("host-side veth peer ifindex %d (pod %s) not found in root netns: %w", p.hostIfidx, p.ifName, err)}
					return
				}
				backIdx, err := vethPeerIfindex("/proc/1/root", peerIface.Name)
				if err != nil || backIdx != p.podIfidx {
					closeOnFail()
					resultCh <- tcResult{err: fmt.Errorf("host-side peer %s (ifindex %d) does not point back at pod %s (ifindex %d); refusing to attach", peerIface.Name, p.hostIfidx, p.ifName, p.podIfidx)}
					return
				}
			}
			for _, p := range peers {
				created, err := ensure(rootNetns, p.hostIfidx, true, rootNS)
				if err != nil {
					closeOnFail()
					resultCh <- tcResult{err: fmt.Errorf("attaching tc ingress to host veth ifindex %d (pod %s): %w", p.hostIfidx, p.ifName, err)}
					return
				}
				if created {
					m.log.Debugw("Attached tc patch to host-side veth", "pid", pid, "podInterface", p.ifName, "hostIfindex", p.hostIfidx)
				}
			}
		}

		if len(out) == 0 {
			optOut := strings.EqualFold(m.egressInterface, "none") || strings.EqualFold(m.egressInterface, "lo-only")
			if optOut {
				// Explicit opt-out: nothing to attach, report success.
				resultCh <- tcResult{links: out}
				return
			}
			// No external interface resolved (e.g. no default route yet,
			// mid-CNI-setup). Fail so a later exec/reconcile retries
			// instead of marking the netns attached with no coverage.
			resultCh <- tcResult{err: fmt.Errorf("no external interface resolved in pid %d netns; nothing attached", pid)}
			return
		}
		resultCh <- tcResult{links: out}
	}()

	res := <-resultCh
	if res.err != nil {
		return res.err
	}

	// The attachments the kernel no longer has, and those of interfaces the
	// netns no longer routes through, are detached.
	for k, l := range have {
		if _, ok := res.links[k]; !ok {
			dead = append(dead, l)
		}
	}
	m.detachAsync(dead, "tc patch attachments the pod's netns no longer has", "pid", pid, "netns_ino", podNetns)
	e.links = res.links
	e.attached = true
	if e.netnsFd == nil {
		e.netnsFd = containerNS
		keepNS = true
	}
	return nil
}

// podTCEntry returns the podTC entry of netns netnsIno, recording a new one
// if there is none.
func (m *TLSUprobeManager) podTCEntry(netnsIno uint64) *podTC {
	m.tcMu.Lock()
	defer m.tcMu.Unlock()
	if m.podTC == nil {
		m.podTC = make(map[uint64]*podTC)
	}
	e := m.podTC[netnsIno]
	if e == nil {
		e = &podTC{}
		m.podTC[netnsIno] = e
	}
	return e
}

// podTCLive reports whether the kernel still has every attachment of e;
// the caller holds e.mu.
func (m *TLSUprobeManager) podTCLive(e *podTC) bool {
	for _, l := range e.links {
		if !tcLinkLive(l) {
			return false
		}
	}
	return true
}

// resolveEgressInterfaces returns the ordered interface names used to locate
// tc attach points for the current netns. Must be called AFTER setns
// to the target netns, since the resolution reads the netns's route tables
// and performs netns-local interface lookups.
//
// The list may include "lo" for backward compatibility with the flag
// semantics below, but the caller never attaches to it: loopback traffic
// never crosses the pod's veth pair, so it cannot be patched from the host
// side (see the attachTCEgress doc comment). The external interface is
// chosen by:
//
//   - empty / "auto": pick the interface of the netns's default IPv4
//     route, or of its default IPv6 route when it has no IPv4 one (see
//     findDefaultRouteInterface). Returns no external interface if no
//     default route exists and logs a warning — external TLS rewrites
//     will NOT apply until a route is configured (typical for a netns
//     mid-CNI-setup).
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
func (m *TLSUprobeManager) resolveEgressInterfaces(netnsOf string) []string {
	var external string
	switch strings.ToLower(m.egressInterface) {
	case "", "auto":
		got, err := findDefaultRouteInterface()
		switch {
		case err != nil:
			m.log.Warnw("default-route auto-detection failed; attaching only to lo — external TLS rewrites will NOT apply",
				"netnsOf", netnsOf, "error", err)
		case got == "":
			m.log.Warnw("no default route (IPv4 or IPv6) in target netns; attaching only to lo — external TLS rewrites will NOT apply (set --egress-interface explicitly if a default route exists under a non-standard name)",
				"netnsOf", netnsOf)
		default:
			external = got
			m.log.Debugw("auto-detected egress interface from default route",
				"netnsOf", netnsOf, "interface", external)
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

// vethPeerIfindex reads the interface's iflink attribute and returns the
// ifindex of its veth peer in the parent (host) netns. Returns 0 — or the
// interface's own ifindex — for interfaces without a peer (physical NICs,
// lo), which callers treat as "not a veth".
//
// sysRoot selects WHICH netns's view to read, because /sys/class/net is
// scoped to the netns of the sysfs MOUNT, not the reader's current netns —
// setns() does not change what a given /sys mount shows. Reading through
// /proc/<pid>/root follows the target process's mount namespace instead:
// pass fmt.Sprintf("/proc/%d/root", pid) for a container's view and
// "/proc/1/root" for the root netns's view.
func vethPeerIfindex(sysRoot, ifName string) (int, error) {
	data, err := os.ReadFile(filepath.Join(sysRoot, "sys", "class", "net", ifName, "iflink"))
	if err != nil {
		return 0, fmt.Errorf("reading iflink for %s under %s: %w", ifName, sysRoot, err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing iflink for %s under %s: %q: %w", ifName, sysRoot, strings.TrimSpace(string(data)), err)
	}
	return idx, nil
}

// threadNetnsPath is the network namespace of the calling OS thread. A
// worker that switches its locked thread into a pod's netns opens it first,
// to switch back to. Not /proc/self/ns/net: that is the main thread's, which
// another worker may have switched into a pod's netns at that moment, and
// returning there would leave this thread in that pod's netns.
const threadNetnsPath = "/proc/thread-self/ns/net"

// findDefaultRouteInterface reads the calling thread's netns routes and
// returns the interface name backing the default IPv4 route or, when there
// is none (an IPv6-only netns), the default IPv6 route. Returns "" if
// neither exists.
func findDefaultRouteInterface() (string, error) {
	// Not /proc/net: that is /proc/self/net, the netns of the main thread,
	// not of a worker thread setns'd into a pod.
	data, err := os.ReadFile("/proc/thread-self/net/route")
	if err != nil {
		return "", fmt.Errorf("reading /proc/thread-self/net/route: %w", err)
	}
	if iface := parseDefaultRouteInterface(data); iface != "" {
		return iface, nil
	}
	data, err = os.ReadFile("/proc/thread-self/net/ipv6_route")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil // a kernel without IPv6
	}
	if err != nil {
		return "", fmt.Errorf("reading /proc/thread-self/net/ipv6_route: %w", err)
	}
	return parseDefaultRoute6Interface(data), nil
}

// rtfReject is RTF_REJECT (include/uapi/linux/ipv6_route.h): an
// unreachable, prohibit or blackhole route.
const rtfReject = 0x0200

// parseDefaultRoute6Interface walks a /proc/net/ipv6_route body ("dst
// dst_len src src_len next_hop metric refcnt use flags iface", in hex) and
// returns the interface of the default route (::/0) with the lowest metric,
// or "" if there is none. Reject routes are skipped: the kernel lists its
// null entry as a ::/0 reject route on lo, metric 0xffffffff, and `ip -6
// route add unreachable default` adds another.
func parseDefaultRoute6Interface(data []byte) string {
	const unspecified = "00000000000000000000000000000000"
	var iface string
	var best uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != unspecified || fields[1] != "00" {
			continue
		}
		metric, err := strconv.ParseUint(fields[5], 16, 32)
		if err != nil {
			continue
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil || flags&rtfReject != 0 {
			continue
		}
		if iface == "" || metric < best {
			iface, best = fields[9], metric
		}
	}
	return iface
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

// UntrackTGID removes a process TGID from the tracked_tgids map. The
// sched_process_exit tracepoint does so for every process that exits; the
// per-binary maps (tls_strategy, the offsets) are keyed by cgroup and
// cleaned up with it.
func (m *TLSUprobeManager) UntrackTGID(tgid uint32) error {
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
// process, for the pod's release (ReleaseCgroupNetns) to detach the tc patch
// program attached in the netns. attachTCEgress records it too.
func (m *TLSUprobeManager) RecordCgroupNetns(cgroupID uint64, pid int) {
	ino, err := netnsInode(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return
	}
	m.cgroupToNetns.Store(cgroupID, ino)
}

// UntrackCgroup removes a container cgroup ID from the tracked_cgroups map
// and cleans up the associated tc attachment state. When the last cgroup
// referencing a netns is untracked, the netns's tc patch program is
// detached and its pinned fd closed, allowing the kernel to free the inode
// for reuse.
func (m *TLSUprobeManager) UntrackCgroup(cgroupID uint64) error {
	err := m.UntrackExitedCgroup(cgroupID)
	m.ReleaseCgroupNetns(cgroupID)
	return err
}

// UntrackExitedCgroup untracks the cgroup of a container that exited while
// its pod lives on (an init container that completed, a container that
// restarted in a new cgroup) as UntrackCgroup does, but keeps the pod's
// network namespace recorded for it: while it is, the pod's tc patch
// program stays attached, and a later container of the pod finds it
// instead of attaching it a second time. ReleaseCgroupNetns releases it,
// with the pod.
func (m *TLSUprobeManager) UntrackExitedCgroup(cgroupID uint64) error {
	m.cgroupPaths.Delete(cgroupID)

	// Detach the uprobes no other container needs, in the background: each
	// detach can wait for an RCU grace period, which must not hold up
	// reconciliation.
	m.detachAsync(m.registry.releaseCgroup(cgroupID), "uprobes of an untracked container", "cgroupID", cgroupID)

	// The per-binary entries of the cgroup's processes: their offsets
	// (tls_offset_config, go_tls_offset_config) and H-extraction strategy
	// (tls_strategy), all keyed by (cgroup_id, exe_inode). Best-effort:
	// failures here only leak map entries until the next sweep.
	dead := func(id uint64) bool { return id == cgroupID }
	for _, mp := range []*ebpf.Map{m.objs.GoTlsOffsetConfig, m.objs.TlsOffsetConfig, m.objs.TlsStrategy} {
		_, _ = deleteBinaryKeys(mp, dead)
	}

	return m.objs.TrackedCgroups.Delete(cgroupID)
}

// ReleaseCgroupNetns forgets the network namespace recorded for a cgroup
// (RecordCgroupNetns). Once no cgroup records it, the netns's tc patch
// program is detached and the pinned netns fd closed, so the kernel can
// reclaim the inode (multi-container pods share a netns).
func (m *TLSUprobeManager) ReleaseCgroupNetns(cgroupID uint64) {
	inoVal, ok := m.cgroupToNetns.LoadAndDelete(cgroupID)
	if !ok {
		return
	}
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
	if otherRefs {
		return
	}
	m.releasePodTC(ino)
}

// releasePodTC detaches the tc patch program attached for netns netnsIno and
// closes the netns fd, once any attach for it in flight is done.
func (m *TLSUprobeManager) releasePodTC(netnsIno uint64) {
	m.tcMu.Lock()
	e := m.podTC[netnsIno]
	delete(m.podTC, netnsIno)
	m.tcMu.Unlock()
	if e == nil {
		return
	}
	e.mu.Lock()
	e.released = true
	closers := make([]io.Closer, 0, len(e.links)+1)
	for _, l := range e.links {
		closers = append(closers, l)
	}
	e.links = nil
	if e.netnsFd != nil {
		// After the links: a clsact filter is removed through its own
		// duplicate of the fd.
		closers = append(closers, e.netnsFd)
		e.netnsFd = nil
	}
	e.mu.Unlock()
	m.detachAsync(closers, "tc patch program of a released pod netns", "netns_ino", netnsIno)
}

// AttachTLS attaches system-wide eBPF uprobes to all TLS libraries in a
// container. The uprobes fire for ALL processes that map the libraries
// (every container of the image shares them, see fileIdentity). The BPF
// cgroup filter restricts interception to tracked containers only.
//
// The attach discovers the uprobes the process needs and ensures them
// through the link registry (links.go): one the registry has is not attached
// again, and the container is recorded as needing it.
func (m *TLSUprobeManager) AttachTLS(pid int, cgroupID uint64) error {
	return m.attachTLS(pid, cgroupID, true)
}

// AttachContainerTLS is AttachTLS for the process of a container the
// container runtime is about to start: the process has not run the
// container's command yet, and its executable is still the runtime's own. It
// attaches the TLS libraries in the container's filesystem, which every
// process of the container that loads them goes through (the command's, and
// the processes it starts), and the pod's tc patch program. The command's
// executable is attached on its exec event (PollExecEvents), with what
// depends on it: the TLS linked into it, and its H-extraction strategy.
func (m *TLSUprobeManager) AttachContainerTLS(pid int, cgroupID uint64) error {
	return m.attachTLS(pid, cgroupID, false)
}

// tlsProcess is a process whose executable an attach looks at.
type tlsProcess struct {
	pid     int
	start   uint64 // procStartTime
	exePath string // /proc/<pid>/exe
	exe     *link.Executable
	exeFile fileKey // exeFileKey; exeFile.ino is the exe_inode of the per-binary maps
}

// discoverProcess opens process pid's executable, and reads what its
// process-scoped uprobes are keyed by.
func discoverProcess(pid int) (*tlsProcess, error) {
	start, err := procStartTime(pid)
	if err != nil {
		return nil, fmt.Errorf("reading the start time of pid %d: %w", pid, err)
	}
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		return nil, fmt.Errorf("opening executable %s: %w", exePath, err)
	}
	file, err := exeFileKey(pid)
	if err != nil {
		return nil, fmt.Errorf("stat executable %s: %w", exePath, err)
	}
	return &tlsProcess{pid: pid, start: start, exePath: exePath, exe: ex, exeFile: file}, nil
}

// uprobeSpec is a uprobe an attach discovered: its key in the link registry,
// and how to attach it.
type uprobeSpec struct {
	key    uprobeLinkKey
	attach func() ([]io.Closer, error)
}

// exeUprobe is the uprobe running prog at symbol (or file offset addr) of
// p's executable, for p only.
func (m *TLSUprobeManager) exeUprobe(p *tlsProcess, symbol string, addr uint64, prog uprobeProg) *uprobeSpec {
	return &uprobeSpec{
		key: uprobeLinkKey{pid: p.pid, start: p.start, file: p.exeFile, symbol: symbol, addr: addr, prog: prog},
		attach: func() ([]io.Closer, error) {
			return m.attachUprobe(p.exe, symbol, prog, &link.UprobeOptions{PID: p.pid, Address: addr})
		},
	}
}

// libUprobe is the uprobe running prog at symbol of the library ex, file
// file, for every process that maps it.
func (m *TLSUprobeManager) libUprobe(ex *link.Executable, file fileKey, symbol string, prog uprobeProg) *uprobeSpec {
	return &uprobeSpec{
		key: uprobeLinkKey{file: file, symbol: symbol, prog: prog},
		attach: func() ([]io.Closer, error) {
			return m.attachUprobe(ex, symbol, prog, nil)
		},
	}
}

// ensureUprobe attaches the uprobe of spec unless the link registry has it,
// and records container cgroupID as needing it. It reports whether it
// attached it.
func (m *TLSUprobeManager) ensureUprobe(spec *uprobeSpec, cgroupID uint64) (bool, error) {
	return m.registry.ensure(&spec.key, cgroupID, spec.attach)
}

// attachUprobe attaches prog at symbol (or opts.Address) of ex.
func (m *TLSUprobeManager) attachUprobe(ex *link.Executable, symbol string, prog uprobeProg, opts *link.UprobeOptions) ([]io.Closer, error) {
	switch prog {
	case progSSLWrite, progGoTLSWrite:
		p := m.objs.BpfUprobeSslWrite
		if prog == progGoTLSWrite {
			p = m.objs.BpfUprobeGoTlsWrite
		}
		up, err := ex.Uprobe(symbol, p, opts)
		if err != nil {
			return nil, err
		}
		return []io.Closer{up}, nil
	case progEVPCipherInit:
		up, err := ex.Uprobe(symbol, m.objs.BpfUprobeEvpCipherInit, opts)
		if err != nil {
			return nil, err
		}
		ret, err := ex.Uretprobe(symbol, m.objs.BpfUretprobeEvpCipherInit, opts)
		if err != nil {
			_ = up.Close()
			return nil, err
		}
		return []io.Closer{up, ret}, nil
	default:
		return nil, fmt.Errorf("unknown uprobe program %d", prog)
	}
}

// retainProcess detaches the process-scoped uprobes recorded for process
// pid's PID that are not for the process and executable it runs now: those
// of the executable it ran before an exec, and those of an earlier process
// with its PID. A process that exited is left to the sweep.
func (m *TLSUprobeManager) retainProcess(pid int) {
	start, err := procStartTime(pid)
	if err != nil {
		return
	}
	exe, err := exeFileKey(pid)
	if err != nil {
		return
	}
	m.detachAsync(m.registry.retainProcess(pid, start, exe), "uprobes of a process's previous executable", "pid", pid)
}

// attachTLS is AttachTLS, for the process's executable too when withExe.
func (m *TLSUprobeManager) attachTLS(pid int, cgroupID uint64, withExe bool) error {
	// Register the process for DNS/connect tracking.
	if err := m.TrackTGID(uint32(pid)); err != nil {
		m.log.Errorw("failed to track TGID for DNS/connect", "error", err, "pid", pid)
	} else {
		logging.Tracew(m.log, "tracking TGID for DNS/connect verification", "pid", pid)
	}

	// H extraction now happens in the entry uprobe via 4-step pointer chain.
	// The offsets are pushed to the BPF config map by pushTLSOffsets below.

	tlsSymbols := []string{"SSL_write", "SSL_write_ex", "gnutls_record_send", "gnutls_record_send2"}
	attached := false

	// 1-2. The TLS linked into the executable.
	var proc *tlsProcess
	if withExe {
		p, err := discoverProcess(pid)
		if err != nil {
			return err
		}
		proc = p
		defer m.retainProcess(pid)
		done, exeAttached := m.attachExecutable(proc, cgroupID, tlsSymbols)
		if done {
			return nil
		}
		attached = exeAttached
	}

	// 3. Scan all TLS shared libraries in the container filesystem and attach
	// system-wide uprobes. Uses /proc/<pid>/root to access the container's
	// overlay mount: a library's uprobe fires for any process that maps it,
	// in this container or another of the image.
	containerLibs := findContainerTLSLibraries(pid)
	logging.Tracew(m.log, "found container TLS libraries", "pid", pid, "count", len(containerLibs), "libs", containerLibs)

	for _, containerPath := range containerLibs {
		hostPath := fmt.Sprintf("/proc/%d/root%s", pid, containerPath)
		libEx, err := link.OpenExecutable(hostPath)
		if err != nil {
			continue
		}
		file, err := fileIdentity(hostPath)
		if err != nil {
			continue
		}
		for _, sym := range tlsSymbols {
			created, err := m.ensureUprobe(m.libUprobe(libEx, file, sym, progSSLWrite), cgroupID)
			if err != nil {
				continue
			}
			if created {
				m.log.Debugw("Attached uprobe (system-wide)", "pid", pid, "symbol", sym, "lib", containerPath)
			}
			attached = true
		}
	}

	if attached {
		// Try to detect the OpenSSL version and push struct offsets for the
		// XOR-patch path. Non-fatal: if detection fails, the XOR path simply
		// won't activate and the shadow secret is sent as-is (fail-secure).
		m.pushTLSOffsets(pid, cgroupID, containerLibs, withExe)

		// Attach the libcrypto EVP_CipherInit_ex hooks for the libcrypto-hook
		// H-extraction strategy. If libcrypto.so is found and at least one of
		// EVP_CipherInit_ex2 / EVP_CipherInit_ex resolves, write
		// tls_strategy[(cgroup, exe)] = STRATEGY_LIBCRYPTO_HOOK so SSL_write
		// routes through h_extract → cache lookup. Otherwise (BoringSSL,
		// statically linked) leave strategy at 0 (default) — the binary stays
		// on the kprobe-walks-chain path. Without the executable (the
		// container runtime's own, until it runs the container's command),
		// the hooks are attached but the strategy is left to the command's
		// exec event, which knows what the command is (a Bun binary must
		// stay on the kprobe walk).
		if m.attachLibcryptoCipherInit(pid, proc, cgroupID, containerLibs) && proc != nil {
			key := tlsuprobeTlsBinaryKey{CgroupId: cgroupID, ExeInode: proc.exeFile.ino}
			strategyVal := strategyLibcryptoHook
			if err := m.objs.TlsStrategy.Update(&key, &strategyVal, 0); err != nil {
				m.log.Errorw("Failed to set tls_strategy for libcrypto hook",
					"error", err, "pid", pid)
			} else {
				m.log.Debugw("Process on libcrypto-hook H-extraction path",
					"pid", pid)
			}
		}

		// Attach tc egress to the container's eth0 for kernel-only ciphertext
		// patching. Required for secret rewriting.
		if err := m.attachTCEgress(pid, cgroupID); err != nil {
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

// attachExecutable attaches the uprobes for the TLS linked into a process's
// executable: Go crypto/tls, a Bun single-executable, or a statically linked
// OpenSSL, BoringSSL or GnuTLS exporting symbols. done reports an executable
// that carries all of the process's TLS (Go, Bun): its offsets are pushed and
// the pod's tc program attached, and there is nothing else to attach.
// attached reports that symbols were attached in the executable.
//
// The uprobes are process-scoped: the executable is the process's own, and
// a uprobe on a binary in a container's overlay does not fire for the same
// binary seen through another mount.
func (m *TLSUprobeManager) attachExecutable(p *tlsProcess, cgroupID uint64, symbols []string) (done, attached bool) {
	pid := p.pid

	// 1. Try Go crypto/tls (statically linked into the binary).
	goWriteSym := "crypto/tls.(*Conn).Write"
	if created, err := m.ensureUprobe(m.exeUprobe(p, goWriteSym, 0, progGoTLSWrite), cgroupID); err == nil {
		if created {
			m.log.Debugw("Attached Go uprobe", "pid", pid, "symbol", goWriteSym)
		}

		// Push Go-specific struct offsets for H extraction and attach tc egress
		// for ciphertext patching. Both are required for the XOR-patch path.
		// Key by cgroup_id, not PID — the BPF kprobe sees root-NS PIDs and
		// can't look up by our local-NS PID in nested deployments (kind/k3d).
		m.pushGoTLSOffsets(pid, cgroupID)
		if err := m.attachTCEgress(pid, cgroupID); err != nil {
			m.log.Errorw("Failed to attach tc egress for Go TLS — secrets will not be rewritten", "error", err, "pid", pid)
		}
		return true, false
	}

	// 2. Bun single-executable (e.g. Claude Code): detect by version string
	// embedded in the binary ("bun/X.Y.Z") and attach at the pre-computed
	// SSL_write file offset. The binary is symbol-stripped, so the normal
	// symbol-scan below would fail. UprobeOptions.Address bypasses symbol
	// resolution in cilium/ebpf when non-zero (link/uprobe.go:167-169).
	if bunOff, bunVer, ok := DetectBun(p.exePath); ok && bunOff.SSLWriteOffset > 0 {
		created, err := m.ensureUprobe(m.exeUprobe(p, "", bunOff.SSLWriteOffset, progSSLWrite), cgroupID)
		if err == nil {
			if created {
				m.log.Infow("Bun single-executable detected — attached at SSL_write file offset",
					"pid", pid, "version", bunVer,
					"ssl_write_offset", fmt.Sprintf("0x%x", bunOff.SSLWriteOffset))
			}
			// Push BoringSSL chain offsets — Bun statically links BoringSSL and
			// uses the same SSL→s3→aead_write_ctx→AES_KEY walk.
			val := bpfTLSOffsets{
				SSLToVersion:     0xFFFFFFFF,
				SSLToWBIO:        bunOff.BoringSSL.SSLToWBIO,
				TLSLib:           bpfTLSLibBoringSSL,
				BsslSSLToS3:      bunOff.BoringSSL.SSLToS3,
				BsslS3ToAEAD:     bunOff.BoringSSL.S3ToAEAD,
				BsslAEADToAESKey: bunOff.BoringSSL.AEADToAESKey,
			}
			m.pushOffsetVal(val, cgroupID, p.exeFile.ino)
			m.log.Debugw("Pushed BoringSSL offsets for Bun process",
				"pid", pid, "cgroupID", cgroupID, "offsets", fmt.Sprintf("%+v", bunOff.BoringSSL))
			if err := m.attachTCEgress(pid, cgroupID); err != nil {
				m.log.Errorw("Failed to attach tc egress for Bun — secrets will not be rewritten",
					"error", err, "pid", pid)
			}
			return true, false
		}
		m.log.Warnw("Bun detected but SSL_write uprobe failed — falling through to symbol scan",
			"pid", pid, "version", bunVer, "error", err)
	}

	// Try main executable first (statically linked OpenSSL/BoringSSL/GnuTLS).
	for _, sym := range symbols {
		created, err := m.ensureUprobe(m.exeUprobe(p, sym, 0, progSSLWrite), cgroupID)
		if err != nil {
			continue
		}
		if created {
			m.log.Debugw("Attached uprobe to main exe", "pid", pid, "symbol", sym)
		}
		attached = true
	}
	return false, attached
}

// Strategy values must match #defines in pkg/ebpf/bpf/tls_uprobe.c.
const (
	strategyKprobeWalk    uint8 = 0
	strategyLibcryptoHook uint8 = 1
)

// processUsesBoringSSL reports whether any of the process's TLS libraries,
// or its main exe when withExe, is BoringSSL. Used to keep BoringSSL on the
// kprobe-walk H strategy (it must not take the OpenSSL libcrypto-hook path).
func (m *TLSUprobeManager) processUsesBoringSSL(pid int, containerLibs []string, withExe bool) bool {
	paths := containerLibs
	if withExe {
		paths = append([]string{fmt.Sprintf("/proc/%d/exe", pid)}, containerLibs...)
	}
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
// the process's binary as STRATEGY_LIBCRYPTO_HOOK.
//
// Tries two attach points:
//
//  1. The main executable of p (when the attach looks at it), PID-scoped.
//     This catches apps that statically link OpenSSL into the binary — most
//     notably Node.js, which bundles OpenSSL 3.x inside the `node` ELF and
//     exports EVP_CipherInit_ex / _ex2 directly. PID-scoped because the exe
//     is the process's own, and we don't want the hook firing for unrelated
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
func (m *TLSUprobeManager) attachLibcryptoCipherInit(pid int, p *tlsProcess, cgroupID uint64, containerLibs []string) bool {
	// BoringSSL must stay on STRATEGY_KPROBE_WALK. Its libcrypto also exports
	// EVP_CipherInit_ex, but BoringSSL's cipher init does NOT populate the
	// OpenSSL evp_h_cache that h_extract reads, and the OpenSSL provider chain
	// h_extract walks doesn't exist in BoringSSL. Hooking it would set
	// STRATEGY_LIBCRYPTO_HOOK and route SSL_write to h_extract, which bails on
	// ssl_to_wrl==0 — bypassing the kprobe BoringSSL H-walk entirely (the path
	// that recomputes H from the AES round keys). So skip the hook for BoringSSL.
	if m.processUsesBoringSSL(pid, containerLibs, p != nil) {
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
	if p != nil {
		exeAttached := false
		for _, sym := range cipherInitSymbols {
			created, err := m.ensureUprobe(m.exeUprobe(p, sym, 0, progEVPCipherInit), cgroupID)
			if err != nil {
				continue
			}
			if created {
				m.log.Debugw("Attached EVP_CipherInit hooks (main exe, PID-scoped)",
					"pid", pid, "symbol", sym)
			}
			attached = true
			exeAttached = true
		}
		if !exeAttached {
			m.log.Debugw("Main exe has no EVP_CipherInit symbols — likely dynamically links libcrypto",
				"pid", pid)
		}
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
		var file fileKey
		if err == nil {
			file, err = fileIdentity(hostPath)
		}
		if err != nil {
			m.log.Debugw("Failed to open libcrypto for cipher_init attach",
				"pid", pid, "lib", containerPath, "error", err)
			continue
		}
		libAttached := false
		for _, sym := range cipherInitSymbols {
			created, err := m.ensureUprobe(m.libUprobe(libEx, file, sym, progEVPCipherInit), cgroupID)
			if err != nil {
				m.log.Debugw("EVP_CipherInit hook attach failed",
					"pid", pid, "symbol", sym, "lib", containerPath, "error", err)
				continue
			}
			if created {
				m.log.Debugw("Attached EVP_CipherInit hooks (libcrypto.so, system-wide)",
					"pid", pid, "symbol", sym, "lib", containerPath)
			}
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
// Without withExe (the executable is the container runtime's own), only the
// container's libraries are read, and only the cgroup's fallback entry
// (exe_inode 0) is written, which the container's processes use until their
// own executable's is pushed.
func (m *TLSUprobeManager) pushTLSOffsets(pid int, cgroupID uint64, containerLibs []string, withExe bool) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Try the main executable FIRST — if the binary statically links OpenSSL
	// (e.g., Node.js bundles OpenSSL 3.5), its struct offsets differ from the
	// system libssl. The main exe's version takes precedence because the
	// PID-scoped uprobe fires for its SSL_write, not the shared library's.
	// Fall back to shared libraries for dynamically linked apps.
	var exeInode uint64
	paths := containerLibs
	if withExe {
		// Resolve the exe's inode — stat follows the /proc/<pid>/exe symlink to
		// the actual on-disk binary.
		var st syscall.Stat_t
		if err := syscall.Stat(exePath, &st); err != nil {
			m.log.Errorw("Failed to stat exe for TLS offset push", "error", err, "pid", pid)
			return
		}
		exeInode = st.Ino
		paths = append([]string{exePath}, containerLibs...)
	}

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
				OsslAlgctxToGCMKey:    offsets.AlgctxToGCMKey,
				OsslAlgctxToKS:        offsets.AlgctxToKeySched,
				OsslAlgctxToVAESHKey1: offsets.AlgctxToVAESHKey1,
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
	// OpenSSL GCM gate + AVX-512 HashKey_1 recovery (see ossl_read_gcm_h).
	OsslAlgctxToGCMKey    uint32
	OsslAlgctxToKS        uint32
	OsslAlgctxToVAESHKey1 uint32
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
// and a node with many kloak pods holds hundreds of uprobes (the link
// registry, the pods' tc programs); closing serially blows past kubelet's
// terminationGracePeriodSeconds and the pod is SIGKILL'd before the Go
// runtime gets to flush exit hooks (which lost us the e2e covcounters
// flush, among other things). Close concurrently with a bounded worker
// pool so wall time stays inside the grace period.
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
	// Links no longer needed may still be detaching (detachAsync). They
	// are no longer in the registry, so this is the only wait for them.
	detached := make(chan struct{})
	go func() {
		m.detachWG.Wait()
		close(detached)
	}()
	select {
	case <-detached:
	case <-time.After(10 * time.Second):
		m.log.Warnw("timed out waiting for released links to detach; proceeding with teardown")
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
	links = append(links, m.registry.drain()...)
	m.tcMu.Lock()
	for ino, e := range m.podTC {
		e.mu.Lock()
		e.released = true
		for _, l := range e.links {
			links = append(links, l)
		}
		e.links = nil
		if e.netnsFd != nil {
			links = append(links, e.netnsFd)
			e.netnsFd = nil
		}
		e.mu.Unlock()
		delete(m.podTC, ino)
	}
	m.tcMu.Unlock()
	m.dnsRewriteMu.Lock()
	for uid, a := range m.dnsRewrite {
		links = append(links, a.links...)
		links = append(links, a.netns)
		delete(m.dnsRewrite, uid)
	}
	m.dnsRewriteMu.Unlock()

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
	jobs := make(chan io.Closer, workers)
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
	stop := closeOnDone(ctx, m.procReader)
	defer stop()
	for {
		record, err := m.procReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
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

// closeOnDone closes r once ctx is done, the only way to stop a Read that
// blocks until a record comes in. Close closes it again, which does nothing.
// The returned function cancels it.
func closeOnDone(ctx context.Context, r *ringbuf.Reader) (stop func() bool) {
	return context.AfterFunc(ctx, func() { _ = r.Close() })
}

// PollEvents logs the secret-binding violations reported by the data plane
// until ctx is done, and with trace logging the BPF debug counters every
// 5 s. Secrets are synced to the eBPF maps by SyncSecrets.
func (m *TLSUprobeManager) PollEvents(ctx context.Context) error {
	m.log.Infow("Starting eBPF binding-violation reader")

	// The counters are only logged at trace level.
	var counters sync.WaitGroup
	defer counters.Wait()
	if m.log.Desugar().Core().Enabled(logging.TraceLevel) {
		counters.Go(func() {
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					m.DumpDebugCounters()
				}
			}
		})
	}

	stop := closeOnDone(ctx, m.reader)
	defer stop()
	for {
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			m.log.Errorw("reading from ringbuf", "error", err)
			continue
		}

		var event secretBindingEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &event); err != nil {
			m.log.Errorw("failed to parse secret binding event", "error", err)
			continue
		}
		m.logBindingViolation(&event)
	}
}

// dnsIPKey matches C struct dns_ip_key (16-byte IPv4-mapped-IPv6).
type dnsIPKey struct {
	IP [16]byte
}

// PopulateTrustedDNSServers makes trusted_dns_servers hold exactly ips, and
// enables the whitelist: only answers from them are believed (none when ips
// is empty). Servers that went away (a replaced CoreDNS pod) are removed.
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

	want := make(map[dnsIPKey]bool, len(ips))
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
		want[key] = true
		if err := m.objs.TrustedDnsServers.Update(&key, &val, 0); err != nil {
			return fmt.Errorf("adding trusted DNS server %s: %w", ip, err)
		}
	}
	var stale []dnsIPKey
	var k dnsIPKey
	var v uint8
	iter := m.objs.TrustedDnsServers.Iterate()
	for iter.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("reading trusted DNS servers: %w", err)
	}
	for i := range stale {
		if err := m.objs.TrustedDnsServers.Delete(&stale[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("removing trusted DNS server %s: %w", netip.AddrFrom16(stale[i].IP).Unmap(), err)
		}
	}

	m.log.Infow("DNS server whitelist enabled", "count", len(ips), "removed", len(stale))
	return nil
}

// SyncSecrets makes the eBPF maps hold the secret source's current secrets:
// secret_map, the virtual IPs of their hosts, and the pod bindings over them
// (secret_acl, vip_pod_host). A failed snapshot leaves the maps as they
// were. A failed map operation does not stop the others; the error reports
// it, and a retry completes the maps.
func (m *TLSUprobeManager) SyncSecrets(ctx context.Context) error {
	if m.secretSource == nil {
		return nil
	}
	snapshot, err := m.secretSource.Snapshot(ctx)
	if err != nil {
		// Pruning against a failed snapshot would drop every secret.
		return fmt.Errorf("snapshot secrets: %w", err)
	}
	hosts, secretsErr := applySecrets(m.objs.SecretMap, snapshot, m.log)
	var vipErr error
	if m.virtualIPs != nil {
		vipErr = m.virtualIPs.sync(hosts, time.Now())
	}

	m.bindMu.Lock()
	defer m.bindMu.Unlock()
	m.lastSnapshot = snapshot
	aclErr := syncSecretACL(m.objs.SecretAcl, snapshot, m.bindings, m.log)
	var podHostErr error
	if m.virtualIPs != nil {
		podHostErr = syncVipPodHost(m.objs.VipPodHost, vipPodHosts(snapshot, m.bindings, m.bindingMode == SecretBindingAudit), m.log)
	}
	return errors.Join(secretsErr, vipErr, aclErr, podHostErr)
}

// SetSecretBindingMode configures what the data plane does when a process
// redeems a placeholder of a secret its pod does not reference. The BPF
// default (an unwritten map) is enforce, so a failed write fails closed.
func (m *TLSUprobeManager) SetSecretBindingMode(mode SecretBindingMode) {
	m.bindMu.Lock()
	m.bindingMode = mode
	m.bindMu.Unlock()
	key, val := uint32(0), mode.bpfValue()
	if err := m.objs.SecretBindingMode.Update(&key, &val, ebpf.UpdateAny); err != nil {
		m.log.Errorw("failed to set secret binding mode; enforcing", "mode", mode, "error", err)
	}
}

// SetSNICheckMode configures what the data plane does when a secret
// restricted to a hostname is written on a connection whose ClientHello did
// not name that host. The BPF default (an unwritten map) is enforce, so a
// failed write fails closed.
func (m *TLSUprobeManager) SetSNICheckMode(mode SNICheckMode) {
	key, val := uint32(0), mode.bpfValue()
	if err := m.objs.SniCheckMode.Update(&key, &val, ebpf.UpdateAny); err != nil {
		m.log.Errorw("failed to set SNI check mode; enforcing", "mode", mode, "error", err)
	}
}

// BindPodSecrets records which secrets a pod may redeem and grants them to
// its container cgroups at once, so the pod's first TLS writes are rewritten.
// It also lets the pod at podIPs (its network, which
// exists before its containers do) get the fake IPs of those secrets'
// hosts. It replaces any previous binding for the pod: addresses, cgroups
// or references that went away are revoked at once. podUID keys the
// binding; pod (namespace/name) is only used in logs.
func (m *TLSUprobeManager) BindPodSecrets(podUID, pod string, podIPs []netip.Addr, cgroupIDs []uint64, refs []secrets.Ref) {
	m.bindMu.Lock()
	defer m.bindMu.Unlock()
	m.bindLocked(podUID, &podBinding{pod: pod, podIPs: podIPs, cgroupIDs: cgroupIDs, refs: refs})
}

// BindPodNetwork is BindPodSecrets for a pod whose containers may not exist
// yet (its sandbox is being created): it keeps the container cgroups of the
// pod's current binding, if any, and replaces its addresses and references.
func (m *TLSUprobeManager) BindPodNetwork(podUID, pod string, podIPs []netip.Addr, refs []secrets.Ref) {
	m.bindMu.Lock()
	defer m.bindMu.Unlock()
	m.bindLocked(podUID, &podBinding{pod: pod, podIPs: podIPs, cgroupIDs: m.bindings[podUID].cgroupIDs, refs: refs})
}

// BindPodContainer adds a container's cgroup to a pod's binding, for a
// container the container runtime is about to start, which the pod's
// status does not list yet: its writes redeem the pod's secrets from the
// first one. It keeps the binding's other cgroups and its addresses (podIPs
// when it has none yet), and replaces its references.
func (m *TLSUprobeManager) BindPodContainer(podUID, pod string, podIPs []netip.Addr, cgroupID uint64, refs []secrets.Ref) {
	m.bindMu.Lock()
	defer m.bindMu.Unlock()
	cur := m.bindings[podUID]
	if len(cur.podIPs) > 0 {
		podIPs = cur.podIPs
	}
	cgroupIDs := cur.cgroupIDs
	if !slices.Contains(cgroupIDs, cgroupID) {
		cgroupIDs = append(slices.Clone(cgroupIDs), cgroupID)
	}
	m.bindLocked(podUID, &podBinding{pod: pod, podIPs: podIPs, cgroupIDs: cgroupIDs, refs: refs})
}

// bindLocked records b as podUID's binding, grants it, and revokes what the
// pod's previous binding granted that b does not; the caller holds bindMu.
func (m *TLSUprobeManager) bindLocked(podUID string, b *podBinding) {
	pod := b.pod
	prev, rebind := m.bindings[podUID]
	m.bindings[podUID] = *b

	allowed := uint8(1)
	single := map[string]podBinding{podUID: *b}
	acl := secretACL(m.lastSnapshot, single)
	for key := range acl {
		if err := m.objs.SecretAcl.Update(&key, &allowed, ebpf.UpdateAny); err != nil {
			m.log.Errorw("failed to grant secret binding", "error", err, "pod", pod, "cgroupID", key.CgroupID)
		}
	}
	var podHosts map[vipPodHostKey]struct{}
	if m.virtualIPs != nil {
		podHosts = vipPodHosts(m.lastSnapshot, single, m.bindingMode == SecretBindingAudit)
		for key := range podHosts {
			if err := m.objs.VipPodHost.Update(&key, &allowed, ebpf.UpdateAny); err != nil {
				m.log.Errorw("failed to grant the pod its hosts' virtual IPs", "error", err, "pod", pod)
			}
		}
	}
	if rebind {
		m.revokeLostLocked(&prev, acl, podHosts)
	}
}

// revokeLostLocked revokes what a pod's previous binding prev granted and
// its new one, which grants acl and podHosts, does not: the cgroup of a
// container that restarted, a reference or an address that went away. What
// another binding grants is kept (an address a new pod already holds). The
// caller holds bindMu.
func (m *TLSUprobeManager) revokeLostLocked(prev *podBinding, acl map[secretACLKey]struct{}, podHosts map[vipPodHostKey]struct{}) {
	single := map[string]podBinding{"": *prev}
	var lostACL []secretACLKey
	for key := range secretACL(m.lastSnapshot, single) {
		if _, ok := acl[key]; !ok {
			lostACL = append(lostACL, key)
		}
	}
	var lostHosts []vipPodHostKey
	if m.virtualIPs != nil {
		for key := range vipPodHosts(m.lastSnapshot, single, m.bindingMode == SecretBindingAudit) {
			if _, ok := podHosts[key]; !ok {
				lostHosts = append(lostHosts, key)
			}
		}
	}

	// Most rebinds change nothing: only then look at every binding.
	if len(lostACL) > 0 {
		kept := secretACL(m.lastSnapshot, m.bindings)
		for i := range lostACL {
			if _, ok := kept[lostACL[i]]; ok {
				continue
			}
			if err := m.objs.SecretAcl.Delete(&lostACL[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				m.log.Errorw("failed to revoke secret binding", "error", err, "pod", prev.pod, "cgroupID", lostACL[i].CgroupID)
			}
		}
	}
	if len(lostHosts) > 0 {
		kept := vipPodHosts(m.lastSnapshot, m.bindings, m.bindingMode == SecretBindingAudit)
		for i := range lostHosts {
			if _, ok := kept[lostHosts[i]]; ok {
				continue
			}
			if err := m.objs.VipPodHost.Delete(&lostHosts[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				m.log.Errorw("failed to remove a pod's virtual IP host", "error", err, "pod", prev.pod,
					"podIP", netip.AddrFrom16(lostHosts[i].PodIP).Unmap().String())
			}
		}
	}
}

// UnbindPod revokes everything a pod could redeem, immediately.
func (m *TLSUprobeManager) UnbindPod(podUID string) {
	m.bindMu.Lock()
	defer m.bindMu.Unlock()
	b, ok := m.bindings[podUID]
	if !ok {
		return
	}
	delete(m.bindings, podUID)

	podCgroups := make(map[uint64]struct{}, len(b.cgroupIDs))
	for _, cg := range b.cgroupIDs {
		podCgroups[cg] = struct{}{}
	}
	var stale []secretACLKey
	var k secretACLKey
	var v uint8
	iter := m.objs.SecretAcl.Iterate()
	for iter.Next(&k, &v) {
		if _, ok := podCgroups[k.CgroupID]; ok {
			stale = append(stale, k)
		}
	}
	if err := iter.Err(); err != nil {
		m.log.Errorw("error iterating BPF secret_acl", "error", err, "pod", b.pod)
	}
	for i := range stale {
		if err := m.objs.SecretAcl.Delete(&stale[i]); err != nil {
			m.log.Errorw("failed to revoke secret binding", "error", err, "pod", b.pod)
		}
	}
	// The pod's address may already belong to a new pod: keep what the
	// remaining bindings grant.
	if m.virtualIPs != nil && len(b.podIPs) > 0 {
		// Failures are logged entry by entry, and the next secret sync
		// prunes what is left.
		_ = syncVipPodHost(m.objs.VipPodHost, vipPodHosts(m.lastSnapshot, m.bindings, m.bindingMode == SecretBindingAudit), m.log)
	}
}

// bindingLogInterval bounds how often the same (cgroup, placeholder)
// violation is logged.
const bindingLogInterval = time.Minute

// logBindingViolation reports a placeholder redeemed outside its binding,
// or on a connection whose SNI is not the secret's host.
func (m *TLSUprobeManager) logBindingViolation(ev *secretBindingEvent) {
	key := bindingLogKey{
		acl:       secretACLKey{CgroupID: ev.CgroupID, Key: ev.Key},
		reason:    ev.Reason,
		sniStatus: ev.SNIStatus,
	}
	now := time.Now()

	m.bindMu.Lock()
	if last, ok := m.bindingLogged[key]; ok && now.Sub(last) < bindingLogInterval {
		m.bindMu.Unlock()
		return
	}
	m.bindingLogged[key] = now
	for k, at := range m.bindingLogged {
		if now.Sub(at) >= bindingLogInterval {
			delete(m.bindingLogged, k)
		}
	}
	pod, secret := describeBindingEvent(ev, m.bindings, m.lastSnapshot)
	m.bindMu.Unlock()

	if ev.Reason == secretEventSNI {
		m.logSNIViolation(ev, pod, secret)
		return
	}

	if ev.Audit == 1 {
		m.log.Warnw("secret binding violation (audit mode, rewrite allowed): pod used a secret it does not reference",
			"pod", pod, "secret", secret, "tgid", ev.Tgid, "cgroupID", ev.CgroupID)
		return
	}
	m.log.Warnw("secret binding violation (rewrite refused): pod used a secret it does not reference",
		"pod", pod, "secret", secret, "tgid", ev.Tgid, "cgroupID", ev.CgroupID)
}

// logSNIViolation reports a host-restricted secret written on a connection
// whose ClientHello did not name the host (spinningfactory/kloak#328).
func (m *TLSUprobeManager) logSNIViolation(ev *secretBindingEvent, pod, secret string) {
	reason, sni := describeSNIEvent(ev)
	fields := []any{"pod", pod, "secret", secret, "reason", reason, "sni", sni,
		"tgid", ev.Tgid, "cgroupID", ev.CgroupID}
	if ev.MemoryBIO == 1 {
		// Memory-BIO writers (Node.js, Bun) are matched to a socket by the
		// next tcp_sendmsg of the process, which may belong to another
		// connection; the write is retried on its own socket.
		fields = append(fields, "note", "memory-BIO process: the refused socket may be another connection of the same process")
	}
	if ev.Audit == 1 {
		m.log.Warnw("SNI check violation (audit mode, rewrite allowed): connection's TLS SNI is not the secret's host", fields...)
		return
	}
	m.log.Warnw("SNI check violation (rewrite refused): connection's TLS SNI is not the secret's host", fields...)
}

// debugCounterNames maps index to human-readable name (must match C enum in
// pkg/ebpf/bpf/tls_uprobe.c — DBG_* constants).
var debugCounterNames = []string{
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
	"openssl_gcm_gate_fail", "openssl_h_from_hkey1",
	"secret_binding_deny", "secret_binding_audit",
	"sni_captured", "sni_deny", "sni_audit",
	"vip_dns_rewritten", "vip_dns_unchanged", "vip_connect_redirect", "vip_connect_refused",
	"vip_dns_unbound", "vip_sock_host_deny", "vip_sock_addr_deny",
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

	// BoringSSL H-walk diagnostic capture (last walk + offset scan). Only
	// filled by KLOAK_DEBUG (BPF_DEBUG=1) builds; AEAD stays 0 otherwise.
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
