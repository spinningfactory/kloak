package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	"github.com/go-logr/logr"
	"golang.org/x/sys/unix"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/spinningfactory/kloak/pkg/storage"
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
	Port        uint16  // 0 = wildcard, otherwise port number (host byte order)
	Protocol    uint8   // IPPROTO_TCP (6) = TCP, IPPROTO_UDP (17) = UDP
	_           [1]byte // padding to align PrefixLen (uint32)
	PrefixLen   uint32
	FullPrefix  [42]byte // SECRET_PREFIX_MAX
	_           [2]byte  // trailing padding to match C struct alignment
}

// watchedHostKey matches C struct watched_host_key
type watchedHostKey struct {
	Host [64]byte
}

// Generate eBPF bindings. The KLOAK_TARGET_ARCH env var (set by Dockerfile or
// Makefile) controls which __TARGET_ARCH_xxx define is passed to clang.
// Defaults to arm64 for local development on macOS/Lima.
//go:generate sh -c "ARCH=${KLOAK_TARGET_ARCH:-arm64}; go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags \"-O2 -g -Wall -Werror -D__TARGET_ARCH_${ARCH}\" tlsuprobe bpf/tls_uprobe.c -- -I../ebpf"

// TLSUprobeManager manages the loading and attaching of eBPF uprobes for TLS interception.
type TLSUprobeManager struct {
	objs       *tlsuprobeObjects
	reader     *ringbuf.Reader
	procReader *ringbuf.Reader
	log        logr.Logger
	links      []link.Link

	// store provides access to secrets
	store storage.Storage
	// cgroupRoot is the path to the cgroup v2 filesystem (e.g. /sys/fs/cgroup)
	cgroupRoot string
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
}

// tcAttachEntry holds an open fd to a network namespace to prevent inode reuse.
type tcAttachEntry struct {
	netnsFd *os.File // kept open to pin the inode
}

// setupCgroupAncestor finds the kubepods cgroup directory and stores its fd
// in the BPF cgroup_ancestor map. This enables bpf_current_task_under_cgroup()
// in the exec tracepoint to catch all container execs without per-container
// cgroup tracking.
func setupCgroupAncestor(objs *tlsuprobeObjects, cgroupRoot string, log logr.Logger) error {
	// Find the kubepods cgroup directory. Strategy:
	// 1. Try well-known direct paths
	// 2. Walk the cgroup tree
	// 3. Derive from the controller's own cgroup path (/proc/self/cgroup)
	//    since the controller runs under kubepods
	candidates := []string{
		filepath.Join(cgroupRoot, "kubepods.slice"),
		filepath.Join(cgroupRoot, "kubepods"),
	}

	// Walk the tree to handle nested cgroups (k3d/Docker)
	_ = filepath.WalkDir(cgroupRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == "kubepods" || name == "kubepods.slice" {
			candidates = append([]string{path}, candidates...)
			return filepath.SkipAll
		}
		return nil
	})

	// Derive from controller's own cgroup — the controller itself runs
	// under kubepods, so we can find it from /proc/self/cgroup
	if selfCgroup, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(selfCgroup), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[0] == "0" {
				// Find the kubepods ancestor in the path
				cgPath := parts[2]
				for _, marker := range []string{"/kubepods.slice", "/kubepods"} {
					if idx := strings.Index(cgPath, marker); idx >= 0 {
						ancestorPath := filepath.Join(cgroupRoot, cgPath[:idx+len(marker)])
						candidates = append([]string{ancestorPath}, candidates...)
					}
				}
			}
		}
	}

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
		log.Info("Configured cgroup ancestor for exec tracepoint", "path", path)
		return nil
	}

	// List top-level entries to help diagnose cgroup layout
	var topLevel []string
	if entries, err := os.ReadDir(cgroupRoot); err == nil {
		for _, e := range entries {
			topLevel = append(topLevel, e.Name())
		}
	}
	log.Error(nil, "kubepods cgroup not found — exec tracepoint will not detect container processes",
		"cgroupRoot", cgroupRoot, "candidates", candidates, "topLevelDirs", topLevel)
	return fmt.Errorf("kubepods cgroup not found in %s", cgroupRoot)
}

// NewTLSUprobeManager initializes a new uprobe manager.
func NewTLSUprobeManager(store storage.Storage, cgroupRoot string) (*TLSUprobeManager, error) {
	log := ctrl.Log.WithName("ebpf-uprobe")

	objs := &tlsuprobeObjects{}
	if err := loadTlsuprobeObjects(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 1 << 20, // 1 MB
			LogLevel:     ebpf.LogLevelBranch,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Print only the error summary (includes rejection reason).
			// The full verifier log can be 100K+ lines and overflows container log buffers.
			log.Error(err, "eBPF verifier rejected program")
		} else {
			log.Error(err, "eBPF loading failed (not a verifier error, check dmesg)",
				"error_type", fmt.Sprintf("%T", err))
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
		log.Error(err, "failed to setup cgroup ancestor — exec tracepoint will not catch initial container processes")
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
		objs:       objs,
		reader:     reader,
		procReader: procReader,
		log:        log,
		store:      store,
		cgroupRoot: cgroupRoot,
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
		m.links = append(m.links, l)
		m.log.Info("Attached tracepoint", "group", t.group, "name", t.name)
	}

	// Attach kprobe/kretprobe on udp_recvmsg for language-agnostic DNS interception.
	kp, err := link.Kprobe("udp_recvmsg", m.objs.KprobeUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe udp_recvmsg: %w", err)
	}
	m.links = append(m.links, kp)
	m.log.Info("Attached kprobe", "function", "udp_recvmsg")

	krp, err := link.Kretprobe("udp_recvmsg", m.objs.KretprobeUdpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe udp_recvmsg: %w", err)
	}
	m.links = append(m.links, krp)
	m.log.Info("Attached kretprobe", "function", "udp_recvmsg")

	// Attach kprobe on tcp_sendmsg to bridge xor_pending → tc_pending.
	// This runs after SSL_write encrypts and calls write/send, giving us
	// access to the struct sock (source port) for per-connection keying.
	tkp, err := link.Kprobe("tcp_sendmsg", m.objs.BpfKprobeTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe tcp_sendmsg: %w", err)
	}
	m.links = append(m.links, tkp)
	m.log.Info("Attached kprobe", "function", "tcp_sendmsg")

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
	netnsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	if fi, err := os.Stat(netnsPath); err == nil {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			if _, loaded := m.tcAttached.Load(stat.Ino); loaded {
				m.log.V(1).Info("tc egress already attached for this netns", "pid", pid, "netns_ino", stat.Ino)
				return nil
			}
		}
	}

	// Open the netns fd for two purposes:
	// 1. setns to enter the container's network namespace
	// 2. Keep it open (stored in tcAttached) to pin the inode
	containerNS, err := os.Open(netnsPath)
	if err != nil {
		return fmt.Errorf("opening container netns %s: %w", netnsPath, err)
	}
	// NOTE: containerNS is NOT closed here — it's stored in tcAttachEntry
	// to pin the netns inode. Closed in UntrackCgroup when the pod is deleted.

	// Save our current network namespace.
	selfNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		_ = containerNS.Close()
		return fmt.Errorf("opening self netns: %w", err)
	}
	defer func() { _ = selfNS.Close() }()

	// Lock OS thread — setns is per-thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Switch to the container's network namespace.
	if err := unix.Setns(int(containerNS.Fd()), unix.CLONE_NEWNET); err != nil {
		_ = containerNS.Close()
		return fmt.Errorf("setns to container netns: %w", err)
	}

	// Ensure we return to our original netns.
	defer func() {
		if err := unix.Setns(int(selfNS.Fd()), unix.CLONE_NEWNET); err != nil {
			m.log.Error(err, "failed to restore original netns")
		}
	}()

	// Attach tc egress to both eth0 (external) and lo (intra-pod loopback).
	for _, ifName := range []string{"eth0", "lo"} {
		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			// lo should always exist; eth0 might not in some setups.
			if ifName == "lo" {
				_ = containerNS.Close()
				return fmt.Errorf("finding %s in container netns: %w", ifName, err)
			}
			m.log.V(1).Info("interface not found, skipping", "pid", pid, "interface", ifName)
			continue
		}

		tcLink, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   m.objs.TcEgressPatch,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			_ = containerNS.Close()
			return fmt.Errorf("attaching tc egress to %s (ifindex %d) in pid %d netns: %w", ifName, iface.Index, pid, err)
		}
		m.links = append(m.links, tcLink)
		m.log.Info("Attached tc egress to container", "pid", pid, "interface", ifName, "ifindex", iface.Index)
	}

	// Store the open netns fd keyed by inode. The open fd pins the inode —
	// the kernel won't reuse it until we close the fd in UntrackCgroup.
	if fi, err := os.Stat(netnsPath); err == nil {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			m.tcAttached.Store(stat.Ino, &tcAttachEntry{netnsFd: containerNS})
		}
	}
	return nil
}

// TrackTGID adds a process TGID to the tracked_tgids map, enabling
// DNS/connect tracepoint processing for that process.
func (m *TLSUprobeManager) TrackTGID(tgid uint32) error {
	val := uint8(1)
	return m.objs.TrackedTgids.Update(tgid, &val, 0)
}

// UntrackTGID removes a process TGID from the tracked_tgids map.
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

	return m.objs.TrackedCgroups.Delete(cgroupID)
}

// AttachTLS attaches system-wide eBPF uprobes to all TLS libraries in a
// container. The uprobes fire for ALL processes in the container (same overlay
// mount = same inode). The BPF cgroup filter restricts interception to tracked
// containers only.
func (m *TLSUprobeManager) AttachTLS(pid int) error {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	// Register the process for DNS/connect tracking.
	if err := m.TrackTGID(uint32(pid)); err != nil {
		m.log.Error(err, "failed to track TGID for DNS/connect", "pid", pid)
	} else {
		m.log.Info("Tracking TGID for DNS/connect verification", "pid", pid)
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
		m.log.Info("Attached Go uprobe", "pid", pid, "symbol", goWriteSym)
		m.links = append(m.links, up)
		return nil
	}

	// 2. Scan all TLS shared libraries in the container filesystem and attach
	// system-wide uprobes. Uses /proc/<pid>/root to access the container's
	// overlay mount — all processes in the same container share the same
	// overlay inode, so the uprobe fires for any of them.
	sslSymbols := []string{"SSL_write", "SSL_write_ex"}
	gnutlsSymbols := []string{"gnutls_record_send", "gnutls_record_send2"}
	attached := false

	// Try main executable first (statically linked OpenSSL/BoringSSL/GnuTLS).
	// Use PID-scoped because the main exe is unique per container.
	for _, sym := range append(sslSymbols, gnutlsSymbols...) {
		if up, err := ex.Uprobe(sym, m.objs.BpfUprobeSslWrite, &link.UprobeOptions{PID: pid}); err == nil {
			m.log.Info("Attached uprobe to main exe", "pid", pid, "symbol", sym)
			m.links = append(m.links, up)
			attached = true
		}
	}

	// Scan container filesystem for all TLS shared libraries
	containerLibs := findContainerTLSLibraries(pid)
	m.log.Info("Found container TLS libraries", "pid", pid, "count", len(containerLibs), "libs", containerLibs)

	for _, containerPath := range containerLibs {
		hostPath := fmt.Sprintf("/proc/%d/root%s", pid, containerPath)
		libEx, err := link.OpenExecutable(hostPath)
		if err != nil {
			continue
		}
		for _, sym := range append(sslSymbols, gnutlsSymbols...) {
			if up, err := libEx.Uprobe(sym, m.objs.BpfUprobeSslWrite, nil); err == nil {
				m.log.Info("Attached uprobe (system-wide)", "pid", pid, "symbol", sym, "lib", containerPath)
				m.links = append(m.links, up)
				attached = true
			}
		}
	}

	if attached {
		// Try to detect the OpenSSL version and push struct offsets for the
		// XOR-patch path. Non-fatal: if detection fails, the XOR path simply
		// won't activate and the shadow secret is sent as-is (fail-secure).
		m.pushTLSOffsets(pid, containerLibs)

		// Attach tc egress to the container's eth0 for kernel-only ciphertext
		// patching. Required for secret rewriting.
		if err := m.attachTCEgress(pid); err != nil {
			m.log.Error(err, "Failed to attach tc egress to container — secrets will not be rewritten", "pid", pid)
		}

		return nil
	}
	return fmt.Errorf("could not find compatible TLS symbols for PID %d", pid)
}

// pushTLSOffsets detects the OpenSSL version in the container's TLS libraries
// and pushes struct offsets to the tls_offset_config BPF map. This enables the
// XOR-patch path for TLS 1.3 AES-GCM connections.
func (m *TLSUprobeManager) pushTLSOffsets(pid int, containerLibs []string) {
	for _, libPath := range containerLibs {
		version, offsets, err := DetectOpenSSLVersion(pid, libPath)
		if err != nil {
			m.log.V(1).Info("OpenSSL version detection skipped", "lib", libPath, "reason", err)
			continue
		}

		// Push offsets to the BPF config map.
		// Must match struct tls_offsets in tls_uprobe.c.
		type bpfTLSOffsets struct {
			SSLToWRL       uint32
			WRLToEncCtx    uint32
			EncCtxToAlgctx uint32
			AlgctxToH      uint32
		}
		val := bpfTLSOffsets(offsets)
		if err := m.objs.TlsOffsetConfig.Update(uint32(0), &val, 0); err != nil {
			m.log.Error(err, "Failed to push TLS offsets to BPF map")
			continue
		}

		m.log.Info("Pushed TLS offsets for XOR-patch path",
			"lib", libPath, "version", version,
			"offsets", fmt.Sprintf("%+v", offsets))
		return // Only need one successful push.
	}
}

// findContainerTLSLibraries scans common library directories in the container's
// root filesystem for all TLS libraries. Returns container-relative paths
// (e.g., "/usr/lib/aarch64-linux-gnu/libssl.so.3").
func findContainerTLSLibraries(pid int) []string {
	rootPrefix := fmt.Sprintf("/proc/%d/root", pid)
	libDirs := []string{"/usr/lib", "/lib", "/usr/local/lib"}

	seen := make(map[string]bool)
	var libs []string

	addIfTLS := func(hostPath string) {
		if isTLSLibrary(filepath.Base(hostPath)) && !seen[hostPath] {
			seen[hostPath] = true
			libs = append(libs, strings.TrimPrefix(hostPath, rootPrefix))
		}
	}

	for _, dir := range libDirs {
		hostDir := rootPrefix + dir
		entries, err := os.ReadDir(hostDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			fullPath := filepath.Join(hostDir, e.Name())
			if e.IsDir() {
				archEntries, err := os.ReadDir(fullPath)
				if err != nil {
					continue
				}
				for _, ae := range archEntries {
					if !ae.IsDir() {
						addIfTLS(filepath.Join(fullPath, ae.Name()))
					}
				}
			} else {
				addIfTLS(fullPath)
			}
		}
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
func (m *TLSUprobeManager) Close() error {
	var errs []error
	for _, l := range m.links {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	m.links = nil

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
	if len(errs) > 0 {
		return fmt.Errorf("errors closing uprobe manager: %v", errs)
	}
	return nil
}

// PollExecEvents reads process exec events from the proc_events ring buffer
// and attaches TLS uprobes to newly exec'd processes in tracked containers.
func (m *TLSUprobeManager) PollExecEvents(ctx context.Context) error {
	m.log.Info("Starting process exec event poller")
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
			m.log.Error(err, "reading from proc events ringbuf")
			continue
		}

		var event procEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			m.log.Error(err, "failed to parse proc event")
			continue
		}

		if event.Type == 1 { // exec
			// Only attach to processes whose cgroup was explicitly registered by
			// the controller via TrackCgroup (i.e. kloak-enabled pods).
			// sched_process_exec fires for ALL kubepods containers; without this
			// guard, AttachTLS would attach tc egress to non-kloak pods and
			// corrupt their outbound TLS (wrong H key → bad GHASH tag).
			if _, ok := m.cgroupPaths.Load(event.CgroupID); !ok {
				m.log.V(1).Info("exec in untracked cgroup, skipping", "tgid", event.Tgid, "cgroupID", event.CgroupID)
				continue
			}
			m.log.Info("Detected exec in tracked container, attaching uprobes", "tgid", event.Tgid, "cgroupID", event.CgroupID)
			if err := m.AttachTLS(int(event.Tgid)); err != nil {
				// libssl may not be loaded yet (e.g. Python hasn't imported ssl).
				// Retry after a delay to catch lazy-loaded libraries.
				m.log.V(1).Info("first attach attempt failed, scheduling retry", "tgid", event.Tgid, "err", err)
				go func(tgid uint32) {
					time.Sleep(2 * time.Second)
					if err := m.AttachTLS(int(tgid)); err != nil {
						m.log.V(1).Info("retry attach also failed", "tgid", tgid, "err", err)
					}
				}(event.Tgid)
			}
		}
	}
}

// PollEvents reads TLS events from the ring buffer and periodically syncs secrets to the eBPF map.
func (m *TLSUprobeManager) PollEvents(ctx context.Context) error {
	m.log.Info("Starting eBPF TLS event poller and secret syncer")

	// Trigger an initial sync
	m.syncSecretsToBPF()

	// Periodic re-sync ticker. The initial sync may have found an empty store
	// (secret reconciler hasn't run yet), so we must keep re-syncing.
	syncTicker := time.NewTicker(5 * time.Second)
	defer syncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-syncTicker.C:
			m.syncSecretsToBPF()
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
			m.log.Error(err, "reading from ringbuf")
			continue
		}

		var event tlsEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			m.log.Error(err, "failed to parse ringbuf event")
			continue
		}

		if event.IsRewritten == 1 {
			m.log.Info("REWRITE SUCCESS: eBPF synchronously rewrote a secret", "pid", event.Pid)
		} else {
			m.log.V(2).Info("Intercepted TLS packet (no rewrite)", "pid", event.Pid, "len", event.Len)
		}
	}
}

// syncSecretsToBPF updates the eBPF map with the latest shadow secret values
// and the watched_hosts map with hostnames from secret entries.
func (m *TLSUprobeManager) syncSecretsToBPF() {
	if err := syncSecrets(m.objs.SecretMap, m.objs.WatchedHosts, m.store, m.log); err != nil {
		m.log.Error(err, "failed to sync secrets to BPF map")
	}
}

// debugCounterNames maps index to human-readable name (must match C enum).
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
	"tc_skip_reclen", "tc_skip_load", "tc_skip_store", "tc_skip_nontls",
	"tc_no_tail", "tc_empty", "tc_no_entry",
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
			m.log.Info("eBPF debug counter", "name", name, "count", total)
		}
	}
}
