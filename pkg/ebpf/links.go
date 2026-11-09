//go:build linux

package ebpf

// Link registry (spinningfactory/kloak#107, Phase 0).
//
// Every uprobe kloak attaches is recorded here under a key that says what the
// kernel attached it to, so a uprobe is attached once however many times the
// attach paths (AttachTLS from the pod reconciler, AttachContainerTLS from
// NRI, the exec event poller and its retries) discover it, and detached once
// nothing needs it any more:
//
//   - A process-scoped uprobe (on a process's executable: Go crypto/tls, a
//     Bun binary, a statically linked OpenSSL) is keyed by the process (PID
//     and start time, so a reused PID is another process), the executable,
//     the symbol or file offset and the program. It is detached when the
//     process exits (sweepDeadProcesses), when the process runs another
//     executable (retainProcess), or with its container.
//   - A library uprobe fires for every process that maps the library, so it
//     is keyed by the library's file as the kernel's uprobe is (fileIdentity:
//     containers of one image share it), the symbol and the program, and is
//     shared by the containers that need it: it is detached when the last of
//     them is untracked (releaseCgroup).
//
// The tc patch programs are recorded per pod network namespace (podTC in
// uprobe.go), under tcLinkKey, and checked against the kernel (tcLinkLive)
// before kloak relies on one.
//
// Every uprobe is pinned under its key (uprobePinName, Phase 1), so that it
// stays attached across controller restarts: the next controller adopts the
// pins (adopt), its reconciliation claims the uprobes the containers still
// need, and the others are detached (releaseUnclaimed).

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// uprobeProg is the program a uprobe runs.
type uprobeProg uint8

const (
	progSSLWrite      uprobeProg = iota + 1 // bpf_uprobe_ssl_write
	progGoTLSWrite                          // bpf_uprobe_go_tls_write
	progEVPCipherInit                       // bpf_uprobe_evp_cipher_init and its uretprobe
)

// fileKey identifies a file the way the kernel's uprobes do: by its inode.
//
// A file in a container image is reached through the container's overlayfs
// mount, whose device number is the mount's own, so stat gives each
// container its own (dev, ino) for a file their image shares. The uprobe is
// registered on the inode under the overlay (the image layer's), and fires
// for the processes of every container that maps it. /proc/<pid>/maps shows
// the overlay's device number too on current kernels (it shows the file as
// the process sees it since Linux 6.8). For such a file, handle is its
// overlayfs file ID (fileIdentity), which names the layer's file and is the
// same in every container, with its inode number and change time.
// Otherwise dev and ino are the file's.
type fileKey struct {
	dev, ino uint64
	ctime    int64  // ns; overlay files only
	handle   string // hex of the first 16 bytes of the handle's SHA-256; overlay files only
}

// atHandleFID is AT_HANDLE_FID (Linux 6.5): name_to_handle_at returns a
// handle that identifies the file, even on a filesystem that cannot open a
// file by handle (an overlay without nfs_export).
const atHandleFID = 0x200

// fileIdentity returns the key of the file at path, following symlinks.
//
// For a file on overlayfs (a container's root filesystem), it is the
// overlay's file ID handle (Linux 6.6+), which overlayfs encodes from the
// file's origin in the image layer, with the layer filesystem's UUID. A file
// copied up into the container's upper layer (written to, or its metadata
// changed, in the container) is the container's own, and the kernel
// attaches its uprobe on the copy; overlayfs still encodes its origin, and
// keeps its inode number, but the copy-up changed the copy's ctime, which
// stat returns. So with the handle go the inode number and ctime. On older
// kernels, or on another filesystem, the key is (dev, ino) from stat.
func fileIdentity(path string) (fileKey, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fileKey{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err == nil && fs.Type == unix.OVERLAYFS_SUPER_MAGIC {
		if h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, unix.AT_SYMLINK_FOLLOW|atHandleFID); err == nil {
			var b bytes.Buffer
			_ = binary.Write(&b, binary.LittleEndian, h.Type())
			b.Write(h.Bytes())
			// A digest: the key goes into the uprobe's pin name, and a
			// handle can be up to 128 bytes.
			sum := sha256.Sum256(b.Bytes())
			return fileKey{ino: st.Ino, ctime: st.Ctim.Nano(), handle: hex.EncodeToString(sum[:16])}, nil
		}
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, nil //nolint:unconvert // Dev is uint32 on some arches
}

// procStartTime returns the start time of process pid (field 22 of
// /proc/<pid>/stat, in clock ticks since boot): with the PID, it names one
// process, whatever process reuses the PID later.
func procStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	return parseProcStartTime(data)
}

// parseProcStartTime reads the start time from a /proc/<pid>/stat body. The
// command name (field 2) is in parentheses and may hold spaces and
// parentheses itself: the fields are counted from the last ')'.
func parseProcStartTime(data []byte) (uint64, error) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, errors.New("no command name in /proc/<pid>/stat")
	}
	// Field 3 (state) is the first after the command name; start time is
	// field 22.
	fields := bytes.Fields(data[end+1:])
	const startTimeField = 22 - 3
	if len(fields) <= startTimeField {
		return 0, fmt.Errorf("/proc/<pid>/stat has %d fields after the command name", len(fields))
	}
	return strconv.ParseUint(string(fields[startTimeField]), 10, 64)
}

// exeFileKey returns the key process-scoped uprobes use for the executable of
// process pid: its (dev, ino) as stat sees it through /proc/<pid>/exe. The
// overlay's per-mount device number does no harm there, the uprobe being the
// process's own.
func exeFileKey(pid int) (fileKey, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/exe", pid), &st); err != nil {
		return fileKey{}, err
	}
	return fileKey{dev: uint64(st.Dev), ino: st.Ino}, nil //nolint:unconvert // Dev is uint32 on some arches
}

// processCurrent reports whether process p still runs, and runs the same
// executable.
func processCurrent(p procExe) bool {
	start, err := procStartTime(p.pid)
	if err != nil || start != p.start {
		return false
	}
	exe, err := exeFileKey(p.pid)
	return err == nil && exe == p.exe
}

// uprobeLinkKey identifies a uprobe attachment: what the kernel attached it
// to and which program it runs.
type uprobeLinkKey struct {
	// pid is the process a process-scoped uprobe fires for (with start, its
	// start time), 0 for a uprobe on a library, which fires for every
	// process that maps it.
	pid    int
	start  uint64
	file   fileKey
	symbol string // the symbol, or "" when attached at addr
	addr   uint64 // file offset (a symbol-stripped Bun binary's SSL_write)
	prog   uprobeProg
}

// uprobeEntry is an attached uprobe: its links (an entry and a return
// probe for progEVPCipherInit) and the containers (cgroup IDs) that need it.
// An adopted uprobe (one a previous controller pinned) has none until an
// attach claims it.
type uprobeEntry struct {
	links   []io.Closer
	cgroups map[uint64]struct{}
}

// linkRegistry records the uprobes kloak attached, by uprobeLinkKey.
type linkRegistry struct {
	mu      sync.Mutex
	uprobes map[uprobeLinkKey]*uprobeEntry
}

// ensure makes the uprobe for key attached for container cgroupID: it calls
// attach unless the uprobe is attached already, and records cgroupID as
// needing it. It reports whether attach ran. A failed attach is not
// recorded, so a later call tries again.
//
// Attaches are serialized: two attach paths that discover the same uprobe at
// once must not both attach it, which would run the program twice per call.
func (r *linkRegistry) ensure(key *uprobeLinkKey, cgroupID uint64, attach func() ([]io.Closer, error)) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.uprobes[*key]; ok {
		e.cgroups[cgroupID] = struct{}{}
		return false, nil
	}
	links, err := attach()
	if err != nil {
		return false, err
	}
	if r.uprobes == nil {
		r.uprobes = make(map[uprobeLinkKey]*uprobeEntry)
	}
	r.uprobes[*key] = &uprobeEntry{links: links, cgroups: map[uint64]struct{}{cgroupID: {}}}
	return true, nil
}

// adopt records the uprobe of key, with its links, as a previous controller
// pinned it: no container needs it until an attach claims it (ensure), and
// releaseUnclaimed drops it otherwise.
func (r *linkRegistry) adopt(key *uprobeLinkKey, links []io.Closer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.uprobes == nil {
		r.uprobes = make(map[uprobeLinkKey]*uprobeEntry)
	}
	r.uprobes[*key] = &uprobeEntry{links: links, cgroups: map[uint64]struct{}{}}
}

// releaseUnclaimed drops the adopted uprobes no attach claimed (those of the
// containers that went while no controller ran), and returns their links,
// for the caller to close.
func (r *linkRegistry) releaseUnclaimed() []io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []io.Closer
	for k, e := range r.uprobes {
		if len(e.cgroups) == 0 {
			out = append(out, e.links...)
			delete(r.uprobes, k)
		}
	}
	return out
}

// releaseCgroup records that container cgroupID needs none of its uprobes
// any more, and returns the links of those no other container needs, for the
// caller to close.
func (r *linkRegistry) releaseCgroup(cgroupID uint64) []io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []io.Closer
	for k, e := range r.uprobes {
		if _, ok := e.cgroups[cgroupID]; !ok {
			continue
		}
		delete(e.cgroups, cgroupID)
		if len(e.cgroups) == 0 {
			out = append(out, e.links...)
			delete(r.uprobes, k)
		}
	}
	return out
}

// retainProcess drops the process-scoped uprobes recorded for PID pid that
// are not for process (pid, start) running executable exe: those of an
// earlier process that had the PID, and those of the executable the process
// ran before an exec, which it no longer maps. It returns their links, for
// the caller to close.
//
// It goes by what the process runs now, not by what one attach ensured, so
// that two attaches of the process on either side of an exec agree.
func (r *linkRegistry) retainProcess(pid int, start uint64, exe fileKey) []io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []io.Closer
	for k, e := range r.uprobes {
		if k.pid != pid || (k.start == start && k.file == exe) {
			continue
		}
		out = append(out, e.links...)
		delete(r.uprobes, k)
	}
	return out
}

// procExe is the process (and executable) process-scoped uprobes are for.
type procExe struct {
	pid   int
	start uint64
	exe   fileKey
}

// sweepProcesses drops the process-scoped uprobes for which current reports
// false: the process exited, or runs another executable. It returns their
// links, for the caller to close. current is called once per process and
// executable, without the registry's lock held.
func (r *linkRegistry) sweepProcesses(current func(procExe) bool) []io.Closer {
	r.mu.Lock()
	procs := make(map[procExe]struct{})
	for k := range r.uprobes {
		if k.pid != 0 {
			procs[procExe{k.pid, k.start, k.file}] = struct{}{}
		}
	}
	r.mu.Unlock()

	stale := make(map[procExe]struct{})
	for p := range procs {
		if !current(p) {
			stale[p] = struct{}{}
		}
	}
	if len(stale) == 0 {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	var out []io.Closer
	for k, e := range r.uprobes {
		if _, ok := stale[procExe{k.pid, k.start, k.file}]; ok && k.pid != 0 {
			out = append(out, e.links...)
			delete(r.uprobes, k)
		}
	}
	return out
}

// counts returns how many uprobes are recorded and how many links they hold.
func (r *linkRegistry) counts() (uprobes, links int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.uprobes {
		links += len(e.links)
	}
	return len(r.uprobes), links
}

// drain forgets every uprobe and returns all their links, for Close.
func (r *linkRegistry) drain() []io.Closer {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []io.Closer
	for _, e := range r.uprobes {
		out = append(out, e.links...)
	}
	r.uprobes = nil
	return out
}

// tcLinkKey identifies a tc patch program attachment: the interface, by its
// index in its network namespace, the hook and the program.
type tcLinkKey struct {
	netns   uint64 // inode of the interface's network namespace
	ifindex int
	ingress bool
	prog    ebpf.ProgramID
}

// tcLinkLive reports whether the kernel still has the tc attachment l: a
// TCX link is detached (ifindex 0) once its interface is gone, and a
// cls_bpf filter goes with its interface's qdisc. An attachment kloak
// cannot check is taken as live.
func tcLinkLive(l io.Closer) bool {
	switch l := l.(type) {
	case *clsactFilter:
		return l.live()
	case link.Link:
		info, err := l.Info()
		if err != nil {
			return false
		}
		if tcx := info.TCX(); tcx != nil {
			return tcx.Ifindex != 0
		}
		return true
	default:
		return true
	}
}

// live reports whether the filter is still on its interface. It may run on
// any goroutine: the netlink handle is opened in the filter's netns.
func (f *clsactFilter) live() bool {
	h, err := netlink.NewHandleAt(netns.NsHandle(f.nsFd), unix.NETLINK_ROUTE)
	if err != nil {
		return false
	}
	defer h.Close()
	lk, err := h.LinkByIndex(f.filter.LinkIndex)
	if err != nil {
		return false
	}
	filters, err := h.FilterList(lk, f.filter.Parent)
	if err != nil {
		return false
	}
	for _, flt := range filters {
		if bf, ok := flt.(*netlink.BpfFilter); ok &&
			bf.Handle == f.filter.Handle && bf.Priority == f.filter.Priority && bf.Name == f.filter.Name {
			return true
		}
	}
	return false
}

// programID returns prog's kernel ID, or 0 if the kernel does not report it.
func programID(prog *ebpf.Program) ebpf.ProgramID {
	info, err := prog.Info()
	if err != nil {
		return 0
	}
	id, _ := info.ID()
	return id
}
