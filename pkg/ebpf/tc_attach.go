//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	// clsactFilterPriority is the cls_bpf priority Kloak uses. Lower runs
	// first; 1 puts the patch ahead of filters a CNI may install that
	// redirect the packet (a redirect ends the filter chain, so a patch
	// placed after it would never run). Kloak's programs return
	// TC_ACT_UNSPEC, so the filters after it still run.
	clsactFilterPriority = 1
	// clsactFilterHandle identifies Kloak's filter within that priority
	// ("kl"). It must be fixed: classic tc filters outlive the process that
	// installed them, so a restarted controller has to REPLACE the filter a
	// previous instance left behind. Stacking a second copy would apply the
	// XOR patch twice and corrupt the GCM tag.
	clsactFilterHandle = 0x6b6c
	clsactFilterName   = "kloak_tc_patch"
)

// attachTCX is link.AttachTCX, swappable in tests to simulate a kernel
// without TCX support.
var attachTCX = link.AttachTCX

// tcModeResolver remembers, process-wide, whether the kernel supports TCX
// so that only the first attach pays for the failed probe.
type tcModeResolver struct {
	configured TCAttachMode
	// useClsact flips to true the first time TCX reports ErrNotSupported
	// in auto mode.
	useClsact atomic.Bool
}

func newTCModeResolver(mode TCAttachMode) *tcModeResolver {
	r := &tcModeResolver{configured: mode}
	if mode == TCAttachClsact {
		r.useClsact.Store(true)
	}
	return r
}

// attachTCProgram attaches prog to ifindex in the netns the calling thread is
// currently in (the caller has already setns'd and holds the OS thread).
// nsFd must be an open handle to that same netns; the clsact path keeps a
// duplicate of it so the filter can be removed later from any thread.
//
// A TCX link of prog the hook has already (one a previous controller of the
// same build pinned) is adopted rather than attached again: the program
// would run twice, and patch each record twice. A new TCX link is pinned
// under the generation (pinRoot.tcxPin), to outlive the controller. A
// cls_bpf filter outlives it anyway, and replaces the one there.
// Whichever mode attaches, prog's attachment of the other mode on the hook
// (after --tc-attach-mode changed) is removed, for the same reason.
//
// The returned io.Closer detaches the program.
func (m *TLSUprobeManager) attachTCProgram(prog *ebpf.Program, ifindex int, ingress bool, nsFd *os.File) (io.Closer, error) {
	attach := ebpf.AttachTCXEgress
	if ingress {
		attach = ebpf.AttachTCXIngress
	}
	if !m.tcMode.useClsact.Load() {
		if l := m.adoptTCX(prog, ifindex, attach); l != nil {
			deleteClsactFilter(ifindex, ingress)
			return l, nil
		}
		// First on the hook: a program before it (a CNI's) could redirect
		// the packet, and the patch would never run. Kloak's programs
		// return TC_ACT_UNSPEC (TCX_NEXT), so the others still run.
		l, err := attachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: attach, Anchor: link.Head()})
		if err == nil {
			deleteClsactFilter(ifindex, ingress)
			return m.pinTCX(l), nil
		}
		if m.tcMode.configured != TCAttachAuto || !errors.Is(err, ebpf.ErrNotSupported) {
			return nil, err
		}
		if m.tcMode.useClsact.CompareAndSwap(false, true) {
			m.log.Infow("Kernel does not support TCX (needs Linux 6.6+); attaching the tc patch program with a clsact qdisc and cls_bpf filter instead",
				"error", err)
		}
	}
	if l := m.adoptTCX(prog, ifindex, attach); l != nil {
		if err := l.Close(); err != nil {
			return nil, fmt.Errorf("detaching the TCX link the clsact filter replaces: %w", err)
		}
	}
	return attachClsact(prog, ifindex, ingress, nsFd)
}

// adoptTCX returns the TCX link that runs prog on the hook (ifindex, attach)
// of the calling thread's netns, or nil if there is none.
func (m *TLSUprobeManager) adoptTCX(prog *ebpf.Program, ifindex int, attach ebpf.AttachType) *ownedLink {
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		return nil // no TCX here
	}
	want := programID(prog)
	for _, p := range res.Programs {
		id, ok := p.LinkID()
		if p.ID != want || !ok {
			continue
		}
		l, err := link.NewFromID(id)
		if err != nil {
			continue
		}
		if m.pins == nil {
			return &ownedLink{Link: l}
		}
		if path := m.pins.tcxPin(id); fileExists(path) {
			return &ownedLink{Link: l, pin: path}
		}
		return m.pinTCX(l)
	}
	return nil
}

// pinTCX pins the TCX link l under the generation, by its ID.
func (m *TLSUprobeManager) pinTCX(l link.Link) *ownedLink {
	if m.pins == nil {
		return &ownedLink{Link: l}
	}
	info, err := l.Info()
	if err != nil {
		return &ownedLink{Link: l}
	}
	return m.pins.pinLink(l, m.pins.tcxPin(info.ID))
}

// deleteClsactFilter removes kloak's cls_bpf filter from the hook
// (ifindex, ingress) of the calling thread's netns, if it has one.
func deleteClsactFilter(ifindex int, ingress bool) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return
	}
	defer h.Close()
	lk, err := h.LinkByIndex(ifindex)
	if err != nil {
		return
	}
	parent := uint32(netlink.HANDLE_MIN_EGRESS)
	if ingress {
		parent = netlink.HANDLE_MIN_INGRESS
	}
	filters, err := h.FilterList(lk, parent)
	if err != nil {
		return
	}
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && isKloakFilter(bf) {
			_ = h.FilterDel(bf)
		}
	}
}

// isKloakFilter reports whether f is a cls_bpf filter attachClsact made.
func isKloakFilter(f *netlink.BpfFilter) bool {
	return f.Handle == clsactFilterHandle && f.Priority == clsactFilterPriority && f.Name == clsactFilterName
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// clsactFilter is an attached cls_bpf filter. Close removes it.
type clsactFilter struct {
	nsFd   int // dup'd netns fd, owned by the filter
	filter *netlink.BpfFilter
}

func attachClsact(prog *ebpf.Program, ifindex int, ingress bool, nsFd *os.File) (io.Closer, error) {
	// The calling thread is already in the target netns, so a plain handle
	// opens its sockets there.
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("opening netlink handle: %w", err)
	}
	defer h.Close()

	// Add the clsact qdisc if the interface doesn't have one yet. Never
	// replace or delete an existing one: a CNI (Cilium, Calico eBPF, ...)
	// may own it and have its own filters on it.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := h.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("adding clsact qdisc to ifindex %d: %w", ifindex, err)
	}

	parent := uint32(netlink.HANDLE_MIN_EGRESS)
	if ingress {
		parent = netlink.HANDLE_MIN_INGRESS
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    clsactFilterHandle,
			Priority:  clsactFilterPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         clsactFilterName,
		DirectAction: true,
	}
	// Replace, not add: see clsactFilterHandle.
	if err := h.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("attaching cls_bpf filter to ifindex %d: %w", ifindex, err)
	}

	dup, err := unix.Dup(int(nsFd.Fd()))
	if err != nil {
		_ = h.FilterDel(filter)
		return nil, fmt.Errorf("duplicating netns fd: %w", err)
	}
	return &clsactFilter{nsFd: dup, filter: filter}, nil
}

// release closes the filter's netns handle and leaves the filter in place:
// a cls_bpf filter outlives the controller, and the next one replaces it.
func (f *clsactFilter) release() error {
	return unix.Close(f.nsFd)
}

// Close removes the filter. It may run on any goroutine: the netlink handle
// is opened inside the filter's netns explicitly. The clsact qdisc is left in
// place (it may be shared). A missing interface or filter is not an error —
// the pod's veth is usually already gone by the time the controller exits.
func (f *clsactFilter) Close() error {
	defer func() { _ = unix.Close(f.nsFd) }()
	h, err := netlink.NewHandleAt(netns.NsHandle(f.nsFd), unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("opening netlink handle in filter netns: %w", err)
	}
	defer h.Close()
	if err := h.FilterDel(f.filter); err != nil &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("removing cls_bpf filter from ifindex %d: %w", f.filter.LinkIndex, err)
	}
	return nil
}
