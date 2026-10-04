//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// tcTestEnv is a throwaway netns; tests attach to its loopback interface. The test's OS
// thread stays switched into it until cleanup, matching how attachTCEgress
// calls attachTCProgram (thread already setns'd into the target netns).
type tcTestEnv struct {
	ns      netns.NsHandle
	nsFile  *os.File
	ifindex int
	link    netlink.Link
	prog    *ebpf.Program
}

func newTCTestEnv(t *testing.T) *tcTestEnv {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_NET_ADMIN + CAP_BPF)")
	}
	runtime.LockOSThread()
	orig, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Skipf("netns.Get: %v", err)
	}
	ns, err := netns.New() // also switches this thread into it
	if err != nil {
		orig.Close()
		runtime.UnlockOSThread()
		t.Skipf("cannot create netns: %v", err)
	}
	t.Cleanup(func() {
		_ = netns.Set(orig)
		orig.Close()
		ns.Close()
		runtime.UnlockOSThread()
	})

	// The netns's own loopback: always present, and unlike a dummy link
	// it doesn't need a kernel module.
	l, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		t.Skipf("cannot load sched_cls program: %v", err)
	}
	t.Cleanup(func() { _ = prog.Close() })

	// Give nsFile its own fd. Wrapping ns's fd directly would let the
	// *os.File finalizer close that fd number after this test, by which time
	// a later test may have reused it for its own netns handle.
	dupFd, err := unix.Dup(int(ns))
	if err != nil {
		t.Fatal(err)
	}
	nsFile := os.NewFile(uintptr(dupFd), "test-netns")
	t.Cleanup(func() { _ = nsFile.Close() })
	return &tcTestEnv{ns: ns, nsFile: nsFile, ifindex: l.Attrs().Index, link: l, prog: prog}
}

// inTestNS fails the test if the calling thread is not in the test netns.
// Everything that attaches must run on the test's own goroutine (no t.Run
// subtests, no extra goroutines): another goroutine's thread is in the
// host netns and would attach to the host's interfaces.
func (e *tcTestEnv) inTestNS(t *testing.T) {
	t.Helper()
	cur, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer cur.Close()
	if !cur.Equal(e.ns) {
		t.Fatalf("not running in the test netns (current %s, test %s, tid %d); refusing to touch host interfaces",
			cur.UniqueId(), e.ns.UniqueId(), unix.Gettid())
	}
}

func (e *tcTestEnv) kloakFilters(t *testing.T, parent uint32) []*netlink.BpfFilter {
	t.Helper()
	e.inTestNS(t)
	filters, err := netlink.FilterList(e.link, parent)
	if err != nil {
		t.Fatalf("FilterList: %v", err)
	}
	var out []*netlink.BpfFilter
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Handle == clsactFilterHandle {
			out = append(out, bf)
		}
	}
	return out
}

func testManager(mode TCAttachMode) *TLSUprobeManager {
	return &TLSUprobeManager{log: zap.NewNop().Sugar(), tcMode: newTCModeResolver(mode)}
}

func TestAttachClsact_ReplacesInsteadOfStacking(t *testing.T) {
	e := newTCTestEnv(t)

	e.inTestNS(t)
	first, err := attachClsact(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	// A restarted controller attaches again while the previous filter is
	// still installed. Must replace, not add a second copy.
	second, err := attachClsact(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatalf("second attach: %v", err)
	}
	got := e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 kloak filter after re-attach, got %d", len(got))
	}
	if !got[0].DirectAction || got[0].Priority != clsactFilterPriority {
		t.Errorf("filter attrs: directAction=%v prio=%d", got[0].DirectAction, got[0].Priority)
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_EGRESS)); n != 0 {
		t.Errorf("ingress attach leaked %d egress filters", n)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 0 {
		t.Fatalf("filter still present after Close: %d", n)
	}
	// Closing an already-removed filter is not an error.
	if err := second.Close(); err != nil {
		t.Fatalf("close second (already removed): %v", err)
	}
}

func TestAttachClsact_KeepsExistingQdisc(t *testing.T) {
	e := newTCTestEnv(t)
	e.inTestNS(t)
	// Simulate a CNI that already owns a clsact qdisc on the interface.
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{LinkIndex: e.ifindex, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT},
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		t.Fatalf("pre-adding clsact: %v", err)
	}
	c, err := attachClsact(e.prog, e.ifindex, false, e.nsFile)
	if err != nil {
		t.Fatalf("attach with existing qdisc: %v", err)
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_EGRESS)); n != 1 {
		t.Fatalf("want 1 egress filter, got %d", n)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := netlink.QdiscList(e.link)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			found = true
		}
	}
	if !found {
		t.Error("Close removed a clsact qdisc kloak did not own")
	}
}

func TestClsactFilterClose_FromAnotherThread(t *testing.T) {
	e := newTCTestEnv(t)
	e.inTestNS(t)
	c, err := attachClsact(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	// Manager.Close runs closers on worker goroutines that are NOT in the
	// filter's netns; Close must enter it explicitly.
	errCh := make(chan error, 1)
	go func() { errCh <- c.Close() }()
	if err := <-errCh; err != nil {
		t.Fatalf("Close from another goroutine: %v", err)
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 0 {
		t.Fatalf("filter not removed: %d left", n)
	}
}

// noTCX simulates a kernel without TCX (Linux < 6.6) for the duration of
// the test.
func noTCX(t *testing.T) {
	real := attachTCX
	t.Cleanup(func() { attachTCX = real })
	attachTCX = func(link.TCXOptions) (link.Link, error) {
		return nil, fmt.Errorf("simulated old kernel: %w", ebpf.ErrNotSupported)
	}
}

func TestAttachTCProgram_AutoFallsBackToClsact(t *testing.T) {
	e := newTCTestEnv(t)
	noTCX(t)
	e.inTestNS(t)
	m := testManager(TCAttachAuto)
	c, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, ok := c.(*clsactFilter); !ok {
		t.Fatalf("got %T, want *clsactFilter", c)
	}
	if !m.tcMode.useClsact.Load() {
		t.Error("fallback decision not remembered")
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 1 {
		t.Fatalf("want 1 ingress filter, got %d", n)
	}
}

func TestAttachTCProgram_TCXModeDoesNotFallBack(t *testing.T) {
	e := newTCTestEnv(t)
	noTCX(t)
	e.inTestNS(t)
	m := testManager(TCAttachTCX)
	if _, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile); !errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatalf("want ErrNotSupported, got %v", err)
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 0 {
		t.Fatalf("tcx mode installed %d clsact filters", n)
	}
}

func TestAttachTCProgram_AutoKeepsOtherTCXErrors(t *testing.T) {
	e := newTCTestEnv(t)
	real := attachTCX
	t.Cleanup(func() { attachTCX = real })
	attachTCX = func(link.TCXOptions) (link.Link, error) { return nil, unix.EPERM }
	e.inTestNS(t)
	m := testManager(TCAttachAuto)
	if _, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile); !errors.Is(err, unix.EPERM) {
		t.Fatalf("want EPERM, got %v", err)
	}
	if m.tcMode.useClsact.Load() {
		t.Error("a non-ErrNotSupported error must not switch to clsact")
	}
}

func TestAttachTCProgram_ClsactModeNeverTriesTCX(t *testing.T) {
	e := newTCTestEnv(t)
	real := attachTCX
	t.Cleanup(func() { attachTCX = real })
	attachTCX = func(link.TCXOptions) (link.Link, error) {
		return nil, errors.New("TCX attempted in clsact mode")
	}
	e.inTestNS(t)
	m := testManager(TCAttachClsact)
	c, err := m.attachTCProgram(e.prog, e.ifindex, false, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_EGRESS)); n != 1 {
		t.Fatalf("want 1 egress filter, got %d", n)
	}
}

func TestAttachTCProgram_AutoUsesTCXWhenAvailable(t *testing.T) {
	e := newTCTestEnv(t)
	e.inTestNS(t)
	m := testManager(TCAttachAuto)
	c, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if errors.Is(err, ebpf.ErrNotSupported) {
		t.Skip("kernel has no TCX")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, ok := c.(link.Link); !ok {
		t.Fatalf("got %T, want a TCX link", c)
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 0 {
		t.Errorf("TCX path installed %d clsact filters", n)
	}
}
