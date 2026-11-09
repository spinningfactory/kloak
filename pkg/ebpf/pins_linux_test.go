//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

func TestUprobePinNameRoundTrip(t *testing.T) {
	keys := []uprobeLinkKey{
		{file: fileKey{ino: 803803, ctime: 1730000000123456789, handle: "00112233445566778899aabbccddeeff"}, symbol: "SSL_write", prog: progSSLWrite},
		{pid: 4242, start: 987654321, file: fileKey{dev: 0x10303, ino: 0x1234}, symbol: "crypto/tls.(*Conn).Write", prog: progGoTLSWrite},
		{pid: 7, start: 1, file: fileKey{dev: 1, ino: 2}, addr: 0x3a5f20, prog: progSSLWrite}, // Bun, by file offset
		{file: fileKey{dev: 0xfd01, ino: 99}, symbol: "EVP_CipherInit_ex2", prog: progEVPCipherInit},
		{file: fileKey{dev: 1, ctime: -1}, symbol: "a.b-c_d/e", prog: progSSLWrite}, // separators in the symbol
	}
	names := make(map[string]bool)
	for _, k := range keys {
		for idx := 0; idx < k.prog.links(); idx++ {
			name, ok := uprobePinName(&k, idx)
			if !ok {
				t.Fatalf("%+v: no pin name", k)
			}
			if strings.ContainsAny(name, "/.\x00") || len(name) > 255 {
				t.Fatalf("%q is not a file name", name)
			}
			if names[name] {
				t.Fatalf("two uprobe links named %q", name)
			}
			names[name] = true
			got, gotIdx, err := parseUprobePinName(name)
			if err != nil {
				t.Fatalf("parse %q: %v", name, err)
			}
			if got != k || gotIdx != idx {
				t.Errorf("%q: got %+v link %d, want %+v link %d", name, got, gotIdx, k, idx)
			}
		}
	}
}

func TestUprobePinNameTooLong(t *testing.T) {
	k := uprobeLinkKey{file: fileKey{dev: 1, ino: 2}, symbol: strings.Repeat("x", 300), prog: progSSLWrite}
	if _, ok := uprobePinName(&k, 0); ok {
		t.Error("a 300-byte symbol got a pin name")
	}
}

func TestParseUprobePinNameRejects(t *testing.T) {
	k := uprobeLinkKey{file: fileKey{dev: 1, ino: 2}, symbol: "SSL_write", prog: progSSLWrite}
	valid, _ := uprobePinName(&k, 0)
	f := strings.Split(valid, uprobePinSep)
	with := func(i int, v string) string {
		g := append([]string(nil), f...)
		g[i] = v
		return strings.Join(g, uprobePinSep)
	}
	for _, name := range []string{
		"",
		"garbage",
		with(0, "u2"),                  // another encoding
		with(1, "9"),                   // no such program
		with(10, "1"),                  // the second link of a one-link uprobe
		with(7, "zz"),                  // a handle that is not hex
		with(9, "!!"),                  // a symbol that is not base64
		valid + uprobePinSep + "extra", // a field too many
	} {
		if _, _, err := parseUprobePinName(name); err == nil {
			t.Errorf("parsed %q", name)
		}
	}
}

// TestLinkRegistryAdopt checks that an adopted uprobe is not attached again
// by the attach that claims it, and that releaseUnclaimed drops only the
// unclaimed ones.
func TestLinkRegistryAdopt(t *testing.T) {
	var r linkRegistry
	lib := uprobeLinkKey{file: libssl, symbol: "SSL_write", prog: progSSLWrite}
	proc := uprobeLinkKey{pid: 7, start: 100, file: exeA, symbol: "SSL_write", prog: progSSLWrite}
	libLinks, _, libClosed := fakeAttach(1)
	procLinks, _, procClosed := fakeAttach(1)
	l, _ := libLinks()
	p, _ := procLinks()
	r.adopt(&lib, l)
	r.adopt(&proc, p)

	created, err := r.ensure(&lib, 1, func() ([]io.Closer, error) {
		t.Error("an adopted uprobe was attached again")
		return nil, errors.New("attached again")
	})
	if err != nil || created {
		t.Fatalf("claiming an adopted uprobe: created %v, %v", created, err)
	}
	closeAll(t, r.releaseUnclaimed())
	if *procClosed != 1 || *libClosed != 0 {
		t.Fatalf("releaseUnclaimed closed the claimed uprobe's links %d times and the unclaimed one's %d times; want 0 and 1", *libClosed, *procClosed)
	}
	if n, _ := r.counts(); n != 1 {
		t.Fatalf("%d uprobes left, want the claimed one", n)
	}
	closeAll(t, r.releaseCgroup(1))
	if *libClosed != 1 {
		t.Errorf("the claimed uprobe was not released with its container")
	}
}

// eventually polls cond for up to 5 s: a link loses its last reference to
// an unpin in deferred work, so it goes shortly after.
func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// testPinRoot returns a pin root for this test under /sys/fs/bpf, torn down
// after it. It skips without bpffs.
func testPinRoot(t *testing.T) *pinRoot {
	t.Helper()
	if err := requireBPFFS("/sys/fs/bpf"); err != nil {
		t.Skipf("no bpffs: %v", err)
	}
	name := strings.NewReplacer("/", "_").Replace(t.Name())
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("kloak-test-%d-%s", os.Getpid(), name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("cannot write to bpffs: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = teardownPins(dir, true, testLog()) })
	return &pinRoot{dir: dir, build: buildID(), log: testLog()}
}

// openTestPipeline opens the pipeline in r as a controller starting does.
func openTestPipeline(t *testing.T, r *pinRoot) (*tlsuprobeObjects, *dispatchObjects, bool) {
	t.Helper()
	spec := loadSpec(t)
	if err := prepareVirtualIPPins(spec, r.dir, testLog()); err != nil {
		t.Fatal(err)
	}
	adoptable, err := r.prepare()
	if err != nil {
		t.Fatal(err)
	}
	objs, dispatch, pins, adopted, err := openPipeline(spec, r, adoptable, r.dir, testLog())
	if err != nil {
		skipUnlessRejected(t, err)
	}
	if pins == nil {
		t.Fatal("the pipeline was not pinned")
	}
	return objs, dispatch, adopted
}

func programIDs(t *testing.T, objs any) map[string]ciliumebpf.ProgramID {
	t.Helper()
	progs, _ := objectFields(objs)
	out := make(map[string]ciliumebpf.ProgramID, len(progs))
	for name, p := range progs {
		out[name] = programID(*p)
	}
	return out
}

func TestPinnedPipelineAdopted(t *testing.T) {
	r := testPinRoot(t)
	objs, dispatch, adopted := openTestPipeline(t, r)
	if adopted {
		t.Fatal("a fresh pin root adopted a pipeline")
	}
	want := programIDs(t, objs)
	wantTrampolines := programIDs(t, dispatch)
	if err := r.writeMeta(); err != nil {
		t.Fatal(err)
	}
	_ = dispatch.Close()
	_ = objs.Close()

	// The next controller of the build adopts the same programs.
	objs, dispatch, adopted = openTestPipeline(t, r)
	t.Cleanup(func() { _ = dispatch.Close(); _ = objs.Close() })
	if !adopted {
		t.Fatal("the pinned pipeline was not adopted")
	}
	for name, id := range programIDs(t, objs) {
		if id != want[name] {
			t.Errorf("program %s is %d, want the pinned %d", name, id, want[name])
		}
	}
	for name, id := range programIDs(t, dispatch) {
		if id != wantTrampolines[name] {
			t.Errorf("trampoline %s is %d, want the pinned %d", name, id, wantTrampolines[name])
		}
	}
	format, build, err := readMeta(r.metaPath())
	if err != nil || format != pinFormat || build != r.build {
		t.Errorf("meta: format %d, build %s, %v; want %d, %s", format, build, err, pinFormat, r.build)
	}
	for slot, prog := range map[uint32]*ciliumebpf.Program{
		dispatchSlotSSLWrite:   objs.BpfUprobeSslWrite,
		dispatchSlotGoTLSWrite: objs.BpfUprobeGoTlsWrite,
		dispatchSlotEVPInit:    objs.BpfUprobeEvpCipherInit,
		dispatchSlotEVPInitRet: objs.BpfUretprobeEvpCipherInit,
	} {
		var id uint32
		if err := dispatch.KloakDispatch.Lookup(slot, &id); err != nil || ciliumebpf.ProgramID(id) != programID(prog) {
			t.Errorf("trampoline slot %d holds program %d (%v), want %d", slot, id, err, programID(prog))
		}
	}
}

func TestPinnedPipelineOfAnotherBuild(t *testing.T) {
	r := testPinRoot(t)
	other := &pinRoot{dir: r.dir, build: strings.Repeat("ab", 32), log: testLog()}
	objs, dispatch, _ := openTestPipeline(t, other)
	_ = dispatch.Close()
	_ = objs.Close()

	adoptable, err := r.prepare()
	if err != nil {
		t.Fatal(err)
	}
	if adoptable {
		t.Error("another build's pipeline is adoptable")
	}
	if dirExists(other.genDir()) {
		t.Error("another build's pipeline was not torn down")
	}
	if !dirExists(other.dispatchDir()) {
		t.Error("the trampolines went with another build's pipeline")
	}
}

func TestPinnedPipelineIncomplete(t *testing.T) {
	r := testPinRoot(t)
	objs, dispatch, _ := openTestPipeline(t, r)
	_ = dispatch.Close()
	_ = objs.Close()
	// A crash before the load finished pinning.
	if err := os.Remove(filepath.Join(r.genDir(), "ready")); err != nil {
		t.Fatal(err)
	}
	if adoptable, err := r.prepare(); err != nil || adoptable {
		t.Fatalf("an incomplete pipeline: adoptable %v, %v", adoptable, err)
	}
	if dirExists(r.genDir()) {
		t.Error("an incomplete pipeline was not torn down")
	}
}

func TestTeardownPins(t *testing.T) {
	r := testPinRoot(t)
	objs, dispatch, _ := openTestPipeline(t, r)
	if err := r.writeMeta(); err != nil {
		t.Fatal(err)
	}
	var k secretKey
	copy(k.Prefix[:], "kl::test")
	if err := objs.SecretMap.Update(&k, &secretValue{Len: 4}, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dispatch.Close(); _ = objs.Close() })

	if err := teardownPins(r.dir, false, testLog()); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{r.gensDir(), r.dispatchDir(), filepath.Join(r.dir, "links"), r.metaPath()} {
		if fileExists(d) {
			t.Errorf("%s is left after a teardown", d)
		}
	}
	for _, name := range virtualIPMaps {
		if !fileExists(filepath.Join(r.dir, name)) {
			t.Errorf("the virtual IP state %s went with a teardown", name)
		}
	}
	// What is left of the pipeline has nothing to rewrite with, or to.
	if err := objs.SecretMap.Lookup(&k, &secretValue{}); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Errorf("secret_map still holds a secret after the teardown: %v", err)
	}
	var id uint32
	if err := dispatch.KloakDispatch.Lookup(uint32(dispatchSlotSSLWrite), &id); err == nil {
		t.Errorf("a trampoline slot still holds program %d after the teardown", id)
	}

	if err := teardownPins(r.dir, true, testLog()); err != nil {
		t.Fatal(err)
	}
	if fileExists(r.dir) {
		t.Error("the pin root is left after an uninstall")
	}
}

// TestTeardownKeptPins checks that a controller that does not keep the
// data plane (persistence off) detaches what a previous one kept.
func TestTeardownKeptPins(t *testing.T) {
	r := testPinRoot(t)
	objs, dispatch, _ := openTestPipeline(t, r)
	_ = dispatch.Close()
	_ = objs.Close()
	if err := teardownKeptPins(r.dir, testLog()); err != nil {
		t.Fatal(err)
	}
	if fileExists(r.gensDir()) || fileExists(r.dispatchDir()) {
		t.Error("the kept pipeline is still pinned")
	}
	if !fileExists(filepath.Join(r.dir, virtualIPMaps[0])) {
		t.Error("the virtual IP state went with it")
	}
	// Nothing kept: nothing to do.
	if err := teardownKeptPins(r.dir, testLog()); err != nil {
		t.Fatal(err)
	}
}

// pinnedCounter reads the debug counter name from the pipeline pinned in r.
func pinnedCounter(t *testing.T, r *pinRoot, name string) uint64 {
	t.Helper()
	m, err := ciliumebpf.LoadPinnedMap(filepath.Join(r.genDir(), "maps", "debug_counters"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	return debugCounter(t, &tlsuprobeObjects{tlsuprobeMaps: tlsuprobeMaps{DebugCounters: m}}, name)
}

// TestPinnedUprobeSurvivesRestart attaches the Go crypto/tls Write uprobe on
// this process the way the manager does (on the trampoline, pinned under its
// key), and checks that it keeps running the pipeline while no controller
// runs, that the next controller adopts it instead of attaching a second one,
// and that an uninstall detaches it.
func TestPinnedUprobeSurvivesRestart(t *testing.T) {
	r := testPinRoot(t)
	_, offset := goTLSWriteOffset(t)
	addr := startTLSServer(t)
	write := func() {
		conn := dialTLS(t, addr, "")
		_, _ = conn.Write([]byte("hello"))
		_ = conn.Close()
	}
	start := func() *TLSUprobeManager {
		objs, dispatch, adopted := openTestPipeline(t, r)
		m := &TLSUprobeManager{objs: objs, dispatch: dispatch, pins: r, adopted: adopted, log: testLog(), tcMode: newTCModeResolver(TCAttachAuto)}
		m.adoptedUprobes = m.adoptUprobes()
		return m
	}
	uprobe := func(m *TLSUprobeManager) *uprobeSpec {
		p, err := discoverProcess(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		return m.exeUprobe(p, "", offset, progGoTLSWrite)
	}

	m := start()
	spec := uprobe(m)
	if created, err := m.ensureUprobe(spec, 1); err != nil {
		_ = m.Shutdown(ShutdownUninstall)
		t.Skipf("cannot attach the Go TLS uprobe: %v", err)
	} else if !created {
		t.Fatal("the uprobe was not attached")
	}
	name, _ := uprobePinName(&spec.key, 0)
	pin := filepath.Join(r.uprobeDir(), name)
	if !fileExists(pin) {
		t.Fatalf("the uprobe is not pinned at %s", pin)
	}
	before := debugCounter(t, m.objs, "xor_conn_check")
	write()
	if debugCounter(t, m.objs, "xor_conn_check") <= before {
		t.Fatal("the trampoline did not run the entry program")
	}
	if err := m.Shutdown(ShutdownKeep); err != nil {
		t.Fatal(err)
	}

	// No controller: the pinned uprobe still runs the pinned pipeline.
	before = pinnedCounter(t, r, "xor_conn_check")
	write()
	if pinnedCounter(t, r, "xor_conn_check") <= before {
		t.Fatal("the pinned uprobe stopped running with the controller")
	}

	m = start()
	if !m.adopted || m.adoptedUprobes != 1 {
		t.Fatalf("the next controller adopted the pipeline %v, and %d uprobes; want true and 1", m.adopted, m.adoptedUprobes)
	}
	spec = uprobe(m)
	spec.attach = func() ([]io.Closer, error) {
		t.Error("the adopted uprobe was attached again")
		return nil, errors.New("attached again")
	}
	if created, err := m.ensureUprobe(spec, 1); err != nil || created {
		t.Fatalf("claiming the adopted uprobe: created %v, %v", created, err)
	}
	m.FinishAdopt()
	if n, _ := m.registry.counts(); n != 1 {
		t.Fatalf("%d uprobes after the adoption, want the claimed one", n)
	}
	before = debugCounter(t, m.objs, "xor_conn_check")
	write()
	if debugCounter(t, m.objs, "xor_conn_check") <= before {
		t.Fatal("the adopted uprobe does not run the pipeline")
	}

	l, err := link.LoadPinnedLink(pin, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := l.Info()
	_ = l.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Shutdown(ShutdownUninstall); err != nil {
		t.Fatal(err)
	}
	if fileExists(r.dir) {
		t.Error("the pin root is left after an uninstall")
	}
	if !eventually(func() bool {
		l, err := link.NewFromID(info.ID)
		if err == nil {
			_ = l.Close()
		}
		return err != nil
	}) {
		t.Error("the uprobe is still attached after an uninstall")
	}
}

// tcxOf returns how many times prog is attached on the hook.
func tcxOf(t *testing.T, ifindex int, attach ciliumebpf.AttachType, prog *ciliumebpf.Program) int {
	t.Helper()
	res, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: attach})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range res.Programs {
		if p.ID == programID(prog) {
			n++
		}
	}
	return n
}

// TestAttachTCProgram_AdoptsPinnedTCX checks that a controller finding its
// build's TCX link on a hook (pinned by the previous one) adopts it: a
// second link would patch each record twice.
func TestAttachTCProgram_AdoptsPinnedTCX(t *testing.T) {
	e := newTCTestEnv(t)
	e.needTCX(t)
	r := testPinRoot(t)
	if err := os.MkdirAll(r.tcxLinkDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	e.inTestNS(t)

	m := testManager(TCAttachTCX)
	m.pins = r
	first, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	pinned, ok := first.(*ownedLink)
	if !ok || pinned.pin == "" || !fileExists(pinned.pin) {
		t.Fatalf("the TCX link is not pinned: %#v", first)
	}
	// The controller restarts: its handle goes, the pin keeps the link.
	if err := pinned.release(); err != nil {
		t.Fatal(err)
	}

	m = testManager(TCAttachTCX)
	m.pins = r
	second, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := second.(*ownedLink); !ok || got.pin != pinned.pin {
		t.Errorf("attached %#v, want the pinned link %s", second, pinned.pin)
	}
	if n := tcxOf(t, e.ifindex, ciliumebpf.AttachTCXIngress, e.prog); n != 1 {
		t.Fatalf("the program is attached %d times, want once", n)
	}

	// Pods gone while no controller ran: a TCX link no pod claimed goes.
	if err := second.(*ownedLink).release(); err != nil {
		t.Fatal(err)
	}
	m = testManager(TCAttachTCX)
	m.pins = r
	if n := m.releaseUnclaimedTCX(); n != 1 {
		t.Errorf("released %d unclaimed TCX links, want 1", n)
	}
	if !eventually(func() bool { return tcxOf(t, e.ifindex, ciliumebpf.AttachTCXIngress, e.prog) == 0 }) {
		t.Errorf("an unclaimed TCX link is still attached")
	}
}

// TestAttachTCProgram_ModeSwitchAttachesOnce checks that after
// --tc-attach-mode changes, the program the previous mode attached is
// removed from the hook: TCX programs run before the cls_bpf filters, and
// both would patch each record.
func TestAttachTCProgram_ModeSwitchAttachesOnce(t *testing.T) {
	e := newTCTestEnv(t)
	e.needTCX(t)
	e.needClsact(t)
	r := testPinRoot(t)
	if err := os.MkdirAll(r.tcxLinkDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	e.inTestNS(t)

	m := testManager(TCAttachTCX)
	m.pins = r
	tcx, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcx.(*ownedLink).release()

	m = testManager(TCAttachClsact)
	m.pins = r
	filter, err := m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !eventually(func() bool { return tcxOf(t, e.ifindex, ciliumebpf.AttachTCXIngress, e.prog) == 0 }) {
		t.Errorf("the TCX link is still attached under the cls_bpf filter")
	}
	if fileExists(tcx.(*ownedLink).pin) {
		t.Errorf("the replaced TCX link is still pinned")
	}
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 1 {
		t.Fatalf("%d cls_bpf filters, want 1", n)
	}
	_ = filter.(releaser).release() // the filter outlives the controller

	m = testManager(TCAttachTCX)
	m.pins = r
	tcx, err = m.attachTCProgram(e.prog, e.ifindex, true, e.nsFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcx.Close() })
	if n := len(e.kloakFilters(t, netlink.HANDLE_MIN_INGRESS)); n != 0 {
		t.Errorf("the cls_bpf filter is still there under the TCX link (%d)", n)
	}
	if n := tcxOf(t, e.ifindex, ciliumebpf.AttachTCXIngress, e.prog); n != 1 {
		t.Errorf("the program is attached %d times with TCX, want once", n)
	}
}
