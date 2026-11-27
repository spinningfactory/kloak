//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// Regression tests for patches that do not fit where they are applied
// (kloak#383 phase 0): a placeholder bpf_xor_path cannot read whole.

// prescanChunkLen is MAX_DATA_SIZE in tls_uprobe.c: the bytes prescan_chunk
// reads per chunk.
const prescanChunkLen = prescanChunkStride + secrets.ShadowPrefixLen - 1

// xorPathFixture is the Go crypto/tls Write uprobe attached to this process,
// with bpf_xor_path in its tail-call slot, one secret this process's cgroup
// is bound to, and a TLS server to write to (see prescanWrite).
type xorPathFixture struct {
	objs   *tlsuprobeObjects
	addr   string
	secret secrets.Secret
}

func newXorPathFixture(t *testing.T) *xorPathFixture {
	t.Helper()
	objs := loadTestObjects(t)
	cgroupID := selfCgroupID(t)
	if err := objs.ProgArray.Put(uint32(1), uint32(objs.BpfXorPath.FD())); err != nil {
		t.Fatal(err)
	}

	const owner, real = "ns/bounds", "REAL-BOUNDS-VALUE-0123"
	gen := secrets.NewShadowGenerator(nil, testLog())
	shadow, err := gen.Generate(len(real), secrets.HuffmanBits(real), owner, 20)
	if err != nil {
		t.Fatal(err)
	}
	s := secrets.Secret{OwnerID: owner, Key: "value", Real: real, Shadow: shadow}
	snapshot := []secrets.Secret{s}
	if _, err := applySecrets(objs.SecretMap, snapshot, testLog()); err != nil {
		t.Fatal(err)
	}
	bindings := map[string]podBinding{"uid": {pod: "ns/client", cgroupIDs: []uint64{cgroupID}, refs: []secrets.Ref{{OwnerID: owner}}}}
	if err := syncSecretACL(objs.SecretAcl, snapshot, bindings, true, testLog()); err != nil {
		t.Fatal(err)
	}

	exe, offset := goTLSWriteOffset(t)
	ex, err := link.OpenExecutable(exe)
	if err != nil {
		t.Fatal(err)
	}
	up, err := ex.Uprobe("", objs.BpfUprobeGoTlsWrite, &link.UprobeOptions{Address: offset, PID: os.Getpid()})
	if err != nil {
		t.Skipf("cannot attach the Go TLS uprobe: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	return &xorPathFixture{objs: objs, addr: startTLSServer(t), secret: s}
}

// stagedPatch is a patch of xor_pending.
type stagedPatch struct {
	offset, len uint32
	delta       []byte
}

// stagedPatch returns the only patch the uprobe staged in xor_pending for
// this process's last write.
func (f *xorPathFixture) stagedPatch(t *testing.T) stagedPatch {
	t.Helper()
	var v tlsuprobeXorPendingVal
	if err := f.objs.XorPending.Lookup(uint32(os.Getpid()), &v); err != nil {
		t.Fatalf("no staged patch: %v", err)
	}
	if v.PatchCount != 1 {
		t.Fatalf("%d staged patches, want 1", v.PatchCount)
	}
	p := v.Patches[0]
	return stagedPatch{offset: p.SecretOffset, len: p.SecretLen, delta: p.XorDelta[:]}
}

// checkDelta checks that a staged patch is the secret's at offset off: its
// delta is shadow XOR real over the placeholder, and zero past it.
func (f *xorPathFixture) checkDelta(t *testing.T, p stagedPatch, off int) {
	t.Helper()
	s := f.secret
	if p.offset != uint32(off) || p.len != uint32(len(s.Real)) {
		t.Fatalf("patch at %d, %d bytes; want %d, %d", p.offset, p.len, off, len(s.Real))
	}
	for i, b := range p.delta {
		want := byte(0)
		if i < len(s.Real) {
			want = s.Shadow[i] ^ s.Real[i]
		}
		if b != want {
			t.Fatalf("delta byte %d is %#x, want %#x", i, b, want)
		}
	}
}

// pagePresent reports whether the page holding addr is mapped in this
// process (/proc/self/pagemap: bit 63 of its entry).
func pagePresent(t *testing.T, addr uintptr) bool {
	t.Helper()
	f, err := os.Open("/proc/self/pagemap")
	if err != nil {
		t.Skipf("pagemap: %v", err)
	}
	defer func() { _ = f.Close() }()
	var e [8]byte
	if _, err := f.ReadAt(e[:], int64(addr/uintptr(os.Getpagesize()))*8); err != nil {
		t.Skipf("pagemap: %v", err)
	}
	return binary.LittleEndian.Uint64(e[:])>>63 == 1
}

// unmappedTail returns payload in shared memory: its first onFirst bytes at
// the end of one page, mapped, and the rest at the start of the next page,
// whose contents are there but which is not mapped yet. A BPF program cannot
// read it (it cannot fault the page in); the TLS library's read of the
// buffer, after the uprobe, maps it.
func unmappedTail(t *testing.T, payload []byte, onFirst int) []byte {
	t.Helper()
	pg := os.Getpagesize()
	fd, err := unix.MemfdCreate("kloak-bounds", 0)
	if err != nil {
		t.Skipf("memfd: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Ftruncate(fd, int64(2*pg)); err != nil {
		t.Fatal(err)
	}
	// The second page's bytes go in through the file, which maps nothing.
	if _, err := unix.Pwrite(fd, payload[onFirst:], int64(pg)); err != nil {
		t.Fatal(err)
	}
	m, err := unix.Mmap(fd, 0, 2*pg, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Munmap(m) })
	// The first page's through the mapping: a write fault maps that page
	// alone (a read fault would map the pages around it).
	copy(m[pg-onFirst:pg], payload[:onFirst])
	if !pagePresent(t, uintptr(unsafe.Pointer(&m[pg-1]))) || pagePresent(t, uintptr(unsafe.Pointer(&m[pg]))) {
		t.Skip("the kernel did not map exactly the first page")
	}
	return m[pg-onFirst : pg+len(payload)-onFirst]
}

// TestXorPathShadowRead checks that bpf_xor_path reads a placeholder's own
// bytes, and nothing past them. The write's buffer ends on a page that is
// not mapped yet, as a buffer of the app can end before a page the process
// never touched (or that was swapped out): the uprobe cannot read it.
func TestXorPathShadowRead(t *testing.T) {
	f := newXorPathFixture(t)
	shadow := f.secret.Shadow
	// The write's first prescanChunkLen bytes are prescan_chunk's first
	// chunk, on the first page: it finds the key of a placeholder starting
	// there. The second chunk reaches the next page and reads nothing.
	const onFirst = prescanChunkLen
	payload := bytes.Repeat([]byte{'.'}, onFirst+64)

	t.Run("ends before an unmapped page", func(t *testing.T) {
		// The read of the placeholder stays on the mapped page; one of
		// SECRET_MAX_LEN bytes would reach the next and fail.
		p := bytes.Clone(payload)
		off := onFirst - len(shadow)
		copy(p[off:], shadow)
		_ = prescanWrite(t, f.objs, f.addr, unmappedTail(t, p, onFirst))
		f.checkDelta(t, f.stagedPatch(t), off)
	})

	t.Run("runs into an unmapped page", func(t *testing.T) {
		// The key is on the mapped page, the rest of the placeholder on the
		// next: it is skipped and counted, not patched with the delta the
		// zeros of a failed read give (real itself, so that the peer would
		// get shadow XOR real).
		p := bytes.Clone(payload)
		off := onFirst - secrets.ShadowPrefixLen - 4
		copy(p[off:], shadow)
		buf := unmappedTail(t, p, onFirst)

		failed := debugCounter(t, f.objs, "xor_shadow_read_fail")
		matched := debugCounter(t, f.objs, "xor_prescan_match")
		if got := prescanWrite(t, f.objs, f.addr, buf); got != nil {
			t.Errorf("staged %v for a placeholder it could not read", got)
		}
		if d := debugCounter(t, f.objs, "xor_prescan_match") - matched; d != 1 {
			t.Fatalf("xor_prescan_match +%d, want +1", d)
		}
		if d := debugCounter(t, f.objs, "xor_shadow_read_fail") - failed; d != 1 {
			t.Errorf("xor_shadow_read_fail +%d, want +1", d)
		}

		// The TLS library's read mapped the page: the same write is patched.
		_ = prescanWrite(t, f.objs, f.addr, buf)
		f.checkDelta(t, f.stagedPatch(t), off)
	})
}
