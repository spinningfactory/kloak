//go:build linux

package ebpf

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// Regression tests for patches that do not fit where they are applied
// (kloak#383 phase 0): a placeholder bpf_xor_path cannot read whole, one cut
// off at the end of its write, and a patch tc_egress_patch would apply past
// its record's application data.

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

// TestXorPathPlaceholderCut checks that a placeholder cut off at the end of
// its write (the prescan finds its key, the rest is in the app's next write)
// is skipped and counted, not staged at its full length: tc would patch it
// past the write's plaintext, over the record's content type and tag.
func TestXorPathPlaceholderCut(t *testing.T) {
	f := newXorPathFixture(t)
	shadow := f.secret.Shadow
	prefix := []byte("X-Secret: ")

	cut := debugCounter(t, f.objs, "xor_placeholder_cut")
	matched := debugCounter(t, f.objs, "xor_prescan_match")
	if got := prescanWrite(t, f.objs, f.addr, append(bytes.Clone(prefix), shadow[:len(shadow)-5]...)); got != nil {
		t.Errorf("staged %v for a placeholder cut off at the end of the write", got)
	}
	if d := debugCounter(t, f.objs, "xor_prescan_match") - matched; d != 1 {
		t.Fatalf("xor_prescan_match +%d, want +1", d)
	}
	if d := debugCounter(t, f.objs, "xor_placeholder_cut") - cut; d != 1 {
		t.Errorf("xor_placeholder_cut +%d, want +1", d)
	}

	// Ending with the write, it is patched.
	_ = prescanWrite(t, f.objs, f.addr, append(bytes.Clone(prefix), shadow...))
	f.checkDelta(t, f.stagedPatch(t), len(prefix))
}

// tlsRecord seals plaintext into an AES-GCM application_data record with
// f's key: TLS 1.3 (nonceLen 0: the inner content type follows the
// plaintext, the nonce is implicit) or TLS 1.2 (nonceLen 8: an explicit
// nonce precedes the ciphertext). open decrypts it from a copy of its bytes.
func tlsRecord(t *testing.T, f *tcPatchFixture, plaintext []byte, nonceLen int, nonceByte byte) (record []byte, open func([]byte) ([]byte, error)) {
	t.Helper()
	inner := bytes.Clone(plaintext)
	if nonceLen == 0 {
		inner = append(inner, 0x17)
	}
	nonce := bytes.Repeat([]byte{nonceByte}, 12)
	hdr := []byte{0x17, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:], uint16(nonceLen+len(inner)+f.aead.Overhead()))
	// The additional data only has to be the same both ways: tc never
	// recomputes it.
	record = append(append(bytes.Clone(hdr), nonce[12-nonceLen:]...), f.aead.Seal(nil, nonce, inner, hdr)...)
	return record, func(rec []byte) ([]byte, error) {
		return f.aead.Open(nil, nonce, rec[5+nonceLen:], rec[:5])
	}
}

// TestTCEgressPatchBounds checks that tc_egress_patch applies a patch only
// when all of it lies in its record's application data (tc_patch_fits): up
// to the last data byte, not over a TLS 1.3 record's inner content type, a
// TLS 1.2 record's tag, nor past the record, into the next one (a write
// larger than one record, whose patch is in a later record). A refused
// patch is counted, leaves the record as the TLS library wrote it, and does
// not stop the write's other patches.
func TestTCEgressPatchBounds(t *testing.T) {
	f := newTCPatchFixture(t, true)
	src, dst := netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.20")

	// A TLS 1.2 connection: the same key, an explicit nonce.
	const ssl12 = fixtureSSLPtr + 0x1000
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x42}, 16)) // newTCPatchFixture's key
	if err != nil {
		t.Fatal(err)
	}
	var h [16]byte
	block.Encrypt(h[:], make([]byte, 16))
	ck := tlsuprobeTlsConnKey{Tgid: fixtureTgid, SslPtr: ssl12}
	cs := tlsuprobeTlsConnState{GhashH: h, CipherType: 1, NonceLen: 8}
	if err := f.objs.TlsConnState.Update(&ck, &cs, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	// The write is "S=" + shadow + "\n"; the patch replaces the shadow, and
	// with extra bytes of delta it also covers what follows: the newline,
	// then the content type (TLS 1.3) or the tag (TLS 1.2).
	n := len(fixtureShadow)
	newline := []byte("S=" + fixtureReal + "!")
	for i, c := range []struct {
		name     string
		nonceLen int
		extra    int    // patch bytes past the shadow
		want     []byte // the record's plaintext after tc; nil: unchanged
	}{
		{"TLS 1.3: up to the last data byte", 0, 1, append(bytes.Clone(newline), 0x17)},
		{"TLS 1.3: over the inner content type", 0, 2, nil},
		{"TLS 1.2: up to the last byte", 8, 1, newline},
		{"TLS 1.2: into the tag", 8, 2, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			sport := uint16(41000 + i)
			record, open := tlsRecord(t, f, f.plaintext, c.nonceLen, 0x07)
			pv := f.pending(t, 1000)
			if c.nonceLen == 8 {
				pv.SslPtr = ssl12
			}
			pv.Patches[0].SecretLen = uint32(n + c.extra)
			pv.Patches[0].XorDelta[n] = '\n' ^ '!'
			pv.Patches[0].XorDelta[n+1] = 0x01 // the content type 0x17 -> 0x16, or a tag byte
			dk := f.destKey(dst, sport)
			if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}

			refused := debugCounter(t, f.objs, "tc_patch_out_of_record")
			in := tcpFrame(src, dst, sport, 443, 1000, record)
			out := runTC(t, f.objs.TcEgressPatch, in)
			d := debugCounter(t, f.objs, "tc_patch_out_of_record") - refused
			if c.want == nil {
				if !bytes.Equal(out, in) {
					t.Error("a patch past the application data was applied")
				}
				if d != 1 {
					t.Errorf("tc_patch_out_of_record +%d, want +1", d)
				}
				return
			}
			pt, err := open(out[l4Offset(out)+20:])
			if err != nil {
				t.Fatalf("record does not decrypt: %v", err)
			}
			if !bytes.Equal(pt, c.want) {
				t.Errorf("plaintext %q, want %q", pt, c.want)
			}
			if d != 0 {
				t.Errorf("tc_patch_out_of_record +%d, want +0", d)
			}
		})
	}

	t.Run("past the first record of the write", func(t *testing.T) {
		// A write larger than one record, anchored to its first: the
		// segment holds that record, then another. The write's first patch
		// is in the first record; its second is past it, in the write's
		// next record, which tc does not decrypt: it must not be XORed into
		// the second record's bytes at the first record's offsets.
		const sport = 41100
		first, openFirst := tlsRecord(t, f, f.plaintext, 0, 0x07)
		second, openSecond := tlsRecord(t, f, bytes.Repeat([]byte{'x'}, 60), 0, 0x08)
		pv := f.pending(t, 1000)
		pv.PlaintextLen += 100 // the write's other records
		pv.PatchCount = 2
		pv.Patches[1].SecretOffset = uint32(len(f.plaintext) + 10)
		pv.Patches[1].SecretLen = uint32(n)
		for i := 0; i < n; i++ {
			pv.Patches[1].XorDelta[i] = 0x5a
		}
		dk := f.destKey(dst, sport)
		if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}

		refused := debugCounter(t, f.objs, "tc_patch_out_of_record")
		out := runTC(t, f.objs.TcEgressPatch, tcpFrame(src, dst, sport, 443, 1000, append(bytes.Clone(first), second...)))
		payload := out[l4Offset(out)+20:]
		pt, err := openFirst(payload[:len(first)])
		if err != nil {
			t.Fatalf("first record does not decrypt: %v", err)
		}
		if want := append([]byte("S="+fixtureReal+"\n"), 0x17); !bytes.Equal(pt, want) {
			t.Errorf("first record %q, want %q", pt, want)
		}
		if _, err := openSecond(payload[len(first):]); err != nil {
			t.Errorf("second record changed: %v", err)
		}
		if d := debugCounter(t, f.objs, "tc_patch_out_of_record") - refused; d != 1 {
			t.Errorf("tc_patch_out_of_record +%d, want +1", d)
		}
	})
}
