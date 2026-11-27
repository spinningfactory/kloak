//go:build linux

package ebpf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/cgroups"
)

// The GHASH engine through tc_egress_patch and its tc_ghash_update tail call
// (spinningfactory/kloak#383): records patched by tc must decrypt, with Go's
// GCM, to the real values under their recomputed tags.

var (
	ghashSrc = netip.MustParseAddr("10.42.0.7")
	ghashDst = netip.MustParseAddr("10.43.0.30")
)

// ghashConn is a TLS connection's record protection as tc sees it: an
// AES-GCM key (its H in tls_conn_state) and the record layout of TLS 1.3 or
// TLS 1.2 (an 8-byte explicit nonce after the header).
type ghashConn struct {
	aead  cipher.AEAD
	h     [16]byte
	tls12 bool
	salt  []byte // TLS 1.2's implicit nonce
	ck    tlsuprobeTlsConnKey
}

func newGhashConn(t *testing.T, objs *tlsuprobeObjects, rng *rand.Rand, keyLen int, tls12 bool, ck tlsuprobeTlsConnKey) *ghashConn {
	t.Helper()
	block, err := aes.NewCipher(randBytes(rng, keyLen))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	c := &ghashConn{aead: aead, tls12: tls12, salt: randBytes(rng, 4), ck: ck}
	block.Encrypt(c.h[:], make([]byte, 16))
	cs := tlsuprobeTlsConnState{GhashH: c.h, CipherType: 1}
	if tls12 {
		cs.NonceLen = 8
	}
	if err := objs.TlsConnState.Update(&ck, &cs, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	return c
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// seal returns the record carrying pt, and a function that decrypts the
// record as it left tc.
func (c *ghashConn) seal(rng *rand.Rand, pt []byte) ([]byte, func([]byte) ([]byte, error)) {
	if c.tls12 {
		explicit := randBytes(rng, 8)
		nonce := append(append([]byte{}, c.salt...), explicit...)
		aad := make([]byte, 13)
		binary.BigEndian.PutUint64(aad, rng.Uint64()) // sequence number
		aad[8], aad[9], aad[10] = 0x17, 0x03, 0x03
		binary.BigEndian.PutUint16(aad[11:], uint16(len(pt)))
		hdr := []byte{0x17, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(hdr[3:], uint16(8+len(pt)+c.aead.Overhead()))
		rec := append(append(hdr, explicit...), c.aead.Seal(nil, nonce, pt, aad)...)
		return rec, func(r []byte) ([]byte, error) { return c.aead.Open(nil, nonce, r[13:], aad) }
	}
	nonce := randBytes(rng, 12)
	inner := append(append([]byte{}, pt...), 0x17) // TLS 1.3 inner content type
	hdr := []byte{0x17, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+c.aead.Overhead()))
	rec := append(append([]byte{}, hdr...), c.aead.Seal(nil, nonce, inner, hdr)...)
	return rec, func(r []byte) ([]byte, error) {
		inner, err := c.aead.Open(nil, nonce, r[5:], r[:5])
		if err != nil {
			return nil, err
		}
		return inner[:len(inner)-1], nil
	}
}

type ghashPatch struct{ off, n int }

// stage stores the tc_pending entry of a write of pt (anchored at TCP
// sequence number 1000) whose placeholders, at patches, are to become real,
// and returns pt as it must decrypt after tc.
func (c *ghashConn) stage(t *testing.T, objs *tlsuprobeObjects, rng *rand.Rand, dk tlsuprobeTcDestKey, pt []byte, patches []ghashPatch) []byte {
	t.Helper()
	var pv tlsuprobeTcPendingVal
	pv.Tgid, pv.SslPtr, pv.Active = c.ck.Tgid, c.ck.SslPtr, 1
	pv.PatchCount = uint32(len(patches))
	pv.PlaintextLen = uint32(len(pt))
	pv.WriteSeq = 1000
	pv.CreatedAt = monotonicNow(t)
	want := append([]byte{}, pt...)
	for i, p := range patches {
		real := randBytes(rng, p.n)
		pv.Patches[i].SecretOffset = uint32(p.off)
		pv.Patches[i].SecretLen = uint32(p.n)
		for j := range real {
			pv.Patches[i].XorDelta[j] = pt[p.off+j] ^ real[j]
		}
		copy(want[p.off:], real)
	}
	if err := objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	return want
}

// ghashFixture is one loaded copy of the objects, with the tail call wired.
type ghashFixture struct {
	objs     *tlsuprobeObjects
	cgroupID uint64
	rng      *rand.Rand
	sport    uint16
}

func loadGhashFixture(t *testing.T) *ghashFixture {
	t.Helper()
	objs := loadTestObjects(t)
	if err := objs.TcProgArray.Put(uint32(0), uint32(objs.TcGhashUpdate.FD())); err != nil {
		t.Fatal(err)
	}
	return &ghashFixture{objs: objs, cgroupID: selfCgroupID(t), rng: rand.New(rand.NewPCG(383, 7)), sport: 42000}
}

// destKey returns the tc_pending key of a new connection (a source port of
// its own, so that no deferred tag of another case is in its way).
func (f *ghashFixture) destKey() (tlsuprobeTcDestKey, uint16) {
	f.sport++
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], f.sport)
	return tlsuprobeTcDestKey{DstIp: ghashDst.As16(), SrcPort: binary.NativeEndian.Uint16(port[:]), CgroupId: f.cgroupID}, f.sport
}

// patchRecord sends the record through tc in segments of at most seg bytes
// (TCP sequence numbers from 1000), and returns the record as it left.
func (f *ghashFixture) patchRecord(t *testing.T, sport uint16, rec []byte, seg int) []byte {
	t.Helper()
	var out []byte
	for at := 0; at < len(rec); at += seg {
		end := min(at+seg, len(rec))
		frame := runTC(t, f.objs.TcEgressPatch, tcpFrame(ghashSrc, ghashDst, sport, 443, 1000+uint32(at), rec[at:end]))
		out = append(out, frame[l4Offset(frame)+20:]...)
	}
	return out
}

func (f *ghashFixture) check(t *testing.T, c *ghashConn, ptLen int, patches []ghashPatch, seg int) {
	t.Helper()
	dk, sport := f.destKey()
	defer func() {
		_ = f.objs.TcPending.Delete(&dk)
		_ = f.objs.TcTagPending.Delete(&dk)
	}()
	pt := randBytes(f.rng, ptLen)
	rec, open := c.seal(f.rng, pt)
	want := c.stage(t, f.objs, f.rng, dk, pt, patches)
	got, err := open(f.patchRecord(t, sport, rec, seg))
	if err != nil {
		t.Fatalf("pt %d, patches %v: record does not decrypt: %v", ptLen, patches, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("pt %d, patches %v: plaintext is not the real values", ptLen, patches)
	}
}

// TestTCGhashPatchMatrix patches one placeholder of every length up to
// SECRET_MAX_LEN at every alignment, at the start and at the end of records
// of several sizes, for TLS 1.3 and TLS 1.2 with AES-128 and AES-256.
func TestTCGhashPatchMatrix(t *testing.T) {
	f := loadGhashFixture(t)
	for _, tls12 := range []bool{false, true} {
		for _, keyLen := range []int{16, 32} {
			t.Run(fmt.Sprintf("tls12=%v/aes%d", tls12, keyLen*8), func(t *testing.T) {
				c := newGhashConn(t, f.objs, f.rng, keyLen, tls12, tlsuprobeTlsConnKey{Tgid: 4243, SslPtr: 0x7f00beef0000})
				for _, ptLen := range []int{30, 129, 1000, 3000} {
					for _, n := range []int{1, 8, 15, 16, 17, 24, 64, 127, 128} {
						if n > ptLen {
							continue
						}
						for a := range 16 {
							if a+n <= ptLen {
								f.check(t, c, ptLen, []ghashPatch{{a, n}}, 1<<16)
							}
							if off := ptLen - n - a; off >= 0 {
								f.check(t, c, ptLen, []ghashPatch{{off, n}}, 1<<16)
							}
						}
					}
				}
			})
		}
	}
}

// TestTCGhashMultiplePatches patches up to XOR_MAX_PATCHES placeholders in
// one record, some sharing a block.
func TestTCGhashMultiplePatches(t *testing.T) {
	f := loadGhashFixture(t)
	for _, tls12 := range []bool{false, true} {
		c := newGhashConn(t, f.objs, f.rng, 16, tls12, tlsuprobeTlsConnKey{Tgid: 4244, SslPtr: 0x7f00beef1000})
		for _, patches := range [][]ghashPatch{
			{{2, 24}, {40, 24}},
			{{0, 8}, {8, 8}},           // two halves of block 0
			{{3, 5}, {9, 4}, {14, 30}}, // three patches across blocks 0..2
			{{0, 128}, {128, 128}, {300, 100}, {2900, 99}},
			{{1000, 17}, {1017, 1}, {1018, 128}, {1146, 50}},
		} {
			f.check(t, c, 3000, patches, 1<<16)
		}
		for range 50 {
			var patches []ghashPatch
			at := f.rng.IntN(64)
			for len(patches) < 4 {
				n := 1 + f.rng.IntN(128)
				if at+n > 3000 {
					break
				}
				patches = append(patches, ghashPatch{at, n})
				at += n + f.rng.IntN(200) // 0: adjacent, often in the same block
			}
			f.check(t, c, 3000, patches, 1<<16)
		}
	}
}

// TestTCGhashLargeRecords patches records up to the largest TLS record
// (16384 bytes of plaintext), whose tag comes in a later segment than the
// patch (the deferred tag): the exponents of the blocks reach the 11 bits
// the engine's powers cover.
func TestTCGhashLargeRecords(t *testing.T) {
	f := loadGhashFixture(t)
	for _, tls12 := range []bool{false, true} {
		c := newGhashConn(t, f.objs, f.rng, 32, tls12, tlsuprobeTlsConnKey{Tgid: 4245, SslPtr: 0x7f00beef2000})
		for _, ptLen := range []int{4000, 16384} {
			for _, patches := range [][]ghashPatch{
				{{0, 128}},
				{{7, 24}, {1500, 128}, {2800, 1}},
				{{2700, 128}},
			} {
				f.check(t, c, ptLen, patches, 2900)
			}
		}
	}
}

// TestTCGhashKeyCache checks the per-connection H state: built once per H
// (its table and powers are H's), and rebuilt when the connection's H
// changes (a TLS 1.3 KeyUpdate, or an ssl_ptr reused by a new connection).
func TestTCGhashKeyCache(t *testing.T) {
	f := loadGhashFixture(t)
	ck := tlsuprobeTlsConnKey{Tgid: 4246, SslPtr: 0x7f00beef3000}
	for range 3 {
		c := newGhashConn(t, f.objs, f.rng, 16, false, ck) // a new H for the same connection
		f.check(t, c, 500, []ghashPatch{{3, 24}}, 1<<16)
		f.check(t, c, 500, []ghashPatch{{100, 128}}, 1<<16) // from the cache

		var ks tlsuprobeGhashKeyState
		if err := f.objs.GhashKeyCache.Lookup(&ck, &ks); err != nil {
			t.Fatal(err)
		}
		hi, lo := binary.BigEndian.Uint64(c.h[:8]), binary.BigEndian.Uint64(c.h[8:])
		if ks.H.Hi != hi || ks.H.Lo != lo {
			t.Fatalf("cached H %016x%016x, want %x", ks.H.Hi, ks.H.Lo, c.h)
		}
		elem := func(hi, lo uint64) [16]byte {
			var b [16]byte
			binary.BigEndian.PutUint64(b[:8], hi)
			binary.BigEndian.PutUint64(b[8:], lo)
			return b
		}
		for i, p := range ks.Pow {
			if got, want := elem(p.Hi, p.Lo), GF128HPower(c.h, 1<<i); got != want {
				t.Errorf("pow[%d] = %x, want H^%d = %x", i, got, 1<<i, want)
			}
		}
		for n, m := range ks.Ht.M {
			var e [16]byte
			e[0] = byte(n << 4)
			if got, want := elem(m.Hi, m.Lo), GF128Mul(e, c.h); got != want {
				t.Errorf("table[%d] = %x, want %x", n, got, want)
			}
		}
	}
}

// TestTCGhashRefusesPatchPastCiphertext checks that a staged patch the
// engine can't hash (running past the record's ciphertext, into the tag) is
// not written: the record leaves as the TLS library wrote it.
func TestTCGhashRefusesPatchPastCiphertext(t *testing.T) {
	f := loadGhashFixture(t)
	c := newGhashConn(t, f.objs, f.rng, 16, false, tlsuprobeTlsConnKey{Tgid: 4247, SslPtr: 0x7f00beef4000})
	dk, sport := f.destKey()
	defer func() { _ = f.objs.TcPending.Delete(&dk) }()
	pt := randBytes(f.rng, 100)
	rec, open := c.seal(f.rng, pt)
	pv := tlsuprobeTcPendingVal{Tgid: c.ck.Tgid, SslPtr: c.ck.SslPtr, PatchCount: 1, Active: 1, PlaintextLen: 100, WriteSeq: 1000}
	pv.CreatedAt = monotonicNow(t)
	pv.Patches[0].SecretOffset, pv.Patches[0].SecretLen = 90, 24 // 101 ciphertext bytes
	for i := range 24 {
		pv.Patches[0].XorDelta[i] = 0x5a
	}
	if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	out := f.patchRecord(t, sport, rec, 1<<16)
	if !bytes.Equal(out, rec) {
		got, err := open(out)
		t.Fatalf("record changed (decrypts: %v, %v)", err == nil, bytes.Equal(got, pt))
	}
}

// BenchmarkTCGhash reports the kernel's run time of tc_egress_patch and its
// tc_ghash_update tail call (BPF_PROG_TEST_RUN) for one record: placeholders
// of 24 to 4 x 128 bytes, in records of 100 to 3000 bytes, with the
// connection's H state cached or not. Run as root:
//
//	go test -exec "sudo -E" -run '^$' -bench TCGhash ./pkg/ebpf/
func BenchmarkTCGhash(b *testing.B) {
	objs := &tlsuprobeObjects{}
	if err := loadTlsuprobeObjects(objs, nil); err != nil {
		var ve *ciliumebpf.VerifierError
		if errors.As(err, &ve) {
			b.Fatalf("the verifier rejected a program: %-20v", ve)
		}
		b.Skipf("eBPF objects not available: %v", err)
	}
	defer objs.Close()
	if err := objs.TcProgArray.Put(uint32(0), uint32(objs.TcGhashUpdate.FD())); err != nil {
		b.Fatal(err)
	}
	cgroupID, err := benchCgroupID()
	if err != nil {
		b.Skipf("cgroup ID: %v", err)
	}
	rng := rand.New(rand.NewPCG(383, 8))
	ck := tlsuprobeTlsConnKey{Tgid: 4248, SslPtr: 0x7f00beef5000}
	block, _ := aes.NewCipher(randBytes(rng, 16))
	aead, _ := cipher.NewGCM(block)
	var h [16]byte
	block.Encrypt(h[:], make([]byte, 16))
	cs := tlsuprobeTlsConnState{GhashH: h, CipherType: 1}
	if err := objs.TlsConnState.Update(&ck, &cs, ciliumebpf.UpdateAny); err != nil {
		b.Fatal(err)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 43000)
	dk := tlsuprobeTcDestKey{DstIp: ghashDst.As16(), SrcPort: binary.NativeEndian.Uint16(port[:]), CgroupId: cgroupID}

	for _, c := range []struct {
		name    string
		ptLen   int
		patches []ghashPatch
	}{
		{"24B-in-100B", 100, []ghashPatch{{2, 24}}},
		{"128B-in-1000B", 1000, []ghashPatch{{2, 128}}},
		{"128B-at-start-of-3000B", 3000, []ghashPatch{{2, 128}}},
		{"4x128B-in-3000B", 3000, []ghashPatch{{0, 128}, {500, 128}, {1000, 128}, {2800, 128}}},
	} {
		pt := randBytes(rng, c.ptLen)
		nonce := randBytes(rng, 12)
		inner := append(append([]byte{}, pt...), 0x17)
		hdr := []byte{0x17, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+aead.Overhead()))
		rec := append(append([]byte{}, hdr...), aead.Seal(nil, nonce, inner, hdr)...)
		frame := tcpFrame(ghashSrc, ghashDst, 43000, 443, 1000, rec)
		var pv tlsuprobeTcPendingVal
		pv.Tgid, pv.SslPtr, pv.Active, pv.WriteSeq = ck.Tgid, ck.SslPtr, 1, 1000
		pv.PatchCount, pv.PlaintextLen = uint32(len(c.patches)), uint32(c.ptLen)
		for i, p := range c.patches {
			pv.Patches[i].SecretOffset, pv.Patches[i].SecretLen = uint32(p.off), uint32(p.n)
			for j := range p.n {
				pv.Patches[i].XorDelta[j] = byte(j + 1)
			}
		}
		for _, cached := range []bool{true, false} {
			b.Run(fmt.Sprintf("%s/cached=%v", c.name, cached), func(b *testing.B) {
				var total time.Duration
				for range b.N {
					pv.CreatedAt = benchMonotonicNow()
					if err := objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
						b.Fatal(err)
					}
					if !cached {
						_ = objs.GhashKeyCache.Delete(&ck)
					}
					_, d, err := objs.TcEgressPatch.Benchmark(frame, 1, nil)
					if err != nil {
						b.Fatal(err)
					}
					total += d
				}
				b.ReportMetric(float64(total.Nanoseconds())/float64(b.N), "kernel-ns/op")
			})
		}
	}
}

// benchCgroupID is selfCgroupID for a benchmark.
func benchCgroupID() (uint64, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return cgroups.GetCgroupInodeFromPath(filepath.Join("/sys/fs/cgroup", p))
		}
	}
	return 0, errors.New("not on cgroup v2")
}

// benchMonotonicNow is monotonicNow for a benchmark.
func benchMonotonicNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}
