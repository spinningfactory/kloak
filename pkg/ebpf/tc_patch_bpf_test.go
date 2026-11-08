//go:build linux

package ebpf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/spinningfactory/kloak/pkg/cgroups"
)

// tcpFrame wraps payload in Ethernet, IPv4 or IPv6 (by src's family) and TCP
// headers. The TCP checksum is left zero: tc_egress_patch, like the stack on
// a veth, leaves it to checksum offload.
func tcpFrame(src, dst netip.Addr, sport, dport uint16, seq uint32, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4 // data offset: 20 bytes
	tcp[13] = 0x18   // PSH, ACK
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[20:], payload)
	return ipFrame(src, dst, unix.IPPROTO_TCP, tcp)
}

// selfCgroupID returns the cgroup v2 ID of this process.
func selfCgroupID(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			id, err := cgroups.GetCgroupInodeFromPath(filepath.Join("/sys/fs/cgroup", p))
			if err != nil {
				t.Skipf("cgroup ID: %v", err)
			}
			return id
		}
	}
	t.Skip("not on cgroup v2")
	return 0
}

// monotonicNow returns CLOCK_MONOTONIC in nanoseconds: bpf_ktime_get_ns.
func monotonicNow(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Nano())
}

// tcPatchFixture is a TLS 1.3 AES-128-GCM record carrying a placeholder at
// offset 2 of its plaintext, and the connection state tc needs to patch it.
type tcPatchFixture struct {
	objs      *tlsuprobeObjects
	cgroupID  uint64
	aead      cipher.AEAD
	nonce     []byte
	plaintext []byte
	record    []byte
}

const (
	fixtureTgid, fixtureSSLPtr = 4242, 0x7f00dead0000
	fixtureShadow              = "kl::Xq7pL0vR2mN9sT4wY6zB"
	fixtureReal                = "REAL-TC-PATCH-KEY-123456" // same length
)

// newTCPatchFixture loads the objects and stores the connection's H. With
// tailCall, the tc_ghash_update tail call is wired as the manager wires it.
func newTCPatchFixture(t *testing.T, tailCall bool) *tcPatchFixture {
	t.Helper()
	objs := loadTestObjects(t)
	cgroupID := selfCgroupID(t)
	if tailCall {
		if err := objs.TcProgArray.Put(uint32(0), uint32(objs.TcGhashUpdate.FD())); err != nil {
			t.Fatal(err)
		}
	}

	key := bytes.Repeat([]byte{0x42}, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	var h [16]byte
	block.Encrypt(h[:], make([]byte, 16))
	ck := tlsuprobeTlsConnKey{Tgid: fixtureTgid, SslPtr: fixtureSSLPtr}
	cs := tlsuprobeTlsConnState{GhashH: h, CipherType: 1, NonceLen: 0} // AES-GCM, TLS 1.3
	if err := objs.TlsConnState.Update(&ck, &cs, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("S=" + fixtureShadow + "\n")
	nonce := bytes.Repeat([]byte{0x07}, 12)
	inner := append(append([]byte{}, plaintext...), 0x17) // TLS 1.3 inner content type
	hdr := []byte{0x17, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+aead.Overhead()))
	record := append(append([]byte{}, hdr...), aead.Seal(nil, nonce, inner, hdr)...)
	return &tcPatchFixture{objs: objs, cgroupID: cgroupID, aead: aead, nonce: nonce, plaintext: plaintext, record: record}
}

// destKey is the tc_pending key of a connection from sport to dst.
func (f *tcPatchFixture) destKey(dst netip.Addr, sport uint16) tlsuprobeTcDestKey {
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], sport)
	// SrcPort holds the port in network byte order.
	return tlsuprobeTcDestKey{DstIp: dst.As16(), SrcPort: binary.NativeEndian.Uint16(port[:]), CgroupId: f.cgroupID}
}

// pending is the tc_pending entry the tcp_sendmsg kprobe stages for the
// record's write, created now; writeSeq 0 is a memory-BIO write's.
func (f *tcPatchFixture) pending(t *testing.T, writeSeq uint32) tlsuprobeTcPendingVal {
	var pv tlsuprobeTcPendingVal
	pv.Tgid, pv.SslPtr, pv.PatchCount, pv.Active = fixtureTgid, fixtureSSLPtr, 1, 1
	pv.PlaintextLen = uint32(len(f.plaintext))
	pv.WriteSeq = writeSeq
	pv.CreatedAt = monotonicNow(t)
	pv.Patches[0].SecretOffset = 2
	pv.Patches[0].SecretLen = uint32(len(fixtureShadow))
	for i := range fixtureShadow {
		pv.Patches[0].XorDelta[i] = fixtureShadow[i] ^ fixtureReal[i]
	}
	return pv
}

// open decrypts the record in a TCP frame tc let through.
func (f *tcPatchFixture) open(t *testing.T, frame []byte) []byte {
	t.Helper()
	got := frame[l4Offset(frame)+20:]
	pt, err := f.aead.Open(nil, f.nonce, got[5:], got[:5])
	if err != nil {
		t.Fatalf("record does not decrypt: %v", err)
	}
	return pt
}

// TestTCEgressPatch runs tc_egress_patch, and its tc_ghash_update tail call,
// on a TLS 1.3 AES-128-GCM record carrying a placeholder, sent over IPv4 and
// over IPv6: the record must decrypt to the real value under its recomputed
// tag, and the tc_pending entry is used up. BPF_PROG_RUN gives the skb a
// socket of its own, with the packet's addresses, in this process's cgroup:
// the program keys on those.
func TestTCEgressPatch(t *testing.T) {
	f := newTCPatchFixture(t, true)
	for _, c := range []struct {
		name     string
		src, dst netip.Addr
		writeSeq uint32
	}{
		{"IPv4", netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.20"), 1000},
		{"IPv6", netip.MustParseAddr("fd42::7"), netip.MustParseAddr("fd43::20"), 1000},
		{"memory BIO", netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.21"), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			const sport = 40001
			dk := f.destKey(c.dst, sport)
			pv := f.pending(t, c.writeSeq)
			if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}

			// Another connection's packet (other source port) is left alone.
			other := tcpFrame(c.src, c.dst, sport+1, 443, 1000, f.record)
			if out := runTC(t, f.objs.TcEgressPatch, other); !bytes.Equal(out, other) {
				t.Error("another connection's record patched")
			}

			out := runTC(t, f.objs.TcEgressPatch, tcpFrame(c.src, c.dst, sport, 443, 1000, f.record))
			if want := append([]byte("S="+fixtureReal+"\n"), 0x17); !bytes.Equal(f.open(t, out), want) {
				t.Errorf("plaintext %q, want %q", f.open(t, out), want)
			}
			if err := f.objs.TcPending.Lookup(&dk, &pv); err != nil || pv.Active != 0 {
				t.Errorf("tc_pending entry after the patch: active %d, %v", pv.Active, err)
			}
		})
	}
}

// TestTCEgressPatchLeavesRecordWithoutTag checks that tc_egress_patch writes
// nothing itself: when the tail call to tc_ghash_update fails (here: no
// program in the slot), the record leaves as the TLS library wrote it,
// placeholder and matching tag, not patched under a stale tag.
func TestTCEgressPatchLeavesRecordWithoutTag(t *testing.T) {
	f := newTCPatchFixture(t, false)
	src, dst := netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.20")
	dk := f.destKey(dst, 40001)
	pv := f.pending(t, 1000)
	if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	in := tcpFrame(src, dst, 40001, 443, 1000, f.record)
	if out := runTC(t, f.objs.TcEgressPatch, in); !bytes.Equal(out, in) {
		t.Fatal("record changed without its tag")
	}
}

// TestTCEgressPatchMemoryBIOExactRecord checks that a memory-BIO write
// (matched by record framing alone) is not patched into a record whose
// length does not fit its plaintext: it may be another write's. The entry
// waits for its own record.
func TestTCEgressPatchMemoryBIOExactRecord(t *testing.T) {
	f := newTCPatchFixture(t, true)
	src, dst := netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.20")
	dk := f.destKey(dst, 40001)
	pv := f.pending(t, 0)
	pv.PlaintextLen += 3 // the staged write was longer than this record
	if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	in := tcpFrame(src, dst, 40001, 443, 1000, f.record)
	if out := runTC(t, f.objs.TcEgressPatch, in); !bytes.Equal(out, in) {
		t.Error("another write's record patched")
	}
	if err := f.objs.TcPending.Lookup(&dk, &pv); err != nil || pv.Active != 1 {
		t.Errorf("tc_pending entry: active %d, %v; want it waiting", pv.Active, err)
	}

	// Anchored to its sequence number, a write larger than one record is
	// patched in its first record (the one the segment starts with).
	pv = f.pending(t, 1000)
	pv.PlaintextLen += 3
	if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if out := runTC(t, f.objs.TcEgressPatch, in); bytes.Equal(out, in) {
		t.Error("an anchored write larger than its record was not patched")
	}
}

// TestTCEgressPatchExpiry checks that a tc_pending entry no record used is
// dropped once older than its TTL, and that a deferred tag that can no
// longer be patched does not hold back the connection's next records.
func TestTCEgressPatchExpiry(t *testing.T) {
	f := newTCPatchFixture(t, true)
	src, dst := netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.20")
	const sport = 40001
	dk := f.destKey(dst, sport)
	in := tcpFrame(src, dst, sport, 443, 1000, f.record)

	for _, c := range []struct {
		name     string
		writeSeq uint32
		age      uint64
	}{
		{"memory BIO", 0, 3e9},   // > XOR_PENDING_TTL_NS
		{"anchored", 1000, 11e9}, // > TC_PENDING_TTL_NS
	} {
		t.Run(c.name, func(t *testing.T) {
			pv := f.pending(t, c.writeSeq)
			pv.CreatedAt -= c.age
			if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if out := runTC(t, f.objs.TcEgressPatch, in); !bytes.Equal(out, in) {
				t.Error("expired entry patched a record")
			}
			if err := f.objs.TcPending.Lookup(&dk, &pv); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
				t.Errorf("expired entry kept: %v", err)
			}
		})
	}

	for _, c := range []struct {
		name   string
		tagSeq uint32
		age    uint64
	}{
		{"expired", 5000, 11e9},
		{"segment past the tag", 900, 0},
		{"tag split across segments", 1000 + uint32(len(f.record)) - 8, 0},
	} {
		t.Run("deferred tag "+c.name, func(t *testing.T) {
			tv := tlsuprobeTcTagVal{TagTcpSeq: c.tagSeq, CreatedAt: monotonicNow(t) - c.age}
			if err := f.objs.TcTagPending.Update(&dk, &tv, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			pv := f.pending(t, 1000)
			if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			out := runTC(t, f.objs.TcEgressPatch, in)
			if want := append([]byte("S="+fixtureReal+"\n"), 0x17); !bytes.Equal(f.open(t, out), want) {
				t.Error("a stale deferred tag held back the next record's patch")
			}
			if err := f.objs.TcTagPending.Lookup(&dk, &tv); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
				t.Errorf("stale deferred tag kept: %v", err)
			}
		})
	}

	// A deferred tag in a later segment is waited for: this segment, a
	// continuation of its record, is left alone.
	t.Run("deferred tag in a later segment", func(t *testing.T) {
		tv := tlsuprobeTcTagVal{TagTcpSeq: 1000 + uint32(len(f.record)) + 100, CreatedAt: monotonicNow(t)}
		if err := f.objs.TcTagPending.Update(&dk, &tv, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		pv := f.pending(t, 1000)
		if err := f.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if out := runTC(t, f.objs.TcEgressPatch, in); !bytes.Equal(out, in) {
			t.Error("a continuation segment was patched")
		}
		if err := f.objs.TcTagPending.Lookup(&dk, &tv); err != nil {
			t.Errorf("deferred tag dropped: %v", err)
		}
		_ = f.objs.TcTagPending.Delete(&dk)
	})
}
