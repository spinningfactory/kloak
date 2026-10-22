//go:build linux

package ebpf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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

// TestTCEgressPatch runs tc_egress_patch, and its tc_ghash_update tail call,
// on a TLS 1.3 AES-128-GCM record carrying a placeholder, sent over IPv4 and
// over IPv6: the record must decrypt to the real value under its recomputed
// tag, and the tc_pending entry is used up. BPF_PROG_RUN gives the skb a
// socket of its own, with the packet's addresses, in this process's cgroup:
// the program keys on those.
func TestTCEgressPatch(t *testing.T) {
	objs := loadTestObjects(t)
	cgroupID := selfCgroupID(t)
	if err := objs.TcProgArray.Put(uint32(0), uint32(objs.TcGhashUpdate.FD())); err != nil {
		t.Fatal(err)
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
	const tgid, sslPtr = 4242, 0x7f00dead0000
	ck := tlsuprobeTlsConnKey{Tgid: tgid, SslPtr: sslPtr}
	cs := tlsuprobeTlsConnState{GhashH: h, CipherType: 1, NonceLen: 0} // AES-GCM, TLS 1.3
	if err := objs.TlsConnState.Update(&ck, &cs, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	const shadow, real = "kl::Xq7pL0vR2mN9sT4wY6zB", "REAL-TC-PATCH-KEY-123456" // same length
	plaintext := []byte("S=" + shadow + "\n")
	nonce := bytes.Repeat([]byte{0x07}, 12)
	inner := append(append([]byte{}, plaintext...), 0x17) // TLS 1.3 inner content type
	hdr := []byte{0x17, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+aead.Overhead()))
	record := append(append([]byte{}, hdr...), aead.Seal(nil, nonce, inner, hdr)...)

	for _, c := range []struct {
		name     string
		src, dst netip.Addr
	}{
		{"IPv4", netip.MustParseAddr("10.42.0.7"), netip.MustParseAddr("10.43.0.20")},
		{"IPv6", netip.MustParseAddr("fd42::7"), netip.MustParseAddr("fd43::20")},
	} {
		t.Run(c.name, func(t *testing.T) {
			const sport = 40001
			var port [2]byte
			binary.BigEndian.PutUint16(port[:], sport)
			// SrcPort holds the port in network byte order.
			dk := tlsuprobeTcDestKey{DstIp: c.dst.As16(), SrcPort: binary.NativeEndian.Uint16(port[:]), CgroupId: cgroupID}
			var pv tlsuprobeTcPendingVal
			pv.Tgid, pv.SslPtr, pv.PatchCount, pv.Active = tgid, sslPtr, 1, 1
			pv.PlaintextLen = uint32(len(plaintext))
			pv.Patches[0].SecretOffset = 2
			pv.Patches[0].SecretLen = uint32(len(shadow))
			for i := range shadow {
				pv.Patches[0].XorDelta[i] = shadow[i] ^ real[i]
			}
			if err := objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}

			// Another connection's packet (other source port) is left alone.
			other := tcpFrame(c.src, c.dst, sport+1, 443, 1000, record)
			if out := runTC(t, objs.TcEgressPatch, other); !bytes.Equal(out, other) {
				t.Error("another connection's record patched")
			}

			out := runTC(t, objs.TcEgressPatch, tcpFrame(c.src, c.dst, sport, 443, 1000, record))
			got := out[l4Offset(out)+20:]
			pt, err := aead.Open(nil, nonce, got[5:], got[:5])
			if err != nil {
				t.Fatalf("patched record does not decrypt: %v", err)
			}
			if want := append([]byte("S="+real+"\n"), 0x17); !bytes.Equal(pt, want) {
				t.Errorf("plaintext %q, want %q", pt, want)
			}
			if err := objs.TcPending.Lookup(&dk, &pv); err != nil || pv.Active != 0 {
				t.Errorf("tc_pending entry after the patch: active %d, %v", pv.Active, err)
			}
		})
	}
}
