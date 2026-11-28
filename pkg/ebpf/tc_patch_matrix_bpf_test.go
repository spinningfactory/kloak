//go:build linux

package ebpf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
)

// maxPatchLen is the longest patch tc takes: SECRET_MAX_LEN, the size of a
// staged patch's XOR delta.
var maxPatchLen = len(tlsuprobeTcPendingVal{}.Patches[0].XorDelta)

// tcMSS is the TCP payload of a full segment on a 1500-byte MTU link with
// timestamps, where the matrix cuts records that span segments.
const tcMSS = 1448

// tcConn is one TLS connection as tc_egress_patch sees it: the AES-GCM
// protection of its records, done here with crypto/cipher, the TCP stream
// they leave on, and its state in the BPF maps (tls_conn_state: H and the
// TLS version; tc_pending: what the tcp_sendmsg kprobe staged for a write).
type tcConn struct {
	objs     *tlsuprobeObjects
	vers     uint16 // tls.VersionTLS12 or tls.VersionTLS13
	aead     cipher.AEAD
	h        [16]byte
	iv       []byte // TLS 1.3: the 12-byte write IV; TLS 1.2: the 4-byte implicit nonce
	recSeq   uint64 // the next record's sequence number
	tcpSeq   uint32 // the TCP sequence number of the stream's next byte
	src, dst netip.Addr
	sport    uint16
	tgid     uint32
	ssl      uint64
	cgroupID uint64
}

// tcRecord is an application_data record as the TLS library sent it.
type tcRecord struct {
	seq       uint32 // TCP sequence number of its first byte
	wire      []byte // header and body
	nonce     []byte
	aad       []byte // TLS 1.2's; TLS 1.3's is the record header
	plaintext []byte // its application data
}

// tcPatch is a placeholder in a write and the value tc patches in for it.
type tcPatch struct {
	off    int    // offset in the write's plaintext
	shadow []byte // the placeholder, as the app wrote it
	real   []byte // same length
}

// newTCConn returns connection id (a distinct source port and SSL object)
// of the given TLS version, with an AES key of keyLen bytes, its H stored in
// tls_conn_state with the version known. Its map entries are removed when
// the test ends.
func newTCConn(t *testing.T, objs *tlsuprobeObjects, cgroupID uint64, vers uint16, keyLen, id int) *tcConn {
	t.Helper()
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(id*31 + i)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	c := &tcConn{
		objs: objs, vers: vers, aead: aead,
		recSeq: uint64(id) << 8, tcpSeq: 1000 + uint32(id)<<20,
		src: netip.MustParseAddr("10.42.0.7"), dst: netip.AddrFrom4([4]byte{10, 43, byte(id >> 8), byte(id)}),
		sport: 40000 + uint16(id), tgid: 4343, ssl: 0x7f00beef0000 + uint64(id)<<12, cgroupID: cgroupID,
	}
	block.Encrypt(c.h[:], make([]byte, 16))
	ivLen := 12
	if vers == tls.VersionTLS12 {
		ivLen = 4
	}
	c.iv = bytes.Repeat([]byte{byte(id)}, ivLen)
	c.setVersionKnown(t, true)
	t.Cleanup(func() {
		ck := c.connKey()
		dk := c.destKey()
		_ = objs.TlsConnState.Delete(&ck)
		_ = objs.TcPending.Delete(&dk)
		_ = objs.TcTagPending.Delete(&dk)
	})
	return c
}

func (c *tcConn) connKey() tlsuprobeTlsConnKey {
	return tlsuprobeTlsConnKey{Tgid: c.tgid, SslPtr: c.ssl}
}

// destKey is the connection's tc_pending and tc_tag_pending key.
func (c *tcConn) destKey() tlsuprobeTcDestKey {
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], c.sport)
	return tlsuprobeTcDestKey{DstIp: c.dst.As16(), SrcPort: binary.NativeEndian.Uint16(port[:]), CgroupId: c.cgroupID}
}

// setVersionKnown stores the connection's H, and its TLS version, or the
// version as unknown (TLS libraries without a version offset: tc then
// tells the version from the record's length).
func (c *tcConn) setVersionKnown(t *testing.T, known bool) {
	t.Helper()
	cs := tlsuprobeTlsConnState{GhashH: c.h, CipherType: 1, NonceLen: 0xFF} // AES-GCM
	if known {
		cs.NonceLen = uint8(c.explicitNonceLen())
	}
	ck := c.connKey()
	if err := c.objs.TlsConnState.Update(&ck, &cs, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func (c *tcConn) explicitNonceLen() int {
	if c.vers == tls.VersionTLS12 {
		return 8
	}
	return 0
}

// seal encrypts plaintext into the connection's next record, at the next
// TCP sequence number.
func (c *tcConn) seal(plaintext []byte) tcRecord {
	r := tcRecord{seq: c.tcpSeq, plaintext: bytes.Clone(plaintext)}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], c.recSeq)
	c.recSeq++
	hdr := []byte{0x17, 0x03, 0x03, 0, 0}
	if c.vers == tls.VersionTLS13 {
		r.nonce = bytes.Clone(c.iv)
		for i := range seq {
			r.nonce[4+i] ^= seq[i]
		}
		inner := append(bytes.Clone(plaintext), 0x17) // inner content type, no padding
		binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+c.aead.Overhead()))
		r.wire = c.aead.Seal(bytes.Clone(hdr), r.nonce, inner, hdr)
	} else {
		r.nonce = append(bytes.Clone(c.iv), seq[:]...)
		r.aad = append(seq[:], 0x17, 0x03, 0x03, byte(len(plaintext)>>8), byte(len(plaintext)))
		binary.BigEndian.PutUint16(hdr[3:], uint16(8+len(plaintext)+c.aead.Overhead()))
		r.wire = c.aead.Seal(append(hdr, seq[:]...), r.nonce, plaintext, r.aad)
	}
	c.tcpSeq += uint32(len(r.wire))
	return r
}

// open decrypts a record's bytes as they left tc, and returns its
// application data, or why the receiver would reject it.
func (c *tcConn) open(r tcRecord, wire []byte) ([]byte, error) {
	if c.vers == tls.VersionTLS13 {
		inner, err := c.aead.Open(nil, r.nonce, wire[5:], wire[:5])
		if err != nil {
			return nil, err
		}
		if typ := inner[len(inner)-1]; typ != 0x17 {
			return inner[:len(inner)-1], fmt.Errorf("inner content type %#x, not application_data", typ)
		}
		return inner[:len(inner)-1], nil
	}
	// The explicit nonce as it left: tc must not have changed it.
	nonce := append(bytes.Clone(c.iv), wire[5:13]...)
	return c.aead.Open(nil, nonce, wire[13:], r.aad)
}

// write lays the patches' placeholders out in a write of n bytes of
// random plaintext.
func tcWrite(rng *rand.Rand, n int, patches ...tcPatch) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(rng.UintN(256))
	}
	for _, x := range patches {
		copy(p[x.off:], x.shadow)
	}
	return p
}

// patched returns the write as the receiver must get it: each placeholder
// replaced by its real value.
func tcPatched(write []byte, patches ...tcPatch) []byte {
	p := bytes.Clone(write)
	for _, x := range patches {
		copy(p[x.off:], x.real)
	}
	return p
}

// newTCPatch returns a patch of n random bytes at off.
func newTCPatch(rng *rand.Rand, off, n int) tcPatch {
	x := tcPatch{off: off, shadow: make([]byte, n), real: make([]byte, n)}
	for i := 0; i < n; i++ {
		x.shadow[i] = byte(rng.UintN(256))
		x.real[i] = byte(rng.UintN(256))
	}
	return x
}

// stage writes the tc_pending entry the tcp_sendmsg kprobe stages for a
// write of writeLen plaintext bytes: anchored to the TCP sequence number
// its first record starts at (a socket BIO), or with writeSeq 0 matched by
// record framing alone (a memory BIO: Node.js, Bun).
//
// TODO(kloak#383): phase 1 replaces the staged XOR deltas with references
// to the secret store; this is the one place that changes.
func (c *tcConn) stage(t *testing.T, writeSeq uint32, writeLen int, patches ...tcPatch) {
	t.Helper()
	if len(patches) > len(tlsuprobeTcPendingVal{}.Patches) {
		t.Fatalf("%d patches: tc_pending holds %d", len(patches), len(tlsuprobeTcPendingVal{}.Patches))
	}
	var pv tlsuprobeTcPendingVal
	pv.Tgid, pv.SslPtr, pv.Active = c.tgid, c.ssl, 1
	pv.PatchCount = uint32(len(patches))
	pv.PlaintextLen = uint32(writeLen)
	pv.WriteSeq = writeSeq
	pv.CreatedAt = monotonicNow(t)
	for i, x := range patches {
		if len(x.shadow) > maxPatchLen {
			t.Fatalf("a %d-byte patch: tc_pending holds %d", len(x.shadow), maxPatchLen)
		}
		pv.Patches[i].SecretOffset = uint32(x.off)
		pv.Patches[i].SecretLen = uint32(len(x.shadow))
		for j := range x.shadow {
			pv.Patches[i].XorDelta[j] = x.shadow[j] ^ x.real[j]
		}
	}
	dk := c.destKey()
	if err := c.objs.TcPending.Update(&dk, &pv, ciliumebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

// segments cuts the stream of bytes starting at TCP sequence number seq into
// frames, at the given offsets into it.
func (c *tcConn) segments(stream []byte, seq uint32, cuts ...int) [][]byte {
	var frames [][]byte
	at := 0
	for _, cut := range append(cuts, len(stream)) {
		if cut <= at {
			continue
		}
		frames = append(frames, tcpFrame(c.src, c.dst, c.sport, 443, seq+uint32(at), stream[at:cut]))
		at = cut
	}
	return frames
}

// send runs each frame through tc_egress_patch, in order, and returns the
// TCP payloads that left, concatenated.
func (c *tcConn) send(t *testing.T, frames ...[]byte) []byte {
	t.Helper()
	var out []byte
	for _, f := range frames {
		o := runTC(t, c.objs.TcEgressPatch, f)
		out = append(out, o[l4Offset(o)+20:]...)
	}
	return out
}

// mssCuts returns the offsets at which TCP cuts a stream of n bytes into
// full segments of mss bytes.
func mssCuts(n, mss int) []int {
	var cuts []int
	for at := mss; at < n; at += mss {
		cuts = append(cuts, at)
	}
	return cuts
}

func concatRecords(recs ...tcRecord) []byte {
	var s []byte
	for _, r := range recs {
		s = append(s, r.wire...)
	}
	return s
}

// What the receiver makes of a record that left tc.
type recState int

const (
	recOriginal recState = iota // as the TLS library sent it
	recPatched                  // authenticates, to the plaintext with the real values in
	recBadTag                   // fails authentication: the receiver's bad_record_mac
	recWrong                    // authenticates, to another plaintext
)

func (s recState) String() string {
	return [...]string{"original", "patched", "bad tag", "wrong plaintext"}[s]
}

// tcVerdict is the receiver's view of each record of a stream, and why.
type tcVerdict struct {
	states []recState
	fixed  []bool // the record is what the receiver must get: patched, or original when it has no placeholder
	why    []string
}

// safe reports whether every record authenticates to what was written or
// to what had to be patched: nothing the receiver rejects or misreads.
func (v tcVerdict) safe() bool {
	for _, s := range v.states {
		if s == recBadTag || s == recWrong {
			return false
		}
	}
	return true
}

// patched reports whether the receiver gets every record as it must: the
// placeholders replaced, everything else intact.
func (v tcVerdict) patched() bool {
	for _, f := range v.fixed {
		if !f {
			return false
		}
	}
	return true
}

// is reports whether the records are in exactly these states.
func (v tcVerdict) is(states ...recState) bool {
	if len(states) != len(v.states) {
		return false
	}
	for i := range states {
		if states[i] != v.states[i] {
			return false
		}
	}
	return true
}

func (v tcVerdict) String() string {
	parts := make([]string, len(v.states))
	for i, s := range v.states {
		parts[i] = fmt.Sprintf("record %d %s", i+1, s)
		if v.why[i] != "" {
			parts[i] += " (" + v.why[i] + ")"
		}
	}
	return strings.Join(parts, ", ")
}

// judge decrypts each record of out, the bytes that left tc for the stream
// of recs (starting at recs[0]'s sequence number), and compares it to want,
// its application data with the real values in place of the placeholders.
func (c *tcConn) judge(t *testing.T, out []byte, recs []tcRecord, want [][]byte) tcVerdict {
	t.Helper()
	in := concatRecords(recs...)
	if len(out) != len(in) {
		t.Fatalf("%d bytes left tc, %d went in", len(out), len(in))
	}
	var v tcVerdict
	at := 0
	for i, r := range recs {
		w := out[at : at+len(r.wire)]
		at += len(r.wire)
		state, why := recOriginal, ""
		if !bytes.Equal(w, r.wire) {
			pt, err := c.open(r, w)
			switch {
			case err != nil && pt == nil:
				state, why = recBadTag, err.Error()
			case err != nil:
				state, why = recWrong, err.Error()
			case bytes.Equal(pt, want[i]):
				state = recPatched
			default:
				state, why = recWrong, diffRange(pt, want[i])
			}
		}
		v.states = append(v.states, state)
		v.why = append(v.why, why)
		v.fixed = append(v.fixed, state == recPatched || (state == recOriginal && bytes.Equal(r.plaintext, want[i])))
	}
	return v
}

// diffRange describes where got differs from want.
func diffRange(got, want []byte) string {
	first, last := -1, -1
	for i := range want {
		if got[i] != want[i] {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	return fmt.Sprintf("plaintext bytes %d..%d differ from the patched write's", first, last)
}

// checkPatched sends a one-record write of writeLen bytes carrying the
// patches through tc, in one frame (a GSO packet) or with mss in segments of
// that many bytes, and checks that the receiver gets it patched, that the
// tc_pending entry is used up, and that no deferred tag is left behind.
func (c *tcConn) checkPatched(t *testing.T, name string, rng *rand.Rand, mss, writeLen int, anchored, versionKnown bool, patches ...tcPatch) bool {
	t.Helper()
	c.setVersionKnown(t, versionKnown)
	dk := c.destKey()
	_ = c.objs.TcTagPending.Delete(&dk)
	write := tcWrite(rng, writeLen, patches...)
	r := c.seal(write)
	writeSeq := uint32(0)
	if anchored {
		writeSeq = r.seq
	}
	c.stage(t, writeSeq, writeLen, patches...)
	var cuts []int
	if mss > 0 {
		cuts = tagWhole(mssCuts(len(r.wire), mss), len(r.wire))
	}
	frames := c.segments(r.wire, r.seq, cuts...)
	v := c.judge(t, c.send(t, frames...), []tcRecord{r}, [][]byte{tcPatched(write, patches...)})
	ok := true
	if !v.patched() {
		t.Errorf("%s (%d segments, anchored %v, version known %v): %s", name, len(frames), anchored, versionKnown, v)
		ok = false
	}
	var pv tlsuprobeTcPendingVal
	if err := c.objs.TcPending.Lookup(&dk, &pv); err != nil || pv.Active != 0 {
		t.Errorf("%s: tc_pending entry after the record: active %d, %v", name, pv.Active, err)
		ok = false
	}
	var tv tlsuprobeTcTagVal
	if err := c.objs.TcTagPending.Lookup(&dk, &tv); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Errorf("%s: a deferred tag is left: %v", name, err)
		ok = false
	}
	return ok
}

// tagWhole moves a cut that would split the record's tag (its last 16
// bytes, the record ending at n) to the tag's first byte: tc patches a
// deferred tag only whole (see TestTCPatchGapSplitTag).
func tagWhole(cuts []int, n int) []int {
	for i, cut := range cuts {
		if cut > n-16 && cut < n {
			cuts[i] = n - 16
		}
	}
	return cuts
}

// TestTCPatchMatrix runs tc_egress_patch, and its tc_ghash_update tail call,
// on one-record writes in every layout tc patches today: each patch length
// up to SECRET_MAX_LEN at each GHASH block alignment, TLS 1.2 and 1.3,
// AES-128 and AES-256, patches ending on the record's last application
// byte, up to four patches per record, and records up to the 16 KiB maximum
// whose tag comes in a later segment. Writes are anchored to their TCP
// sequence number (socket BIO) or matched by their length (memory BIO), with
// the TLS version known or told from the record's length. Every record must
// decrypt, under crypto/cipher's GCM, to the write with the real values in
// place of the placeholders. BPF_PROG_RUN takes a frame of one page at most,
// so a record that fits one segment has at most ~3.5 KB here.
func TestTCPatchMatrix(t *testing.T) {
	objs := loadTestObjects(t)
	if err := objs.TcProgArray.Put(uint32(0), uint32(objs.TcGhashUpdate.FD())); err != nil {
		t.Fatal(err)
	}
	cgroupID := selfCgroupID(t)
	versions := []uint16{tls.VersionTLS12, tls.VersionTLS13}
	id := 0
	conn := func(t *testing.T, vers uint16, keyLen int) *tcConn {
		id++
		return newTCConn(t, objs, cgroupID, vers, keyLen, id)
	}
	// Each subtest stops at maxErrors: one bug fails most of a matrix.
	const maxErrors = 5

	t.Run("one patch", func(t *testing.T) {
		for _, vers := range versions {
			for align := 0; align < 16; align++ {
				t.Run(fmt.Sprintf("%s/align %d", tls.VersionName(vers), align), func(t *testing.T) {
					c := conn(t, vers, 16+16*(align&1))
					rng := rand.New(rand.NewPCG(uint64(vers), uint64(align)))
					errs := 0
					for n := 1; n <= maxPatchLen; n++ {
						// 0: the patch ends on the record's last application byte.
						for _, tail := range []int{0, 1 + n*7%41} {
							// The GHASH block the patch starts in: the first,
							// and up to ~2.9 KB into the record.
							block := []int{0, 1, 2, 7, 64, 180}[(n+tail)%6]
							off := 16*block + align
							name := fmt.Sprintf("%d bytes at offset %d, %d after", n, off, tail)
							if !c.checkPatched(t, name, rng, 0, off+n+tail, (n+align)%3 != 0, n%5 != 0, newTCPatch(rng, off, n)) {
								if errs++; errs == maxErrors {
									t.Fatal("stopping here")
								}
							}
						}
					}
				})
			}
		}
	})

	t.Run("several patches", func(t *testing.T) {
		for _, vers := range versions {
			for count := 2; count <= len(tlsuprobeTcPendingVal{}.Patches); count++ {
				t.Run(fmt.Sprintf("%s/%d patches", tls.VersionName(vers), count), func(t *testing.T) {
					c := conn(t, vers, 16)
					rng := rand.New(rand.NewPCG(uint64(vers), uint64(count)))
					errs := 0
					for i := 0; i < 150; i++ {
						// Short and long patches, back to back or apart,
						// sharing GHASH blocks or not.
						off := rng.IntN(48)
						var patches []tcPatch
						var layout []string
						for p := 0; p < count; p++ {
							n := 1 + rng.IntN(maxPatchLen)
							if rng.IntN(2) == 0 {
								n = 1 + rng.IntN(16)
							}
							patches = append(patches, newTCPatch(rng, off, n))
							layout = append(layout, fmt.Sprintf("%d@%d", n, off))
							off += n + []int{0, 0, rng.IntN(16), rng.IntN(48)}[rng.IntN(4)]
						}
						end := patches[count-1].off + len(patches[count-1].shadow)
						tail := 0
						if i%2 == 1 {
							tail = 1 + rng.IntN(40)
						}
						name := fmt.Sprintf("patches %s, %d bytes after", strings.Join(layout, " "), tail)
						if !c.checkPatched(t, name, rng, 0, end+tail, i%3 != 0, true, patches...) {
							if errs++; errs == maxErrors {
								t.Fatal("stopping here")
							}
						}
					}
				})
			}
		}
	})

	// A record larger than a segment: the patch in its first segment, the
	// tag in its last, deferred (tc_tag_pending). Up to the maximum record,
	// whose first blocks take H to the highest powers (~1025).
	t.Run("records spanning segments", func(t *testing.T) {
		for _, vers := range versions {
			for _, writeLen := range []int{tcMSS + 1, 4096, 8191, 16384} {
				t.Run(fmt.Sprintf("%s/%d bytes", tls.VersionName(vers), writeLen), func(t *testing.T) {
					c := conn(t, vers, 32)
					rng := rand.New(rand.NewPCG(uint64(vers), uint64(writeLen)))
					errs := 0
					for _, n := range []int{1, 15, 16, 17, 64, maxPatchLen - 1, maxPatchLen} {
						for _, align := range []int{0, 1, 8, 15} {
							off := 16*(n%5) + align
							name := fmt.Sprintf("%d bytes at offset %d", n, off)
							if !c.checkPatched(t, name, rng, tcMSS, writeLen, n%2 == 0, true, newTCPatch(rng, off, n)) {
								if errs++; errs == maxErrors {
									t.Fatal("stopping here")
								}
							}
						}
					}
				})
			}
		}
	})
}
