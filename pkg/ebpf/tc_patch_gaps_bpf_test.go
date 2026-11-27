//go:build linux

package ebpf

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// The tests in this file pin down the gaps kloak#383 found in today's data
// plane, which secrets longer than a few hundred bytes run into all the
// time: a write or a record cut across TCP segments, records, writes or
// retransmissions. Each one checks that the receiver gets a record it can
// use: patched, or left as the TLS library wrote it (the placeholder goes
// out, the request fails, nothing is corrupted). Where tc corrupts records
// today, the test skips, saying which phase of kloak#383 fixes it, as long
// as it sees exactly the corruption observed when it was written; any
// other unsafe outcome fails.

// gapCheck judges the outcome of a gap's scenario: today is what the
// receiver got when the test was written, phase the step of kloak#383 that
// closes the gap.
func gapCheck(t *testing.T, v tcVerdict, phase, scenario string, today ...recState) {
	t.Helper()
	switch {
	case v.patched():
		t.Logf("%s: patched (%s)", scenario, v)
	case v.is(today...) && !v.safe():
		t.Skipf("kloak#383 %s: %s: %s", phase, scenario, v)
	case v.safe():
		t.Logf("%s: not patched, but nothing is corrupted (kloak#383 %s patches it): %s", scenario, phase, v)
	default:
		t.Errorf("%s: %s; when this test was written: %v", scenario, v, today)
	}
}

// goRecordLens returns the plaintext lengths of the records Go's crypto/tls
// cuts a write of n bytes into early in a connection (dynamic record
// sizing, Conn.maxPayloadSizeForWrite): the first one fits an estimated MSS
// of 1208 bytes, each next one is that much larger, up to 16 KiB.
func goRecordLens(vers uint16, n int) []int {
	per := 1208 - 5 - 16 // the MSS estimate, the record header, the AEAD's tag
	if vers == tls.VersionTLS13 {
		per-- // the inner content type
	} else {
		per -= 8 // the explicit nonce
	}
	var lens []int
	for i := 1; n > 0; i++ {
		l := min(per*i, 16384, n)
		lens = append(lens, l)
		n -= l
	}
	return lens
}

// sealWrite cuts a write into records of the given plaintext lengths, as
// the TLS library does, and returns them with what the receiver must get
// in each: patched, its application data with the real values in.
func (c *tcConn) sealWrite(write, patched []byte, lens []int) ([]tcRecord, [][]byte) {
	var recs []tcRecord
	var want [][]byte
	at := 0
	for _, l := range lens {
		recs = append(recs, c.seal(write[at:at+l]))
		want = append(want, patched[at:at+l])
		at += l
	}
	return recs, want
}

func gapConn(t *testing.T, vers uint16, id int) *tcConn {
	t.Helper()
	objs := loadTestObjects(t)
	if err := objs.TcProgArray.Put(uint32(0), uint32(objs.TcGhashUpdate.FD())); err != nil {
		t.Fatal(err)
	}
	return newTCConn(t, objs, selfCgroupID(t), vers, 16, id)
}

var gapVersions = []uint16{tls.VersionTLS12, tls.VersionTLS13}

// TestTCPatchGapPastMatchedRecord: a write that Go cuts into two records
// (dynamic record sizing: the first ~1.2 KB), with the placeholder in the
// second record or across the two. The kprobe anchors the write's patches
// to its first record, and tc patches that record: it checks a patch's
// length against the record, not where the patch ends. When the records
// leave in one segment (coalesced while the congestion window is full), the
// patch lands in the next record's bytes, at the first record's offsets
// (shifted by its header and tag), and no tag covers it.
func TestTCPatchGapPastMatchedRecord(t *testing.T) {
	for i, vers := range gapVersions {
		c := gapConn(t, vers, 100+i)
		first := goRecordLens(vers, 1<<20)[0]
		for _, tc := range []struct {
			name     string
			off, n   int
			split    bool // each record in its own segment
			today    []recState
			phaseFix string
		}{
			{"placeholder in record 2, one segment", first + 300, 24, false, []recState{recOriginal, recBadTag}, "phase 0 (refuse) / phase 3 (patch)"},
			{"128-byte placeholder in record 2, one segment", first + 300, maxPatchLen, false, []recState{recOriginal, recBadTag}, "phase 0 (refuse) / phase 3 (patch)"},
			{"placeholder across the records, one segment", first - 10, 24, false, []recState{recBadTag, recOriginal}, "phase 0 (refuse) / phase 3 (patch)"},
			{"placeholder in record 2, a segment per record", first + 300, 24, true, nil, "phase 3"},
			// Its own segment holds the first record's tag, which the patch runs over.
			{"placeholder across the records, a segment per record", first - 10, 24, true, []recState{recBadTag, recOriginal}, "phase 0 (refuse) / phase 3 (patch)"},
		} {
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(vers), tc.name), func(t *testing.T) {
				rng := rand.New(rand.NewPCG(1, uint64(tc.off)))
				p := newTCPatch(rng, tc.off, tc.n)
				write := tcWrite(rng, first+800, p)
				recs, want := c.sealWrite(write, tcPatched(write, p), goRecordLens(vers, len(write)))
				if len(recs) != 2 {
					t.Fatalf("%d records", len(recs))
				}
				c.stage(t, recs[0].seq, len(write), p)
				stream := concatRecords(recs...)
				var cuts []int
				if tc.split {
					cuts = []int{len(recs[0].wire)}
				}
				out := c.send(t, c.segments(stream, recs[0].seq, cuts...)...)
				gapCheck(t, c.judge(t, out, recs, want), tc.phaseFix, tc.name, tc.today...)
			})
		}
	}
}

// TestTCPatchGapTruncatedPlaceholder: a write that ends in the middle of a
// placeholder, its rest in the next write (Go's net/http cuts a long header
// line at its 4 KiB bufio.Writer). bpf_xor_path stages the whole
// placeholder's patch for the first write (see
// TestXorPathTruncatedPlaceholder), and tc applies it past the record's
// application data, over a TLS 1.3 record's inner content type and the
// tag, while the tag it recomputes covers the content type but not the
// bytes of the patch past it. A patch that runs past the segment is not
// applied (its ciphertext cannot be read); one that runs one byte past a
// TLS 1.3 record's data changes its content type under a valid tag.
func TestTCPatchGapTruncatedPlaceholder(t *testing.T) {
	for i, vers := range gapVersions {
		c := gapConn(t, vers, 110+i)
		for _, tc := range []struct {
			name             string
			in               int // bytes of the placeholder in the first write
			n                int
			oneSegment       bool // both writes' records leave in one segment
			today12, today13 []recState
		}{
			{"12 of 24 bytes", 12, 24, false, []recState{recBadTag, recOriginal}, []recState{recBadTag, recOriginal}},
			{"23 of 24 bytes", 23, 24, false, []recState{recBadTag, recOriginal}, []recState{recWrong, recOriginal}},
			{"8 of 128 bytes", 8, maxPatchLen, false, nil, nil},
			{"8 of 128 bytes, one segment", 8, maxPatchLen, true, []recState{recBadTag, recBadTag}, []recState{recBadTag, recBadTag}},
		} {
			today := tc.today13
			if vers == tls.VersionTLS12 {
				today = tc.today12
			}
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(vers), tc.name), func(t *testing.T) {
				rng := rand.New(rand.NewPCG(2, uint64(tc.in)))
				const firstLen = 600
				p := newTCPatch(rng, firstLen-tc.in, tc.n)
				both := tcWrite(rng, firstLen+200, p)
				patched := tcPatched(both, p)
				recs, want := c.sealWrite(both, patched, []int{firstLen, 200})
				// What the uprobe stages for the first write: the whole
				// placeholder, its delta read from the app's buffer.
				c.stage(t, recs[0].seq, firstLen, p)
				var cuts []int
				if !tc.oneSegment {
					cuts = []int{len(recs[0].wire)}
				}
				out := c.send(t, c.segments(concatRecords(recs...), recs[0].seq, cuts...)...)
				gapCheck(t, c.judge(t, out, recs, want), "phase 0 (refuse) / phase 3 (continuation across writes)", tc.name, today...)
			})
		}
	}
}

// TestTCPatchGapPatchAcrossSegments: a record cut into two segments with
// the patch across the cut, or wholly in the second segment. tc patches in
// the segment that holds the record's header: it cannot read the patch's
// ciphertext there and leaves the record alone. The entry stays until it
// expires; the record goes out with the placeholder.
func TestTCPatchGapPatchAcrossSegments(t *testing.T) {
	for i, vers := range gapVersions {
		c := gapConn(t, vers, 120+i)
		cut := tcMSS - 5 - c.explicitNonceLen() // the first plaintext byte of segment 2
		for _, tc := range []struct {
			name   string
			off, n int
		}{
			{"across the cut", cut - 10, 24},
			{"128 bytes across the cut", cut - 64, maxPatchLen},
			{"in segment 2", cut + 100, 24},
		} {
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(vers), tc.name), func(t *testing.T) {
				rng := rand.New(rand.NewPCG(3, uint64(tc.off)))
				p := newTCPatch(rng, tc.off, tc.n)
				write := tcWrite(rng, 2000, p)
				r := c.seal(write)
				c.stage(t, r.seq, len(write), p)
				out := c.send(t, c.segments(r.wire, r.seq, tcMSS)...)
				gapCheck(t, c.judge(t, out, []tcRecord{r}, [][]byte{tcPatched(write, p)}), "phase 2", tc.name, recOriginal)
			})
		}
	}
}

// TestTCPatchGapSplitTag: a record whose patch is in its first segment and
// whose tag is split across two segments. tc patches the ciphertext, defers
// the tag (tc_tag_pending), and patches a deferred tag only whole: the
// segment holding its second part drops it (tc_tag_action), and the record
// leaves patched under the TLS library's tag.
func TestTCPatchGapSplitTag(t *testing.T) {
	for i, vers := range gapVersions {
		c := gapConn(t, vers, 130+i)
		for _, tc := range []struct {
			name     string
			writeLen int
			cuts     func(wireLen int) []int
			today    []recState
		}{
			{"tag whole in segment 2", 1500, func(n int) []int { return []int{n - 16} }, nil},
			{"tag across segments 1 and 2", 1500, func(n int) []int { return []int{n - 8} }, []recState{recBadTag}},
			{"tag across segments 2 and 3", 2500, func(n int) []int { return []int{tcMSS, n - 5} }, []recState{recBadTag}},
		} {
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(vers), tc.name), func(t *testing.T) {
				rng := rand.New(rand.NewPCG(4, uint64(tc.writeLen)))
				p := newTCPatch(rng, 40, 24)
				write := tcWrite(rng, tc.writeLen, p)
				r := c.seal(write)
				c.stage(t, r.seq, len(write), p)
				out := c.send(t, c.segments(r.wire, r.seq, tc.cuts(len(r.wire))...)...)
				v := c.judge(t, out, []tcRecord{r}, [][]byte{tcPatched(write, p)})
				if tc.today == nil && !v.patched() {
					t.Errorf("not patched: %s", v)
				}
				gapCheck(t, v, "phase 2", tc.name, tc.today...)
			})
		}
	}
}

// TestTCPatchGapRetransmit: TCP retransmits from its own queue, which tc's
// writes never reach (it patches a private copy of the skb), so a
// retransmitted segment comes through tc as the TLS library wrote it.
// tc_pending was used up by the first transmission: the copy leaves
// unpatched. When the record spans segments, the receiver puts the record
// together from patched and unpatched segments.
func TestTCPatchGapRetransmit(t *testing.T) {
	for i, vers := range gapVersions {
		c := gapConn(t, vers, 140+i)
		t.Run(tls.VersionName(vers)+"/one segment, retransmitted", func(t *testing.T) {
			rng := rand.New(rand.NewPCG(5, 1))
			p := newTCPatch(rng, 40, 24)
			write := tcWrite(rng, 300, p)
			r := c.seal(write)
			c.stage(t, r.seq, len(write), p)
			frames := c.segments(r.wire, r.seq)
			want := [][]byte{tcPatched(write, p)}
			if v := c.judge(t, c.send(t, frames...), []tcRecord{r}, want); !v.patched() {
				t.Fatalf("first transmission: %s", v)
			}
			gapCheck(t, c.judge(t, c.send(t, frames...), []tcRecord{r}, want), "phase 2", "the retransmission", recOriginal)
		})
		for _, tc := range []struct {
			name  string
			again []int // segments retransmitted, in order, after both went once
			today []recState
		}{
			{"two segments, the tag's retransmitted", []int{1}, []recState{recBadTag}},
			{"two segments, the patch's retransmitted", []int{0}, []recState{recBadTag}},
		} {
			t.Run(tls.VersionName(vers)+"/"+tc.name, func(t *testing.T) {
				rng := rand.New(rand.NewPCG(5, 2))
				p := newTCPatch(rng, 40, 24)
				write := tcWrite(rng, 2000, p)
				r := c.seal(write)
				c.stage(t, r.seq, len(write), p)
				frames := c.segments(r.wire, r.seq, tcMSS)
				want := [][]byte{tcPatched(write, p)}
				first := [][]byte{c.send(t, frames[0]), c.send(t, frames[1])}
				if v := c.judge(t, append(append([]byte{}, first[0]...), first[1]...), []tcRecord{r}, want); !v.patched() {
					t.Fatalf("first transmission: %s", v)
				}
				// The receiver keeps the retransmitted copy of what it lost.
				got := first
				for _, s := range tc.again {
					got[s] = c.send(t, frames[s])
				}
				gapCheck(t, c.judge(t, append(append([]byte{}, got[0]...), got[1]...), []tcRecord{r}, want), "phase 2", tc.name, tc.today...)
			})
		}
		t.Run(tls.VersionName(vers)+"/two segments, retransmitted as one", func(t *testing.T) {
			rng := rand.New(rand.NewPCG(5, 3))
			p := newTCPatch(rng, 40, 24)
			write := tcWrite(rng, 2000, p)
			r := c.seal(write)
			c.stage(t, r.seq, len(write), p)
			_ = c.send(t, c.segments(r.wire, r.seq, tcMSS)...)
			// tcp_retrans_try_collapse merges segments of the queue.
			out := c.send(t, c.segments(r.wire, r.seq)...)
			gapCheck(t, c.judge(t, out, []tcRecord{r}, [][]byte{tcPatched(write, p)}), "phase 2", "the collapsed retransmission", recOriginal)
		})
	}
}

// TestTCPatchGapSecondWrite: tc_pending holds one write per connection, and
// the tcp_sendmsg kprobe overwrites it (BPF_ANY). A second write staged
// before the first one's record reaches tc (a full congestion window,
// HTTP/2 streams) takes its place:
//   - socket BIO: the first record leaves with its placeholder, the second
//     is patched (anchored to its own sequence number);
//   - memory BIO (Node.js, Bun): the entry is matched by the record's length
//     alone, so the first record of that length gets the second write's
//     patches, at the second write's offsets.
func TestTCPatchGapSecondWrite(t *testing.T) {
	for i, vers := range gapVersions {
		c := gapConn(t, vers, 150+i)
		for _, tc := range []struct {
			name     string
			anchored bool
			today    []recState
		}{
			{"socket BIO", true, []recState{recOriginal, recPatched}},
			{"memory BIO", false, []recState{recWrong, recOriginal}},
		} {
			t.Run(fmt.Sprintf("%s/%s", tls.VersionName(vers), tc.name), func(t *testing.T) {
				rng := rand.New(rand.NewPCG(6, 1))
				// Two writes of the same length, the placeholders at
				// different offsets.
				p1, p2 := newTCPatch(rng, 30, 24), newTCPatch(rng, 100, 24)
				w1, w2 := tcWrite(rng, 300, p1), tcWrite(rng, 300, p2)
				r1, r2 := c.seal(w1), c.seal(w2)
				seq1, seq2 := uint32(0), uint32(0)
				if tc.anchored {
					seq1, seq2 = r1.seq, r2.seq
				}
				c.stage(t, seq1, len(w1), p1)
				c.stage(t, seq2, len(w2), p2) // before r1 reaches tc
				stream := concatRecords(r1, r2)
				out := c.send(t, c.segments(stream, r1.seq, len(r1.wire))...)
				v := c.judge(t, out, []tcRecord{r1, r2}, [][]byte{tcPatched(w1, p1), tcPatched(w2, p2)})
				gapCheck(t, v, "phase 2", tc.name, tc.today...)
			})
		}
	}
}

// TestXorPathTruncatedPlaceholder runs the Go crypto/tls Write uprobe, and
// bpf_xor_path behind it, on a write that ends in the middle of a
// placeholder whose key (its first 8 bytes) is in the write. bpf_xor_path
// stages the whole placeholder's patch: offset plus length past the end of
// the write, its delta computed from whatever follows the write in the
// app's memory. tc then applies it past the record (see
// TestTCPatchGapTruncatedPlaceholder).
func TestXorPathTruncatedPlaceholder(t *testing.T) {
	objs := loadTestObjects(t)
	cgroupID := selfCgroupID(t)
	if err := objs.ProgArray.Put(uint32(1), uint32(objs.BpfXorPath.FD())); err != nil {
		t.Fatal(err)
	}
	gen := secrets.NewShadowGenerator(nil, testLog())
	var snapshot []secrets.Secret
	var refs []secrets.Ref
	long := "REAL-TRUNCATED-" + strings.Repeat("0123456789", maxPatchLen/10)
	for _, real := range []string{"REAL-TRUNCATED-VALUE-024", long[:maxPatchLen]} {
		owner := fmt.Sprintf("ns/truncated-%d", len(real))
		shadow, err := gen.Generate(len(real), secrets.HuffmanBits(real), owner, 20)
		if err != nil {
			t.Fatal(err)
		}
		gen.Record(shadow, owner)
		snapshot = append(snapshot, secrets.Secret{OwnerID: owner, Key: "value", Real: real, Shadow: shadow})
		refs = append(refs, secrets.Ref{OwnerID: owner})
	}
	if _, err := applySecrets(objs.SecretMap, snapshot, testLog()); err != nil {
		t.Fatal(err)
	}
	bindings := map[string]podBinding{"uid": {pod: "ns/client", cgroupIDs: []uint64{cgroupID}, refs: refs}}
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
	defer func() { _ = up.Close() }()
	addr := startTLSServer(t)

	for _, s := range snapshot {
		for _, in := range []int{secrets.ShadowPrefixLen, len(s.Shadow) / 2, len(s.Shadow) - 1} {
			t.Run(fmt.Sprintf("%d of %d bytes", in, len(s.Shadow)), func(t *testing.T) {
				payload := []byte("GET / HTTP/1.1\r\nX-Secret: " + s.Shadow[:in])
				got := prescanWrite(t, objs, addr, payload)
				var v tlsuprobeXorPendingVal
				if err := objs.XorPending.Lookup(uint32(os.Getpid()), &v); errors.Is(err, ciliumebpf.ErrKeyNotExist) || len(got) == 0 {
					t.Logf("refused: nothing staged")
					return
				} else if err != nil {
					t.Fatal(err)
				}
				off, n := v.Patches[0].SecretOffset, v.Patches[0].SecretLen
				if int(off+n) <= len(payload) {
					t.Fatalf("staged %d bytes at %d, in a %d-byte write: the placeholder is cut there", n, off, len(payload))
				}
				t.Skipf("kloak#383 phase 0 (refuse) / phase 3 (continuation across writes): staged %d bytes at offset %d of a %d-byte write, %d past its end",
					n, off, len(payload), int(off+n)-len(payload))
			})
		}
	}
}
