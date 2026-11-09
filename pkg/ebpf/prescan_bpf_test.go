//go:build linux

package ebpf

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// prescanChunkStride is CHUNK_STRIDE in tls_uprobe.c: chunk k of a write
// starts at k * prescanChunkStride.
const prescanChunkStride = 256 - (secrets.ShadowPrefixLen - 1)

// prescanPatch is the part of an xor_pending patch the prescan decides.
type prescanPatch struct {
	offset uint32
	key    string
}

// TestPrescanConfirmsSlots runs the Go crypto/tls Write uprobe, and the
// bpf_xor_path tail call behind it, on this process's own TLS writes. A
// placeholder candidate (kl::, or its HPACK Huffman prefix) takes one of the
// four match slots only when its key is in secret_map, so candidates that are
// not (a literal kl:: in a header or body, the Huffman prefix in binary data)
// no longer hide the placeholders after them. Needs root (or CAP_BPF +
// CAP_PERFMON) and a kernel that can attach uprobes; skipped otherwise.
func TestPrescanConfirmsSlots(t *testing.T) {
	objs := loadTestObjects(t)
	cgroupID := selfCgroupID(t)
	if err := objs.ProgArray.Put(uint32(1), uint32(objs.BpfXorPath.FD())); err != nil {
		t.Fatal(err)
	}

	// Real shadows, so each one also has its HPACK Huffman key in secret_map.
	gen := secrets.NewShadowGenerator(nil, testLog())
	var snapshot []secrets.Secret
	add := func(owner, real string) secrets.Secret {
		shadow, err := gen.Generate(len(real), secrets.HuffmanBits(real), owner, 20)
		if err != nil {
			t.Fatal(err)
		}
		gen.Record(shadow, owner)
		s := secrets.Secret{OwnerID: owner, Key: "value", Real: real, Shadow: shadow}
		snapshot = append(snapshot, s)
		return s
	}
	var bound []secrets.Secret
	for _, real := range []string{"REAL-PRESCAN-VALUE-0", "REAL-PRESCAN-VALUE-1", "REAL-PRESCAN-VALUE-2", "REAL-PRESCAN-VALUE-3", "REAL-PRESCAN-VALUE-4"} {
		bound = append(bound, add("ns/bound-"+real[len(real)-1:], real))
	}
	var unbound []secrets.Secret
	for _, real := range []string{"REAL-PRESCAN-UNBOUND-0", "REAL-PRESCAN-UNBOUND-1", "REAL-PRESCAN-UNBOUND-2", "REAL-PRESCAN-UNBOUND-3"} {
		unbound = append(unbound, add("ns/other-"+real[len(real)-1:], real))
	}
	if _, err := applySecrets(objs.SecretMap, snapshot, testLog()); err != nil {
		t.Fatal(err)
	}
	var refs []secrets.Ref
	for _, s := range bound {
		refs = append(refs, secrets.Ref{OwnerID: s.OwnerID})
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

	events, err := ringbuf.NewReader(objs.SecretBindingEvents)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = events.Close() }()

	addr := startTLSServer(t)
	keyOf := func(s secrets.Secret) string { return s.Shadow[:secrets.ShadowPrefixLen] }
	huffman := func(s secrets.Secret) []byte { return hpack.AppendHuffmanString(nil, s.Shadow) }
	// A lookalike: kl:: plus 4 characters, one character off a real key.
	lookalike := []byte(keyOf(bound[0]))
	if lookalike[7] == 'Z' {
		lookalike[7] = 'Y'
	} else {
		lookalike[7] = 'Z'
	}
	decoys := "X-Decoy: kl::aaaa kl::bbbb kl::cccc kl::dddd kl::eeee\r\n" +
		"X-Lookalike: " + string(lookalike) + "\r\n" +
		"X-Huffman: \xeb\x45\xcb\x00\x00\x00\x00\x00\r\n"

	type tc struct {
		name    string
		payload []byte
		want    []prescanPatch
		refused []string // keys reported on secret_binding_events
	}
	var cases []tc

	{
		p := []byte("GET / HTTP/1.1\r\n" + decoys + "X-Secret: ")
		off := uint32(len(p))
		p = append(p, bound[0].Shadow+"\r\n\r\n"...)
		cases = append(cases, tc{name: "decoys before a placeholder", payload: p,
			want: []prescanPatch{{off, keyOf(bound[0])}}})
	}
	{
		// HTTP/2: the decoys, then a Huffman-coded placeholder.
		p := []byte(decoys)
		off := uint32(len(p))
		h := huffman(bound[1])
		p = append(p, h...)
		cases = append(cases, tc{name: "decoys before a Huffman placeholder", payload: p,
			want: []prescanPatch{{off, string(h[:secrets.ShadowPrefixLen])}}})
	}
	{
		// A git pack or gzip body: binary data full of candidates, then a
		// placeholder straddling two chunks.
		rng := rand.New(rand.NewPCG(1, 2))
		p := make([]byte, 64<<10)
		for i := range p {
			p[i] = byte(rng.UintN(256))
		}
		off := 200*prescanChunkStride - 3
		for i := 100; i+secrets.ShadowPrefixLen <= off; i += 997 {
			copy(p[i:], "\xeb\x45\xcb")
		}
		for i := 50; i+secrets.ShadowPrefixLen <= off; i += 3001 {
			copy(p[i:], "kl::")
		}
		copy(p[off:], bound[2].Shadow)
		cases = append(cases, tc{name: "binary body", payload: p,
			want: []prescanPatch{{uint32(off), keyOf(bound[2])}}})
	}
	{
		// Each placeholder is found once, wherever it sits against the
		// chunks: across a boundary, last and first start position of a chunk.
		p := bytes.Repeat([]byte{'.'}, 4*prescanChunkStride+64)
		offs := []uint32{prescanChunkStride - 3, 2*prescanChunkStride - 1, 3 * prescanChunkStride}
		var want []prescanPatch
		for i, off := range offs {
			copy(p[off:], bound[i].Shadow)
			want = append(want, prescanPatch{off, keyOf(bound[i])})
		}
		cases = append(cases, tc{name: "chunk boundaries", payload: p, want: want})
	}
	{
		// Four slots: a fifth placeholder in the same write is not rewritten.
		var p []byte
		var want []prescanPatch
		for i, s := range bound {
			p = append(p, "X-Decoy: kl::zzzz\r\nX-Secret: "...)
			if i < 4 {
				want = append(want, prescanPatch{uint32(len(p)), keyOf(s)})
			}
			p = append(p, s.Shadow+"\r\n"...)
		}
		cases = append(cases, tc{name: "four slots", payload: p, want: want})
	}
	{
		// A placeholder of a secret the pod does not reference is in
		// secret_map: it takes a slot, and bpf_xor_path reports the refusal.
		p := []byte("X-Other: " + unbound[0].Shadow + "\r\n" + decoys + "X-Secret: ")
		off := uint32(len(p))
		p = append(p, bound[0].Shadow+"\r\n"...)
		cases = append(cases, tc{name: "unbound placeholder reported", payload: p,
			want:    []prescanPatch{{off, keyOf(bound[0])}},
			refused: []string{keyOf(unbound[0])}})
	}
	{
		// Refused placeholders still use up the slots: four of them hide a
		// fifth, bound, placeholder, but each refusal is reported.
		var p []byte
		var refused []string
		for _, s := range unbound {
			p = append(p, "X-Other: "+s.Shadow+"\r\n"...)
			refused = append(refused, keyOf(s))
		}
		p = append(p, "X-Secret: "+bound[0].Shadow+"\r\n"...)
		cases = append(cases, tc{name: "refused placeholders take slots", payload: p, refused: refused})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matchBefore := debugCounter(t, objs, "xor_prescan_match")
			unconfirmedBefore := debugCounter(t, objs, "xor_prescan_unconfirmed")
			got := prescanWrite(t, objs, addr, c.payload)
			if !slices.Equal(got, c.want) {
				t.Errorf("patches %v, want %v", got, c.want)
			}

			wantRefused := slices.Clone(c.refused)
			slices.Sort(wantRefused)
			if gotRefused := readRefusedKeys(t, events, len(wantRefused)); !slices.Equal(gotRefused, wantRefused) {
				t.Errorf("refused keys %q, want %q", gotRefused, wantRefused)
			}

			confirmed, unconfirmed := prescanModel(c.payload, objs)
			if d := debugCounter(t, objs, "xor_prescan_match") - matchBefore; d != confirmed {
				t.Errorf("xor_prescan_match +%d, want +%d", d, confirmed)
			}
			if d := debugCounter(t, objs, "xor_prescan_unconfirmed") - unconfirmedBefore; d != unconfirmed {
				t.Errorf("xor_prescan_unconfirmed +%d, want +%d", d, unconfirmed)
			}
		})
	}

	// The plain-text delta is shadow XOR real: the patch is aimed at the
	// placeholder's bytes.
	t.Run("delta", func(t *testing.T) {
		payload := []byte("GET / HTTP/1.1\r\n" + decoys + "X-Secret: " + bound[3].Shadow + "\r\n")
		_ = prescanWrite(t, objs, addr, payload)
		var v tlsuprobeXorPendingVal
		if err := objs.XorPending.Lookup(uint32(os.Getpid()), &v); err != nil {
			t.Fatal(err)
		}
		s := bound[3]
		if v.PatchCount != 1 || v.Patches[0].SecretLen != uint32(len(s.Real)) {
			t.Fatalf("patch count %d, len %d", v.PatchCount, v.Patches[0].SecretLen)
		}
		for i := range s.Real {
			if v.Patches[0].XorDelta[i] != s.Shadow[i]^s.Real[i] {
				t.Fatalf("delta byte %d is %#x, want %#x", i, v.Patches[0].XorDelta[i], s.Shadow[i]^s.Real[i])
			}
		}
	})
}

// goTLSWriteOffset returns this test binary's path and the file offset of its
// crypto/tls.(*Conn).Write. go test strips the symbol table, so the uprobe is
// attached by offset: the function's address, mapped back to the file
// through /proc/self/maps.
func goTLSWriteOffset(t *testing.T) (string, uint64) {
	t.Helper()
	pc := uint64(reflect.ValueOf((*tls.Conn).Write).Pointer())
	if fn := runtime.FuncForPC(uintptr(pc)); fn == nil || fn.Name() != "crypto/tls.(*Conn).Write" || uint64(fn.Entry()) != pc {
		t.Skipf("(*tls.Conn).Write is not at %#x", pc)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(maps), "\n") {
		// start-end perms offset dev inode path
		f := strings.Fields(line)
		if len(f) < 6 || f[5] != exe {
			continue
		}
		var start, end uint64
		if _, err := fmt.Sscanf(f[0], "%x-%x", &start, &end); err != nil {
			t.Fatal(err)
		}
		fileOff, err := strconv.ParseUint(f[2], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if pc >= start && pc < end {
			return exe, pc - start + fileOff
		}
	}
	t.Skipf("no mapping of %s holds %#x", exe, pc)
	return "", 0
}

// prescanWrite sends payload in one crypto/tls Write on a new connection to
// addr, and returns the patches the uprobe staged in xor_pending for it.
func prescanWrite(t *testing.T, objs *tlsuprobeObjects, addr string, payload []byte) []prescanPatch {
	t.Helper()
	tgid := uint32(os.Getpid())
	if err := objs.XorPending.Delete(tgid); err != nil && !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Fatal(err)
	}
	conn := dialTLS(t, addr, "")
	defer func() { _ = conn.Close() }()
	// The uprobe runs at Write's entry, on the whole buffer. The server reads
	// one byte and closes, so a write of several records may then be reset:
	// that does not change what was staged.
	_, _ = conn.Write(payload)

	var v tlsuprobeXorPendingVal
	if err := objs.XorPending.Lookup(tgid, &v); errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		return nil
	} else if err != nil {
		t.Fatal(err)
	}
	var patches []prescanPatch
	for i := 0; i < int(v.PatchCount) && i < len(v.Patches); i++ {
		var k [secrets.ShadowPrefixLen]byte
		for j, b := range v.Patches[i].Key.Prefix {
			k[j] = byte(b)
		}
		patches = append(patches, prescanPatch{v.Patches[i].SecretOffset, string(k[:])})
	}
	return patches
}

// readRefusedKeys reads n binding refusals from secret_binding_events, and
// checks that no other one follows. Returns their keys, sorted.
func readRefusedKeys(t *testing.T, events *ringbuf.Reader, n int) []string {
	t.Helper()
	var keys []string
	for {
		wait := 2 * time.Second
		if len(keys) == n {
			wait = 100 * time.Millisecond // anything more is unexpected
		}
		events.SetDeadline(time.Now().Add(wait))
		rec, err := events.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		var ev secretBindingEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			t.Fatalf("decoding secret_binding_event: %v", err)
		}
		if ev.Reason != secretEventBinding || ev.Audit != 0 || ev.Tgid != uint32(os.Getpid()) {
			t.Errorf("unexpected event: reason %d, audit %d, tgid %d", ev.Reason, ev.Audit, ev.Tgid)
		}
		keys = append(keys, string(ev.Key[:]))
	}
	slices.Sort(keys)
	return keys
}

// prescanModel counts, as the prescan should, the candidates of payload whose
// key is in secret_map (confirmed, up to four) and those whose key is not
// (unconfirmed, up to the fourth confirmed one).
func prescanModel(payload []byte, objs *tlsuprobeObjects) (confirmed, unconfirmed uint64) {
	for p := 0; p+secrets.ShadowPrefixLen <= len(payload) && confirmed < 4; p++ {
		w := payload[p:]
		if !bytes.HasPrefix(w, []byte("kl::")) && !bytes.HasPrefix(w, []byte{0xeb, 0x45, 0xcb}) {
			continue
		}
		var key secretKey
		copy(key.Prefix[:], w)
		var val secretValue
		if objs.SecretMap.Lookup(&key, &val) == nil {
			confirmed++
		} else {
			unconfirmed++
		}
	}
	return confirmed, unconfirmed
}

// debugCounter returns the total of a debug counter, by its debugCounterNames name.
func debugCounter(t *testing.T, objs *tlsuprobeObjects, name string) uint64 {
	t.Helper()
	idx := slices.Index(debugCounterNames, name)
	if idx < 0 {
		t.Fatalf("no debug counter %q", name)
	}
	var vals []uint64
	if err := objs.DebugCounters.Lookup(uint32(idx), &vals); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total
}
