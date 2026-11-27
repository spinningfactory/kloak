//go:build linux

package ebpf

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/net/http2/hpack"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// mapLen counts the entries of m.
func mapLen(t *testing.T, m *ciliumebpf.Map) int {
	t.Helper()
	n := 0
	key := make([]byte, m.KeySize())
	var prev any
	for {
		if err := m.NextKey(prev, &key); err != nil {
			if errors.Is(err, ciliumebpf.ErrKeyNotExist) {
				return n
			}
			t.Fatalf("iterating %v: %v", m, err)
		}
		n++
		prev = key
	}
}

// newSizedTestStore is newTestStore with a secret_chunks of capacity chunks
// and a maximum value length of maxLen.
func newSizedTestStore(t *testing.T, capacity uint32, maxLen int) *secretStore {
	t.Helper()
	spec := loadSpec(t).Maps["secret_chunks"].Copy()
	spec.MaxEntries = capacity
	chunks, err := ciliumebpf.NewMap(spec)
	if err != nil {
		t.Skipf("eBPF maps not available: %v", err)
	}
	t.Cleanup(func() { _ = chunks.Close() })
	return newSecretStore(createTestSecretMap(t), chunks, maxLen, testLog())
}

// storedChunks reads back the chunks of key's secret_map entry: its
// generation and its chunks, which must all be there.
func storedChunks(t *testing.T, st *secretStore, key secretKey) (secretValue, []secretChunk) {
	t.Helper()
	var val secretValue
	if err := st.secrets.Lookup(&key, &val); err != nil {
		t.Fatalf("secret_map entry %q: %v", key.Prefix[:], err)
	}
	if val.Gen == 0 {
		t.Fatalf("secret_map entry %q has generation 0", key.Prefix[:])
	}
	chunks := make([]secretChunk, chunkCount(int(val.Len)))
	for i := range chunks {
		if err := st.chunks.Lookup(&secretChunkKey{Key: key, Gen: val.Gen, Idx: uint32(i)}, &chunks[i]); err != nil {
			t.Fatalf("chunk %d of %q (gen %d): %v", i, key.Prefix[:], val.Gen, err)
		}
	}
	// No chunk past the last.
	if err := st.chunks.Lookup(&secretChunkKey{Key: key, Gen: val.Gen, Idx: uint32(len(chunks))}, &secretChunk{}); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Errorf("chunk %d of %q (gen %d) exists: %v", len(chunks), key.Prefix[:], val.Gen, err)
	}
	return val, chunks
}

// checkChunks checks chunks against the placeholder and real value as on
// the wire: the shadow, its delta to real with padBits low bits of the last
// byte 0, and zeros past the end.
func checkChunks(t *testing.T, what string, chunks []secretChunk, shadow, real []byte, padBits uint8) {
	t.Helper()
	if len(chunks) != chunkCount(len(shadow)) {
		t.Fatalf("%s: %d chunks, want %d", what, len(chunks), chunkCount(len(shadow)))
	}
	for i := 0; i < len(chunks)*secretChunkLen; i++ {
		c := &chunks[i/secretChunkLen]
		gotShadow, gotDelta := c.Shadow[i%secretChunkLen], c.Delta[i%secretChunkLen]
		var wantShadow, wantDelta byte
		if i < len(shadow) {
			wantShadow, wantDelta = shadow[i], shadow[i]^real[i]
			if i == len(shadow)-1 {
				wantDelta &= byte(0xff << padBits)
			}
		}
		if gotShadow != wantShadow || gotDelta != wantDelta {
			t.Fatalf("%s: byte %d: shadow %#x delta %#x, want %#x %#x", what, i, gotShadow, gotDelta, wantShadow, wantDelta)
		}
	}
}

// testValue returns n bytes of a value, different for each seed.
func testValue(prefix string, n int, seed byte) string {
	b := []byte(prefix + strings.Repeat("x", max(0, n-len(prefix))))[:n]
	for i := len(prefix); i < n; i++ {
		b[i] = 'a' + (byte(i)*7+seed)%26
	}
	return string(b)
}

// TestStoreEntryChunks checks the chunks of entries across the chunk
// boundaries, and the pad bits of an HPACK entry's last byte.
func TestStoreEntryChunks(t *testing.T) {
	for _, n := range []int{1, 8, 255, 256, 257, 511, 512, 513, 1000} {
		shadow := []byte(testValue("kl::", n, 1))
		real := []byte(testValue("", n, 2))
		for _, pad := range []uint8{0, 1, 7} {
			e := newStoreEntry(secretKey{}, &secretValue{}, shadow, real, pad)
			checkChunks(t, "entry", e.chunks, shadow, real, pad)
			if e.sum != chunkSum(uint32(n), e.chunks) {
				t.Errorf("len %d: sum is not chunkSum", n)
			}
		}
	}
	// The sum tells content apart.
	a := newStoreEntry(secretKey{}, &secretValue{}, []byte("kl::aaaa"), []byte("realreal"), 0)
	b := newStoreEntry(secretKey{}, &secretValue{}, []byte("kl::aaaa"), []byte("realreaL"), 0)
	if a.sum == b.sum {
		t.Error("different deltas have the same sum")
	}
}

// TestDataPlaneMaxLen ties the shared limit to SECRET_MAX_LEN: the sync
// copies a value of up to secrets.DataPlaneMaxLen bytes in real_secret.
func TestDataPlaneMaxLen(t *testing.T) {
	bpf := reflect.TypeOf(tlsuprobeSecretValue{}.RealSecret).Len()
	mirror := reflect.TypeOf(secretValue{}.RealSecret).Len()
	if bpf != secrets.DataPlaneMaxLen || mirror != bpf {
		t.Errorf("SECRET_MAX_LEN is %d, secretValue.RealSecret %d, secrets.DataPlaneMaxLen %d",
			bpf, mirror, secrets.DataPlaneMaxLen)
	}
	if got := (SecretStoreConfig{MaxSecretLen: secrets.MaxLenLimit}).maxLen(); got != secrets.DataPlaneMaxLen {
		t.Errorf("the sync takes values of up to %d bytes, the data plane %d", got, secrets.DataPlaneMaxLen)
	}
}

// TestStoreApply_Chunks checks what apply writes for a secret: its
// placeholder's chunks and its HPACK-Huffman form's, each under its own
// generation, and an entry of several chunks.
func TestStoreApply_Chunks(t *testing.T) {
	st := newTestStore(t)
	p := hpackTailPairs[1] // pad bits 1
	snapshot := []secrets.Secret{{OwnerID: "ns/a", Key: "k", Real: p.real, Shadow: p.shadow, Host: "example.com"}}
	if _, err := st.apply(snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}
	var raw secretKey
	copy(raw.Prefix[:], p.shadow)
	rawVal, chunks := storedChunks(t, st, raw)
	checkChunks(t, "placeholder", chunks, []byte(p.shadow), []byte(p.real), 0)

	huffShadow := hpack.AppendHuffmanString(nil, p.shadow)
	huffReal := hpack.AppendHuffmanString(nil, p.real)
	var huff secretKey
	copy(huff.Prefix[:], huffShadow)
	huffVal, chunks := storedChunks(t, st, huff)
	if huffVal.PadBits == 0 {
		t.Fatalf("fixture %q has no pad bits", p.shadow)
	}
	checkChunks(t, "Huffman", chunks, huffShadow, huffReal, huffVal.PadBits)
	if huffVal.Gen == rawVal.Gen {
		t.Errorf("both entries have generation %d", rawVal.Gen)
	}
	// The pad bits are Huffman(shadow)'s EOS padding in the shadow, 0 in
	// the delta.
	last := chunks[(len(huffShadow)-1)/secretChunkLen].Shadow[(len(huffShadow)-1)%secretChunkLen]
	if mask := byte(1)<<huffVal.PadBits - 1; last&mask != mask {
		t.Errorf("Huffman shadow's last byte %#x does not end in %d EOS bits", last, huffVal.PadBits)
	}
	if st.used != mapLen(t, st.chunks) {
		t.Errorf("used %d, secret_chunks holds %d", st.used, mapLen(t, st.chunks))
	}

	// The store takes any length (the sync limits it to the data plane's).
	long := newSizedTestStore(t, 64, 1000)
	shadow, real := testValue("kl::long", 700, 3), testValue("", 700, 4)
	if _, err := long.apply([]secrets.Secret{{OwnerID: "ns/a", Key: "k", Real: real, Shadow: shadow}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	copy(raw.Prefix[:], shadow)
	_, chunks = storedChunks(t, long, raw)
	checkChunks(t, "700 bytes", chunks, []byte(shadow), []byte(real), 0)
}

// TestStoreApply_Generations checks that an unchanged secret keeps its
// generation, that a changed one gets a new one whose chunks are all
// written, and that the previous generation goes only after the grace
// period.
func TestStoreApply_Generations(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	sec := shortSecret(1, "realval1")
	var key secretKey
	copy(key.Prefix[:], sec.Shadow)
	apply := func(s secrets.Secret, at time.Time) secretValue {
		t.Helper()
		if _, err := st.apply([]secrets.Secret{s}, at); err != nil {
			t.Fatal(err)
		}
		val, _ := storedChunks(t, st, key)
		return val
	}
	first := apply(sec, now)
	chunksAfterFirst := mapLen(t, st.chunks)

	// No churn: the same secret, and one whose restrictions changed.
	if v := apply(sec, now.Add(time.Second)); v.Gen != first.Gen {
		t.Errorf("an unchanged secret went from generation %d to %d", first.Gen, v.Gen)
	}
	sec.Host, sec.Port = "api.example.com", 443
	v := apply(sec, now.Add(2*time.Second))
	if v.Gen != first.Gen || string(v.AllowedHost[:v.HostLen]) != sec.Host || v.Port != 443 {
		t.Errorf("a restriction change: gen %d (want %d), host %q, port %d", v.Gen, first.Gen, v.AllowedHost[:v.HostLen], v.Port)
	}
	if n := mapLen(t, st.chunks); n != chunksAfterFirst || len(st.retired) != 0 {
		t.Errorf("unchanged secrets churned: %d chunks (want %d), %d retired", n, chunksAfterFirst, len(st.retired))
	}

	// A rotation: a new generation, the previous one kept for the grace
	// period.
	sec.Real = "realval2"
	changedAt := now.Add(3 * time.Second)
	second := apply(sec, changedAt)
	if second.Gen == first.Gen {
		t.Fatalf("a changed secret kept generation %d", first.Gen)
	}
	_, chunks := storedChunks(t, st, key)
	checkChunks(t, "rotated", chunks, []byte(sec.Shadow), []byte(sec.Real), 0)
	oldChunk := secretChunkKey{Key: key, Gen: first.Gen}
	if err := st.chunks.Lookup(&oldChunk, &secretChunk{}); err != nil {
		t.Errorf("the previous generation went at once: %v", err)
	}
	// A sync within the grace period keeps it.
	apply(sec, changedAt.Add(secretStoreGrace-time.Second))
	if err := st.chunks.Lookup(&oldChunk, &secretChunk{}); err != nil {
		t.Errorf("the previous generation went within the grace period: %v", err)
	}
	if freed, _, err := st.collect(changedAt.Add(secretStoreGrace)); err != nil || freed != 1 {
		t.Errorf("collect after the grace period freed %d, %v; want the previous generation's chunk", freed, err)
	}
	if err := st.chunks.Lookup(&oldChunk, &secretChunk{}); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Errorf("the previous generation is left after the grace period: %v", err)
	}
	if st.used != mapLen(t, st.chunks) {
		t.Errorf("used %d, secret_chunks holds %d", st.used, mapLen(t, st.chunks))
	}
}

// TestStoreApply_Prune checks that a secret gone from the snapshot leaves
// secret_map at once, and secret_chunks after the grace period.
func TestStoreApply_Prune(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	p := hpackTailPairs[0]
	if _, err := st.apply([]secrets.Secret{{OwnerID: "ns/a", Key: "k", Real: p.real, Shadow: p.shadow}}, now); err != nil {
		t.Fatal(err)
	}
	if n := mapLen(t, st.secrets); n != 2 {
		t.Fatalf("secret_map has %d entries, want the placeholder's and its Huffman form's", n)
	}
	chunks := mapLen(t, st.chunks)
	if _, err := st.apply(nil, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n := mapLen(t, st.secrets); n != 0 {
		t.Errorf("secret_map has %d entries after the secret went", n)
	}
	if n := mapLen(t, st.chunks); n != chunks {
		t.Errorf("secret_chunks has %d entries right after the secret went, want its %d until the grace period", n, chunks)
	}
	if _, err := st.apply(nil, now.Add(time.Second+secretStoreGrace)); err != nil {
		t.Fatal(err)
	}
	if n := mapLen(t, st.chunks); n != 0 || st.used != 0 {
		t.Errorf("secret_chunks has %d entries (used %d) after the grace period", n, st.used)
	}
}

// shortSecret is a secret of one entry: its placeholder's Huffman code is
// shorter than a key, so it has no HTTP/2 entry.
func shortSecret(i int, real string) secrets.Secret {
	return secrets.Secret{OwnerID: "ns/s" + strconv.Itoa(i), Key: "k", Real: real, Shadow: "kl::000" + strconv.Itoa(i)}
}

// TestStoreApply_Full checks what a full store does: a new secret is left
// out, a changed one is withdrawn (never rewritten with its previous value),
// and both are written once the grace period has freed room. Nothing is
// written in part.
func TestStoreApply_Full(t *testing.T) {
	st := newSizedTestStore(t, 2, secrets.DataPlaneMaxLen)
	now := time.Now()
	a, b, c := shortSecret(1, "realval1"), shortSecret(2, "realval2"), shortSecret(3, "realval3")
	key := func(s secrets.Secret) *secretKey {
		var k secretKey
		copy(k.Prefix[:], s.Shadow)
		return &k
	}
	if _, err := st.apply([]secrets.Secret{a, b}, now); err != nil {
		t.Fatal(err)
	}
	if n := mapLen(t, st.secrets); n != 2 || st.refusedFull != 0 {
		t.Fatalf("secret_map has %d entries (refused %d), want both secrets", n, st.refusedFull)
	}

	// A new secret: no room, left out.
	if _, err := st.apply([]secrets.Secret{a, b, c}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := st.secrets.Lookup(key(c), &secretValue{}); !errors.Is(err, ciliumebpf.ErrKeyNotExist) || st.refusedFull != 1 {
		t.Errorf("a secret with no room: %v, refused %d; want it left out", err, st.refusedFull)
	}

	// A rotation with no room for the new generation: the secret is
	// withdrawn, its previous generation retired.
	a2 := a
	a2.Real = "realvalX"
	rotatedAt := now.Add(2 * time.Second)
	if _, err := st.apply([]secrets.Secret{a2, b}, rotatedAt); err != nil {
		t.Fatal(err)
	}
	if err := st.secrets.Lookup(key(a), &secretValue{}); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Errorf("a changed secret with no room for its new value is still in secret_map: %v", err)
	}
	if st.refusedFull != 1 || len(st.retired) != 1 {
		t.Errorf("refused %d, %d retired generations; want the changed secret refused and its previous generation retired", st.refusedFull, len(st.retired))
	}
	if st.used > st.capacity || mapLen(t, st.chunks) > st.capacity {
		t.Errorf("used %d of %d", st.used, st.capacity)
	}
	if secretStoreRefusedFull(t) != 1 {
		t.Errorf("refused{reason=full} = %v, want 1", secretStoreRefusedFull(t))
	}

	// Within the grace period, still no room.
	if freed, refused, err := st.collect(rotatedAt.Add(secretStoreGrace - time.Second)); err != nil || freed != 0 || !refused {
		t.Errorf("collect within the grace period: freed %d, refused %v, %v", freed, refused, err)
	}
	// Then the retired generation frees room, and the retry writes it.
	freed, refused, err := st.collect(rotatedAt.Add(secretStoreGrace))
	if err != nil || freed != 1 || !refused {
		t.Fatalf("collect after the grace period: freed %d, refused %v, %v; want 1, true", freed, refused, err)
	}
	if _, err := st.apply([]secrets.Secret{a2, b}, rotatedAt.Add(secretStoreGrace)); err != nil {
		t.Fatal(err)
	}
	val, chunks := storedChunks(t, st, *key(a2))
	checkChunks(t, "rotated", chunks, []byte(a2.Shadow), []byte(a2.Real), 0)
	if string(val.RealSecret[:val.Len]) != a2.Real || st.refusedFull != 0 {
		t.Errorf("after the retry: real %q, refused %d", val.RealSecret[:val.Len], st.refusedFull)
	}
}

func secretStoreRefusedFull(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	if err := secretStoreRefused.WithLabelValues("full").Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetGauge().GetValue()
}

// TestStoreApply_WriteFailure checks that a changed secret whose new
// generation fails to be written is withdrawn and the error reported (the
// sync is retried), and that an unchanged one is left as it is.
func TestStoreApply_WriteFailure(t *testing.T) {
	st := newTestStore(t)
	now := time.Now()
	a := shortSecret(1, "realval1")
	var key secretKey
	copy(key.Prefix[:], a.Shadow)
	if _, err := st.apply([]secrets.Secret{a}, now); err != nil {
		t.Fatal(err)
	}
	// The next generation's first chunk is taken: its write fails.
	blocker := secretChunkKey{Key: key, Gen: st.lastGen + 1}
	if err := st.chunks.Update(&blocker, &secretChunk{}, ciliumebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	a2 := a
	a2.Real = "realvalX"
	if _, err := st.apply([]secrets.Secret{a2}, now.Add(time.Second)); err == nil {
		t.Error("a failed chunk write was not reported")
	}
	if err := st.secrets.Lookup(&key, &secretValue{}); !errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		t.Errorf("a changed secret whose new value failed to be written is still in secret_map: %v", err)
	}
	// The retry writes it.
	if _, err := st.apply([]secrets.Secret{a2}, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if val, _ := storedChunks(t, st, key); string(val.RealSecret[:val.Len]) != a2.Real {
		t.Errorf("after the retry: real %q", val.RealSecret[:val.Len])
	}
}

// TestStoreRebuild checks that a controller adopting the maps of a previous
// one rebuilds the store's state: no generation churns for the secrets it
// syncs again, a retired generation is still deleted, and an entry whose
// chunks are not all there is written again.
func TestStoreRebuild(t *testing.T) {
	prev := newTestStore(t)
	now := time.Now()
	p := hpackTailPairs[2]
	a := secrets.Secret{OwnerID: "ns/a", Key: "k", Real: p.real, Shadow: p.shadow}
	b, c := shortSecret(2, "realval2"), shortSecret(3, "realval3")
	snapshot := []secrets.Secret{a, b, c}
	if _, err := prev.apply(snapshot, now); err != nil {
		t.Fatal(err)
	}
	b.Real = "realvalY" // a rotation: b's previous generation is retired
	snapshot = []secrets.Secret{a, b, c}
	if _, err := prev.apply(snapshot, now); err != nil {
		t.Fatal(err)
	}
	// c's chunk is lost.
	var ck secretKey
	copy(ck.Prefix[:], c.Shadow)
	if err := prev.chunks.Delete(&secretChunkKey{Key: ck, Gen: prev.entries[ck].gen}); err != nil {
		t.Fatal(err)
	}

	st := newSecretStore(prev.secrets, prev.chunks, prev.maxLen, testLog())
	restart := now.Add(5 * time.Second)
	if err := st.rebuild(restart); err != nil {
		t.Fatal(err)
	}
	if st.lastGen != prev.lastGen || len(st.retired) != 1 || st.used != mapLen(t, st.chunks)+1 {
		t.Errorf("rebuilt: last gen %d (want %d), %d retired (want 1), used %d (secret_chunks holds %d, and c's lost one)",
			st.lastGen, prev.lastGen, len(st.retired), st.used, mapLen(t, st.chunks))
	}
	for k, e := range prev.entries {
		got := st.entries[k]
		if k == ck {
			if got.valid {
				t.Error("an entry with a lost chunk was rebuilt valid")
			}
			continue
		}
		if got != e {
			t.Errorf("entry %q rebuilt as %+v, want %+v", k.Prefix[:], got, e)
		}
	}

	lastGen := st.lastGen
	if _, err := st.apply(snapshot, restart); err != nil {
		t.Fatal(err)
	}
	if st.lastGen != lastGen+1 {
		t.Errorf("after the restart's sync: %d new generations, want 1 (c's)", st.lastGen-lastGen)
	}
	_, chunks := storedChunks(t, st, ck)
	checkChunks(t, "c rewritten", chunks, []byte(c.Shadow), []byte(c.Real), 0)

	// The generations nothing points at go after a grace period from the
	// restart: b's previous one and c's.
	if _, _, err := st.collect(restart.Add(secretStoreGrace)); err != nil {
		t.Fatal(err)
	}
	if st.used != mapLen(t, st.chunks) || len(st.retired) != 0 {
		t.Errorf("after the grace period: used %d, secret_chunks holds %d, %d retired", st.used, mapLen(t, st.chunks), len(st.retired))
	}
	want := 0
	for _, e := range st.entries {
		want += e.chunks
	}
	if n := mapLen(t, st.chunks); n != want {
		t.Errorf("secret_chunks holds %d, the entries %d", n, want)
	}
}

// TestStoreEmpty checks that an uninstall takes the secrets out of both
// maps.
func TestStoreEmpty(t *testing.T) {
	st := newTestStore(t)
	p := hpackTailPairs[0]
	if _, err := st.apply([]secrets.Secret{{OwnerID: "ns/a", Key: "k", Real: p.real, Shadow: p.shadow}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.empty(); err != nil {
		t.Fatal(err)
	}
	if n, c := mapLen(t, st.secrets), mapLen(t, st.chunks); n != 0 || c != 0 {
		t.Errorf("after empty: secret_map %d, secret_chunks %d entries", n, c)
	}
}
