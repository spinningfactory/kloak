package secrets

import (
	"math"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// seeded returns a reproducible random byte stream, so that the
// statistical tests below can't flake.
func seeded(seed uint64) *mrand.ChaCha8 {
	var s [32]byte
	for i := range s {
		s[i] = byte(seed >> (8 * (i % 8)))
	}
	s[31] ^= 0x5a
	return mrand.NewChaCha8(s)
}

// chiSquareCritical approximates the chi-square value with df degrees of
// freedom that a uniform sample exceeds with probability 0.001
// (Wilson–Hilferty).
func chiSquareCritical(df int) float64 {
	const z = 3.090 // the standard normal's 0.999 quantile
	d := float64(df)
	return d * math.Pow(1-2/(9*d)+z*math.Sqrt(2/(9*d)), 3)
}

// chiSquare is the chi-square statistic of counts against the expected
// probabilities p (same keys).
func chiSquare[K comparable](counts map[K]int, p map[K]float64, total int) float64 {
	var x float64
	for k, pk := range p {
		e := pk * float64(total)
		d := float64(counts[k]) - e
		x += d * d / e
	}
	return x
}

// TestIntnFromByte_Exact proves that intn is exactly uniform given uniform
// bytes: over the 256 byte values, every result in [0, n) has the same
// number of bytes, and only the rest are rejected.
func TestIntnFromByte_Exact(t *testing.T) {
	for n := 2; n <= 256; n++ {
		counts := make([]int, n)
		rejected := 0
		for b := 0; b < 256; b++ {
			v, ok := intnFromByte(byte(b), n)
			if !ok {
				rejected++
				continue
			}
			if v < 0 || v >= n {
				t.Fatalf("n=%d: byte %d gives %d", n, b, v)
			}
			counts[v]++
		}
		for v, c := range counts {
			if c != 256/n {
				t.Fatalf("n=%d: %d has %d bytes, want %d", n, v, c, 256/n)
			}
		}
		if rejected != 256%n {
			t.Fatalf("n=%d: %d bytes rejected, want %d", n, rejected, 256%n)
		}
	}
}

// TestRandStream_Intn checks the stream's draws (buffer refills
// included) with a chi-square test, for the sizes the generator draws
// from: code length windows (1-4) and buckets.
func TestRandStream_Intn(t *testing.T) {
	sizes := []int{2, 3, 4}
	for k := MinBits; k <= MaxBits; k++ {
		sizes = append(sizes, len(huffmanBuckets[k]))
	}
	for _, n := range sizes {
		rs := newRandStream(seeded(uint64(n)))
		const total = 200_000
		counts := map[int]int{}
		p := map[int]float64{}
		for v := 0; v < n; v++ {
			p[v] = 1 / float64(n)
		}
		for i := 0; i < total; i++ {
			v, err := rs.intn(n)
			if err != nil {
				t.Fatal(err)
			}
			counts[v]++
		}
		if x, crit := chiSquare(counts, p, total), chiSquareCritical(n-1); x > crit {
			t.Errorf("intn(%d): chi-square %.1f > %.1f", n, x, crit)
		}
	}
	if v, err := newRandStream(strings.NewReader("")).intn(1); err != nil || v != 0 {
		t.Errorf("intn(1) = %d, %v: want 0 with no draw", v, err)
	}
	if _, err := newRandStream(strings.NewReader("short")).intn(2); err == nil {
		t.Error("a failed read was not reported")
	}
}

// pickWeights returns the probabilities pickTailByte draws each byte with
// from code state c: the code length uniform in [lo, hi], then the byte
// uniform in its bucket, the nested bytes excluded and the rest scaled.
func pickWeights(c *shadowCode, lo, hi int) map[byte]float64 {
	p := map[byte]float64{}
	var sum float64
	for k := lo; k <= hi; k++ {
		for _, b := range huffmanBuckets[k] {
			if !c.nested(b) {
				w := 1 / float64(hi-lo+1) / float64(len(huffmanBuckets[k]))
				p[b] = w
				sum += w
			}
		}
	}
	for b := range p {
		p[b] /= sum
	}
	return p
}

// TestPickTailByte_Distribution checks each tail byte's pick with a
// chi-square test, for every window of code lengths.
func TestPickTailByte_Distribution(t *testing.T) {
	for lo := MinBits; lo <= MaxBits; lo++ {
		for hi := lo; hi <= MaxBits; hi++ {
			code := newShadowCode()
			code.add('a')
			p := pickWeights(&code, lo, hi)
			rs := newRandStream(seeded(uint64(lo*10 + hi)))
			const total = 100_000
			counts := map[byte]int{}
			for i := 0; i < total; i++ {
				b, ok, err := pickTailByte(rs, &code, lo, hi)
				if err != nil || !ok {
					t.Fatalf("[%d, %d]: %v, %v", lo, hi, ok, err)
				}
				if p[b] == 0 {
					t.Fatalf("[%d, %d]: picked %q, which it can't", lo, hi, b)
				}
				counts[b]++
			}
			if x, crit := chiSquare(counts, p, total), chiSquareCritical(len(p)-1); x > crit {
				t.Errorf("[%d, %d]: chi-square %.1f > %.1f over %d bytes", lo, hi, x, crit, len(p))
			}
		}
	}
}

// TestGenerateShadow_Distribution checks the first tail byte of whole
// shadows: at a target in the middle of the window, every code length is
// open there.
func TestGenerateShadow_Distribution(t *testing.T) {
	const n = 64
	target := prefixHuffmanBits + (n-len(ValuePrefix))*(MinBits+MaxBits)/2
	code := newShadowCode()
	p := pickWeights(&code, MinBits, MaxBits)
	rs := seeded(7)
	const total = 50_000
	counts := map[byte]int{}
	for i := 0; i < total; i++ {
		s, err := generateShadow(rs, n, target)
		if err != nil {
			t.Fatal(err)
		}
		counts[s[len(ValuePrefix)]]++
	}
	if x, crit := chiSquare(counts, p, total), chiSquareCritical(len(p)-1); x > crit {
		t.Errorf("first tail byte: chi-square %.1f > %.1f", x, crit)
	}
}

// codeBits returns the bits of Huffman(s), and its length in bits.
func codeBits(s string) ([]byte, int) {
	enc := hpack.AppendHuffmanString(nil, s)
	n := HuffmanBits(s)
	bits := make([]byte, n)
	for i := range bits {
		bits[i] = enc[i/8] >> (7 - i%8) & 1
	}
	return bits, n
}

// nestedCandidates returns the bit offsets, other than 0, at which a
// placeholder candidate lies wholly inside Huffman(s): an independent check
// of what shadowCode excludes.
func nestedCandidates(s string) []int {
	bits, n := codeBits(s)
	var at []int
	for _, c := range []struct {
		v uint64
		n int
	}{{candidateHuffman, 24}, {candidateRaw, 32}} {
		for off := 1; off+c.n <= n; off++ {
			var w uint64
			for i := 0; i < c.n; i++ {
				w = w<<1 | uint64(bits[off+i])
			}
			if w == c.v {
				at = append(at, off)
			}
		}
	}
	return at
}

// checkShadow checks a shadow of length n for target bits: its prefix, its
// length, its alphabet, its exact Huffman bit length, and no nested
// candidate.
func checkShadow(t *testing.T, s string, n, target int) {
	t.Helper()
	if len(s) != n || !strings.HasPrefix(s, ValuePrefix) {
		t.Fatalf("len %d, target %d: got %d bytes starting %q", n, target, len(s), s[:min(len(s), 8)])
	}
	if got := HuffmanBits(s); got != target {
		t.Fatalf("len %d: %d Huffman bits, want %d", n, got, target)
	}
	for i := len(ValuePrefix); i < len(s); i++ {
		k := huffmanBitsTable[s[i]]
		if k < MinBits || k > MaxBits || !slices.Contains(huffmanBuckets[k], s[i]) {
			t.Fatalf("len %d: byte %q at %d is not in the alphabet", n, s[i], i)
		}
	}
	if at := nestedCandidates(s); len(at) > 0 {
		t.Fatalf("len %d: nested candidates at bits %v", n, at)
	}
}

// TestGenerateShadow_Properties checks shadows over many lengths and
// targets, the window's edges included, up to 1 MiB.
func TestGenerateShadow_Properties(t *testing.T) {
	rs := seeded(11)
	targets := func(n int) []int {
		tail := n - len(ValuePrefix)
		lo, hi := prefixHuffmanBits+tail*MinBits, prefixHuffmanBits+tail*MaxBits
		out := []int{lo, hi, (lo + hi) / 2}
		if hi > lo {
			out = append(out, lo+1, hi-1, lo+int(rs.Uint64()%uint64(hi-lo)))
		}
		return out
	}
	lengths := []int{}
	for n := len(ValuePrefix); n <= 300; n++ {
		lengths = append(lengths, n)
	}
	lengths = append(lengths, 1000, 4096, 64<<10, MaxLenLimit)
	for _, n := range lengths {
		for _, target := range targets(n) {
			s, err := generateShadow(rs, n, target)
			if err != nil {
				t.Fatalf("len %d, target %d: %v", n, target, err)
			}
			checkShadow(t, s, n, target)
		}
	}
	// And with crypto/rand.
	for _, n := range []int{8, 129, 4096} {
		target := prefixHuffmanBits + (n-len(ValuePrefix))*6
		s, err := generateShadowValue(n, target)
		if err != nil {
			t.Fatal(err)
		}
		checkShadow(t, s, n, target)
	}
}

// candidateWays finds tail byte sequences whose code holds a candidate
// (pattern, n bits) starting j bits into the code of their first byte:
// what follows is decoded from the pattern's bits (the code is prefix-free)
// and must be tail bytes, the last of them possibly cut short. It returns
// each sequence whole (its last byte the first that ends the candidate).
func candidateWays(pattern uint64, n int) [][]byte {
	pat := make([]byte, n)
	for i := range pat {
		pat[i] = byte(pattern>>(n-1-i)) & 1
	}
	var alphabet []byte
	for k := MinBits; k <= MaxBits; k++ {
		alphabet = append(alphabet, huffmanBuckets[k]...)
	}
	bitsOf := func(b byte) []byte {
		k := huffmanBitsTable[b]
		out := make([]byte, k)
		for i := range out {
			out[i] = byte(huffmanCodes[b]>>(k-1-i)) & 1
		}
		return out
	}
	// decode returns the tail bytes p decodes to, the last one completing
	// a prefix of p's end, or nil.
	decode := func(p []byte) []byte {
		var out []byte
		for len(p) > 0 {
			found := false
			for _, b := range alphabet {
				c := bitsOf(b)
				m := min(len(c), len(p))
				if slices.Equal(c[:m], p[:m]) {
					out = append(out, b)
					p = p[m:]
					found = true
					break
				}
			}
			if !found {
				return nil
			}
		}
		return out
	}
	var ways [][]byte
	for _, a := range alphabet {
		c := bitsOf(a)
		for j := 0; j < len(c); j++ {
			rest := c[j:]
			m := min(len(rest), n)
			if !slices.Equal(rest[:m], pat[:m]) {
				continue
			}
			if m == n {
				ways = append(ways, []byte{a})
			} else if d := decode(pat[m:]); d != nil {
				ways = append(ways, append([]byte{a}, d...))
			}
		}
	}
	return ways
}

// TestNestedCandidatesArePossible shows why shadowCode is needed: tail
// bytes whose codes line up into each candidate exist, and shadowCode
// catches every one of them.
func TestNestedCandidatesArePossible(t *testing.T) {
	for _, c := range []struct {
		name string
		v    uint64
		n    int
	}{{"Huffman(kl::)", candidateHuffman, 24}, {"kl::", candidateRaw, 32}} {
		ways := candidateWays(c.v, c.n)
		if len(ways) == 0 {
			t.Errorf("%s: no tail bytes line up into it", c.name)
		}
		for _, w := range ways {
			s := ValuePrefix + "a" + string(w)
			if len(nestedCandidates(s)) == 0 {
				t.Fatalf("%s: %q holds no candidate", c.name, w)
			}
			code := newShadowCode()
			flagged := false
			for i := len(ValuePrefix); i < len(s); i++ {
				if code.nested(s[i]) {
					flagged = i == len(s)-1
					break
				}
				code.add(s[i])
			}
			if !flagged {
				t.Errorf("%s: shadowCode does not flag the last byte of %q", c.name, w)
			}
		}
		t.Logf("%s: %d ways, e.g. %q", c.name, len(ways), ways[0])
	}
}

// TestPickTailByte_ExcludesNested checks that a pick never completes a
// candidate, at a state one byte short of one, and reports a dead end when
// every byte of the window would.
func TestPickTailByte_ExcludesNested(t *testing.T) {
	deadEnds := 0
	for _, w := range candidateWays(candidateHuffman, 24) {
		code := newShadowCode()
		code.add('a')
		for _, b := range w[:len(w)-1] {
			code.add(b)
		}
		last := w[len(w)-1]
		k := huffmanBitsTable[last]
		if !code.nested(last) {
			t.Fatalf("%q: its last byte is not nested", w)
		}
		if !code.anyFits(k, k) {
			deadEnds++
			if _, ok, err := pickTailByte(newRandStream(seeded(1)), &code, k, k); ok || err != nil {
				t.Errorf("%q: a dead end picked a byte (%v)", w, err)
			}
			continue
		}
		rs := newRandStream(seeded(uint64(len(w))))
		for i := 0; i < 2000; i++ {
			b, ok, err := pickTailByte(rs, &code, k, k)
			if err != nil || !ok {
				t.Fatalf("%q: %v, %v", w, ok, err)
			}
			if code.nested(b) {
				t.Fatalf("%q: picked %q, which completes the candidate", w, b)
			}
		}
	}
	t.Logf("%d dead ends", deadEnds)
}

// TestCanShadow_Long checks the feasibility bounds at 1 MiB and beyond,
// and that no length or bit count overflows them.
func TestCanShadow_Long(t *testing.T) {
	for _, n := range []int{MaxLenLimit, 1 << 30} {
		tail := n - len(ValuePrefix)
		lo, hi := prefixHuffmanBits+tail*MinBits, prefixHuffmanBits+tail*MaxBits
		for target, ok := range map[int]bool{lo - 1: false, lo: true, hi: true, hi + 1: false} {
			if err := CanShadow(n, target); (err == nil) != ok {
				t.Errorf("CanShadow(%d, %d) = %v, want ok %v", n, target, err, ok)
			}
		}
	}
	for _, c := range [][2]int{{math.MaxInt, math.MaxInt}, {math.MaxInt, 0}, {math.MaxInt, math.MinInt}, {-1, 0}, {math.MinInt, 0}, {8, -1}, {8, math.MaxInt}} {
		if err := CanShadow(c[0], c[1]); err == nil {
			t.Errorf("CanShadow(%d, %d) accepted", c[0], c[1])
		}
	}
	// The most Huffman bits a byte takes (30), over 1 MiB.
	if got, want := HuffmanBits(strings.Repeat("\n", MaxLenLimit)), 30*MaxLenLimit; got != want {
		t.Errorf("HuffmanBits of 1 MiB of newlines = %d, want %d", got, want)
	}
	if got := HuffmanBits(strings.Repeat("a", MaxLenLimit)); got != 5*MaxLenLimit {
		t.Errorf("HuffmanBits of 1 MiB of a = %d", got)
	}
}

// TestGenerateShadow_FailedRead checks that a failed read of the random
// stream is an error, not a shadow.
func TestGenerateShadow_FailedRead(t *testing.T) {
	_, err := generateShadow(strings.NewReader("x"), 4096, prefixHuffmanBits+4092*6)
	if err == nil {
		t.Fatal("a shadow from a stream that ran out")
	}
	if !strings.Contains(err.Error(), "reading random bytes") {
		t.Errorf("error %q", err)
	}
}

// TestPickTailByte_DeadEnd checks a state no byte of the window fits: the
// code holds a candidate but its last bit, and every code of the window
// starts with that bit (5-bit codes with 0, 7- and 8-bit ones with 1).
// buildShadow then starts over.
func TestPickTailByte_DeadEnd(t *testing.T) {
	for _, c := range []struct {
		name   string
		v      uint64
		lo, hi int
	}{{"Huffman(kl::)", candidateHuffman, 7, 8}, {"kl::", candidateRaw, 5, 5}} {
		code := shadowCode{reg: c.v >> 1, n: 100}
		if code.anyFits(c.lo, c.hi) {
			t.Fatalf("%s: a byte of [%d, %d] fits", c.name, c.lo, c.hi)
		}
		if _, ok, err := pickTailByte(newRandStream(seeded(3)), &code, c.lo, c.hi); ok || err != nil {
			t.Errorf("%s: a dead end picked a byte (%v)", c.name, err)
		}
		// One bit further back, the window has bytes again.
		code = shadowCode{reg: c.v >> 2, n: 100}
		if _, ok, err := pickTailByte(newRandStream(seeded(3)), &code, c.lo, c.hi); !ok || err != nil {
			t.Errorf("%s: no byte one bit earlier (%v, %v)", c.name, ok, err)
		}
	}
}
