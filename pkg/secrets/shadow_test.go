package secrets

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestGenerateShadowValue_Length(t *testing.T) {
	// Exercises the construction across the practical length range.
	// The target bit count sits at the midpoint of the alphabet's
	// per-byte window so every length is comfortably feasible — the
	// boundary cases (unsatisfiability at length × density extremes)
	// live in TestGenerateShadowValue_UnsatisfiableReturnsError.
	cases := []int{8, 16, 32, 64, 128}
	for _, n := range cases {
		tailLen := n - len(ValuePrefix)
		midBitsPerByte := (MinBits + MaxBits) / 2 // 6 for {5,7}
		target := prefixHuffmanBits + tailLen*midBitsPerByte
		got, err := generateShadowValue(n, target)
		if err != nil {
			t.Errorf("originalLen=%d: unexpected error: %v", n, err)
			continue
		}
		if len(got) != n {
			t.Errorf("originalLen=%d: got len(shadow)=%d, want %d", n, len(got), n)
		}
		if !strings.HasPrefix(got, ValuePrefix) {
			t.Errorf("originalLen=%d: shadow %q does not start with %q", n, got, ValuePrefix)
		}
		if HuffmanBits(got) != target {
			t.Errorf("originalLen=%d: shadow Huffman bits=%d, want %d", n, HuffmanBits(got), target)
		}
	}
}

func TestGenerateShadowValue_HuffmanBitExact(t *testing.T) {
	// The headline correctness property of the byte-by-byte construction:
	// shadow's Huffman bit length equals real's exactly. This is the
	// invariant the BPF sync path needs so it can rewrite the wire slot
	// without any EOS padding — see PR description (and RFC 7541 §5.2
	// for why over-padding is illegal).
	//
	// Run a mix of character classes (low/medium/high Huffman density,
	// uppercase/lowercase/digits/dashes) and repeat each enough times to
	// flush out any sampling-dependent invariant violation. The previous
	// random-then-tune algorithm only met the invariant in the byte-rounded
	// sense and could land 1–7 bits short of bit equality; this test
	// would have failed that algorithm immediately.
	cases := []struct {
		real     string
		attempts int
	}{
		// Each real is chosen so its Huffman bit count lands inside the
		// feasibility window [prefixHuffmanBits + tailLen*MinBits,
		// prefixHuffmanBits + tailLen*MaxBits] for shadow length =
		// len(real). Density extremes (all-'a', all-'z') belong in the
		// unsatisfiable test instead.
		{"sk-live-0123456789abcdef", 200},
		{"REAL-ALLOWED-KEY-12345", 200},
		{"lowercase-secret-triggering-hpack-bug", 200},
		{"PASSWORD123", 200},
		{"Bearer-token-with-mixed-CASE-and-digits-123", 200},
	}
	for _, tc := range cases {
		realHL := HuffmanBits(tc.real)
		for i := 0; i < tc.attempts; i++ {
			shadow, err := generateShadowValue(len(tc.real), realHL)
			if err != nil {
				t.Fatalf("real=%q attempt=%d: unexpected error: %v", tc.real, i, err)
			}
			if shadowHL := HuffmanBits(shadow); shadowHL != realHL {
				t.Fatalf("real=%q attempt=%d: shadow Huffman bits %d != real Huffman bits %d (shadow=%q)",
					tc.real, i, shadowHL, realHL, shadow)
			}
			// Cross-check against the hpack package: bit equality implies
			// byte equality, so the wire-slot byte counts match too —
			// which is what the BPF rewrite ultimately depends on.
			if hpack.HuffmanEncodeLength(shadow) != hpack.HuffmanEncodeLength(tc.real) {
				t.Fatalf("real=%q attempt=%d: shadow Huffman bytes %d != real Huffman bytes %d",
					tc.real, i, hpack.HuffmanEncodeLength(shadow), hpack.HuffmanEncodeLength(tc.real))
			}
		}
	}
}

func TestGenerateShadowValue_UnsatisfiableReturnsError(t *testing.T) {
	// Feasibility is `tailBits ∈ [tailLen*MinBits, tailLen*MaxBits]`.
	// The two failure modes are:
	//   - target ABOVE the window: very high-density real ('z', 'X')
	//     packed into a short shadow can't be reached because every tail
	//     byte caps at MaxBits.
	//   - target BELOW the window: a real of all-low-bit chars
	//     ('a', 'c', '0') needs fewer bits than MinBits*tailLen.
	// Both surface as ErrHuffmanInvariantUnsatisfiable — the construction
	// never silently violates the invariant.
	cases := []struct {
		name     string
		real     string
		shadowN  int
		mustFail bool
	}{
		// Above-the-window: shadow tail can supply at most tailLen*MaxBits
		// bits, but real demands more. 'X' is 8 bits/byte; 16 chars of
		// 'X' = 128 bits, minus prefix's 27 = 101 bits required from
		// (16-4)=12 tail bytes — needs 8.4 bits/byte, above MaxBits=7.
		{"X×16 in shadowN=16", strings.Repeat("X", 16), 16, true},
		// Above-the-window classic from the prior algorithm's test:
		// 32 chars of 'X' demand more bits than the tail can supply.
		{"X×32 in shadowN=32", strings.Repeat("X", 32), 32, true},
		// Below-the-window: 'a' is 5 bits, real-of-all-'a' at length 16
		// = 80 bits; tail must hit 80-27 = 53 bits in 12 bytes = 4.4
		// bits/byte, below MinBits=5. Not satisfiable.
		{"a×16 in shadowN=16", strings.Repeat("a", 16), 16, true},
		// Below-the-window again: 24 chars of 'a' = 120 bits, tail target =
		// 120-27 = 93 in 20 bytes = 4.65 bits/byte — still below MinBits.
		{"a×24 in shadowN=24", strings.Repeat("a", 24), 24, true},
		// Comfortable middle: mixed real fits squarely in the window.
		{"mixed real fits", "REAL-ALLOWED-KEY-12345", 22, false},
	}
	for _, tc := range cases {
		_, err := generateShadowValue(tc.shadowN, HuffmanBits(tc.real))
		if tc.mustFail {
			if !errors.Is(err, ErrHuffmanInvariantUnsatisfiable) {
				t.Errorf("%s: expected ErrHuffmanInvariantUnsatisfiable, got %v", tc.name, err)
			}
		} else if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
	}
}

func TestGenerateShadowValue_TooShortRejected(t *testing.T) {
	// Any originalLen below len(ValuePrefix) cannot embed the literal
	// "kl::" the BPF scanner looks for. The function rejects rather
	// than silently truncating the prefix.
	for _, n := range []int{0, 1, 3} {
		_, err := generateShadowValue(n, 0)
		if !errors.Is(err, ErrHuffmanInvariantUnsatisfiable) {
			t.Errorf("originalLen=%d: expected ErrHuffmanInvariantUnsatisfiable, got %v", n, err)
		}
	}
}

func TestGenerateShadowValue_PrefixOnly(t *testing.T) {
	// originalLen == len(ValuePrefix), tail is empty. The only satisfiable
	// target is realHuffmanBits == prefixHuffmanBits; any other bit count
	// is unreachable because there's no tail to absorb the difference.
	got, err := generateShadowValue(len(ValuePrefix), prefixHuffmanBits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ValuePrefix {
		t.Errorf("got %q, want %q (prefix-only shadow)", got, ValuePrefix)
	}
	// Off-target requests fail cleanly.
	if _, err := generateShadowValue(len(ValuePrefix), prefixHuffmanBits+1); !errors.Is(err, ErrHuffmanInvariantUnsatisfiable) {
		t.Errorf("expected unsat for bit count above prefix; got %v", err)
	}
	if _, err := generateShadowValue(len(ValuePrefix), prefixHuffmanBits-1); !errors.Is(err, ErrHuffmanInvariantUnsatisfiable) {
		t.Errorf("expected unsat for bit count below prefix; got %v", err)
	}
}

func TestShadowGenerator_NoCollisionEmptySeed(t *testing.T) {
	g := NewShadowGenerator(nil, nil)
	got, err := g.Generate(32, prefixHuffmanBits+(32-len(ValuePrefix))*((MinBits+MaxBits)/2), "owner-a", 3)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(got) != 32 {
		t.Errorf("got len=%d, want 32", len(got))
	}
}

func TestShadowGenerator_SkipsCollisionFromOtherOwner(t *testing.T) {
	// Seed with a synthetic prefix held by owner-b. Generate is strict
	// (avoids every occupied prefix regardless of owner), so it must
	// never return a value whose prefix matches the seed. We can't
	// force the regeneration deterministically (crypto/rand), but we
	// can verify the contract empirically across many iterations.
	//
	// Generate auto-records its returns, so the used-set grows each
	// iteration; bumping maxRetries to 20 keeps the test bulletproof
	// against the birthday-paradox failure mode.
	seedPrefix := "kl::0000"
	seed := map[string]map[string]struct{}{
		seedPrefix: {"owner-b": struct{}{}},
	}
	g := NewShadowGenerator(seed, nil)

	// Target the midpoint of the feasibility window for shadow length 32
	// so every Generate succeeds; we're testing collision avoidance, not
	// the feasibility predicate.
	realHL := prefixHuffmanBits + (32-len(ValuePrefix))*((MinBits+MaxBits)/2)
	for i := 0; i < 50; i++ {
		got, err := g.Generate(32, realHL, "owner-a", 20)
		if err != nil {
			t.Fatalf("iter %d: Generate: %v", i, err)
		}
		if got[:ShadowPrefixLen] == seedPrefix {
			t.Errorf("iter %d: returned colliding shadow %q (prefix %q held by owner-b)", i, got, seedPrefix)
		}
	}
}

func TestShadowGenerator_GenerateAutoRecords(t *testing.T) {
	// A freshly-minted shadow must be globally unique within the
	// generator's universe — including against earlier Generate calls
	// from the SAME ownerID. Two keys of the same Secret must not
	// land on the same 8-byte prefix.
	g := NewShadowGenerator(nil, nil)
	hl := prefixHuffmanBits + (32-len(ValuePrefix))*((MinBits+MaxBits)/2)
	a, err := g.Generate(32, hl, "owner-a", 20)
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	b, err := g.Generate(32, hl, "owner-a", 20)
	if err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if a[:ShadowPrefixLen] == b[:ShadowPrefixLen] {
		t.Errorf("two consecutive Generate calls under owner-a produced the same prefix %q (a=%q, b=%q)",
			a[:ShadowPrefixLen], a, b)
	}
	// Confirm via the public surface that owner-a is recorded for
	// both prefixes (not just the second).
	if !g.Collides(a, "owner-b") {
		t.Errorf("first Generate's prefix should be recorded; Collides(_, owner-b) returned false")
	}
	if !g.Collides(b, "owner-b") {
		t.Errorf("second Generate's prefix should be recorded; Collides(_, owner-b) returned false")
	}
}

func TestShadowGenerator_OwnIDExcluded(t *testing.T) {
	// A shadow already recorded under owner-a must not collide with a
	// new request from the same owner-a (this is the reconcile-twice
	// case: the controller should be allowed to re-emit the same
	// shadow for its own secret).
	seedPrefix := "kl::1111"
	seed := map[string]map[string]struct{}{
		seedPrefix: {"owner-a": struct{}{}},
	}
	g := NewShadowGenerator(seed, nil)

	if g.Collides(seedPrefix+"abcdefghijkl", "owner-a") {
		t.Errorf("Collides should be false for owner-a's own previous shadow")
	}
	if !g.Collides(seedPrefix+"abcdefghijkl", "owner-b") {
		t.Errorf("Collides should be true for owner-b colliding with owner-a")
	}
}

func TestShadowGenerator_Record(t *testing.T) {
	g := NewShadowGenerator(nil, nil)
	shadow := "kl::01ABCDEFGH"
	g.Record(shadow, "owner-x")

	if !g.Collides(shadow, "owner-y") {
		t.Errorf("Record didn't take effect: owner-y should collide with owner-x's recorded shadow")
	}
	if g.Collides(shadow, "owner-x") {
		t.Errorf("owner-x should not collide with its own recorded shadow")
	}
}

func TestShadowGenerator_TooShortIgnored(t *testing.T) {
	// Defensive: Record/Collides on a shadow shorter than the prefix
	// length should be a no-op rather than panicking.
	g := NewShadowGenerator(nil, nil)
	g.Record("short", "owner-x")
	if g.Collides("short", "owner-y") {
		t.Errorf("Collides on too-short shadow should return false")
	}
}

func TestHuffmanBits_MatchesHpackBytes(t *testing.T) {
	// HuffmanBits is the bit-exact sibling of hpack.HuffmanEncodeLength
	// (which returns bytes after rounding up). Bit count must round up
	// to the byte count for every input — that's the relationship the
	// shadow generator relies on when claiming "bit-exact construction
	// implies byte-exact wire match".
	cases := []string{
		"",
		"a",
		"kl::",
		"REAL-ALLOWED-KEY-12345",
		"lowercase-secret-triggering-hpack-bug",
		strings.Repeat("z", 100),
		strings.Repeat("X", 100),
	}
	for _, s := range cases {
		bits := HuffmanBits(s)
		gotBytes := (bits + 7) / 8
		wantBytes := int(hpack.HuffmanEncodeLength(s))
		if gotBytes != wantBytes {
			t.Errorf("HuffmanBits(%q)=%d → %d bytes; hpack.HuffmanEncodeLength=%d",
				s, bits, gotBytes, wantBytes)
		}
	}
}
