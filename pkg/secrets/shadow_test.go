package secrets

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestGenerateShadowValue_Length(t *testing.T) {
	cases := []int{8, 16, 32, 64, 128}
	for _, n := range cases {
		got, err := generateShadowValue(n, int(hpack.HuffmanEncodeLength(strings.Repeat("a", n))))
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
	}
}

func TestGenerateShadowValue_HuffmanInvariant(t *testing.T) {
	// The shadow's HPACK Huffman encoding must be >= the real's, so the
	// HTTP/2 path can patch the rewritten value into a fixed wire buffer
	// without overflow. Run the all-'z' worst case many times to flush
	// out any randomness-dependent invariant violations — the previous
	// tail-tuning loop only mutated digits, so an all-letters random
	// outcome silently produced a shadow that violated the invariant
	// roughly once every few hundred CI runs.
	//
	// Short lengths (8, 9) sit right at the satisfiability boundary for
	// the all-'z' real; the 36-bit "kloak:" prefix leaves only a few
	// tail bytes, so the test exercises both the "barely satisfiable"
	// edge (8, 9) and the comfortable middle (64).
	cases := []struct {
		real     string
		attempts int
	}{
		{"sk-live-0123456789abcdef", 1},
		{strings.Repeat("A", 32), 1},
		{strings.Repeat("z", 8), 200},
		{strings.Repeat("z", 9), 200},
		{strings.Repeat("z", 64), 1000},
		{"PASSWORD123", 1},
	}
	for _, tc := range cases {
		realHL := int(hpack.HuffmanEncodeLength(tc.real))
		for i := 0; i < tc.attempts; i++ {
			shadow, err := generateShadowValue(len(tc.real), realHL)
			if err != nil {
				t.Fatalf("real=%q attempt=%d: unexpected error: %v", tc.real, i, err)
			}
			shadowHL := int(hpack.HuffmanEncodeLength(shadow))
			if shadowHL < realHL {
				t.Fatalf("real=%q attempt=%d: shadow Huffman len %d < real Huffman len %d (shadow=%q)",
					tc.real, i, shadowHL, realHL, shadow)
			}
		}
	}
}

func TestGenerateShadowValue_UnsatisfiableReturnsError(t *testing.T) {
	// 'X' and 'Z' both Huffman-encode to 8 bits — HPACK's maximum for
	// printable ASCII letters. A real value composed entirely of 'X' has
	// Huffman length N bytes. The largest possible shadow tail uses the
	// same 8-bit chars from longHuffmanChars, giving shadow Huffman
	// bits = 37 ("kloak:") + 8(N-6) = 8N - 11, which rounds up to N-1
	// bytes for N ≥ 2. shadow is always exactly 1 byte short → the
	// function must return ErrHuffmanInvariantUnsatisfiable rather
	// than silently violate the wire-buffer invariant.
	unsat := []int{10, 11, 12, 13, 14, 15, 20, 32}
	for _, n := range unsat {
		real := strings.Repeat("X", n)
		_, err := generateShadowValue(n, int(hpack.HuffmanEncodeLength(real)))
		if !errors.Is(err, ErrHuffmanInvariantUnsatisfiable) {
			t.Errorf("originalLen=%d all-'X' real: expected ErrHuffmanInvariantUnsatisfiable, got %v", n, err)
		}
	}
}

func TestGenerateShadowValue_TruncationPreservesPrefix(t *testing.T) {
	// Even at the minimum supported length (ShadowPrefixLen=8), the
	// prefix "kloak:" must be present so the BPF scanner detects the
	// shadow. At length 8 the shadow is exactly "kloak:XX" (6-char
	// prefix + 2 random tail chars).
	got, err := generateShadowValue(ShadowPrefixLen, int(hpack.HuffmanEncodeLength("abcdefgh")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(got, ValuePrefix) {
		t.Errorf("8-byte shadow %q does not start with %q", got, ValuePrefix)
	}
	if len(got) != ShadowPrefixLen {
		t.Errorf("got len=%d, want %d", len(got), ShadowPrefixLen)
	}
}

func TestShadowGenerator_NoCollisionEmptySeed(t *testing.T) {
	g := NewShadowGenerator(nil, nil)
	got, err := g.Generate(32, int(hpack.HuffmanEncodeLength("real-value")), "owner-a", 3)
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
	seedPrefix := "kloak:00"
	seed := map[string]map[string]struct{}{
		seedPrefix: {"owner-b": struct{}{}},
	}
	g := NewShadowGenerator(seed, nil)

	for i := 0; i < 50; i++ {
		got, err := g.Generate(32, int(hpack.HuffmanEncodeLength("real")), "owner-a", 20)
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
	a, err := g.Generate(32, int(hpack.HuffmanEncodeLength("v1")), "owner-a", 20)
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	b, err := g.Generate(32, int(hpack.HuffmanEncodeLength("v2")), "owner-a", 20)
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
	seedPrefix := "kloak:11"
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
	shadow := "kloak:01ABCDEFGH"
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
