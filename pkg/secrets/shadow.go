package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"go.uber.org/zap"
)

const (
	// ShadowPrefixLen is the length of the prefix used for BPF map key
	// collision detection. The BPF program keys lookups on the first 8
	// bytes of the shadow, so two shadows sharing those 8 bytes would
	// alias in the map.
	ShadowPrefixLen = 8

	// ValuePrefix is the literal prefix every shadow secret carries.
	// Must match what the eBPF program expects.
	//
	// Chosen at 4 bytes (27 HPACK Huffman bits) rather than the historical
	// 6-byte "kloak:" (37 bits) to widen the byte-by-byte construction's
	// feasibility window for short shadows. The +7-bit fixed slack against
	// the alphabet's 5-bit floor is the same either way (lower bound at
	// density 5+7/N), but with 27 prefix bits we get density headroom up to
	// 7−1/N at the top instead of 7−5/N — meaning hex secrets (density
	// ≈5.63) and short low-density tokens fit at much smaller N. See PR
	// description for the openssl-hex / openssl-base64 / JWT density data.
	ValuePrefix = "kl::"
)

// ShadowGenerator mints shadow values that don't 8-byte-prefix-collide
// with any other owner already known to it. Each Source supplies its
// own seed via NewShadowGenerator: the k8s adapter seeds from a List of
// existing shadow secrets in the cluster; a file-backed source seeds
// from the entries it just parsed (no cross-process universe to worry
// about).
//
// The collision-tracking state is owned by the generator instead of
// being passed as a parameter on every call, so each Source has a
// natural place to keep it for the duration of its lifetime.
type ShadowGenerator struct {
	// used maps 8-byte prefixes to the set of owner IDs that occupy
	// them. A new shadow whose prefix is occupied by an owner OTHER
	// than the requester is rejected and the generator retries.
	used map[string]map[string]struct{}
	log  *zap.SugaredLogger
}

// NewShadowGenerator returns a generator seeded with the given prefix
// occupancy map. Pass nil for an empty seed (e.g. fresh load from a
// YAML file). Pass a non-nil map to start from a known set of in-use
// prefixes (e.g. shadows that already exist in the k8s cluster).
//
// The generator takes ownership of the map; callers should not mutate
// it after this call.
func NewShadowGenerator(seed map[string]map[string]struct{}, log *zap.SugaredLogger) *ShadowGenerator {
	if seed == nil {
		seed = make(map[string]map[string]struct{})
	}
	return &ShadowGenerator{used: seed, log: log}
}

// Generate returns a shadow value of exactly originalLen bytes whose
// 8-byte prefix is occupied by NO owner currently known to the
// generator. A freshly-minted shadow must be globally unique inside
// the generator's universe — otherwise two keys of the same Secret
// (which share an ownerID) could land on the same prefix because an
// owner-excluded check would let it through. Distinct from Collides,
// which keeps the owner-exclusion semantic for the "reuse my own
// existing shadow" decision.
//
// On success the chosen prefix is recorded under ownerID so subsequent
// Generate calls within the same generator avoid it. Retries up to
// maxRetries times before giving up.
//
// realHuffmanBits is the EXACT HPACK Huffman bit length of the real
// secret value the caller wants to shadow — computed by the caller via
// HuffmanBits(realSecret). It's a bit count, not a byte count: the
// byte-by-byte construction guarantees a shadow whose Huffman bit
// length equals realHuffmanBits exactly, which means the encoded byte
// length matches as well (no padding required). Passing the bit count
// instead of the cleartext keeps the real secret out of this package's
// scope entirely.
func (g *ShadowGenerator) Generate(originalLen, realHuffmanBits int, ownerID string, maxRetries int) (string, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		shadow, err := generateShadowValue(originalLen, realHuffmanBits)
		if err != nil {
			// ErrHuffmanInvariantUnsatisfiable is deterministic for
			// (originalLen, realHuffmanBits) — the feasibility check is
			// pure arithmetic, so retrying won't help. rand.Int failures
			// are also retry-pointless.
			return "", err
		}
		// Empty ownerID → strict global check: any occupant collides.
		if !g.collides(shadow, "") {
			g.Record(shadow, ownerID)
			return shadow, nil
		}
		if g.log != nil {
			g.log.Warnw("8-byte BPF key collision detected, regenerating",
				"attempt", attempt+1, "maxRetries", maxRetries,
				"prefix", shadow[:ShadowPrefixLen])
		}
	}
	return "", fmt.Errorf("failed to generate unique shadow value after %d attempts", maxRetries)
}

// Record marks shadow as in use by ownerID. Sources call this after
// persisting a generated shadow so that subsequent Generate calls within
// the same generator avoid the prefix.
func (g *ShadowGenerator) Record(shadow, ownerID string) {
	if len(shadow) < ShadowPrefixLen {
		return
	}
	prefix := shadow[:ShadowPrefixLen]
	if g.used[prefix] == nil {
		g.used[prefix] = make(map[string]struct{})
	}
	g.used[prefix][ownerID] = struct{}{}
}

// Collides reports whether shadow's 8-byte prefix is occupied by any
// owner other than ownerID. Exposed for callers (e.g. the k8s
// reconciler) that want to validate a candidate before generating.
func (g *ShadowGenerator) Collides(shadow, ownerID string) bool {
	return g.collides(shadow, ownerID)
}

func (g *ShadowGenerator) collides(shadow, ownerID string) bool {
	if len(shadow) < ShadowPrefixLen {
		return false
	}
	prefix := shadow[:ShadowPrefixLen]
	for owner := range g.used[prefix] {
		if owner != ownerID {
			return true
		}
	}
	return false
}

// generateShadowValue constructs a shadow whose plaintext length is
// exactly originalLen AND whose HPACK Huffman bit length is exactly
// realHuffmanBits. Both invariants hold by construction, not by
// random-then-tune retry — see the algorithm comment below.
//
// Why bit-EXACT, not byte-AT-LEAST: the BPF map sync in pkg/ebpf/sync.go
// rewrites the shadow's encoded slot on the wire with the real's
// Huffman bytes. If shadow's bit count exceeds real's, the sync code
// previously padded with 0xFF (HPACK EOS bits) up to the byte boundary.
// RFC 7541 §5.2 forbids EOS padding longer than 7 bits — strict HPACK
// decoders (nghttp2, AWS ALB) reset the stream when they see more.
// Matching bit counts exactly removes any need for padding at all and
// makes the rewrite safe against every HPACK-compliant peer.
//
// The function NEVER sees the real cleartext — only its bit length —
// which keeps secret-leak surface area in this package to nil.
//
// Returns ErrHuffmanInvariantUnsatisfiable when no shadow of length
// originalLen can hit the bit target. The feasibility check is a single
// inequality up front (no randomness consumed on the error path), and
// the predicate is a function of (tail length, target bits) only — so
// the time spent on the error path is independent of realHuffmanBits's
// magnitude, removing a timing oracle on the real's encoded length.
func generateShadowValue(originalLen, realHuffmanBits int) (string, error) {
	// Feasibility runs first; on failure no randomness is consumed and
	// the error path is constant-time w.r.t. realHuffmanBits's magnitude
	// (no timing oracle).
	if err := CanShadow(originalLen, realHuffmanBits); err != nil {
		return "", err
	}
	tailLen := originalLen - len(ValuePrefix)
	tailBits := realHuffmanBits - prefixHuffmanBits

	// Byte-by-byte construction. The loop invariant: at the start of
	// iteration i, `remaining` is the bit budget the suffix
	// tail[i..tailLen) must total. The [lo, hi] clamp is the per-byte
	// window that keeps the remaining suffix feasible at every step —
	// it's the intersection of [MinBits, MaxBits] (alphabet limits) and
	// [remaining - left*MaxBits, remaining - left*MinBits] (so the
	// remaining `left` bytes can still hit `remaining - k`).
	//
	// The feasibility precheck guarantees lo <= hi at every step (proof:
	// induction — entering iter i with remaining ∈ [left+1)*MinBits,
	// (left+1)*MaxBits] yields lo ≤ hi, and the chosen k preserves
	// remaining ∈ [left*MinBits, left*MaxBits] for the next iter).
	tail := make([]byte, tailLen)
	remaining := tailBits
	for i := 0; i < tailLen; i++ {
		left := tailLen - i - 1
		lo := MinBits
		if v := remaining - left*MaxBits; v > lo {
			lo = v
		}
		hi := MaxBits
		if v := remaining - left*MinBits; v < hi {
			hi = v
		}

		// Pick a code length k ∈ [lo, hi] uniformly at random, then
		// pick a byte uniformly from the bucket of that code length.
		// Two CSPRNG draws per byte, control flow independent of
		// realHuffmanBits — see function-level comment on timing.
		k, err := randIntInclusive(lo, hi)
		if err != nil {
			return "", fmt.Errorf("rand.Int for code length: %w", err)
		}
		bucket := huffmanBuckets[k]
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(bucket))))
		if err != nil {
			return "", fmt.Errorf("rand.Int for bucket pick: %w", err)
		}
		tail[i] = bucket[idx.Int64()]
		remaining -= k
	}

	return ValuePrefix + string(tail), nil
}

// randIntInclusive returns a uniform random int in [lo, hi] (both ends
// inclusive) drawn from crypto/rand. Returns lo immediately when the
// range is a single value so we don't pay for a CSPRNG draw on the
// trivial case (tail positions near the end of a tight-feasibility run
// frequently hit this branch).
func randIntInclusive(lo, hi int) (int, error) {
	if hi <= lo {
		return lo, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if err != nil {
		return 0, err
	}
	return lo + int(n.Int64()), nil
}

// ErrHuffmanInvariantUnsatisfiable is returned by generateShadowValue
// when no shadow of the requested length can match the real secret's
// HPACK Huffman bit length. Kloak fails-closed on such secrets: the
// reconciler refuses to mint a shadow (so neither HTTP/1.1 nor HTTP/2
// rewrite gets enabled) rather than producing a shadow that would
// silently break the HTTP/2 wire invariant. The validating webhook
// catches this at admission time via CanShadow so users learn at
// `kubectl apply` rather than at runtime.
var ErrHuffmanInvariantUnsatisfiable = errors.New("shadow Huffman bit length cannot match real's")

// CanShadow returns nil iff a shadow can be minted for a real value of
// the given plaintext length and Huffman bit count. The two failure
// modes both surface as ErrHuffmanInvariantUnsatisfiable:
//
//   - originalLen < len(ValuePrefix): the shadow can't even carry the
//     "kl::" marker the BPF scanner looks for.
//   - realHuffmanBits outside [prefixHuffmanBits + tailLen*MinBits,
//     prefixHuffmanBits + tailLen*MaxBits]: the alphabet's per-byte
//     5–7 bits/byte range can't produce a tail that matches the real's
//     Huffman length, which means the HTTP/2 wire-buffer invariant
//     can't be satisfied (the shadow's encoded length would differ
//     from the real's by enough to require >7 bits of EOS padding,
//     forbidden by RFC 7541 §5.2).
//
// Used by both generateShadowValue (the actual minting path) and the
// validating webhook (admission-time rejection) so the predicate has a
// single source of truth.
func CanShadow(originalLen, realHuffmanBits int) error {
	if originalLen < len(ValuePrefix) {
		return fmt.Errorf("%w: originalLen=%d < %d (ValuePrefix length)",
			ErrHuffmanInvariantUnsatisfiable, originalLen, len(ValuePrefix))
	}
	tailLen := originalLen - len(ValuePrefix)
	tailBits := realHuffmanBits - prefixHuffmanBits
	// Special case tailLen == 0: the shadow IS the prefix; only
	// tailBits == 0 (realHuffmanBits == prefixHuffmanBits) is
	// satisfiable. The same bounds check handles this naturally
	// (0*MinBits == 0*MaxBits == 0).
	if tailBits < tailLen*MinBits || tailBits > tailLen*MaxBits {
		return fmt.Errorf(
			"%w: originalLen=%d, target Huffman bits=%d, achievable range=[%d, %d]",
			ErrHuffmanInvariantUnsatisfiable, originalLen, realHuffmanBits,
			prefixHuffmanBits+tailLen*MinBits,
			prefixHuffmanBits+tailLen*MaxBits,
		)
	}
	return nil
}
