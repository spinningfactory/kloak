package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"
)

const (
	// ShadowPrefixLen is the length of the prefix used for BPF map key
	// collision detection. The BPF program keys lookups on the first 8
	// bytes of the shadow, so two shadows sharing those 8 bytes would
	// alias in the map.
	ShadowPrefixLen = 8

	// ValuePrefix is the literal prefix every shadow secret carries.
	// Must match what the eBPF program expects.
	ValuePrefix = "kloak:"
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
// realHuffmanLen is the HPACK Huffman-encoded length of the real
// secret value the caller wants to shadow — computed by the caller
// (typically `int(hpack.HuffmanEncodeLength(realSecret))`). The real
// secret value itself is intentionally NOT passed in; the generator
// only needs the length target to guarantee `len(huffShadow) >=
// realHuffmanLen`, so keeping the cleartext out of this code path's
// scope eliminates a class of inadvertent-logging risks (the cleartext
// can never appear in this package's error messages, panic dumps, or
// stack traces).
func (g *ShadowGenerator) Generate(originalLen, realHuffmanLen int, ownerID string, maxRetries int) (string, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		shadow, err := generateShadowValue(originalLen, realHuffmanLen)
		if err != nil {
			// ErrHuffmanInvariantUnsatisfiable is deterministic for
			// given (originalLen, realHuffmanLen) — retrying won't help.
			// Other errors (rand.Int failures) are also retry-pointless.
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

// generateShadowValue creates a shadow value of exactly originalLen bytes
// whose HPACK Huffman encoding is at least realHuffmanLen bytes long.
// This ensures HTTP/2 HPACK rewriting works — the shadow's Huffman length
// determines the space available in the wire buffer for the rewritten
// value.
//
// realHuffmanLen is `hpack.HuffmanEncodeLength(realSecret)` computed by
// the caller. The real secret value itself never enters this function's
// scope by design: this code path generates random bytes and does not
// need the cleartext for anything other than length matching, so
// keeping it out removes a class of inadvertent-logging hazards (an
// error format string, a panic dump, a future debug log) that could
// otherwise leak the secret.
//
// Returns ErrHuffmanInvariantUnsatisfiable when no shadow of length
// originalLen can reach realHuffmanLen. For very short originalLen
// (say 10) with a high-Huffman-density real (e.g. all 'z's, each 7-bit
// HPACK code), the fixed-Huffman-cost "kloak:" prefix (36 bits) leaves
// too few tail bytes to match real's encoded length — even when every
// tail char is one of HPACK's 7-bit codes. Caller (Generate)
// propagates the error; the BPF map sync path in pkg/ebpf/sync.go
// separately gates the HTTP/2 variant on realHuffmanLen ≤
// len(huffShadow), so the HTTP/1.1 path still works for such secrets —
// they just don't get the HTTP/2 rewrite enabled.
func generateShadowValue(originalLen, realHuffmanLen int) (string, error) {
	// ULID uses Crockford Base32 (uppercase + digits, no hyphens).
	// These chars have long HPACK Huffman codes (7-8 bits), naturally
	// producing longer Huffman encodings than UUID hex (5-6 bits).
	// "kloak:" (6) + ULID (26) = 32 chars total.
	// ULID format: 10 chars timestamp + 16 chars random. For short secrets,
	// truncation would keep only the timestamp (identical for secrets
	// created at the same time). Put the random part first to maximize
	// uniqueness.
	newULID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	ulidRandom := newULID[10:] + newULID[:10] // random first, then timestamp
	baseVal := ValuePrefix + ulidRandom

	var shadow string
	switch {
	case len(baseVal) > originalLen:
		shadow = baseVal[:originalLen]
	case len(baseVal) < originalLen:
		// Pad with random Crockford Base32 chars (same charset as ULID)
		const base32Chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
		padLen := originalLen - len(baseVal)
		padding := make([]byte, padLen)
		for i := range padding {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(base32Chars))))
			if err != nil {
				return "", fmt.Errorf("rand.Int for padding: %w", err)
			}
			padding[i] = base32Chars[n.Int64()]
		}
		shadow = baseVal + string(padding)
	default:
		shadow = baseVal
	}

	// Verify Huffman length is sufficient for HTTP/2 HPACK rewriting.
	// ULID's uppercase chars usually produce long enough Huffman, but the
	// invariant has to hold for the worst real-value case too: 64 bytes
	// of 'z' encode to 7 bits each (one of HPACK's longest codes), so
	// the shadow's tail must reach the same density. Overwrite trailing
	// chars with one of HPACK's guaranteed-7-bit letters until the
	// shadow's Huffman length meets the real's.
	//
	// The previous heuristic only rewrote ASCII digits, which silently
	// did nothing when the random ULID + padding happened to produce an
	// all-letters tail — observed in CI as
	// `TestGenerateShadowValue_HuffmanInvariant` failing once in a few
	// hundred runs with shadow="kloak:WRPSFTSQ…" (no digits anywhere
	// after "kloak:"). Replacing unconditionally fixes that.
	//
	// Boundary is `j >= 6` (not `>= 8`): bytes 0-5 are the literal
	// "kloak:" prefix and must not be mutated, but bytes 6-7 are the
	// random suffix start. Allowing the loop to touch them lets the
	// minimum-supported 8-byte shadow have its Huffman length tuned;
	// otherwise an 8-byte secret with all-uppercase real value never
	// gets its HTTP/2 path enabled. Bytes 6-7 are also part of the BPF
	// 8-byte lookup key, but the key is computed AFTER generation so
	// mutating them here just changes the resulting key — not a hazard.
	shadowHuffLen := int(hpack.HuffmanEncodeLength(shadow))
	if shadowHuffLen < realHuffmanLen {
		shadowBytes := []byte(shadow)
		for j := len(shadowBytes) - 1; j >= 6 && shadowHuffLen < realHuffmanLen; j-- {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(longHuffmanChars))))
			if err != nil {
				return "", fmt.Errorf("rand.Int for tail-tune: %w", err)
			}
			shadowBytes[j] = longHuffmanChars[n.Int64()]
			shadowHuffLen = int(hpack.HuffmanEncodeLength(string(shadowBytes)))
		}
		shadow = string(shadowBytes)
		// Even with every tail char as a 7-bit Huffman code, the fixed-
		// cost "kloak:" prefix can leave shadow Huffman strictly shorter
		// than real's for some short originalLen × high-Huffman-density
		// real combinations (e.g. originalLen=10 with all-'z' real:
		// real=9 bytes Huffman, shadow=8 bytes max). Signal the caller
		// rather than silently violating the wire-buffer invariant.
		if shadowHuffLen < realHuffmanLen {
			return "", fmt.Errorf("%w: originalLen=%d, real Huffman %d > max shadow Huffman %d",
				ErrHuffmanInvariantUnsatisfiable, originalLen, realHuffmanLen, shadowHuffLen)
		}
	}

	return shadow, nil
}

// ErrHuffmanInvariantUnsatisfiable is returned by generateShadowValue
// when no shadow of the requested length can match the real secret's
// HPACK Huffman length. The HTTP/2 rewrite path is skipped for such
// secrets; HTTP/1.1 rewriting still works via the plaintext map entry.
var ErrHuffmanInvariantUnsatisfiable = errors.New("shadow Huffman length cannot reach real's")

// longHuffmanChars are the only ASCII letters whose HPACK Huffman
// code is 8 bits — the maximum bit-length for any printable ASCII
// character in the static table (RFC 7541 Appendix B; verified
// empirically against `golang.org/x/net/http2/hpack`). Overwriting any
// tail char with one of these maximizes shadow Huffman density, which
// is needed to satisfy the invariant against high-density real
// secrets (e.g. all 'z', each 7 bits).
const longHuffmanChars = "XZ"
