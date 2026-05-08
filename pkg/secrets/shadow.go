package secrets

import (
	"crypto/rand"
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
func (g *ShadowGenerator) Generate(originalLen int, realSecret, ownerID string, maxRetries int) (string, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		shadow := generateShadowValue(originalLen, realSecret)
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
// whose HPACK Huffman encoding is at least as long as the real secret's.
// This ensures HTTP/2 HPACK rewriting works — the shadow's Huffman length
// determines the space available in the wire buffer for the rewritten
// value.
//
// Lifted verbatim from pkg/controller/secret_reconciler.go.
func generateShadowValue(originalLen int, realSecret string) string {
	realHuffLen := int(hpack.HuffmanEncodeLength(realSecret))

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
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(base32Chars))))
			padding[i] = base32Chars[n.Int64()]
		}
		shadow = baseVal + string(padding)
	default:
		shadow = baseVal
	}

	// Verify Huffman length is sufficient for HTTP/2 HPACK rewriting.
	// ULID's uppercase chars usually produce long enough Huffman, but for
	// rare cases (short secrets with all-uppercase real values), replace
	// trailing digits with random uppercase letters (longer Huffman codes).
	shadowHuffLen := int(hpack.HuffmanEncodeLength(shadow))
	if shadowHuffLen < realHuffLen {
		shadowBytes := []byte(shadow)
		for j := len(shadowBytes) - 1; j >= 8 && shadowHuffLen < realHuffLen; j-- {
			if shadowBytes[j] >= '0' && shadowBytes[j] <= '9' {
				n, _ := rand.Int(rand.Reader, big.NewInt(26))
				shadowBytes[j] = byte('A') + byte(n.Int64())
				shadowHuffLen = int(hpack.HuffmanEncodeLength(string(shadowBytes)))
			}
		}
		shadow = string(shadowBytes)
	}

	return shadow
}
