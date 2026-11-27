package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

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
			// pure arithmetic, so retrying won't help. A failed read of
			// crypto/rand is also retry-pointless.
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
// random-then-tune retry — see the algorithm comment in buildShadow.
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
	return generateShadow(rand.Reader, originalLen, realHuffmanBits)
}

// maxShadowAttempts bounds the shadows buildShadow starts over: it only
// does when no byte fits a position (shadowCode.nested), which takes 23
// bits of the code to match a candidate's first 23 and a position whose
// window leaves no other byte: it has never been seen.
const maxShadowAttempts = 8

// generateShadow is generateShadowValue drawing its randomness from r
// (crypto/rand.Reader; tests pass a seeded stream).
func generateShadow(r io.Reader, originalLen, realHuffmanBits int) (string, error) {
	// Feasibility runs first; on failure no randomness is consumed and
	// the error path is constant-time w.r.t. realHuffmanBits's magnitude
	// (no timing oracle).
	if err := CanShadow(originalLen, realHuffmanBits); err != nil {
		return "", err
	}
	rs := newRandStream(r)
	for attempt := 0; attempt < maxShadowAttempts; attempt++ {
		shadow, ok, err := buildShadow(rs, originalLen, realHuffmanBits)
		if err != nil {
			return "", fmt.Errorf("reading random bytes: %w", err)
		}
		if ok {
			return shadow, nil
		}
	}
	return "", fmt.Errorf("no shadow of %d bytes without a nested placeholder candidate after %d attempts", originalLen, maxShadowAttempts)
}

// buildShadow draws one shadow (see generateShadowValue), whose feasibility
// CanShadow checked. ok is false at a dead end (pickTailByte): the caller
// starts over.
func buildShadow(rs *randStream, originalLen, realHuffmanBits int) (shadow string, ok bool, err error) {
	tailLen := int64(originalLen - len(ValuePrefix))
	tailBits := int64(realHuffmanBits - prefixHuffmanBits)

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
	//
	// The arithmetic is int64: left*MaxBits overflows a 32-bit int past
	// 256 MiB.
	buf := make([]byte, len(ValuePrefix), originalLen)
	copy(buf, ValuePrefix)
	code := newShadowCode()
	remaining := tailBits
	for i := int64(0); i < tailLen; i++ {
		left := tailLen - i - 1
		lo := max(int64(MinBits), remaining-left*MaxBits)
		hi := min(int64(MaxBits), remaining-left*MinBits)
		b, ok, err := pickTailByte(rs, &code, int(lo), int(hi))
		if err != nil || !ok {
			return "", false, err
		}
		buf = append(buf, b)
		code.add(b)
		remaining -= int64(huffmanBitsTable[b])
	}
	return string(buf), true, nil
}

// pickTailByte draws a tail byte whose code is lo to hi bits long: the
// length uniformly in [lo, hi], then a byte uniformly from its bucket, one
// draw each, as uniform as the stream (randStream.intn). A byte whose code
// would make a placeholder candidate start inside the shadow's code
// (shadowCode.nested) is drawn again: the pick is then uniform over the
// others, with the same weights. ok is false when every byte of [lo, hi]
// would (a dead end).
func pickTailByte(rs *randStream, code *shadowCode, lo, hi int) (b byte, ok bool, err error) {
	for first := true; ; first = false {
		k, err := rs.intn(hi - lo + 1)
		if err != nil {
			return 0, false, err
		}
		bucket := huffmanBuckets[lo+k]
		j, err := rs.intn(len(bucket))
		if err != nil {
			return 0, false, err
		}
		if b = bucket[j]; !code.nested(b) {
			return b, true, nil
		}
		// Rare (see maxShadowAttempts): check once that another byte
		// fits before drawing again, so that the loop ends.
		if first && !code.anyFits(lo, hi) {
			return 0, false, nil
		}
	}
}

// The prescan's candidate filters (is_kloak_prefix and
// is_kloak_prefix_huffman in pkg/ebpf/bpf/helpers.h): the bytes "kl::",
// and the first three bytes of Huffman("kl::"), which start every
// placeholder's code.
const (
	candidateRaw     = 0x6b6c3a3a // "kl::", 32 bits
	candidateHuffman = 0xeb45cb   // 24 bits
)

// shadowCode follows a shadow's HPACK Huffman code as buildShadow builds
// it, so that no placeholder candidate starts inside it.
//
// A raw shadow holds none: its tail alphabet has no ':' and no byte of
// 0x80 and above. Its Huffman code could: the prescan finds a placeholder
// in an HTTP/2 header by the candidates at a byte boundary of the header
// value's code, where the shadow's code can start at any bit offset (after
// the bits of what precedes it in the value), and the codes of tail bytes
// can line up into either candidate across their boundaries
// (TestNestedCandidatesArePossible). A candidate the prescan finds inside a
// placeholder takes a match slot if its 8 bytes are a key of secret_map,
// and is looked up otherwise: buildShadow leaves out every byte that would
// make one start at any bit offset inside the code, other than its first
// (the placeholder's own). One that starts in the code and ends after it,
// in what follows the placeholder, depends on that text.
//
// TODO(kloak#383): once the data plane verifies whole placeholders (phase
// 1), its prescan should also skip candidates inside a verified span: that
// covers those, and placeholders minted before this check.
type shadowCode struct {
	reg uint64 // the code's last bits, the latest lowest
	n   int    // the code's bits so far
}

func newShadowCode() shadowCode {
	var c shadowCode
	for _, b := range []byte(ValuePrefix) {
		c.add(b)
	}
	return c
}

func (c *shadowCode) add(b byte) {
	c.reg = c.reg<<huffmanBitsTable[b] | uint64(huffmanCodes[b])
	c.n += huffmanBitsTable[b]
}

// nested reports whether b's code, appended, ends a candidate that starts
// after the code's first bit.
func (c *shadowCode) nested(b byte) bool {
	k := huffmanBitsTable[b]
	reg := c.reg<<k | uint64(huffmanCodes[b])
	for end := c.n + 1; end <= c.n+k; end++ { // a window ending with bit end-1
		w := reg >> (c.n + k - end)
		if end-24 >= 1 && w&0xffffff == candidateHuffman {
			return true
		}
		if end-32 >= 1 && w&0xffffffff == candidateRaw {
			return true
		}
	}
	return false
}

// anyFits reports whether a byte of code length lo to hi is not nested.
func (c *shadowCode) anyFits(lo, hi int) bool {
	for k := lo; k <= hi; k++ {
		for _, b := range huffmanBuckets[k] {
			if !c.nested(b) {
				return true
			}
		}
	}
	return false
}

// randStream hands out uniform random integers drawn from a buffered
// stream of random bytes (crypto/rand.Reader): one read per
// len(randStream.buf) bytes, where two big.Int draws per shadow byte cost an
// allocation and a read each.
type randStream struct {
	r   io.Reader
	buf [512]byte
	off int // the next unread byte of buf
}

func newRandStream(r io.Reader) *randStream {
	s := &randStream{r: r}
	s.off = len(s.buf)
	return s
}

// intn returns a uniform random int in [0, n), 1 <= n <= 256, by rejection
// sampling of a byte (intnFromByte). n == 1 draws nothing.
func (s *randStream) intn(n int) (int, error) {
	if n <= 1 {
		return 0, nil
	}
	for {
		if s.off == len(s.buf) {
			if _, err := io.ReadFull(s.r, s.buf[:]); err != nil {
				return 0, err
			}
			s.off = 0
		}
		b := s.buf[s.off]
		s.off++
		if v, ok := intnFromByte(b, n); ok {
			return v, nil
		}
	}
}

// intnFromByte maps a uniform random byte to a uniform int in [0, n), 2 <=
// n <= 256: b is accepted when it is below the largest multiple of n that
// fits in a byte, and v is b mod n, so that every v has exactly 256/n
// (rounded down) bytes; the others (256 mod n of them) are rejected, and
// the caller draws again.
func intnFromByte(b byte, n int) (v int, ok bool) {
	if int(b) >= 256-256%n {
		return 0, false
	}
	return int(b) % n, true
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
//     5–MaxBits bits/byte range can't produce a tail that matches the
//     real's Huffman length, which means the HTTP/2 wire-buffer
//     invariant can't be satisfied (the shadow's encoded length would
//     differ from the real's by enough to require >7 bits of EOS
//     padding, forbidden by RFC 7541 §5.2).
//
// IMPORTANT — secret-leak surface: this function never sees the real
// value's bytes (only its Huffman bit count, computed by the caller via
// HuffmanBits). The returned errors are also sanitized to exclude
// `realHuffmanBits` — the bit count is value-derived (sum of per-byte
// HPACK code lengths) and the admission webhook's denial message goes
// back to the kubectl caller, may be captured in apiserver audit logs,
// and could surface in third-party SIEM pipes. Reporting only the
// length and the achievable range (both invariants the caller already
// knows, since they constructed the secret and the algorithm is
// public) gives users actionable diagnostics without exposing any
// statistic of the value's content distribution.
//
// Used by both generateShadowValue (the actual minting path) and the
// validating webhook (admission-time rejection) so the predicate has a
// single source of truth.
func CanShadow(originalLen, realHuffmanBits int) error {
	if originalLen < len(ValuePrefix) {
		return fmt.Errorf("%w: originalLen=%d < %d (ValuePrefix length)",
			ErrHuffmanInvariantUnsatisfiable, originalLen, len(ValuePrefix))
	}
	// int64: tailLen*MaxBits overflows a 32-bit int past 256 MiB.
	tailLen := int64(originalLen) - int64(len(ValuePrefix))
	tailBits := int64(realHuffmanBits) - int64(prefixHuffmanBits)
	lo := int64(prefixHuffmanBits) + tailLen*MinBits
	hi := int64(prefixHuffmanBits) + tailLen*MaxBits
	// Special case tailLen == 0: the shadow IS the prefix; only
	// tailBits == 0 (realHuffmanBits == prefixHuffmanBits) is
	// satisfiable. The same bounds check handles this naturally
	// (0*MinBits == 0*MaxBits == 0).
	if tailBits < tailLen*MinBits {
		// Below the achievable floor — the value's average Huffman
		// density (bits/byte) is too low for any same-length shadow
		// to match. The error names only the direction ("too low")
		// and the achievable range; it deliberately omits the
		// value-derived bit count itself to keep that statistic out
		// of admission-denial messages and audit logs.
		return fmt.Errorf(
			"%w: value's HPACK Huffman density is too low at length %d (achievable range %d–%d bits; use a different value or a longer secret)",
			ErrHuffmanInvariantUnsatisfiable, originalLen, lo, hi)
	}
	if tailBits > tailLen*MaxBits {
		return fmt.Errorf(
			"%w: value's HPACK Huffman density is too high at length %d (achievable range %d–%d bits; use a different value or a longer secret)",
			ErrHuffmanInvariantUnsatisfiable, originalLen, lo, hi)
	}
	return nil
}
