package secrets

import (
	"strings"

	"golang.org/x/net/http2/hpack"
)

// huffmanBitsTable[b] is the exact number of HPACK Huffman bits required
// to encode byte b under the static table in RFC 7541 Appendix B. The
// table is computed once at package init from
// golang.org/x/net/http2/hpack so it stays in sync with whatever the
// installed library produces — encoding a constant N copies of byte b
// gives a multi-byte total, from which the per-byte bit count is exact
// (no padding bits creep in: N=64 makes N*bits a multiple of 8 for any
// integer bits ≥ 1).
var huffmanBitsTable [256]int

// huffmanBuckets[k] is the list of bytes whose Huffman code is exactly
// k bits long, restricted to the alphabet we're willing to emit in a
// shadow tail (alphanumeric ASCII, MinBits..MaxBits). The shadow
// generator picks a code length k inside its feasibility window, then
// uniformly samples a byte from huffmanBuckets[k].
var huffmanBuckets [9][]byte

// MinBits / MaxBits define the alphabet for shadow-tail byte selection.
// MinBits=5 / MaxBits=7 corresponds to ASCII alphanumeric chars except
// 'X' and 'Z' (which are 8 bits each in HPACK Huffman): a 5-bit bucket
// of "012aceiost", a 6-bit bucket of "3456789bdfghlmnpruA", and a
// 7-bit bucket spanning the rest of upper/lowercase alphanumerics.
// All three buckets are well-populated (≥10 candidates) so per-byte
// random selection has meaningful entropy.
//
// Increasing MaxBits to 8 would add 'X' and 'Z' (just 2 candidates),
// shrinking entropy at the top end of the bucket range — not worth it.
// Lowering MinBits below 5 would require dragging in non-alphanumeric
// chars (' ', '%', '/', '=') which would surprise anyone scanning a
// shadow for the literal "kl::" prefix + identifier pattern.
const (
	MinBits = 5
	MaxBits = 7
)

// prefixHuffmanBits is the cached exact Huffman bit count for ValuePrefix
// ("kl::"). The byte-by-byte construction subtracts this from the real's
// total Huffman bits to compute the tail's bit budget.
var prefixHuffmanBits int

func init() {
	// Per-byte bit lengths: encode 64 copies of byte b. The total
	// encoding is exactly (64 * bits_per_b) bits, padded out to whole
	// bytes. Since 64 is a multiple of 8, 64*N is too for any integer N,
	// so the byte count is exact — no rounding loss.
	for b := 0; b < 256; b++ {
		s := strings.Repeat(string([]byte{byte(b)}), 64)
		huffmanBitsTable[b] = int(hpack.HuffmanEncodeLength(s)) * 8 / 64
	}

	// Bucket every alphanumeric ASCII byte by its Huffman bit length.
	// We deliberately exclude non-alphanumerics so shadow tails stay
	// recognizable as identifier-shaped (a holdover from the prior
	// ULID/Crockford choice — humans reading logs should still see a
	// shadow as "kl::<token>", not "kl::<random%punctuation>").
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for _, b := range []byte(alphabet) {
		bits := huffmanBitsTable[b]
		if bits < MinBits || bits > MaxBits {
			continue
		}
		huffmanBuckets[bits] = append(huffmanBuckets[bits], b)
	}

	prefixHuffmanBits = HuffmanBits(ValuePrefix)
}

// HuffmanBits returns the exact HPACK Huffman bit length of s — the sum
// of per-byte code lengths from the static table. This is the granular
// version of hpack.HuffmanEncodeLength (which returns bytes after
// rounding up), and it's what the shadow generator needs to construct a
// tail whose encoded length matches the real's exactly.
func HuffmanBits(s string) int {
	n := 0
	for _, b := range []byte(s) {
		n += huffmanBitsTable[b]
	}
	return n
}
