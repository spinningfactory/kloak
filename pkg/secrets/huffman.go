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
// shadow tail (alphanumeric ASCII + 4 punctuation chars used to widen
// the 8-bit bucket, see MaxBits=8 rationale). The shadow generator
// picks a code length k inside its feasibility window, then uniformly
// samples a byte from huffmanBuckets[k].
var huffmanBuckets [9][]byte

// MinBits / MaxBits define the alphabet for shadow-tail byte selection.
// MinBits=5 is the absolute floor of HPACK's static Huffman table
// (RFC 7541 Appendix B) — there is no code shorter than 5 bits anywhere
// in HPACK, so reals with average density ≤ 5 bits/byte are
// unsupportable regardless of alphabet choice (a +7-bit fixed lower
// slack persists for any non-empty prefix). The validating webhook
// rejects such secrets at admission via secrets.CanShadow.
//
// MaxBits=8 widens the upper window by one bit/byte vs the original
// [5, 7] choice. The 8-bit bucket members are 'X', 'Z' (the only two
// 8-bit ASCII alphanumerics) plus four 8-bit punctuation chars
// "&*,;" so the bucket has 6 candidates of meaningful entropy. The
// trade-off: shadows may include punctuation in their tail
// (e.g. "kl::aB&cD*"), arguably less identifier-shaped than the
// previous alphanumeric-only choice, but in exchange we cover short
// uppercase-heavy reals like "SECRET-8" (54 Huffman bits) which sit
// 3 bits above the [5, 7] ceiling at length 8.
//
// Pushing MaxBits to 10+ would add more punctuation (!"()? at 10 bits)
// and widen the top further. We held the line at 8 because alphabet
// widening beyond that brings diminishing returns and increasingly
// weird-looking shadows — the realistic high-density real population
// (uppercase API keys, base64-with-special) is well covered at 8.
const (
	MinBits = 5
	MaxBits = 8
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

	// Alphabet = all alphanumeric ASCII plus the four 8-bit punctuation
	// chars ("&*,;") chosen to populate huffmanBuckets[8] beyond the
	// two natural alphanumeric residents ('X', 'Z'). Six 8-bit
	// candidates gives the upper-bucket sampling meaningful entropy;
	// the punctuation is rare enough in shadows that human-readable
	// logs still look identifier-shaped ("kl::aB&cD*1" remains
	// scannable as a kloak placeholder).
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ&*,;"
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
