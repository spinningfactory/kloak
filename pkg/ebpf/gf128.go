package ebpf

// GF(2^128) arithmetic for AES-GCM GHASH H power table pre-computation.
// Uses the GHASH convention from NIST SP 800-38D: MSB-first bit ordering,
// irreducible polynomial x^128 + x^7 + x^2 + x + 1 (R = 0xe1 || 0^120).
//
// This Go implementation must produce identical results to the C implementation
// in pkg/ebpf/bpf/helpers.h for cross-validation.

// GF128Mul multiplies two 128-bit elements in GF(2^128) using the GHASH
// bit convention. Both inputs and the result are 16-byte arrays in
// big-endian byte order with MSB-first bit numbering.
func GF128Mul(a, b [16]byte) [16]byte {
	var z [16]byte
	v := b

	for i := 0; i < 128; i++ {
		// If bit i of a is set (MSB-first: bit 0 = MSB of byte 0)
		if a[i/8]&(0x80>>uint(i%8)) != 0 {
			for j := 0; j < 16; j++ {
				z[j] ^= v[j]
			}
		}
		// Right-shift v by 1 bit
		carry := v[15] & 1
		for j := 15; j > 0; j-- {
			v[j] = (v[j] >> 1) | (v[j-1] << 7)
		}
		v[0] >>= 1
		// Reduce if the shifted-out bit was 1
		if carry != 0 {
			v[0] ^= 0xe1
		}
	}
	return z
}

// ComputeHPowerTable precomputes H^(2^i) for i = 0..10, giving powers
// H^1, H^2, H^4, H^8, ..., H^1024. This table enables the eBPF kprobe
// to compute arbitrary H^n via at most 11 GF(2^128) multiplications
// (one per set bit in n).
func ComputeHPowerTable(h [16]byte) [11][16]byte {
	var table [11][16]byte
	table[0] = h // H^1
	for i := 1; i < 11; i++ {
		table[i] = GF128Mul(table[i-1], table[i-1])
	}
	return table
}

// GHASHCompute computes GHASH(H, data) where data is the concatenation of all
// GHASH input blocks (AAD padded + ciphertext padded + length block).
// Returns the 16-byte GHASH output.
func GHASHCompute(h [16]byte, blocks [][16]byte) [16]byte {
	var x [16]byte // X_0 = 0
	for _, block := range blocks {
		// X_i = (X_{i-1} XOR block) * H
		for j := 0; j < 16; j++ {
			x[j] ^= block[j]
		}
		x = GF128Mul(x, h)
	}
	return x
}

// GHASHIncrementalDelta computes the tag delta when ciphertext blocks change.
// changedBlocks maps block index (0-based within ciphertext) to (old XOR new) delta.
// totalCTBlocks is the total number of ciphertext blocks.
// Returns the 16-byte tag delta: new_tag = old_tag XOR delta.
func GHASHIncrementalDelta(h [16]byte, changedBlocks map[int][16]byte, totalCTBlocks int) [16]byte {
	var delta [16]byte
	for blockIdx, blockDelta := range changedBlocks {
		// Power = totalCTBlocks + 1 - blockIdx (accounting for length block)
		power := uint32(totalCTBlocks + 1 - blockIdx)
		hPow := GF128HPower(h, power)
		contrib := GF128Mul(blockDelta, hPow)
		for j := 0; j < 16; j++ {
			delta[j] ^= contrib[j]
		}
	}
	return delta
}

// GF128HPower computes H^power in GF(2^128) via square-and-multiply.
func GF128HPower(h [16]byte, power uint32) [16]byte {
	// Multiplicative identity: polynomial 1 = bit 0 set = MSB of byte 0
	var result [16]byte
	result[0] = 0x80

	base := h
	for power > 0 {
		if power&1 != 0 {
			result = GF128Mul(result, base)
		}
		base = GF128Mul(base, base)
		power >>= 1
	}
	return result
}
