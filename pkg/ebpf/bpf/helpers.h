// helpers.h — Pure logic extracted from tls_uprobe.c for dual-target compilation.
// Compiles as __always_inline eBPF when __BPF__ is defined (clang -target bpf),
// and as regular userspace C otherwise (for unit testing with gcc/clang).

#ifndef KLOAK_HELPERS_H
#define KLOAK_HELPERS_H

#ifdef __BPF__
#define HELPER_INLINE static __always_inline
#else
#include <stdint.h>
#include <string.h>
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#define HELPER_INLINE static inline
#ifndef MAX_HOST_LEN
#define MAX_HOST_LEN 64
#endif
#ifndef SECRET_MAX_LEN
#define SECRET_MAX_LEN 128
#endif
#ifndef MAX_DATA_SIZE
#define MAX_DATA_SIZE 256
#endif
typedef uint16_t __u16;
typedef int int32_t;
#endif

// Parse HTTP "Host: " header from a data buffer.
// Scans data[0..data_len) for "Host: ", then extracts the hostname up to
// the first ':', '\r', or '\n'. Writes into host_out (caller must zero it).
// Returns the hostname length, or 0 if not found or empty.
HELPER_INLINE __u32 parse_http_host(const char *data, __u32 data_len,
                                    char *host_out, __u32 host_max_len) {
  if (data_len > MAX_DATA_SIZE)
    data_len = MAX_DATA_SIZE;

  __u32 host_start = 0;
  for (__u32 i = 0; i < MAX_DATA_SIZE; i++) {
    if (i + 6 > data_len)
      break;
    if (data[i] == 'H' && data[i + 1] == 'o' && data[i + 2] == 's' &&
        data[i + 3] == 't' && data[i + 4] == ':' && data[i + 5] == ' ') {
      host_start = i + 6;
      break;
    }
  }

  if (host_start == 0)
    return 0;

  __u32 host_len = 0;
  for (__u32 j = 0; j < MAX_HOST_LEN; j++) {
    if (j >= host_max_len)
      break;
    __u32 idx = host_start + j;
    if (idx >= data_len)
      break;
    char c = data[idx];
    if (c == '\r' || c == '\n' || c == ':')
      break;
    host_out[j] = c;
    host_len++;
  }
  return host_len;
}

// Compare two host buffers (each MAX_HOST_LEN bytes) as uint64 chunks.
// Returns 1 if all bytes match, 0 otherwise.
// _Static_assert below enforces the 8-byte alignment invariant: if MAX_HOST_LEN
// is ever changed, this will produce a compile error rather than silently
// skipping trailing bytes or reading out of bounds.
_Static_assert(MAX_HOST_LEN % 8 == 0,
               "MAX_HOST_LEN must be a multiple of 8 for hosts_match chunked comparison");
HELPER_INLINE int hosts_match(const char *a, const char *b) {
  for (__u32 i = 0; i < MAX_HOST_LEN; i += 8) {
    __u64 va, vb;
    __builtin_memcpy(&va, a + i, 8);
    __builtin_memcpy(&vb, b + i, 8);
    if (va != vb) return 0;
  }
  return 1;
}

// Clamp a secret value length to [1, SECRET_MAX_LEN] using bitwise arithmetic.
// For val_len in [1, SECRET_MAX_LEN], returns val_len unchanged.
// val_len == 0 returns SECRET_MAX_LEN (unsigned underflow wraps).
// val_len > SECRET_MAX_LEN wraps modulo SECRET_MAX_LEN.
HELPER_INLINE __u32 clamp_write_len(__u32 val_len) {
  return ((val_len - 1) & (SECRET_MAX_LEN - 1)) + 1;
}

// Check if buffer starts with the 4-byte "kl::" prefix (HTTP/1.1 plaintext).
// Returns 1 if it matches, 0 otherwise. Caller must ensure buf has >= 4 bytes.
//
// Historical "kloak:" (6 bytes / 37 Huffman bits) shortened to "kl::"
// (4 bytes / 27 Huffman bits) to widen the byte-by-byte shadow generator's
// feasibility window. The trailing `::` is still distinctive enough that
// the cheap prefix filter rejects ~99.999% of byte windows; the 8-byte
// secret_map lookup confirms genuine matches.
HELPER_INLINE int is_kloak_prefix(const char *buf) {
  return (buf[0] == 'k' && buf[1] == 'l' && buf[2] == ':' && buf[3] == ':')
             ? 1
             : 0;
}

// Check if buffer starts with the HPACK Huffman encoding of "kl::" (HTTP/2).
// The HPACK static Huffman table (RFC 7541 Appendix B) encodes "kl::" as
// 27 bits, of which the first 3 stable bytes are 0xeb 0x45 0xcb. The 4th
// byte's bits depend on the character after the second ":" because the
// 27-bit "kl::" doesn't end on a byte boundary. 3 bytes (24 bits) is
// sufficient to keep BPF false-positive lookups rare; the 8-byte
// secret_map confirms genuine matches.
HELPER_INLINE int is_kloak_prefix_huffman(const unsigned char *buf) {
  return (buf[0] == 0xeb && buf[1] == 0x45 && buf[2] == 0xcb)
             ? 1
             : 0;
}

// ============================================================================
// GF(2^128) arithmetic for AES-GCM GHASH tag recomputation.
// Uses the GHASH convention: MSB-first bit ordering within bytes,
// irreducible polynomial x^128 + x^7 + x^2 + x + 1 (R = 0xe1000...0).
// Reference: NIST SP 800-38D Section 6.3.
// ============================================================================

// Multiply two 128-bit elements in GF(2^128) using the GHASH bit convention.
// result = a * b in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1.
HELPER_INLINE void gf128_mul(const __u8 a[16], const __u8 b[16], __u8 result[16]) {
  __u8 v[16], z[16];
  int i, j;

  __builtin_memset(z, 0, 16);
  __builtin_memcpy(v, b, 16);

  for (i = 0; i < 128; i++) {
    // If bit i of a is set (MSB-first: bit 0 is the MSB of byte 0)
    if (a[i / 8] & ((__u8)0x80 >> (i % 8))) {
      for (j = 0; j < 16; j++)
        z[j] ^= v[j];
    }
    // Right-shift v by 1 bit (MSB-first convention)
    __u8 carry = v[15] & 1;
    for (j = 15; j > 0; j--)
      v[j] = (v[j] >> 1) | (v[j - 1] << 7);
    v[0] >>= 1;
    // If the shifted-out bit was 1, XOR with reduction polynomial
    if (carry)
      v[0] ^= 0xe1;
  }
  __builtin_memcpy(result, z, 16);
}

// Compute H^power in GF(2^128) via square-and-multiply from base H.
// power must be >= 1. Result is written to result[16].
HELPER_INLINE void gf128_h_power(const __u8 h[16], __u32 power, __u8 result[16]) {
  __u8 base[16], tmp[16];
  int i;

  // Multiplicative identity in GHASH convention (NIST SP 800-38D):
  // polynomial 1 = bit 0 set = MSB of byte 0 = 0x80.
  __builtin_memset(result, 0, 16);
  result[0] = 0x80;

  __builtin_memcpy(base, h, 16);
  for (i = 0; i < 11 && power > 0; i++) {
    if (power & 1) {
      gf128_mul(result, base, tmp);
      __builtin_memcpy(result, tmp, 16);
    }
    gf128_mul(base, base, tmp);
    __builtin_memcpy(base, tmp, 16);
    power >>= 1;
  }
}

// Compute H^power using a precomputed table of H^(2^i) for i=0..10.
// Faster than gf128_h_power when the table is available.
HELPER_INLINE void gf128_h_power_table(const __u8 h_powers[11][16],
                                        __u32 power,
                                        __u8 result[16]) {
  __u8 tmp[16];
  int i;

  __builtin_memset(result, 0, 16);
  result[0] = 0x80;

  for (i = 0; i < 11 && power > 0; i++) {
    if (power & (1u << i)) {
      gf128_mul(result, h_powers[i], tmp);
      __builtin_memcpy(result, tmp, 16);
    }
  }
}

// Variant of gf128_mul that uses caller-provided workspace buffers instead of
// stack-allocated arrays. This avoids blowing the 512-byte BPF stack limit
// when the function is inlined multiple times in a single BPF program.
// ws_v and ws_z must each be 16-byte buffers (e.g., fields in a per-CPU map).
HELPER_INLINE void gf128_mul_ws(const __u8 a[16], const __u8 b[16], __u8 result[16],
                                 __u8 ws_v[16], __u8 ws_z[16]) {
  int i, j;

  __builtin_memset(ws_z, 0, 16);
  __builtin_memcpy(ws_v, b, 16);

  for (i = 0; i < 128; i++) {
    if (a[i / 8] & ((__u8)0x80 >> (i % 8))) {
      for (j = 0; j < 16; j++)
        ws_z[j] ^= ws_v[j];
    }
    __u8 carry = ws_v[15] & 1;
    for (j = 15; j > 0; j--)
      ws_v[j] = (ws_v[j] >> 1) | (ws_v[j - 1] << 7);
    ws_v[0] >>= 1;
    if (carry)
      ws_v[0] ^= 0xe1;
  }
  __builtin_memcpy(result, ws_z, 16);
}

// Variant of gf128_h_power that uses caller-provided workspace buffers.
// ws_base and ws_tmp must each be 16-byte buffers, ws_v and ws_z for mul.
HELPER_INLINE void gf128_h_power_ws(const __u8 h[16], __u32 power, __u8 result[16],
                                     __u8 ws_base[16], __u8 ws_tmp[16],
                                     __u8 ws_v[16], __u8 ws_z[16]) {
  int i;

  __builtin_memset(result, 0, 16);
  result[0] = 0x80;

  __builtin_memcpy(ws_base, h, 16);
  for (i = 0; i < 11 && power > 0; i++) {
    if (power & 1) {
      gf128_mul_ws(result, ws_base, ws_tmp, ws_v, ws_z);
      __builtin_memcpy(result, ws_tmp, 16);
    }
    gf128_mul_ws(ws_base, ws_base, ws_tmp, ws_v, ws_z);
    __builtin_memcpy(ws_base, ws_tmp, 16);
    power >>= 1;
  }
}

// Variant of gf128_h_power_table that uses caller-provided workspace.
HELPER_INLINE void gf128_h_power_table_ws(const __u8 h_powers[11][16],
                                            __u32 power, __u8 result[16],
                                            __u8 ws_v[16], __u8 ws_z[16]) {
  __u8 tmp[16]; // 16 bytes on stack is acceptable here
  int i;

  __builtin_memset(result, 0, 16);
  result[0] = 0x80;

  for (i = 0; i < 11 && power > 0; i++) {
    if (power & (1u << i)) {
      gf128_mul_ws(result, h_powers[i], tmp, ws_v, ws_z);
      __builtin_memcpy(result, tmp, 16);
    }
  }
}

// Kloak internal cipher type enum (not TLS cipher suite IDs).
// The cipher type is determined implicitly: successful H extraction = AES-GCM.
#define KLOAK_CIPHER_UNKNOWN 0
#define KLOAK_CIPHER_AES_GCM 1  // AES-128-GCM or AES-256-GCM (TLS 1.2 or 1.3)

// Check if the connection uses AES-GCM (compatible with XOR patching + GHASH).
HELPER_INLINE int is_aes_gcm(__u32 cipher_type) {
  return cipher_type == KLOAK_CIPHER_AES_GCM;
}

// ============================================================================
// AES single-block encryption — used to recover the GHASH subkey H for
// BoringSSL.
//
// OpenSSL persists the raw GHASH subkey H (gcm128_context.H) which kloak reads
// directly. BoringSSL does NOT: its GCM128_KEY keeps only the precomputed,
// CPU-specific GHASH powers table. But BoringSSL itself derives the subkey as
// H = AES_encrypt(0) over the AES round-key schedule it DOES persist
// (gcm128_key_st.aes, an AES_KEY). So kloak reads that schedule and recomputes
// H = AES_block(0) here. This is architecture- and GHASH-impl-independent.
//
// aes_block_encrypt operates on a standard FIPS-197 expanded key schedule
// (rk = (nr+1) consecutive 16-byte round keys, column-major bytes) exactly as
// BoringSSL's AES_KEY.rd_key stores it on a little-endian build (verified
// empirically against BoringSSL on amd64 and arm64). Bounded loops keep it
// eBPF-verifier-friendly; FIPS-197 known-answer tests live in helpers_test.c.
// ============================================================================

static const __u8 KLOAK_AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};

// Specialized GF(2^8) multiply-by-2 and multiply-by-3 for AES MixColumns.
// MixColumns only ever multiplies by 2 or 3, so these two inlines replace the
// general 8-iteration loop, cutting thousands of eBPF instructions and keeping
// verifier complexity low.
HELPER_INLINE __u8 aes_mul2(__u8 x) {
  return (__u8)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}
HELPER_INLINE __u8 aes_mul3(__u8 x) {
  return (__u8)(aes_mul2(x) ^ x);
}

// aes_shift_rows / aes_mix_columns operate IN PLACE on a column-major state
// (byte index = row + 4*col), using only scalar temporaries — important because
// this code is inlined into kloak's already stack-heavy kprobe, and the eBPF
// stack limit is 512 bytes. No 16-byte working arrays.
HELPER_INLINE void aes_shift_rows(__u8 s[16]) {
  __u8 t;
  // row 1: <<1
  t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
  // row 2: <<2 (swap pairs)
  t = s[2]; s[2] = s[10]; s[10] = t;
  t = s[6]; s[6] = s[14]; s[14] = t;
  // row 3: <<3 (== >>1)
  t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}
HELPER_INLINE void aes_mix_columns(__u8 s[16]) {
  for (int c = 0; c < 4; c++) {
    __u8 a0 = s[4 * c + 0], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
    s[4 * c + 0] = (__u8)(aes_mul2(a0) ^ aes_mul3(a1) ^ a2 ^ a3);
    s[4 * c + 1] = (__u8)(a0 ^ aes_mul2(a1) ^ aes_mul3(a2) ^ a3);
    s[4 * c + 2] = (__u8)(a0 ^ a1 ^ aes_mul2(a2) ^ aes_mul3(a3));
    s[4 * c + 3] = (__u8)(aes_mul3(a0) ^ a1 ^ a2 ^ aes_mul2(a3));
  }
}

// aes_block_encrypt encrypts the 16-byte block in `state` IN PLACE under the
// expanded key schedule `rk` ((nr+1)*16 bytes). nr in {10,12,14}. Operating in
// place keeps the BPF stack frame flat (no 16-byte temporaries).
HELPER_INLINE void aes_block_encrypt(const __u8 *rk, __u32 nr, __u8 state[16]) {
  for (int i = 0; i < 16; i++) state[i] ^= rk[i]; // AddRoundKey 0

  // Up to 13 mid rounds (AES-256 nr=14 → 13). Bounded by a constant so the
  // eBPF verifier can unroll; `round < nr` gates the real per-key count.
  for (__u32 round = 1; round < 14 && round < nr; round++) {
    for (int i = 0; i < 16; i++) state[i] = KLOAK_AES_SBOX[state[i]];
    aes_shift_rows(state);
    aes_mix_columns(state);
    const __u8 *k = rk + 16 * round;
    for (int i = 0; i < 16; i++) state[i] ^= k[i];
  }

  // Final round (SubBytes + ShiftRows + AddRoundKey, no MixColumns).
  for (int i = 0; i < 16; i++) state[i] = KLOAK_AES_SBOX[state[i]];
  aes_shift_rows(state);
  const __u8 *k = rk + 16 * nr;
  for (int i = 0; i < 16; i++) state[i] ^= k[i];
}

// aes_recover_h recomputes the GHASH subkey H = AES_encrypt(0) from a persisted
// AES round-key schedule, writing 16 bytes to h_out. Returns 1 on success, 0 if
// `rounds` is not a TLS AES round count (a guard against a bogus offset read).
// h_out doubles as the in-place AES state, so no scratch block is needed.
//
// Dispatch is on a COMPILE-TIME-CONSTANT round count so aes_block_encrypt
// inlines with a constant `nr`: clang then fully unrolls its round loop into
// constant-offset accesses into rd_key, which the eBPF verifier accepts
// (a runtime `nr` would leave a variable-offset access the verifier rejects).
// Only AES-128 (10) and AES-256 (14) are handled — TLS never negotiates
// AES-192-GCM, so 12 is intentionally treated as unsupported.
//
// x86 AES-NI stores AES_KEY.rounds as nr-1 (9 for AES-128, 13 for AES-256),
// so both the canonical and AES-NI values are accepted for each key size.
HELPER_INLINE int aes_recover_h(const __u8 *rd_key, __u32 rounds, __u8 h_out[16]) {
  for (int i = 0; i < 16; i++) h_out[i] = 0; // plaintext block = 0
  if (rounds == 10 || rounds == 9) {  // 9 = x86 AES-NI stores nr-1 for AES-128
    aes_block_encrypt(rd_key, 10, h_out);
    return 1;
  }
  if (rounds == 14 || rounds == 13) {  // 13 = x86 AES-NI stores nr-1 for AES-256
    aes_block_encrypt(rd_key, 14, h_out);
    return 1;
  }
  return 0;
}

#endif // KLOAK_HELPERS_H
