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

// Check if buffer starts with the 6-byte "kloak:" prefix (HTTP/1.1 plaintext).
// Returns 1 if it matches, 0 otherwise. Caller must ensure buf has >= 6 bytes.
HELPER_INLINE int is_kloak_prefix(const char *buf) {
  return (buf[0] == 'k' && buf[1] == 'l' && buf[2] == 'o' && buf[3] == 'a' &&
          buf[4] == 'k' && buf[5] == ':')
             ? 1
             : 0;
}

// Check if buffer starts with the HPACK Huffman encoding of "kloak:" (HTTP/2).
// The HPACK static Huffman table (RFC 7541 Appendix B) encodes "kloak" as
// 4 stable bytes: 0xeb 0x41 0xc7 0xd6. The 5th byte varies depending on
// the character after ":" due to Huffman bit packing. 4 bytes is sufficient
// to avoid false positives — the 8-byte key lookup confirms the match.
HELPER_INLINE int is_kloak_prefix_huffman(const unsigned char *buf) {
  return (buf[0] == 0xeb && buf[1] == 0x41 && buf[2] == 0xc7 &&
          buf[3] == 0xd6)
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

#endif // KLOAK_HELPERS_H
