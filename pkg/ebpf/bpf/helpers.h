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
// libbpf's, from bpf_helpers.h.
#define barrier_var(var) asm volatile("" : "+r"(var))
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

// One of the 128 steps of a GF(2^128) multiply, for bit i of a (MSB-first:
// bit 0 is the MSB of byte 0): z ^= v if the bit is set, then v = v * x, a
// 1-bit right shift that folds the bit shifted out of v[15] back in as R.
// Start with z = 0 and v = b; after steps 0..127, z = a * b.
//
// The loop is fully unrolled, so every index is a constant: left as a loop,
// clang walks v with a pointer offset by a negative constant, which the
// verifier rejects as an unbounded access since Linux 7.2 (it now keeps a
// pointer's constant offset in its variable bounds). It is one pass with no
// branch on the bit: with the branch, clang loads all of v ahead of it and
// spills it, which takes the BPF callback's stack frame from 8 bytes to 144.
// The reduction stays a branch, where the verifier can prune the callback's
// repeated visits once i is dead: made branch-free too, it cost Linux 7.2's
// verifier 60K more instructions in tc_ghash_update.
HELPER_INLINE void gf128_mul_step(const __u8 a[16], __u8 v[16], __u8 z[16],
                                  __u32 i) {
  // The masks keep the index bounded for the verifier (i < 128 anyway).
  __u8 mask = -(__u8)((a[(i >> 3) & 0xF] >> (7 - (i & 7))) & 1);
  __u8 prev = 0;
#pragma GCC unroll 16
  for (int j = 0; j < 16; j++) {
    __u8 cur = v[j];
    z[j] ^= cur & mask;
    v[j] = (cur >> 1) | (__u8)(prev << 7);
    prev = cur;
  }
  if (prev & 1)
    v[0] ^= 0xe1;
}

// Multiply two 128-bit elements in GF(2^128) using the GHASH bit convention.
// result = a * b in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1.
HELPER_INLINE void gf128_mul(const __u8 a[16], const __u8 b[16], __u8 result[16]) {
  __u8 v[16], z[16];

  __builtin_memset(z, 0, 16);
  __builtin_memcpy(v, b, 16);

  for (__u32 i = 0; i < 128; i++)
    gf128_mul_step(a, v, z, i);
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
  __builtin_memset(ws_z, 0, 16);
  __builtin_memcpy(ws_v, b, 16);

  for (__u32 i = 0; i < 128; i++)
    gf128_mul_step(a, ws_v, ws_z, i);
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

// gf128_halve_to_h recovers the GHASH subkey H from the doubled value that
// carry-less-multiply GHASH implementations precompute at key setup:
//
//   V = (bswap128(H) << 1) ^ (MSB ? POLY : 0),  POLY = {hi: 0xC2<<56, lo: 1}
//
// Both Go's gcmAesInit (crypto/aes, the "H·2" register value) and OpenSSL's
// AVX-512 GCM (HashKey_1 in GCM128_CONTEXT.Htable, see ossl_read_gcm_h) store
// H in this form instead of the raw subkey. lo/hi are V's low/high 64-bit
// lanes as loaded from memory. Writes H as the 16-byte big-endian GHASH string.
//
// Reduction indicator: the left shift always clears bit 0, and POLY sets it,
// so lo.bit0 says whether POLY was XORed in. Undo that, then undo the 128-bit
// shift, restoring the MSB that the reduction consumed.
HELPER_INLINE void gf128_halve_to_h(__u64 lo, __u64 hi, __u8 out[16]) {
  __u64 reduced = lo & 1;
  if (reduced) {
    hi ^= 0xC200000000000000ULL;
    lo ^= 0x0000000000000001ULL;
  }
  lo = (lo >> 1) | (hi << 63);
  hi = (hi >> 1) | (reduced << 63);
  for (int i = 0; i < 8; i++) {
    out[i] = (__u8)(hi >> (56 - 8 * i));
    out[8 + i] = (__u8)(lo >> (56 - 8 * i));
  }
}

// ghash_block_delta writes the XOR delta of GHASH block `block` (bytes
// block * 16 .. block * 16 + 15 of the ciphertext; block is masked to 10
// bits) to out:
// byte i is xor_delta[pos - sec_off] when pos = block * 16 + i falls in the
// patch [sec_off, sec_off + len), and 0 elsewhere. len is at most
// SECRET_MAX_LEN.
//
// The range check is arithmetic, not a comparison: BPF has no conditional
// set, so a comparison is a branch, and 16 of them against bounds the
// verifier doesn't know made Linux 7.2's verifier walk ~320K instructions of
// tc_ghash_update here. d is pos - sec_off in 64 bits, negative (top bit
// set) when pos is before the patch; the byte is in the patch when d's top
// bit is clear and d - len's is set. The loop is unrolled so every out index
// is a constant (see gf128_mul_step), and barrier_var keeps each byte's
// arithmetic in its own iteration: without it clang computes all 16 up
// front and spills them, taking the callback's stack frame from 32 bytes to
// 248.
HELPER_INLINE void ghash_block_delta(const __u8 xor_delta[SECRET_MAX_LEN],
                                     __u32 block, __u32 sec_off, __u32 len,
                                     __u8 out[16]) {
  __u64 start = (__u64)(block & 0x3FF) * 16 - sec_off;
#pragma GCC unroll 16
  for (int i = 0; i < 16; i++) {
    __u64 d = start + i;
    barrier_var(d);
    __u8 in = (__u8)((~d & (d - len)) >> 63);
    out[i] = xor_delta[d & (SECRET_MAX_LEN - 1)] & -in;
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
// TLS record framing (tc_egress record selection)
// ============================================================================

#define TLS_CT_CHANGE_CIPHER_SPEC 0x14
#define TLS_CT_ALERT 0x15
#define TLS_CT_HANDSHAKE 0x16
#define TLS_CT_APPLICATION_DATA 0x17

// Largest legal TLSCiphertext.length (RFC 5246 §6.2.3: 2^14 + 2048). Anything
// larger cannot be a record boundary.
#define TLS_MAX_RECORD_LEN (16384 + 2048)

// Smallest application_data record: TLS 1.3 with 0 plaintext bytes =
// 1 (inner content type) + 16 (AEAD tag).
#define TLS_APPDATA_MIN_RECORD_LEN 17

// Per-connection nonce length is not known (no TLS-version offset for this
// TLS library, e.g. BoringSSL statically linked into Bun). Mirrors the 0xFF
// sentinel stored in tls_conn_state.nonce_len.
#define TLS_NONCE_UNKNOWN 0xFF

#define TLS_REC_INVALID 0   // not a record boundary (e.g. continuation bytes)
#define TLS_REC_SKIPPABLE 1 // plausible CCS / alert / handshake record
#define TLS_REC_APPDATA 2   // plausible application_data record

// tls_record_hdr_kind classifies the 5-byte TLS record header at hdr and, for
// any valid header, stores the record body length in *rec_len.
//
// tc_egress uses it to walk records coalesced into one TCP segment. A TLS
// stack may flush non-application records in the same write as the first
// application_data record — e.g. a TLS 1.3 client's ChangeCipherSpec +
// encrypted Finished + first application write (Bun >= 1.4.1 does this) — so
// the record carrying the secret is not necessarily the first in the segment.
//
// The checks are deliberately strict (version 0x0300-0x0303, per-type length
// bounds, CCS body exactly 1 byte) so random ciphertext in a TCP continuation
// segment is very unlikely to be mistaken for a record boundary.
HELPER_INLINE int tls_record_hdr_kind(const __u8 *hdr, __u32 *rec_len) {
  if (hdr[1] != 0x03 || hdr[2] > 0x03)
    return TLS_REC_INVALID;
  __u32 len = ((__u32)hdr[3] << 8) | (__u32)hdr[4];
  if (len > TLS_MAX_RECORD_LEN)
    return TLS_REC_INVALID;

  int kind;
  switch (hdr[0]) {
  case TLS_CT_APPLICATION_DATA:
    if (len < TLS_APPDATA_MIN_RECORD_LEN)
      return TLS_REC_INVALID;
    kind = TLS_REC_APPDATA;
    break;
  case TLS_CT_CHANGE_CIPHER_SPEC:
    // ChangeCipherSpec is always a single 0x01 byte (TLS 1.2 and the TLS 1.3
    // middlebox-compatibility record alike).
    if (len != 1)
      return TLS_REC_INVALID;
    kind = TLS_REC_SKIPPABLE;
    break;
  case TLS_CT_ALERT:
    // Plaintext alerts are 2 bytes; TLS 1.2 encrypted alerts are larger.
    if (len < 2)
      return TLS_REC_INVALID;
    kind = TLS_REC_SKIPPABLE;
    break;
  case TLS_CT_HANDSHAKE:
    if (len < 4) // handshake message header
      return TLS_REC_INVALID;
    kind = TLS_REC_SKIPPABLE;
    break;
  default:
    return TLS_REC_INVALID;
  }
  *rec_len = len;
  return kind;
}

// tls_appdata_reclen_match reports whether an AES-GCM application_data record
// of length rec_len carries exactly pt_len plaintext bytes:
//   TLS 1.3 (nonce_len 0): rec_len = pt_len + 1 (inner type) + 16 (tag)
//   TLS 1.2 (nonce_len 8): rec_len = pt_len + 8 (explicit nonce) + 16 (tag)
// With nonce_len == TLS_NONCE_UNKNOWN either layout matches. On a match the
// nonce length that matched is written to *out_nonce and 1 is returned.
HELPER_INLINE int tls_appdata_reclen_match(__u32 rec_len, __u32 pt_len,
                                           __u32 nonce_len, __u32 *out_nonce) {
  if (pt_len == 0)
    return 0;
  if (nonce_len != 8 && rec_len == pt_len + 17) {
    *out_nonce = 0;
    return 1;
  }
  if (nonce_len != 0 && rec_len == pt_len + 24) {
    *out_nonce = 8;
    return 1;
  }
  return 0;
}

// ============================================================================
// TLS ClientHello SNI extraction (SNI check, spinningfactory/kloak#328)
//
// A secret restricted to a hostname is only rewritten on a connection whose
// first ClientHello named that host, so a shared front end (CDN, cloud load
// balancer) cannot route the real value to another tenant. The ClientHello is
// sent in the clear; tls_parse_sni reads it from the first bytes of a
// tcp_sendmsg buffer copied into a TLS_SNI_BUF_LEN scratch buffer.
// ============================================================================

// Copy size for the ClientHello prefix. Post-quantum key shares
// (X25519MLKEM768) push ClientHellos to ~1.2-1.8 KB, and server_name may come
// after key_share. Must be a power of two: offsets are masked with it for the
// verifier.
#define TLS_SNI_BUF_LEN 2048
#define TLS_SNI_BUF_MASK (TLS_SNI_BUF_LEN - 1)
// Extensions walked before giving up. Real ClientHellos carry ~10-20.
#define TLS_SNI_MAX_EXTS 32

#define TLS_HS_CLIENT_HELLO 0x01
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_ECH 0xfe0d

// tls_parse_sni results. SNI_STATUS_NONE is the zero value, so a zeroed
// sni_state entry reads as "no ClientHello seen yet".
#define SNI_STATUS_NONE 0       // no ClientHello seen on this connection
#define SNI_STATUS_SEEN 1       // ClientHello with a valid host_name
#define SNI_STATUS_ABSENT 2     // ClientHello without server_name
#define SNI_STATUS_ECH 3        // encrypted ClientHello: the outer SNI is not the real host
#define SNI_STATUS_TRUNCATED 4  // server_name not within the copied bytes
#define SNI_STATUS_MALFORMED 5  // lengths inconsistent or host_name invalid
#define SNI_STATUS_MISMATCH 6   // a later ClientHello (HelloRetryRequest) named another host
#define SNI_NOT_CLIENT_HELLO 0xFF // buffer does not start with a ClientHello

// sni_idx masks a buffer offset. The empty asm hides the value from the
// compiler: it can often prove off < TLS_SNI_BUF_LEN from an earlier
// `off + k > len` check and drop the mask, but the verifier loses that link
// once the register is spilled, and rejects the access.
HELPER_INLINE __u32 sni_idx(__u32 off) {
#ifdef __BPF__
  asm volatile("" : "+r"(off));
#endif
  return off & TLS_SNI_BUF_MASK;
}

HELPER_INLINE __u32 sni_rd16(const __u8 *b, __u32 off) {
  return ((__u32)b[sni_idx(off)] << 8) | (__u32)b[sni_idx(off + 1)];
}

// A host_name byte the SNI check accepts: lowercase LDH, '.', '_'.
// Rejecting everything else (notably NUL) keeps a host such as
// "api.example.com\0evil" from comparing equal to a zero-padded
// "api.example.com" in hosts_match.
HELPER_INLINE int sni_host_char_ok(__u8 c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
         c == '.' || c == '_';
}

// tls_parse_sni parses the TLS record at buf[0..len) as a ClientHello and, on
// SNI_STATUS_SEEN, writes the lowercased host_name without a trailing dot to
// host_out (MAX_HOST_LEN bytes, zeroed by the caller) and its length to
// *host_len. Returns SNI_NOT_CLIENT_HELLO when the buffer does not start with
// a handshake record carrying a ClientHello, otherwise an SNI_STATUS_* value.
// An ECH extension wins over a readable server_name: with ECH the outer SNI
// is the front end's public name, not the host the request is for.
HELPER_INLINE __u32 tls_parse_sni(const __u8 *buf, __u32 len, char *host_out,
                                  __u32 *host_len) {
  *host_len = 0;
  if (len > TLS_SNI_BUF_LEN)
    len = TLS_SNI_BUF_LEN;
  // Record header (5) + handshake header (4).
  if (len < 9)
    return SNI_NOT_CLIENT_HELLO;
  if (buf[0] != TLS_CT_HANDSHAKE || buf[1] != 0x03 ||
      buf[5] != TLS_HS_CLIENT_HELLO)
    return SNI_NOT_CLIENT_HELLO;

  __u32 rec_end = 5 + sni_rd16(buf, 3);
  __u32 hs_end = 9 + (((__u32)buf[6] << 16) | sni_rd16(buf, 7));
  // A ClientHello fragmented across records is legal but never seen in
  // practice; refuse rather than reassemble.
  if (hs_end > rec_end)
    return SNI_STATUS_MALFORMED;

  // client_version (2) + random (32).
  __u32 off = 9 + 2 + 32;
  // session_id
  if (off + 1 > len)
    return SNI_STATUS_TRUNCATED;
  off += 1 + buf[sni_idx(off)];
  // cipher_suites
  if (off + 2 > len)
    return SNI_STATUS_TRUNCATED;
  off += 2 + sni_rd16(buf, off);
  // compression_methods
  if (off + 1 > len)
    return SNI_STATUS_TRUNCATED;
  off += 1 + buf[sni_idx(off)];
  if (off > hs_end)
    return SNI_STATUS_MALFORMED;
  if (off == hs_end)
    return SNI_STATUS_ABSENT; // no extensions at all
  if (off + 2 > len)
    return SNI_STATUS_TRUNCATED;
  __u32 ext_end = off + 2 + sni_rd16(buf, off);
  if (ext_end != hs_end)
    return SNI_STATUS_MALFORMED;
  off += 2;

  int ech = 0;
  int found = 0;
  int truncated = 0;
  __u32 n = 0, name_off = 0;
  for (__u32 i = 0; i < TLS_SNI_MAX_EXTS; i++) {
    if (off >= ext_end)
      break;
    if (off + 4 > ext_end)
      return SNI_STATUS_MALFORMED;
    if (off + 4 > len) {
      truncated = 1;
      break;
    }
    __u32 type = sni_rd16(buf, off);
    __u32 elen = sni_rd16(buf, off + 2);
    off += 4;
    if (off + elen > ext_end)
      return SNI_STATUS_MALFORMED;

    if (type == TLS_EXT_ECH)
      ech = 1;

    if (type == TLS_EXT_SERVER_NAME) {
      // A second server_name extension is illegal (RFC 8446 §4.2).
      if (found)
        return SNI_STATUS_MALFORMED;
      if (off + elen > len) {
        truncated = 1;
        break;
      }
      // ServerNameList: list_len (2), name_type (1), name_len (2), name.
      // Only a single host_name entry is accepted.
      if (elen < 5 || sni_rd16(buf, off) != elen - 2 ||
          buf[sni_idx(off + 2)] != 0)
        return SNI_STATUS_MALFORMED;
      n = sni_rd16(buf, off + 3);
      if (n == 0 || n + 5 != elen || n >= MAX_HOST_LEN)
        return SNI_STATUS_MALFORMED;
      // Copied after the walk: a copy loop nested in this one multiplies the
      // paths the BPF verifier explores past its instruction budget.
      name_off = off + 5;
      found = 1;
    }
    off += elen;
  }

  if (ech)
    return SNI_STATUS_ECH;
  // ECH may sit after the copied bytes or past the walk limit: only trust
  // a server_name when every extension was seen.
  if (truncated)
    return SNI_STATUS_TRUNCATED;
  if (off < ext_end)
    return SNI_STATUS_MALFORMED; // more than TLS_SNI_MAX_EXTS extensions
  if (!found)
    return SNI_STATUS_ABSENT;

  for (__u32 j = 0; j < MAX_HOST_LEN; j++) {
    if (j >= n)
      break;
    __u8 c = buf[sni_idx(name_off + j)];
    if (c >= 'A' && c <= 'Z')
      c = c - 'A' + 'a';
    if (!sni_host_char_ok(c))
      return SNI_STATUS_MALFORMED;
    host_out[j & (MAX_HOST_LEN - 1)] = (char)c;
  }
  if (host_out[(n - 1) & (MAX_HOST_LEN - 1)] == '.') {
    host_out[(n - 1) & (MAX_HOST_LEN - 1)] = 0;
    n--;
  }
  if (n == 0)
    return SNI_STATUS_MALFORMED;
  *host_len = n;
  return SNI_STATUS_SEEN;
}

// ============================================================================
// DNS answers for the virtual IP rewrite (tc_dns_rewrite). dns_parse_question
// reads the question of a response and dns_scan_addr_records lists the
// address records of its answer section (A for an A question, AAAA for an
// AAAA one), so the tc program can replace each address with the host's fake
// IP of that family. Both read the first MAX_DNS_PKT bytes of the message,
// copied into a buffer of that size.
// ============================================================================

#ifndef MAX_DNS_PKT
#define MAX_DNS_PKT 512
#endif
#define DNS_MSG_MASK (MAX_DNS_PKT - 1)
_Static_assert((MAX_DNS_PKT & DNS_MSG_MASK) == 0,
               "MAX_DNS_PKT must be a power of two: offsets are masked with it");

// Address records rewritten per answer. An answer with more is left
// unchanged.
#define DNS_MAX_ADDR_RECORDS 8
// Answer section walk budget: one step per owner name label and one per
// record. Covers DNS_MAX_ADDR_RECORDS records under compressed names with room
// for a CNAME chain or uncompressed names.
#define DNS_SCAN_STEPS 64

#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1

// dns_parse_question / dns_scan_addr_records results.
#define DNS_SCAN_OK 0
#define DNS_SCAN_NOT_ANSWER 1 // not an untruncated NOERROR answer to one question
#define DNS_SCAN_BAD_NAME 2   // the question is not a name a watched host can have
#define DNS_SCAN_INCOMPLETE 3 // the answer section is cut short or past the walk budget
#define DNS_SCAN_MALFORMED 4  // lengths or label types are invalid

// An IN A or AAAA record of an answer section.
struct dns_addr_record {
  __u32 off; // offset of the address (RDATA) in the message
  __u32 ttl;
  __u8 ip[16]; // an A record's address in the first 4 bytes
};

// dns_addr_len returns the address length of the records answering a
// question of type qtype: 4 for A, 16 for AAAA, 0 for any other type.
HELPER_INLINE __u32 dns_addr_len(__u32 qtype) {
  if (qtype == DNS_TYPE_A)
    return 4;
  if (qtype == DNS_TYPE_AAAA)
    return 16;
  return 0;
}

// dns_idx masks a message offset, hidden from the compiler like sni_idx.
HELPER_INLINE __u32 dns_idx(__u32 off) {
#ifdef __BPF__
  asm volatile("" : "+r"(off));
#endif
  return off & DNS_MSG_MASK;
}

HELPER_INLINE __u32 dns_rd16(const __u8 *b, __u32 off) {
  return ((__u32)b[dns_idx(off)] << 8) | (__u32)b[dns_idx(off + 1)];
}

// The walks below take one bounded step per name byte, label or record, so
// that BPF can drive them with bpf_loop: unrolled, their branches multiply
// the paths the verifier explores past its instruction budget. Each has a
// begin / step / end triple (step returns 1 once the walk is over) and a
// plain-loop driver used by the userspace tests.
#define DNS_SCAN_RUNNING 0xFF

// Question walk: one step per byte of the question name. A name of
// MAX_HOST_LEN - 1 bytes takes MAX_HOST_LEN + 1 bytes on the wire.
#define DNS_QNAME_STEPS (MAX_HOST_LEN + 1)

struct dns_question {
  char qname[MAX_HOST_LEN]; // lowercased, without the root label, zero-padded
  __u32 qname_len;
  __u32 qtype;
  __u32 ancount;
  __u32 answers_off; // where the answer section starts
  __u32 status;      // DNS_SCAN_*
  __u32 len;         // message length (at most MAX_DNS_PKT)
  __u32 off;         // next byte of the name
  __u32 label_rem;   // bytes left in the current label
};

// dns_question_begin checks that msg[0..len) is an untruncated NOERROR
// response to a single standard query, with at least one answer, and starts
// the walk of its question name. q must be zeroed by the caller.
HELPER_INLINE void dns_question_begin(struct dns_question *q, const __u8 *msg,
                                      __u32 len) {
  q->status = DNS_SCAN_NOT_ANSWER;
  if (len > MAX_DNS_PKT)
    len = MAX_DNS_PKT;
  q->len = len;
  if (len < 12)
    return;
  // QR = 1, opcode QUERY, TC = 0; RCODE NOERROR.
  if ((msg[2] & 0xFA) != 0x80 || (msg[3] & 0x0F) != 0)
    return;
  if (dns_rd16(msg, 4) != 1)
    return;
  q->ancount = dns_rd16(msg, 6);
  if (q->ancount == 0)
    return;
  q->off = 12;
  q->status = DNS_SCAN_RUNNING;
}

// dns_question_step reads one byte of the question name into q->qname. A
// name longer than MAX_HOST_LEN - 1 bytes, compressed, or with a byte a
// hostname cannot hold (sni_host_char_ok, and no '.' inside a label) is
// refused with DNS_SCAN_BAD_NAME: no watched host can match it.
HELPER_INLINE int dns_question_step(struct dns_question *q, const __u8 *msg) {
  if (q->status != DNS_SCAN_RUNNING)
    return 1;
  __u32 off = q->off, len = q->len, n = q->qname_len;
  if (off >= len || off >= MAX_DNS_PKT) {
    q->status = DNS_SCAN_NOT_ANSWER;
    return 1;
  }
  __u8 c = msg[dns_idx(off)];
  q->off = off + 1;
  if (q->label_rem == 0) {
    if (c == 0) { // root label: the name is complete
      // QTYPE, QCLASS
      if (n == 0) {
        q->status = DNS_SCAN_BAD_NAME;
      } else if (off + 1 + 4 > len) {
        q->status = DNS_SCAN_NOT_ANSWER;
      } else {
        q->qtype = dns_rd16(msg, off + 1);
        q->answers_off = off + 1 + 4;
        q->status = DNS_SCAN_OK;
      }
      return 1;
    }
    if (c > 63) { // compression pointer or reserved label type
      q->status = DNS_SCAN_BAD_NAME;
      return 1;
    }
    if (n > 0) {
      if (n >= MAX_HOST_LEN - 1) {
        q->status = DNS_SCAN_BAD_NAME;
        return 1;
      }
      q->qname[n & (MAX_HOST_LEN - 1)] = '.';
      q->qname_len = n + 1;
    }
    q->label_rem = c;
    return 0;
  }
  if (c >= 'A' && c <= 'Z')
    c = c - 'A' + 'a';
  if (c == '.' || !sni_host_char_ok(c) || n >= MAX_HOST_LEN - 1) {
    q->status = DNS_SCAN_BAD_NAME;
    return 1;
  }
  q->qname[n & (MAX_HOST_LEN - 1)] = (char)c;
  q->qname_len = n + 1;
  q->label_rem--;
  return 0;
}

// dns_question_end returns the walk's DNS_SCAN_* result. On DNS_SCAN_OK
// q->qname, q->qname_len, q->qtype, q->ancount and q->answers_off are set.
HELPER_INLINE __u32 dns_question_end(struct dns_question *q) {
  if (q->status == DNS_SCAN_RUNNING) // name longer than the step budget
    q->status = DNS_SCAN_BAD_NAME;
  return q->status;
}

HELPER_INLINE __u32 dns_parse_question(const __u8 *msg, __u32 len,
                                       struct dns_question *q) {
  dns_question_begin(q, msg, len);
  for (__u32 i = 0; i < DNS_QNAME_STEPS; i++)
    if (dns_question_step(q, msg))
      break;
  return dns_question_end(q);
}

// Answer walk: one step per owner name label or per record.
struct dns_answers {
  struct dns_addr_record recs[DNS_MAX_ADDR_RECORDS];
  __u32 n_recs;
  __u32 rr_type; // the record type listed (the question's)
  __u32 rr_len;  // its address length (dns_addr_len), 0: none listed
  __u32 status;  // DNS_SCAN_*
  __u32 len;     // message length (at most MAX_DNS_PKT)
  __u32 off;     // next label or record
  __u32 ancount; // records in the answer section
  __u32 done;    // records walked
  __u32 in_name; // 1 while walking an owner name
};

// dns_answers_begin starts the walk of the ancount records of the answer
// section at msg[off] (dns_question.answers_off), listing the IN records of
// type qtype if it is A or AAAA. a must be zeroed by the caller.
HELPER_INLINE void dns_answers_begin(struct dns_answers *a, __u32 len,
                                     __u32 off, __u32 ancount, __u32 qtype) {
  if (len > MAX_DNS_PKT)
    len = MAX_DNS_PKT;
  a->rr_type = qtype;
  a->rr_len = dns_addr_len(qtype);
  a->len = len;
  a->off = off;
  a->ancount = ancount;
  a->in_name = 1;
  a->status = DNS_SCAN_RUNNING;
}

// dns_answers_step walks one owner name label or one record, listing the IN
// records of type a->rr_type in a->recs. Other records, such as the CNAME
// chain leading to the addresses, are skipped.
HELPER_INLINE int dns_answers_step(struct dns_answers *a, const __u8 *msg) {
  if (a->status != DNS_SCAN_RUNNING)
    return 1;
  if (a->done >= a->ancount) {
    a->status = DNS_SCAN_OK;
    return 1;
  }
  __u32 off = a->off, len = a->len;
  if (a->in_name) {
    if (off >= len || off >= MAX_DNS_PKT) {
      a->status = DNS_SCAN_INCOMPLETE;
      return 1;
    }
    __u8 b = msg[dns_idx(off)];
    if (b == 0) {
      a->off = off + 1;
      a->in_name = 0;
    } else if ((b & 0xC0) == 0xC0) { // a compression pointer ends the name
      a->off = off + 2;
      a->in_name = 0;
    } else if (b & 0xC0) {
      a->status = DNS_SCAN_MALFORMED;
      return 1;
    } else {
      a->off = off + 1 + (__u32)b;
    }
    return 0;
  }
  // TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
  if (off + 10 > len || off >= MAX_DNS_PKT) {
    a->status = DNS_SCAN_INCOMPLETE;
    return 1;
  }
  __u32 type = dns_rd16(msg, off);
  __u32 cls = dns_rd16(msg, off + 2);
  __u32 ttl = (dns_rd16(msg, off + 4) << 16) | dns_rd16(msg, off + 6);
  __u32 rdlen = dns_rd16(msg, off + 8);
  off += 10;
  if (off + rdlen > len) {
    a->status = DNS_SCAN_INCOMPLETE;
    return 1;
  }
  __u32 alen = a->rr_len;
  if (alen && type == a->rr_type && cls == DNS_CLASS_IN) {
    __u32 n = a->n_recs;
    if (rdlen != alen) {
      a->status = DNS_SCAN_MALFORMED;
      return 1;
    }
    if (n >= DNS_MAX_ADDR_RECORDS) {
      a->status = DNS_SCAN_INCOMPLETE;
      return 1;
    }
    struct dns_addr_record *r = &a->recs[n & (DNS_MAX_ADDR_RECORDS - 1)];
    r->off = off;
    r->ttl = ttl;
    for (__u32 k = 0; k < 16; k++)
      r->ip[k] = k < alen ? msg[dns_idx(off + k)] : 0;
    a->n_recs = n + 1;
  }
  a->off = off + rdlen;
  a->done++;
  a->in_name = 1;
  return 0;
}

// dns_answers_end returns DNS_SCAN_OK only when every record was walked:
// rewriting part of an answer would hand the app a mix of fake and real
// addresses.
HELPER_INLINE __u32 dns_answers_end(struct dns_answers *a) {
  if (a->status == DNS_SCAN_RUNNING)
    a->status = a->done >= a->ancount ? DNS_SCAN_OK : DNS_SCAN_INCOMPLETE;
  return a->status;
}

HELPER_INLINE __u32 dns_scan_addr_records(const __u8 *msg, __u32 len,
                                          __u32 off, __u32 ancount,
                                          __u32 qtype, struct dns_answers *a) {
  dns_answers_begin(a, len, off, ancount, qtype);
  for (__u32 i = 0; i < DNS_SCAN_STEPS; i++)
    if (dns_answers_step(a, msg))
      break;
  return dns_answers_end(a);
}

// csum_odd_bytes prepares a 4-byte value that starts at an odd offset from
// the start of a checksummed area for the ones' complement update helpers
// (bpf_l4_csum_replace), which sum it as two aligned 16-bit words. At an odd
// offset each byte lands in the other half of its word, which is the same as
// swapping the bytes of each 16-bit half (RFC 1071 byte order independence).
// The result holds the bytes b1 b0 b3 b2 in memory order, on either
// endianness.
HELPER_INLINE __u32 csum_odd_bytes(__u32 v) {
  return ((v & 0x00FF00FFu) << 8) | ((v >> 8) & 0x00FF00FFu);
}

// ============================================================================
// Virtual IP addresses. Every address is 16 bytes, network byte order: IPv6,
// or IPv4-mapped (::ffff:a.b.c.d) for IPv4. The tests below OR the bytes
// together rather than stop at the first one that decides: one branch per
// test, where an early exit per byte multiplies the paths the verifier walks
// (with clang 19, past its budget in vip_connect6).
// ============================================================================

// vip_addr_eq reports whether the addresses a and b are equal.
HELPER_INLINE int vip_addr_eq(const __u8 *a, const __u8 *b) {
  __u8 diff = 0;
  for (__u32 i = 0; i < 16; i++)
    diff |= a[i] ^ b[i];
  return diff == 0;
}

// vip_addr_v4mapped reports whether ip is an IPv4-mapped address.
HELPER_INLINE int vip_addr_v4mapped(const __u8 *ip) {
  __u8 diff = (__u8)(ip[10] ^ 0xff) | (__u8)(ip[11] ^ 0xff);
  for (__u32 i = 0; i < 10; i++)
    diff |= ip[i];
  return diff == 0;
}

// vip_addr_unspecified reports whether ip is :: or 0.0.0.0 (IPv4-mapped).
HELPER_INLINE int vip_addr_unspecified(const __u8 *ip) {
  __u8 rest = ip[12] | ip[13] | ip[14] | ip[15];
  for (__u32 i = 0; i < 10; i++)
    rest |= ip[i];
  if (rest)
    return 0;
  return (ip[10] | ip[11]) == 0 || (ip[10] & ip[11]) == 0xff;
}

// vip_in_prefix6 reports whether the IPv6 address ip is in the range
// net/mask; never when mask is all zero (no IPv6 range).
HELPER_INLINE int vip_in_prefix6(const __u8 *net, const __u8 *mask,
                                 const __u8 *ip) {
  __u8 diff = 0, any = 0;
  for (__u32 i = 0; i < 16; i++) {
    diff |= (ip[i] & mask[i]) ^ net[i];
    any |= mask[i];
  }
  return diff == 0 && any != 0;
}

// Virtual IP upstreams (vip_upstream): the real addresses the trusted
// resolvers returned for a fake IP's host, in the fake IP's family (from the
// A records for a fake IPv4, the AAAA records for a fake IPv6).
// tc_dns_rewrite records them, the connect redirect picks one.

#define VIP_UPSTREAM_SLOTS 4

struct vip_upstream_slot {
  __u8 ip[16];
  __u64 expires_at; // bpf_ktime_get_boot_ns() at which the record's TTL ran
                    // out; 0 = empty slot
};

struct vip_upstream_val {
  struct vip_upstream_slot slot[VIP_UPSTREAM_SLOTS];
};

// vip_upstream_record adds ip, valid until expires_at (not 0), to v. A slot
// already holding ip keeps the later expiry; otherwise ip takes the slot
// that expires first (an empty one if any). An unspecified address (:: or
// 0.0.0.0) is not recorded.
HELPER_INLINE void vip_upstream_record(struct vip_upstream_val *v,
                                       const __u8 *ip, __u64 expires_at) {
  if (expires_at == 0 || vip_addr_unspecified(ip))
    return;
  __u32 victim = 0;
  __u64 victim_exp = ~0ULL;
  for (__u32 i = 0; i < VIP_UPSTREAM_SLOTS; i++) {
    __u64 exp = v->slot[i].expires_at;
    if (exp && vip_addr_eq(v->slot[i].ip, ip)) {
      if (expires_at > exp)
        v->slot[i].expires_at = expires_at;
      return;
    }
    if (exp < victim_exp) {
      victim_exp = exp;
      victim = i;
    }
  }
  struct vip_upstream_slot *s = &v->slot[victim & (VIP_UPSTREAM_SLOTS - 1)];
  __builtin_memcpy(s->ip, ip, 16);
  s->expires_at = expires_at;
}

// vip_upstream_pick copies to out the address a connect to v's fake IP goes
// to at time now: one of the unexpired addresses, chosen by rnd, or else the
// one that expired last, as a resolver serving a stale answer would.
// Returns 0 (out untouched) when v holds none.
HELPER_INLINE int vip_upstream_pick(const struct vip_upstream_val *v,
                                    __u64 now, __u32 rnd, __u8 *out) {
  __u32 n_live = 0, newest = VIP_UPSTREAM_SLOTS;
  __u64 newest_exp = 0;
  for (__u32 i = 0; i < VIP_UPSTREAM_SLOTS; i++) {
    __u64 exp = v->slot[i].expires_at;
    if (exp == 0)
      continue;
    if (exp > now)
      n_live++;
    if (exp > newest_exp) {
      newest = i;
      newest_exp = exp;
    }
  }
  if (newest == VIP_UPSTREAM_SLOTS)
    return 0;
  __u32 pick = newest;
  if (n_live > 0) {
    // The k-th unexpired slot (no variable index into a stack array: the
    // verifier rejects it).
    __u32 k = rnd % n_live;
    for (__u32 i = 0; i < VIP_UPSTREAM_SLOTS; i++) {
      if (v->slot[i].expires_at <= now)
        continue;
      if (k == 0) {
        pick = i;
        break;
      }
      k--;
    }
  }
  __builtin_memcpy(out, v->slot[pick & (VIP_UPSTREAM_SLOTS - 1)].ip, 16);
  return 1;
}

// Results of vip_socket_check.
#define VIP_SOCK_OK 0
#define VIP_SOCK_DENY_HOST 1 // the socket did not connect to the host's fake IP
#define VIP_SOCK_DENY_ADDR 2 // the socket's real address or port is not the allowed one

// vip_socket_check applies a secret's host, IP and port restrictions to the
// socket a record leaves on (at tcp_sendmsg): a host length of 0 or
// MAX_HOST_LEN and more, an IP length other than 16 and a port of 0 restrict
// nothing.
//   sock_host: the host of the fake IP the socket connected to (zero-padded,
//              as vip_ip_val.host), NULL when it connected to none;
//   daddr16:   the socket's real destination, IPv6 or IPv4-mapped;
//   dport:     the socket's destination port, host byte order.
HELPER_INLINE int vip_socket_check(const char *sock_host, __u32 host_len,
                                   const char *allowed_host, __u32 ip_len,
                                   const __u8 *allowed_ip, const __u8 *daddr16,
                                   __u16 port, __u16 dport) {
  if (host_len > 0 && host_len < MAX_HOST_LEN &&
      (!sock_host || !hosts_match(sock_host, allowed_host)))
    return VIP_SOCK_DENY_HOST;
  if (ip_len == 16 && __builtin_memcmp(daddr16, allowed_ip, 16) != 0)
    return VIP_SOCK_DENY_ADDR;
  if (port != 0 && dport != port)
    return VIP_SOCK_DENY_ADDR;
  return VIP_SOCK_OK;
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
// expanded key schedule `rk` ((nr+1)*16 bytes). nr in {10,14}. Operating in
// place keeps the BPF stack frame flat (no 16-byte temporaries).
HELPER_INLINE void aes_block_encrypt(const __u8 *rk, __u32 nr, __u8 state[16]) {
  for (int i = 0; i < 16; i++) state[i] ^= rk[i]; // AddRoundKey 0

  // Up to 13 mid rounds (AES-256 nr=14 → 13). Bounded by a constant so every
  // round key sits at a constant offset; `round >= nr` ends AES-128 early.
  for (__u32 round = 1; round < 14; round++) {
    if (round >= nr)
      break;
    for (int i = 0; i < 16; i++) state[i] = KLOAK_AES_SBOX[state[i]];
    aes_shift_rows(state);
    aes_mix_columns(state);
    const __u8 *k = rk + 16 * round;
    for (int i = 0; i < 16; i++) state[i] ^= k[i];
  }

  // Final round (SubBytes + ShiftRows + AddRoundKey, no MixColumns). The last
  // round key is picked from two constants rather than computed as rk + 16*nr:
  // nr can be a runtime value, and the verifier rejects a variable offset here.
  for (int i = 0; i < 16; i++) state[i] = KLOAK_AES_SBOX[state[i]];
  aes_shift_rows(state);
  const __u8 *k = nr == 14 ? rk + 16 * 14 : rk + 16 * 10;
  for (int i = 0; i < 16; i++) state[i] ^= k[i];
}

// aes_recover_h recomputes the GHASH subkey H = AES_encrypt(0) from a persisted
// AES round-key schedule, writing 16 bytes to h_out. Returns 1 on success, 0 if
// `rounds` is not a TLS AES round count (a guard against a bogus offset read).
// h_out doubles as the in-place AES state, so no scratch block is needed.
//
// Both key sizes share a single inlined aes_block_encrypt: inlining it once per
// key size doubled the AES code in bssl_recover_h (~480 eBPF instructions and
// ~100 bytes of stack). Only AES-128 (10) and AES-256 (14) are handled — TLS
// never negotiates AES-192-GCM, so 12 is intentionally treated as unsupported.
//
// x86 AES-NI stores AES_KEY.rounds as nr-1 (9 for AES-128, 13 for AES-256),
// so both the canonical and AES-NI values are accepted for each key size.
HELPER_INLINE int aes_recover_h(const __u8 *rd_key, __u32 rounds, __u8 h_out[16]) {
  for (int i = 0; i < 16; i++) h_out[i] = 0; // plaintext block = 0
  __u32 nr;
  if (rounds == 10 || rounds == 9)        // 9 = x86 AES-NI stores nr-1 for AES-128
    nr = 10;
  else if (rounds == 14 || rounds == 13)  // 13 = x86 AES-NI stores nr-1 for AES-256
    nr = 14;
  else
    return 0;
#ifdef __BPF__
  // Hide nr from clang, which otherwise splits the call back into one copy
  // per constant key size.
  asm volatile("" : "+r"(nr));
#endif
  aes_block_encrypt(rd_key, nr, h_out);
  return 1;
}

#endif // KLOAK_HELPERS_H
