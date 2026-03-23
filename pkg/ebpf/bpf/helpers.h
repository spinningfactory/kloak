// helpers.h — Pure logic extracted from tls_uprobe.c for dual-target compilation.
// Compiles as __always_inline eBPF when __BPF__ is defined (clang -target bpf),
// and as regular userspace C otherwise (for unit testing with gcc/clang).

#ifndef KLOAK_HELPERS_H
#define KLOAK_HELPERS_H

#ifdef __BPF__
#define HELPER_INLINE static __always_inline
// After a guard like "if (offset >= DNS_MAX_LEN) return 0", the compiler
// proves offset < DNS_MAX_LEN and ELIMINATES "offset & (DNS_MAX_LEN-1)" as a
// no-op. The BPF verifier then sees an unbounded register in pointer arithmetic.
// This barrier breaks the compiler's value-range reasoning across the fence,
// forcing the AND instruction to be emitted for the verifier.
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var) : :)
#endif
#else
#include <stdint.h>
#include <string.h>
typedef uint8_t  __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#define HELPER_INLINE static inline
#ifndef barrier_var
#define barrier_var(var) ((void)(var))
#endif
#ifndef MAX_HOST_LEN
#define MAX_HOST_LEN 32
#endif
#ifndef SECRET_MAX_LEN
#define SECRET_MAX_LEN 128
#endif
#ifndef MAX_DATA_SIZE
#define MAX_DATA_SIZE 256
#endif
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

// Compare two host buffers (each MAX_HOST_LEN = 32 bytes) as 4x uint64.
// Returns 1 if all 32 bytes match, 0 otherwise.
HELPER_INLINE int hosts_match(const char *a, const char *b) {
  __u64 a0, a1, a2, a3, b0, b1, b2, b3;
  __builtin_memcpy(&a0, a, 8);
  __builtin_memcpy(&a1, a + 8, 8);
  __builtin_memcpy(&a2, a + 16, 8);
  __builtin_memcpy(&a3, a + 24, 8);
  __builtin_memcpy(&b0, b, 8);
  __builtin_memcpy(&b1, b + 8, 8);
  __builtin_memcpy(&b2, b + 16, 8);
  __builtin_memcpy(&b3, b + 24, 8);
  return (a0 == b0 && a1 == b1 && a2 == b2 && a3 == b3) ? 1 : 0;
}

// Clamp a secret value length to [1, SECRET_MAX_LEN] using bitwise arithmetic.
// For val_len in [1, SECRET_MAX_LEN], returns val_len unchanged.
// val_len == 0 returns SECRET_MAX_LEN (unsigned underflow wraps).
// val_len > SECRET_MAX_LEN wraps modulo SECRET_MAX_LEN.
HELPER_INLINE __u32 clamp_write_len(__u32 val_len) {
  return ((val_len - 1) & (SECRET_MAX_LEN - 1)) + 1;
}

// Check if buffer starts with the 6-byte "kloak:" prefix.
// Returns 1 if it matches, 0 otherwise. Caller must ensure buf has >= 6 bytes.
HELPER_INLINE int is_kloak_prefix(const char *buf) {
  return (buf[0] == 'k' && buf[1] == 'l' && buf[2] == 'o' && buf[3] == 'a' &&
          buf[4] == 'k' && buf[5] == ':')
             ? 1
             : 0;
}

// ============================================================================
// DNS packet parsing helpers — pure C, dual-target (eBPF + userspace tests)
// ============================================================================

#define DNS_MAX_LEN     512  // max UDP DNS packet size
#define DNS_HEADER_LEN  12   // fixed DNS header size
#define DNS_MAX_ANSWERS 8    // max answer RRs we process per packet
#define DNS_TYPE_A      1    // IPv4 address record
#define DNS_TYPE_AAAA   28   // IPv6 address record
#define DNS_TTL_CAP     300  // max TTL stored (seconds)

// Convert a 4-byte big-endian IPv4 address into a 16-byte IPv4-mapped IPv6
// address (::ffff:a.b.c.d). ip_out must point to a 16-byte buffer.
HELPER_INLINE void ipv4_to_mapped(__u8 *ip_out, const __u8 *v4) {
  ip_out[0]  = 0; ip_out[1]  = 0; ip_out[2]  = 0; ip_out[3]  = 0;
  ip_out[4]  = 0; ip_out[5]  = 0; ip_out[6]  = 0; ip_out[7]  = 0;
  ip_out[8]  = 0; ip_out[9]  = 0;
  ip_out[10] = 0xff; ip_out[11] = 0xff;
  ip_out[12] = v4[0]; ip_out[13] = v4[1];
  ip_out[14] = v4[2]; ip_out[15] = v4[3];
}

// Skip a DNS name (label sequence or compressed pointer) in a DNS packet.
// Handles:
//   - Label sequence: each label = (length_byte + label_bytes), ends at 0x00
//   - Compressed pointer: high 2 bits = 0xC0 → pointer, advance by 2 bytes
// Returns the new byte offset immediately after the name, or 0 on any
// bounds error. The caller must not dereference pkt[offset] after this
// function unless it verifies the return value is non-zero.
// pkt_len must not exceed DNS_MAX_LEN.
HELPER_INLINE __u32 dns_skip_name(const char *pkt, __u32 pkt_len,
                                   __u32 offset) {
  // Fixed bound: a valid DNS name has at most 127 labels of 1 byte each,
  // but we cap at 8 to stay within BPF verifier complexity budget.
  for (__u32 i = 0; i < 8; i++) {
    if (offset >= pkt_len || offset >= DNS_MAX_LEN)
      return 0; // out of bounds
    // barrier_var prevents the compiler from eliminating the AND mask below.
    // Without it, after the guard proves offset < DNS_MAX_LEN, the compiler
    // optimizes away "offset & (DNS_MAX_LEN-1)" as a no-op, and the BPF
    // verifier then sees an unbounded pointer arithmetic operation.
    barrier_var(offset);
    __u8 b = (__u8)pkt[offset & (DNS_MAX_LEN - 1)];
    if (b == 0)
      return offset + 1; // null terminator: name ends here
    if ((b & 0xC0) == 0xC0)
      return offset + 2; // compressed pointer: 2-byte total
    if ((b & 0xC0) != 0)
      return 0; // reserved bits set: malformed packet
    // Plain label: skip length byte + label_len bytes
    __u32 next = offset + 1 + (__u32)b;
    if (next > pkt_len || next > DNS_MAX_LEN)
      return 0; // label extends beyond packet
    offset = next;
  }
  return 0; // exceeded max labels without finding terminator
}

// Decode a DNS question-section QNAME (no compression) into dotted notation,
// e.g. \x03api\x06stripe\x03com\x00 → "api.stripe.com".
// Reads from pkt[offset] and writes into host_out[0..host_max-1].
// Returns the number of bytes written (not counting any null terminator),
// or 0 if the name could not be decoded. host_out is NOT null-terminated
// by this function (caller zeroes the buffer before calling).
//
// Implementation note: uses a FLAT single loop (not nested) to avoid BPF
// verifier state explosion. Nested loops (8 outer × 63 inner = 504 iterations)
// each produce unique concrete register states that defeat the verifier's state
// pruning, hitting the 1M-instruction limit. A single loop of MAX_HOST_LEN+8
// iterations produces at most 40 states and stays well within the budget.
HELPER_INLINE __u32 dns_decode_qname(const char *pkt, __u32 pkt_len,
                                      __u32 offset, char *host_out,
                                      __u32 host_max) {
  __u32 host_len = 0;
  __u32 label_rem = 0; // bytes remaining in the current label
  __u8  after_first = 0; // have we emitted at least one label yet?

  // Flat loop: reads at most MAX_HOST_LEN content bytes + 8 label-length bytes.
  for (__u32 i = 0; i < MAX_HOST_LEN + 8; i++) {
    if (offset >= pkt_len || offset >= DNS_MAX_LEN)
      break;
    // barrier_var prevents the compiler from eliminating the AND mask below.
    // After the guard above, the compiler proves offset < DNS_MAX_LEN and would
    // eliminate "offset & (DNS_MAX_LEN-1)" as a no-op, leaving the BPF verifier
    // with an unbounded pointer arithmetic operation.
    barrier_var(offset);
    __u8 c = (__u8)pkt[offset & (DNS_MAX_LEN - 1)];
    offset++;

    if (label_rem == 0) {
      if (c == 0)
        break;               // null terminator: name complete
      if ((c & 0xC0) != 0)
        break;               // compression pointer or reserved bits: stop
      if (c > 63)
        break;               // invalid label length per RFC 1035
      label_rem = (__u32)c;
      // Insert '.' separator between labels (not before the first one)
      if (after_first && host_len < host_max)
        host_out[host_len++] = '.';
      after_first = 1;
    } else {
      // Content byte: copy to output if space remains
      label_rem--;
      if (host_len < host_max)
        host_out[host_len++] = c;
    }
  }
  return host_len;
}

#endif // KLOAK_HELPERS_H
