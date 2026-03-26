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
typedef uint32_t __u32;
typedef uint64_t __u64;
#define HELPER_INLINE static inline
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

#endif // KLOAK_HELPERS_H
