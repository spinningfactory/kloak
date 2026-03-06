// go:build ignore

// tls_uprobe.c - eBPF uprobes for TLS interception in Go and OpenSSL apps.
// Uses a per-CPU array as scratch buffer (not ringbuf) to avoid verifier
// issues with ringbuf_mem pointer tracking in loops.
// Supports both x86_64 and ARM64 architectures.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Architecture detection
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__) || defined(__amd64__)
#define bpf_target_x86
#endif

#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
#define bpf_target_arm64
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Buffer size for reading TLS data. Must be a power of 2 for bitmask bounds.
// 256 keeps the phase 2 scan loop under the verifier's 8192-jump limit.
#define MAX_DATA_SIZE 256
// Fixed secret rewrite size
#define SECRET_MAX_LEN 128
// Max host length for matching (compared as 4 x uint64, no loop needed)
#define MAX_HOST_LEN 32

// BPF Map: shadow secret prefix -> real secret value
struct secret_key {
  char prefix[16];
};

struct secret_value {
  __u32 len;
  char real_secret[SECRET_MAX_LEN];
  __u32 host_len;                  // 0 = wildcard (allow all hosts)
  char allowed_host[MAX_HOST_LEN]; // e.g. "httpbin.org"
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct secret_key);
  __type(value, struct secret_value);
} secret_map SEC(".maps");

// Per-CPU array used as scratch space for reading and scanning data.
struct scratch_buf {
  __u64 user_data_ptr;
  __u32 read_len;
  __u32 host_offset;
  __u32 host_value_len; // length of extracted host value
  char host_value[MAX_HOST_LEN]; // extracted host bytes from HTTP header
  char data[MAX_DATA_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratch_buf);
} scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} prog_array SEC(".maps");

// Ringbuffer for lightweight events to userspace (metrics/logging only)
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} tls_events SEC(".maps");

// Lightweight event - no data payload, just metadata
struct tls_event {
  __u32 pid;
  __u32 tgid;
  __u32 len;
  __u8 is_rewritten; // 1 = secret was rewritten in-kernel
};

// -----------------------------------------------------------------------------
// Phase 1: Parse Host header and extract its value into scratch buffer.
// This runs inline in the uprobe entry points (before tail-calling phase 2).
// By extracting host bytes here, phase 2 can compare using fixed-size
// uint64 comparisons with zero loops, staying under verifier limits.
// -----------------------------------------------------------------------------
static __always_inline void parse_host(struct scratch_buf *scratch) {
  scratch->host_offset = 0;
  scratch->host_value_len = 0;
  __builtin_memset(scratch->host_value, 0, MAX_HOST_LEN);

  __u32 read_len = scratch->read_len;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  // Scan the first 256 bytes to find "Host: "
  __u32 host_start = 0;
  for (__u32 i = 0; i < 256; i++) {
    if (i + 6 > read_len)
      break;

    if (scratch->data[i] == 'H' && scratch->data[i + 1] == 'o' &&
        scratch->data[i + 2] == 's' && scratch->data[i + 3] == 't' &&
        scratch->data[i + 4] == ':' && scratch->data[i + 5] == ' ') {
      host_start = i + 6;
      scratch->host_offset = host_start;
      break;
    }
  }

  if (host_start == 0)
    return;

  // Extract host value bytes into scratch->host_value (up to MAX_HOST_LEN)
  // Stop at \r, \n, or : (end of host value)
  __u32 host_len = 0;
  for (__u32 j = 0; j < MAX_HOST_LEN; j++) {
    __u32 idx = host_start + j;
    if (idx >= read_len)
      break;
    char c = scratch->data[idx];
    if (c == '\r' || c == '\n' || c == ':')
      break;
    scratch->host_value[j] = c;
    host_len++;
  }
  scratch->host_value_len = host_len;
}

// -----------------------------------------------------------------------------
// Phase 2: Scan for "kloak:" secrets and rewrite.
// Host comparison uses fixed-size uint64 comparisons (no loops).
// -----------------------------------------------------------------------------
SEC("uprobe/phase2_rewrite")
int bpf_phase2_rewrite(struct pt_regs *ctx) {
  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 0;

  __u32 read_len = scratch_data->read_len;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  int rewritten = 0;

  for (__u32 i = 0; i < MAX_DATA_SIZE; i++) {
    if (i + 16 > read_len)
      break;

    if (scratch_data->data[i] != 'k')
      continue;

    // Check for "kloak:"
    if (scratch_data->data[i + 1] == 'l' && scratch_data->data[i + 2] == 'o' &&
        scratch_data->data[i + 3] == 'a' && scratch_data->data[i + 4] == 'k' &&
        scratch_data->data[i + 5] == ':') {

      struct secret_key key = {};
      __builtin_memcpy(key.prefix, &scratch_data->data[i], 16);

      struct secret_value *val = bpf_map_lookup_elem(&secret_map, &key);
      if (val && val->len > 0 && val->len <= SECRET_MAX_LEN) {

        // Host-based filtering: compare pre-extracted host against allowed_host
        // using fixed-size uint64 comparisons (no loop, no verifier complexity)
        if (val->host_len > 0 && val->host_len < MAX_HOST_LEN) {
          if (scratch_data->host_value_len == 0)
            continue;

          // Compare as 4 x uint64 (covers all 32 bytes)
          __u64 *host_a = (__u64 *)scratch_data->host_value;
          __u64 *host_b = (__u64 *)val->allowed_host;
          if (host_a[0] != host_b[0] || host_a[1] != host_b[1] ||
              host_a[2] != host_b[2] || host_a[3] != host_b[3])
            continue;
        }

        // Rewrite: bounds-check i for the verifier
        __u32 safe_i = i & (MAX_DATA_SIZE - 1);
        char *target = (char *)scratch_data->user_data_ptr + safe_i;

        __u32 write_len = val->len;
        write_len &= (SECRET_MAX_LEN - 1);

        if (write_len == 0)
          continue;

        bpf_probe_write_user(target, val->real_secret, write_len);
        rewritten = 1;
      }
    }
  }

  bpf_printk("kloak phase2: rewritten=%d", rewritten);

  if (rewritten) {
    struct tls_event *event =
        bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (event) {
      event->pid = bpf_get_current_pid_tgid();
      event->tgid = bpf_get_current_pid_tgid() >> 32;
      event->len = read_len;
      event->is_rewritten = 1;
      bpf_ringbuf_submit(event, 0);
    }
  }

  return 0;
}

// -----------------------------------------------------------------------------
// Go crypto/tls.(*Conn).Write uprobe
//
// Go register ABI (1.17+):
//   x86_64: RAX=receiver, RBX=data, RCX=len  (pt_regs offsets: bx=40, cx=88)
//   ARM64:  R0=receiver,  R1=data,  R2=len    (pt_regs: regs[1], regs[2])
// -----------------------------------------------------------------------------

SEC("uprobe/go_tls_write")
int bpf_uprobe_go_tls_write(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid();

  void *data_ptr;
  __u64 data_len;

#if defined(bpf_target_x86)
  // x86_64 Go register ABI: RAX=receiver, RBX=data, RCX=len
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 40);
  bpf_probe_read_kernel(&data_len, sizeof(__u64), (char *)ctx + 88);
#elif defined(bpf_target_arm64)
  // ARM64 Go register ABI: R0=receiver, R1=data, R2=len
  data_ptr = (void *)PT_REGS_PARM2(ctx);
  data_len = PT_REGS_PARM3(ctx);
#else
  return 0;
#endif

  bpf_printk("kloak go_tls: ptr=%llx len=%llu pid=%d", (__u64)data_ptr,
             data_len, pid);

  if (!data_ptr || data_len == 0)
    return 0;

  // Get scratch buffer from per-CPU array
  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 0;

  __u32 read_len = data_len;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  // Read plaintext into scratch buffer (per-CPU array, not ringbuf)
  long ret = bpf_probe_read_user(scratch_data->data, read_len, data_ptr);
  bpf_printk("kloak go_tls: read_user ret=%ld read_len=%u first4=%.4s", ret,
             read_len, scratch_data->data);

  scratch_data->user_data_ptr = (__u64)data_ptr;
  scratch_data->read_len = read_len;

  parse_host(scratch_data);

  // Jump to Phase 2
  bpf_tail_call(ctx, &prog_array, 0);

  return 0;
}

// -----------------------------------------------------------------------------
// OpenSSL/BoringSSL SSL_write uprobe
//
// C calling convention:  SSL_write(SSL *ssl, const void *buf, int num)
//   x86_64: RDI=ssl, RSI=buf, RDX=num  (pt_regs offsets: si=104, dx=96)
//   ARM64:  X0=ssl,  X1=buf,  X2=num   (pt_regs: regs[1], regs[2])
// -----------------------------------------------------------------------------

SEC("uprobe/ssl_write")
int bpf_uprobe_ssl_write(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid();

  void *data_ptr;
  int num;

#if defined(bpf_target_x86)
  // x86_64 C ABI: RDI=ssl, RSI=buf, RDX=num
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 104);
  bpf_probe_read_kernel(&num, sizeof(int), (char *)ctx + 96);
#elif defined(bpf_target_arm64)
  // ARM64 C ABI: X0=ssl, X1=buf, X2=num
  data_ptr = (void *)PT_REGS_PARM2(ctx);
  num = (int)PT_REGS_PARM3(ctx);
#else
  return 0;
#endif

  bpf_printk("kloak ssl: ptr=%llx num=%d pid=%d", (__u64)data_ptr, num, pid);

  if (!data_ptr || num <= 0)
    return 0;

  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 0;

  __u32 read_len = num;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  long ret = bpf_probe_read_user(scratch_data->data, read_len, data_ptr);
  bpf_printk("kloak ssl: read_user ret=%ld len=%u first4=%.4s", ret, read_len,
             scratch_data->data);

  scratch_data->user_data_ptr = (__u64)data_ptr;
  scratch_data->read_len = read_len;

  parse_host(scratch_data);

  // Jump to Phase 2
  bpf_tail_call(ctx, &prog_array, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
