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

// Reduced buffer size to keep verifier happy (512 iterations max)
#define MAX_DATA_SIZE 512
// Fixed secret rewrite size - must be a compile-time constant for
// bpf_probe_write_user
#define SECRET_MAX_LEN 128

// BPF Map: shadow secret prefix -> real secret value
struct secret_key {
  char prefix[16];
};

struct secret_value {
  __u32 len;
  char real_secret[SECRET_MAX_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct secret_key);
  __type(value, struct secret_value);
} secret_map SEC(".maps");

// Per-CPU array used as scratch space for reading and scanning data.
// This avoids scanning ringbuf memory, which causes verifier issues.
struct scratch_buf {
  char data[MAX_DATA_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratch_buf);
} scratch SEC(".maps");

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
// Shared rewrite logic: scan scratch buffer for "kloak:" prefix, look up
// secret_map, and rewrite the original userspace buffer in-place.
// Returns 1 if any secret was rewritten, 0 otherwise.
// -----------------------------------------------------------------------------
static __always_inline int scan_and_rewrite(char *buf, __u32 read_len,
                                            void *user_data_ptr) {
  int rewritten = 0;

  for (__u32 i = 0; i < MAX_DATA_SIZE; i++) {
    // Bounds check: need at least 16 bytes from position i
    if (i + 16 > read_len)
      break;

    // Quick check for 'k' before doing full comparison
    if (buf[i] != 'k')
      continue;

    // Check for "kloak:" prefix
    if (buf[i + 1] != 'l' || buf[i + 2] != 'o' || buf[i + 3] != 'a' ||
        buf[i + 4] != 'k' || buf[i + 5] != ':')
      continue;

    // Found "kloak:" - extract 16-byte key for map lookup
    struct secret_key key = {};
    // Use bounded copy from the scratch buffer
    __builtin_memcpy(key.prefix, &buf[i], 16);

    struct secret_value *val = bpf_map_lookup_elem(&secret_map, &key);
    if (val && val->len > 0 && val->len <= SECRET_MAX_LEN) {
      // Write exactly val->len bytes of the real secret. The verifier
      // accepts variable size here because val->len is bounded above
      // by SECRET_MAX_LEN and the source buffer real_secret is that size.
      char *target = (char *)user_data_ptr + i;
      bpf_probe_write_user(target, val->real_secret, val->len);
      rewritten = 1;
    }
  }
  return rewritten;
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
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;

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

  // Scan and rewrite in-kernel
  int rewritten = scan_and_rewrite(scratch_data->data, read_len, data_ptr);

  bpf_printk("kloak go_tls: rewritten=%d", rewritten);

  // Send lightweight event to userspace
  struct tls_event *event =
      bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
  if (event) {
    event->pid = pid;
    event->tgid = tgid;
    event->len = read_len;
    event->is_rewritten = rewritten ? 1 : 0;
    bpf_ringbuf_submit(event, 0);
  }

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
  __u32 tgid = bpf_get_current_pid_tgid() >> 32;

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

  int rewritten = scan_and_rewrite(scratch_data->data, read_len, data_ptr);

  struct tls_event *event =
      bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
  if (event) {
    event->pid = pid;
    event->tgid = tgid;
    event->len = read_len;
    event->is_rewritten = rewritten ? 1 : 0;
    bpf_ringbuf_submit(event, 0);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
