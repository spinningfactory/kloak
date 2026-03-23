// go:build ignore

// tls_uprobe.c - eBPF uprobes for TLS interception in Go and OpenSSL apps.
// Uses a per-CPU array as scratch buffer (not ringbuf) to avoid verifier
// issues with ringbuf_mem pointer tracking in loops.
// Supports both x86_64 and ARM64 architectures.
// Host filtering uses TLS SNI (protocol-agnostic) with HTTP Host fallback.

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

/* Define KLOAK_DEBUG at compile time to enable verbose bpf_printk tracing.
 * Example: add -DKLOAK_DEBUG to the bpf2go cflags in uprobe.go.
 * Do NOT enable in production: bpf_printk writes to trace_pipe on every
 * TLS write call and adds significant overhead. */

// Buffer size for reading TLS data per chunk. Must be a power of 2 for bitmask.
// Phase 2 uses bpf_loop() to scan the full TLS buffer in 256-byte chunks.
// Requires kernel 5.17+ for bpf_loop().
#define MAX_DATA_SIZE 256
// Fixed secret rewrite size
#define SECRET_MAX_LEN 128
// BPF map key length — short key for lookup (kloak: + 2 UUID chars)
#define SECRET_KEY_LEN 8
// Max prefix bytes stored in secret_value (for future verification use)
#define SECRET_PREFIX_MAX 42
// Chunk stride for bpf_loop scanning: overlap of SECRET_KEY_LEN-1 bytes
// ensures tokens straddling chunk boundaries are always detected.
#define CHUNK_STRIDE (MAX_DATA_SIZE - (SECRET_KEY_LEN - 1)) // 249
// Max host length for matching (compared as 4 x uint64, no loop needed)
#define MAX_HOST_LEN 32
// Max hostname to read from SNI
#define MAX_SNI_LEN 64
// OpenSSL SSL_ctrl cmd value for SSL_set_tlsext_host_name macro
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55

#include "helpers.h"

// BPF Map: shadow secret prefix -> real secret value
struct secret_key {
  char prefix[SECRET_KEY_LEN];
};

struct secret_value {
  __u32 len;
  char real_secret[SECRET_MAX_LEN];
  __u32 host_len;                        // 0 = wildcard (allow all hosts)
  char allowed_host[MAX_HOST_LEN];       // e.g. "httpbin.org"
  __u32 prefix_len;                      // actual prefix length (8..42)
  char full_prefix[SECRET_PREFIX_MAX];   // full kloak:UUID prefix for verification
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct secret_key);
  __type(value, struct secret_value);
} secret_map SEC(".maps");

// -----------------------------------------------------------------------------
// SNI hostname cache: {tgid, ssl_ptr} → hostname
// Populated by SSL_set_tlsext_host_name uprobe (runs once per connection).
// Looked up by SSL_write uprobe to get the destination hostname.
// Uses LRU to auto-evict stale entries when connections close.
// -----------------------------------------------------------------------------
struct conn_key {
  __u64 ssl_ptr; // pointer to SSL object (unique per connection)
  __u32 tgid;
  __u32 _pad;    // explicit padding — BPF hashes the full key including padding
};

struct conn_host {
  __u32 host_len;
  char hostname[MAX_HOST_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct conn_key);
  __type(value, struct conn_host);
} conn_hosts SEC(".maps");

// Per-CPU array used as scratch space for reading and scanning data.
struct scratch_buf {
  __u64 user_data_ptr;
  __u32 read_len;       // bytes read into data[] (max 256, for host parsing)
  __u32 total_data_len; // full TLS write length (for bpf_loop scanning)
  __u32 host_offset;
  __u32 host_value_len; // length of extracted host value
  char host_value[MAX_HOST_LEN]; // host from SNI cache or HTTP header
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
// SNI hostname extraction uprobe.
// Hooks SSL_set_tlsext_host_name(SSL *ssl, const char *name).
// Called once per connection before SSL_connect/handshake.
// Caches {tgid, ssl_ptr} → hostname for later lookup in SSL_write.
// Works for OpenSSL, BoringSSL, and any compatible TLS library.
// -----------------------------------------------------------------------------
SEC("uprobe/ssl_set_host")
int bpf_uprobe_ssl_set_host(void *ctx) {
  void *ssl_ptr;
  void *name_ptr;

#if defined(bpf_target_x86)
  // x86_64 C ABI: RDI=ssl, RSI=name
  // pt_regs offsets: rdi=112, rsi=104
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 112);
  bpf_probe_read_kernel(&name_ptr, sizeof(void *), (char *)ctx + 104);
#elif defined(bpf_target_arm64)
  // ARM64 C ABI: X0=ssl, X1=name
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 0);
  bpf_probe_read_kernel(&name_ptr, sizeof(void *), (char *)ctx + 8);
#else
  return 0;
#endif

  if (!ssl_ptr || !name_ptr)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  // Read the hostname string from user space
  char sni_buf[MAX_SNI_LEN] = {};
  long ret = bpf_probe_read_user_str(sni_buf, sizeof(sni_buf), name_ptr);
  if (ret <= 1) // empty or error
    return 0;

  // Store in conn_hosts map — memset key to zero padding bytes
  struct conn_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.tgid = tgid;
  key.ssl_ptr = (__u64)ssl_ptr;

  struct conn_host host = {};
  // Copy up to MAX_HOST_LEN bytes
  __u32 copy_len = ret - 1; // ret includes null terminator
  if (copy_len > MAX_HOST_LEN)
    copy_len = MAX_HOST_LEN;
  __builtin_memcpy(host.hostname, sni_buf, MAX_HOST_LEN);
  host.host_len = copy_len;

  bpf_map_update_elem(&conn_hosts, &key, &host, BPF_ANY);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak sni: tgid=%u ssl=%llx host=%s", tgid, (__u64)ssl_ptr,
             sni_buf);
#endif

  return 0;
}

// -----------------------------------------------------------------------------
// OpenSSL SSL_ctrl uprobe — catches SNI via the macro expansion.
//
// In OpenSSL, SSL_set_tlsext_host_name(ssl, name) is a macro that expands to:
//   SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, name)
//
// SSL_ctrl signature: long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
//   x86_64: RDI=ssl, RSI=cmd, RDX=larg, RCX=parg
//   ARM64:  X0=ssl,  X1=cmd,  X2=larg,  X3=parg
//
// BoringSSL exports SSL_set_tlsext_host_name as a real function, so it's
// handled by bpf_uprobe_ssl_set_host above. This uprobe covers OpenSSL only.
// -----------------------------------------------------------------------------
SEC("uprobe/ssl_ctrl")
int bpf_uprobe_ssl_ctrl(void *ctx) {
  void *ssl_ptr;
  int cmd;
  void *parg;

#if defined(bpf_target_x86)
  // x86_64 C ABI: RDI=ssl, RSI=cmd, RDX=larg, RCX=parg
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 112);
  bpf_probe_read_kernel(&cmd, sizeof(int), (char *)ctx + 104);
  bpf_probe_read_kernel(&parg, sizeof(void *), (char *)ctx + 88);
#elif defined(bpf_target_arm64)
  // ARM64 C ABI: X0=ssl, X1=cmd, X2=larg, X3=parg
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 0);
  bpf_probe_read_kernel(&cmd, sizeof(int), (char *)ctx + 8);
  bpf_probe_read_kernel(&parg, sizeof(void *), (char *)ctx + 24);
#else
  return 0;
#endif

  // Only handle SSL_CTRL_SET_TLSEXT_HOSTNAME (55)
  if (cmd != SSL_CTRL_SET_TLSEXT_HOSTNAME)
    return 0;

  if (!ssl_ptr || !parg)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  char sni_buf[MAX_SNI_LEN] = {};
  long ret = bpf_probe_read_user_str(sni_buf, sizeof(sni_buf), parg);
  if (ret <= 1)
    return 0;

  struct conn_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.tgid = tgid;
  key.ssl_ptr = (__u64)ssl_ptr;

  struct conn_host host = {};
  __u32 copy_len = ret - 1;
  if (copy_len > MAX_HOST_LEN)
    copy_len = MAX_HOST_LEN;
  __builtin_memcpy(host.hostname, sni_buf, MAX_HOST_LEN);
  host.host_len = copy_len;

  bpf_map_update_elem(&conn_hosts, &key, &host, BPF_ANY);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak ssl_ctrl sni: tgid=%u ssl=%llx host=%s", tgid,
             (__u64)ssl_ptr, sni_buf);
#endif

  return 0;
}

// -----------------------------------------------------------------------------
// Resolve host for the current SSL connection.
// First tries SNI cache (works for all protocols).
// Falls back to HTTP Host header parsing (for Go and connections without SNI).
// -----------------------------------------------------------------------------
static __always_inline void resolve_host(struct scratch_buf *scratch,
                                         __u64 ssl_ptr) {
  scratch->host_offset = 0;
  scratch->host_value_len = 0;
  __builtin_memset(scratch->host_value, 0, MAX_HOST_LEN);

  // Try SNI cache first (protocol-agnostic)
  if (ssl_ptr != 0) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    struct conn_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.tgid = tgid;
    key.ssl_ptr = ssl_ptr;

    struct conn_host *cached = bpf_map_lookup_elem(&conn_hosts, &key);
    if (cached && cached->host_len > 0) {
      __builtin_memcpy(scratch->host_value, cached->hostname, MAX_HOST_LEN);
      scratch->host_value_len = cached->host_len;
      return;
    }
  }

  // Fallback: parse HTTP "Host: " header from the plaintext data.
  // This handles Go connections (which don't call SSL_set_tlsext_host_name)
  // and any connection where SNI wasn't captured.
  scratch->host_value_len = parse_http_host(scratch->data, scratch->read_len,
                                            scratch->host_value, MAX_HOST_LEN);
}

// -----------------------------------------------------------------------------
// Phase 2: Scan full TLS buffer for "kloak:" secrets and rewrite.
// Uses bpf_loop() to iterate over 256-byte chunks with 41-byte overlap,
// covering up to 16KB per TLS record (max ~77 chunks).
// Host comparison uses fixed-size uint64 comparisons (no loops).
// -----------------------------------------------------------------------------

// Context passed to each bpf_loop callback invocation.
struct scan_ctx {
  __u64 user_data_ptr;
  __u32 total_len;
  __u32 host_value_len;
  char host_value[MAX_HOST_LEN];
  int rewritten;
};

// bpf_loop callback: read one 256-byte chunk into the per-CPU scratch buffer
// and scan for kloak: tokens. Uses scratch->data instead of a stack-allocated
// buffer to stay well within the 512-byte BPF stack limit.
static int scan_chunk(__u32 chunk_idx, void *ctx) {
  struct scan_ctx *sctx = (struct scan_ctx *)ctx;

  __u32 offset = chunk_idx * CHUNK_STRIDE;
  if (offset >= sctx->total_len)
    return 1; // stop iteration

  // Re-lookup per-CPU scratch buffer (verifier requires map lookup per frame)
  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 1;

  __u32 read_len = sctx->total_len - offset;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  bpf_probe_read_user(scratch_data->data, read_len,
                      (void *)(sctx->user_data_ptr + offset));

  for (__u32 i = 0; i < MAX_DATA_SIZE; i++) {
    if (i + SECRET_KEY_LEN > read_len)
      break;

    if (!is_kloak_prefix(&scratch_data->data[i]))
      continue;

    // 8-byte key lookup (kloak: + 2 UUID chars).
    // Collision detection is done on the Go side at sync time.
    struct secret_key key = {};
    __builtin_memcpy(key.prefix, &scratch_data->data[i], SECRET_KEY_LEN);

    struct secret_value *val = bpf_map_lookup_elem(&secret_map, &key);
    if (!val || val->len == 0 || val->len > SECRET_MAX_LEN)
      continue;

    // Host-based filtering: compare resolved host against allowed_host
    if (val->host_len > 0 && val->host_len < MAX_HOST_LEN) {
      if (sctx->host_value_len == 0)
        continue;

      if (!hosts_match(sctx->host_value, val->allowed_host))
        continue;
    }

    // Rewrite directly to user memory
    __u32 safe_i = i & (MAX_DATA_SIZE - 1);
    char *target = (char *)(sctx->user_data_ptr + offset + safe_i);

    // Bound write_len to [1, 128] using pure arithmetic so the verifier
    // can prove the range without relying on tracked register state
    // (which gets lost across the host comparison in bpf_loop callbacks).
    // val->len is already checked > 0 and <= SECRET_MAX_LEN above.
    __u32 write_len = clamp_write_len(val->len);

    bpf_probe_write_user(target, val->real_secret, write_len);
    sctx->rewritten = 1;
  }
  return 0;
}

SEC("uprobe/phase2_rewrite")
int bpf_phase2_rewrite(void *ctx) {
  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 0;

  struct scan_ctx sctx = {
    .user_data_ptr = scratch_data->user_data_ptr,
    .total_len = scratch_data->total_data_len,
    .host_value_len = scratch_data->host_value_len,
    .rewritten = 0,
  };
  __builtin_memcpy(sctx.host_value, scratch_data->host_value, MAX_HOST_LEN);

  __u32 num_chunks = (sctx.total_len + CHUNK_STRIDE - 1) / CHUNK_STRIDE;

  bpf_loop(num_chunks, scan_chunk, &sctx, 0);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak phase2: rewritten=%d total_len=%u chunks=%u",
             sctx.rewritten, sctx.total_len, num_chunks);
#endif

  if (sctx.rewritten) {
    struct tls_event *event =
        bpf_ringbuf_reserve(&tls_events, sizeof(struct tls_event), 0);
    if (event) {
      __u64 pid_tgid = bpf_get_current_pid_tgid();
      event->pid  = (__u32)(pid_tgid & 0xFFFFFFFF);
      event->tgid = (__u32)(pid_tgid >> 32);
      event->len = sctx.total_len;
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
//
// Go doesn't call SSL_set_tlsext_host_name, so SNI cache won't have an entry.
// Falls back to HTTP Host header parsing in resolve_host().
// -----------------------------------------------------------------------------

SEC("uprobe/go_tls_write")
int bpf_uprobe_go_tls_write(void *ctx) {
  void *data_ptr;
  __u64 data_len;

#if defined(bpf_target_x86)
  // x86_64 Go register ABI: RAX=receiver, RBX=data, RCX=len
  // pt_regs offsets: rbx=40, rcx=88
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 40);
  bpf_probe_read_kernel(&data_len, sizeof(__u64), (char *)ctx + 88);
#elif defined(bpf_target_arm64)
  // ARM64 Go register ABI: R0=receiver, R1=data, R2=len
  // user_pt_regs offsets: regs[1]=8, regs[2]=16
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 8);
  bpf_probe_read_kernel(&data_len, sizeof(__u64), (char *)ctx + 16);
#else
  return 0;
#endif

#ifdef KLOAK_DEBUG
  __u32 pid = bpf_get_current_pid_tgid();
  bpf_printk("kloak go_tls: ptr=%llx len=%llu pid=%d", (__u64)data_ptr,
             data_len, pid);
#endif

  if (!data_ptr || data_len == 0)
    return 0;

  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 0;

  __u32 read_len = data_len;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  long ret __attribute__((unused)) =
      bpf_probe_read_user(scratch_data->data, read_len, data_ptr);
#ifdef KLOAK_DEBUG
  bpf_printk("kloak go_tls: read_user ret=%ld read_len=%u first4=%.4s", ret,
             read_len, scratch_data->data);
#endif

  scratch_data->user_data_ptr = (__u64)data_ptr;
  scratch_data->read_len = read_len;
  scratch_data->total_data_len = (__u32)data_len;

  // Go doesn't use OpenSSL, no ssl_ptr for SNI lookup — pass 0.
  resolve_host(scratch_data, 0);

  // Jump to Phase 2
  bpf_tail_call(ctx, &prog_array, 0);

  return 0;
}

// -----------------------------------------------------------------------------
// OpenSSL/BoringSSL SSL_write uprobe
//
// C calling convention:  SSL_write(SSL *ssl, const void *buf, int num)
//   x86_64: RDI=ssl, RSI=buf, RDX=num  (pt_regs offsets: di=112, si=104, dx=96)
//   ARM64:  X0=ssl,  X1=buf,  X2=num   (pt_regs: regs[0]=0, regs[1]=8, regs[2]=16)
// -----------------------------------------------------------------------------

SEC("uprobe/ssl_write")
int bpf_uprobe_ssl_write(void *ctx) {
  void *ssl_ptr;
  void *data_ptr;
  int num;

#if defined(bpf_target_x86)
  // x86_64 C ABI: RDI=ssl, RSI=buf, RDX=num
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 112);
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 104);
  bpf_probe_read_kernel(&num, sizeof(int), (char *)ctx + 96);
#elif defined(bpf_target_arm64)
  // ARM64 C ABI: X0=ssl, X1=buf, X2=num
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 0);
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 8);
  bpf_probe_read_kernel(&num, sizeof(int), (char *)ctx + 16);
#else
  return 0;
#endif

#ifdef KLOAK_DEBUG
  __u32 pid = bpf_get_current_pid_tgid();
  bpf_printk("kloak ssl: ssl=%llx ptr=%llx num=%d pid=%d", (__u64)ssl_ptr,
             (__u64)data_ptr, num, pid);
#endif

  if (!data_ptr || num <= 0)
    return 0;

  __u32 zero = 0;
  struct scratch_buf *scratch_data = bpf_map_lookup_elem(&scratch, &zero);
  if (!scratch_data)
    return 0;

  __u32 read_len = num;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  long ret __attribute__((unused)) =
      bpf_probe_read_user(scratch_data->data, read_len, data_ptr);
#ifdef KLOAK_DEBUG
  bpf_printk("kloak ssl: read_user ret=%ld len=%u first4=%.4s", ret, read_len,
             scratch_data->data);
#endif

  scratch_data->user_data_ptr = (__u64)data_ptr;
  scratch_data->read_len = read_len;
  scratch_data->total_data_len = (__u32)num;

  // Look up SNI-cached hostname using the ssl pointer, fall back to HTTP Host
  resolve_host(scratch_data, (__u64)ssl_ptr);

  // Jump to Phase 2
  bpf_tail_call(ctx, &prog_array, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
