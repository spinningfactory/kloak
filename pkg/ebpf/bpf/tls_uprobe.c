// go:build ignore

// tls_uprobe.c - eBPF uprobes for TLS interception in Go and OpenSSL apps.
// Uses a per-CPU array as scratch buffer (not ringbuf) to avoid verifier
// issues with ringbuf_mem pointer tracking in loops.
// Supports both x86_64 and ARM64 architectures.
// Host filtering: DNS-verified IP → hostname (authoritative), with SNI cache
// and HTTP Host header as fallbacks.

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

// ============================================================================
// DNS interception — maps and programs for IP-verified host resolution
// ============================================================================

// tracked_tgids: set of process-group IDs being monitored.
// Tracepoints are node-wide; this map filters them to tracked containers only.
// Populated by Go when AttachTLS succeeds; max_entries >> typical pod count.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);    // tgid
  __type(value, __u8);   // 1 = tracked
} tracked_tgids SEC(".maps");

// dns_ip_map: DNS-verified mapping of {tgid, peer IP} → hostname.
// Populated by the recvfrom tracepoint when a DNS A/AAAA response is received.
// Key uses IPv4-mapped IPv6 for IPv4 addresses so that a single 16-byte field
// covers both address families uniformly.
struct dns_ip_key {
  __u32 tgid;
  __u32 _pad;     // explicit zero-padding for deterministic BPF key hashing
  __u8  ip[16];   // IPv4-mapped or native IPv6
};

struct dns_ip_val {
  char hostname[MAX_HOST_LEN];  // dotted hostname, e.g. "api.stripe.com"
  __u32 host_len;
  __u32 ttl_sec;        // DNS TTL capped at DNS_TTL_CAP
  __u64 inserted_kns;   // bpf_ktime_get_ns() at insertion (for Go-side TTL cleanup)
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct dns_ip_key);
  __type(value, struct dns_ip_val);
} dns_ip_map SEC(".maps");

// conn_ip_map: maps {tgid, fd} → peer IP recorded at connect() time.
// Populated by the connect tracepoint on successful TCP connection.
struct conn_ip_key {
  __u32 tgid;
  __u32 fd;
};

struct conn_ip_val {
  __u8 ip[16]; // IPv4-mapped or native IPv6
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct conn_ip_key);
  __type(value, struct conn_ip_val);
} conn_ip_map SEC(".maps");

// ssl_fd_map: maps {tgid, ssl_ptr} → fd.
// Populated by the SSL_set_fd uprobe so we can find the fd for an ssl_ptr.
// Enables: ssl_ptr → fd → peer IP → DNS hostname (full IP-verified chain).
struct ssl_fd_key {
  __u32 tgid;
  __u32 _pad;
  __u64 ssl_ptr;
};

struct ssl_fd_val {
  __u32 fd;
  __u32 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct ssl_fd_key);
  __type(value, struct ssl_fd_val);
} ssl_fd_map SEC(".maps");

// dns_pending: scratch storage for recvfrom enter→exit correlation.
// Keyed by {tgid, pid} (thread ID) so concurrent threads don't collide.
struct dns_pending_key {
  __u32 tgid;
  __u32 pid;
};

struct dns_pending_val {
  __u64 buf_ptr;   // userspace pointer to receive buffer
  __u64 addr_ptr;  // userspace pointer to src sockaddr (may be NULL)
  __u32 fd;
  __u32 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct dns_pending_key);
  __type(value, struct dns_pending_val);
} dns_pending SEC(".maps");

// connect_pending: scratch storage for connect enter→exit correlation.
struct connect_pending_key {
  __u32 tgid;
  __u32 pid;
};

struct connect_pending_val {
  __u32 fd;
  __u32 _pad;
  __u64 addr_ptr; // userspace pointer to struct sockaddr passed to connect()
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct connect_pending_key);
  __type(value, struct connect_pending_val);
} connect_pending SEC(".maps");

// handshake_pending: scratch storage for SSL_do_handshake → write() fd correlation.
// When SSL_do_handshake(ssl) is called, we store the ssl_ptr here keyed by {tgid, tid}.
// The next sys_enter_write on this thread captures the fd (OpenSSL's ClientHello write)
// and stores it in ssl_fd_map. One-shot: deleted after the first write.
struct handshake_pending_key {
  __u32 tgid;
  __u32 pid; // thread ID (what BPF calls pid)
};

struct handshake_pending_val {
  __u64 ssl_ptr;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct handshake_pending_key);
  __type(value, struct handshake_pending_val);
} handshake_pending SEC(".maps");

// dns_config: DNS server IPs to accept responses from.
// Array of up to 4 entries (supports multiple nameservers from resolv.conf).
// Written by Go on startup. All 16-byte entries use IPv4-mapped form for IPv4.
struct dns_config_val {
  __u8 ip[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 4);
  __type(key, __u32);
  __type(value, struct dns_config_val);
} dns_config SEC(".maps");

// dns_scratch: per-CPU buffer for reading and parsing DNS UDP packets.
// Avoids stack allocation of the 512-byte DNS packet buffer (BPF stack = 512B).
struct dns_scratch_buf {
  char pkt[DNS_MAX_LEN];         // raw DNS packet bytes
  char hostname[MAX_HOST_LEN];   // decoded question QNAME
  __u32 hostname_len;
  __u32 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct dns_scratch_buf);
} dns_scratch SEC(".maps");

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
// DNS helpers — used by tp_exit_recvfrom to parse DNS responses.
// These functions access BPF maps so they live here (not in helpers.h).
// -----------------------------------------------------------------------------

// Returns 1 if src_ip (16-byte IPv4-mapped or IPv6) matches any dns_config entry.
// Loop is fully unrolled with compile-time constant indices to satisfy the BPF
// verifier: a for-loop over a map lookup creates a back-edge that the verifier
// cannot prove terminates once the loop body updates abstract state.
static __always_inline int is_dns_server(__u8 *src_ip) {
  __u64 a0, a1;
  __builtin_memcpy(&a0, src_ip,     8);
  __builtin_memcpy(&a1, src_ip + 8, 8);

// Check one dns_config entry at compile-time constant index idx.
#define _CHECK_DNS_ENTRY(idx) do {                                  \
    __u32 _k = (idx);                                               \
    struct dns_config_val *_cfg = bpf_map_lookup_elem(&dns_config, &_k); \
    if (_cfg) {                                                     \
      __u64 b0, b1;                                                 \
      __builtin_memcpy(&b0, _cfg->ip,     8);                       \
      __builtin_memcpy(&b1, _cfg->ip + 8, 8);                       \
      if (a0 == b0 && a1 == b1) return 1;                           \
    }                                                               \
  } while (0)

  _CHECK_DNS_ENTRY(0);
  _CHECK_DNS_ENTRY(1);
  _CHECK_DNS_ENTRY(2);
  _CHECK_DNS_ENTRY(3);
#undef _CHECK_DNS_ENTRY

  return 0;
}

// Parse a DNS response packet and update dns_ip_map for each A/AAAA answer.
// scratch->pkt[0..pkt_len) must contain the raw DNS packet.
// scratch->hostname and scratch->hostname_len are filled with the question QNAME.
static __always_inline void process_dns_packet(struct dns_scratch_buf *scratch,
                                               __u32 pkt_len, __u32 tgid) {
  if (pkt_len < DNS_HEADER_LEN)
    return;

  const char *pkt = scratch->pkt;

  // Read ANCOUNT (answer RR count) from header bytes 6-7 (big-endian)
  __u16 ancount_be;
  __builtin_memcpy(&ancount_be, pkt + 6, 2);
  __u32 ancount = (__u32)__builtin_bswap16(ancount_be);
  if (ancount == 0)
    return;
  if (ancount > DNS_MAX_ANSWERS)
    ancount = DNS_MAX_ANSWERS;

  // Decode question QNAME into scratch->hostname (dotted notation).
  // Question section starts at offset 12.
  __builtin_memset(scratch->hostname, 0, MAX_HOST_LEN);
  scratch->hostname_len = dns_decode_qname(pkt, pkt_len, DNS_HEADER_LEN,
                                           scratch->hostname, MAX_HOST_LEN);
  if (scratch->hostname_len == 0)
    return;

  // Skip past question section to reach answer section.
  __u32 off = dns_skip_name(pkt, pkt_len, DNS_HEADER_LEN);
  if (off == 0 || off + 4 > pkt_len)
    return;
  off += 4; // skip QTYPE (2) + QCLASS (2)

  // Parse answer RRs
  for (__u32 i = 0; i < DNS_MAX_ANSWERS; i++) {
    if (i >= ancount)
      break;
    if (off >= pkt_len)
      break;

    // Skip answer NAME (usually a compressed pointer 0xC0xx, 2 bytes)
    __u32 name_end = dns_skip_name(pkt, pkt_len, off);
    // Require name_end + 10 fits in both pkt_len and DNS_MAX_LEN so the
    // BPF verifier can prove all subsequent pkt[off..off+9] accesses are
    // within the dns_scratch_buf.pkt[DNS_MAX_LEN] buffer.
    if (name_end == 0 || name_end + 10 > pkt_len || name_end + 10 > DNS_MAX_LEN)
      break;
    off = name_end;

    // Read TYPE (2), CLASS (2), TTL (4), RDLENGTH (2).
    // Mask off with (DNS_MAX_LEN-1) at each access so the BPF verifier sees a
    // concrete [0, 511] bound on the pointer offset — the u32 zero-extension
    // shift pair (<<32 >>32) otherwise widens the verifier's range back to
    // [0, 0xffffffff] even after the name_end + 10 > DNS_MAX_LEN guard above.
    __u16 rtype_be, rdlen_be;
    __u32 ttl_be;
    __builtin_memcpy(&rtype_be, pkt + (off & (DNS_MAX_LEN - 1)),     2);
    __builtin_memcpy(&ttl_be,   pkt + (off & (DNS_MAX_LEN - 1)) + 4, 4);
    __builtin_memcpy(&rdlen_be, pkt + (off & (DNS_MAX_LEN - 1)) + 8, 2);
    __u32 rtype = (__u32)__builtin_bswap16(rtype_be);
    __u32 ttl   = __builtin_bswap32(ttl_be);
    __u32 rdlen = (__u32)__builtin_bswap16(rdlen_be);
    off += 10;

    if (off + rdlen > pkt_len || off + rdlen > DNS_MAX_LEN)
      break;

    if (rtype == DNS_TYPE_A && rdlen == 4) {
      // IPv4 answer: store as IPv4-mapped IPv6.
      // Guard ensures off + 4 <= DNS_MAX_LEN so pkt + off is in-bounds.
      if (off + 4 > DNS_MAX_LEN)
        break;
      struct dns_ip_key key;
      __builtin_memset(&key, 0, sizeof(key));
      key.tgid = tgid;
      // Mask ensures the verifier tracks a concrete [0,511] pointer offset.
      ipv4_to_mapped(key.ip, (__u8 *)(pkt + (off & (DNS_MAX_LEN - 1))));

      struct dns_ip_val val = {};
      __builtin_memcpy(val.hostname, scratch->hostname, MAX_HOST_LEN);
      val.host_len    = scratch->hostname_len;
      val.ttl_sec     = ttl > DNS_TTL_CAP ? DNS_TTL_CAP : ttl;
      val.inserted_kns = bpf_ktime_get_ns();

      bpf_map_update_elem(&dns_ip_map, &key, &val, BPF_ANY);

#ifdef KLOAK_DEBUG
      bpf_printk("kloak dns: tgid=%u host=%s ttl=%u", tgid,
                 scratch->hostname, val.ttl_sec);
#endif

    } else if (rtype == DNS_TYPE_AAAA && rdlen == 16) {
      // IPv6 answer.
      // Guard ensures off + 16 <= DNS_MAX_LEN so pkt + off is in-bounds.
      if (off + 16 > DNS_MAX_LEN)
        break;
      struct dns_ip_key key;
      __builtin_memset(&key, 0, sizeof(key));
      key.tgid = tgid;
      // Mask ensures the verifier tracks a concrete [0,511] pointer offset.
      __builtin_memcpy(key.ip, pkt + (off & (DNS_MAX_LEN - 1)), 16);

      struct dns_ip_val val = {};
      __builtin_memcpy(val.hostname, scratch->hostname, MAX_HOST_LEN);
      val.host_len    = scratch->hostname_len;
      val.ttl_sec     = ttl > DNS_TTL_CAP ? DNS_TTL_CAP : ttl;
      val.inserted_kns = bpf_ktime_get_ns();

      bpf_map_update_elem(&dns_ip_map, &key, &val, BPF_ANY);
    }

    off += rdlen;
  }
}

// -----------------------------------------------------------------------------
// recvfrom tracepoints — intercept DNS responses.
// sys_enter_recvfrom stores the userspace buffer pointer for correlation.
// sys_exit_recvfrom reads the filled buffer, verifies source is the DNS server,
// and parses A/AAAA records into dns_ip_map.
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  __u32 pid  = (__u32)(pid_tgid & 0xFFFFFFFF);

  // Only process tracked container processes
  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;

  // args[4] is src_addr (struct sockaddr __user *) — NULL means caller didn't
  // request the source address; skip those calls (we need the source IP).
  if (ctx->args[4] == 0)
    return 0;

  struct dns_pending_key key = {.tgid = tgid, .pid = pid};
  struct dns_pending_val val = {};
  val.fd       = (__u32)ctx->args[0];
  val.buf_ptr  = ctx->args[1];
  val.addr_ptr = ctx->args[4];

  bpf_map_update_elem(&dns_pending, &key, &val, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
  __s64 ret = ctx->ret;
  if (ret < DNS_HEADER_LEN)
    return 0; // too short to be a valid DNS response

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  __u32 pid  = (__u32)(pid_tgid & 0xFFFFFFFF);

  struct dns_pending_key key = {.tgid = tgid, .pid = pid};
  struct dns_pending_val *v = bpf_map_lookup_elem(&dns_pending, &key);
  if (!v)
    return 0;

  // Consume the pending entry immediately
  __u64 buf_ptr  = v->buf_ptr;
  __u64 addr_ptr = v->addr_ptr;
  bpf_map_delete_elem(&dns_pending, &key);

  // Read source address from userspace to verify it's port 53 + configured DNS server
  __u16 sa_family = 0;
  bpf_probe_read_user(&sa_family, sizeof(sa_family), (void *)addr_ptr);

  __u8 src_ip[16] = {};
  __u16 src_port = 0;

  if (sa_family == 2 /* AF_INET */) {
    // struct sockaddr_in: [sa_family(2)][sin_port(2)][sin_addr(4)]...
    bpf_probe_read_user(&src_port, sizeof(src_port), (void *)(addr_ptr + 2));
    __u8 v4[4] = {};
    bpf_probe_read_user(v4, 4, (void *)(addr_ptr + 4));
    ipv4_to_mapped(src_ip, v4);
  } else if (sa_family == 10 /* AF_INET6 */) {
    // struct sockaddr_in6: [sa_family(2)][sin6_port(2)][sin6_flowinfo(4)][sin6_addr(16)]
    bpf_probe_read_user(&src_port, sizeof(src_port), (void *)(addr_ptr + 2));
    bpf_probe_read_user(src_ip, 16, (void *)(addr_ptr + 8));
  } else {
    return 0;
  }

  // src_port is in network byte order; DNS uses port 53 (0x0035)
  if (src_port != __builtin_bswap16(53))
    return 0;

  // Check that the source IP is a configured DNS server
  if (!is_dns_server(src_ip))
    return 0;

  // Read DNS packet into per-CPU scratch buffer
  __u32 zero = 0;
  struct dns_scratch_buf *scratch = bpf_map_lookup_elem(&dns_scratch, &zero);
  if (!scratch)
    return 0;

  __u32 pkt_len = (__u32)ret;
  if (pkt_len > DNS_MAX_LEN)
    pkt_len = DNS_MAX_LEN;

  bpf_probe_read_user(scratch->pkt, pkt_len, (void *)buf_ptr);

  process_dns_packet(scratch, pkt_len, tgid);
  return 0;
}

// -----------------------------------------------------------------------------
// connect tracepoints — record the peer IP for each TCP connection.
// Enables the ssl_ptr → fd → peer IP → DNS hostname lookup chain.
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_enter_connect(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  __u32 pid  = (__u32)(pid_tgid & 0xFFFFFFFF);

  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;

  if (ctx->args[1] == 0) // NULL addr → not a real connect
    return 0;

  struct connect_pending_key key = {.tgid = tgid, .pid = pid};
  struct connect_pending_val val = {};
  val.fd       = (__u32)ctx->args[0];
  val.addr_ptr = ctx->args[1];

  bpf_map_update_elem(&connect_pending, &key, &val, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tp_exit_connect(struct trace_event_raw_sys_exit *ctx) {
  __s64 ret = ctx->ret;
  // Accept 0 (success) and -EINPROGRESS (-115) for non-blocking connects
  if (ret != 0 && ret != -115)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  __u32 pid  = (__u32)(pid_tgid & 0xFFFFFFFF);

  struct connect_pending_key key = {.tgid = tgid, .pid = pid};
  struct connect_pending_val *v = bpf_map_lookup_elem(&connect_pending, &key);
  if (!v)
    return 0;

  __u32 fd        = v->fd;
  __u64 addr_ptr  = v->addr_ptr;
  bpf_map_delete_elem(&connect_pending, &key);

  // Read destination sockaddr to get peer IP
  __u16 sa_family = 0;
  bpf_probe_read_user(&sa_family, sizeof(sa_family), (void *)addr_ptr);

  struct conn_ip_key ckey = {};
  ckey.tgid = tgid;
  ckey.fd   = fd;
  struct conn_ip_val cval = {};

  if (sa_family == 2 /* AF_INET */) {
    __u8 v4[4] = {};
    bpf_probe_read_user(v4, 4, (void *)(addr_ptr + 4));
    ipv4_to_mapped(cval.ip, v4);
  } else if (sa_family == 10 /* AF_INET6 */) {
    bpf_probe_read_user(cval.ip, 16, (void *)(addr_ptr + 8));
  } else {
    return 0; // not TCP/IP
  }

  bpf_map_update_elem(&conn_ip_map, &ckey, &cval, BPF_ANY);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak connect: tgid=%u fd=%u", tgid, fd);
#endif

  return 0;
}

// -----------------------------------------------------------------------------
// Shared logic for write/writev fd correlation (stage 2 of SSL_do_handshake).
// Called from tp_enter_write and tp_enter_writev with the socket fd.
// Only stores the mapping if the fd is a tracked TCP connection (in conn_ip_map),
// filtering out writes to pipes, files, stdout, etc.
static __always_inline void try_complete_handshake(__u32 tgid, __u32 pid,
                                                   __u32 fd) {
  struct handshake_pending_key hkey = {.tgid = tgid, .pid = pid};
  struct handshake_pending_val *hval =
      bpf_map_lookup_elem(&handshake_pending, &hkey);
  if (!hval)
    return;

  // Only accept fds that are tracked TCP connections (from connect tracepoint).
  // This filters out writes to pipes, files, stdout, etc.
  // For connections established BEFORE tracking, conn_ip_map won't have the fd,
  // so we skip the filter and accept any fd during the handshake window.
  // The handshake_pending entry itself ensures we only capture during TLS setup.

  __u64 ssl_ptr = hval->ssl_ptr;
  bpf_map_delete_elem(&handshake_pending, &hkey);

  struct ssl_fd_key sfk;
  __builtin_memset(&sfk, 0, sizeof(sfk));
  sfk.tgid    = tgid;
  sfk.ssl_ptr = ssl_ptr;

  struct ssl_fd_val sfv = {.fd = fd};
  bpf_map_update_elem(&ssl_fd_map, &sfk, &sfv, BPF_ANY);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak hs_fd: tgid=%u fd=%u ssl=%llx", tgid, fd, ssl_ptr);
#endif
}

// -----------------------------------------------------------------------------
// sys_enter_write tracepoint — stage 2 of SSL_do_handshake fd correlation.
// Catches Python (blocking OpenSSL) which uses write() for socket I/O.
// write(fd, buf, count): args[0]=fd
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;
  __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
  try_complete_handshake(tgid, pid, (__u32)ctx->args[0]);
  return 0;
}

// -----------------------------------------------------------------------------
// sys_enter_writev tracepoint — same as tp_enter_write but for writev().
// Catches Node.js (libuv) which uses writev() for socket I/O.
// writev(fd, iov, iovcnt): args[0]=fd
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_writev")
int tp_enter_writev(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;
  __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
  try_complete_handshake(tgid, pid, (__u32)ctx->args[0]);
  return 0;
}

// -----------------------------------------------------------------------------
// sys_enter_sendmsg tracepoint — same logic for sendmsg().
// Catches Node.js on Linux: libuv uses sendmsg() for TCP stream writes.
// sendmsg(fd, msg, flags): args[0]=fd
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;
  __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
  try_complete_handshake(tgid, pid, (__u32)ctx->args[0]);
  return 0;
}

// -----------------------------------------------------------------------------
// sys_enter_sendto tracepoint — same logic for sendto()/send().
// glibc's send() is sendto() with NULL addr. Some TLS libraries use this.
// sendto(fd, buf, len, flags, addr, addrlen): args[0]=fd
// -----------------------------------------------------------------------------

SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;
  __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
  try_complete_handshake(tgid, pid, (__u32)ctx->args[0]);
  return 0;
}

// -----------------------------------------------------------------------------
// SSL_set_fd uprobe — records ssl_ptr → fd so we can resolve peer IP at
// SSL_write time via: ssl_ptr → fd (ssl_fd_map) → IP (conn_ip_map).
// Called once per SSL object before SSL_connect/SSL_accept.
// SSL_set_fd(SSL *ssl, int fd):
//   x86_64: RDI=ssl, RSI=fd   (pt_regs offsets: rdi=112, rsi=104)
//   ARM64:  X0=ssl,  X1=fd    (pt_regs offsets:   0,       8)
// -----------------------------------------------------------------------------

SEC("uprobe/ssl_set_fd")
int bpf_uprobe_ssl_set_fd(void *ctx) {
  void *ssl_ptr;
  int   fd_int;

#if defined(bpf_target_x86)
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 112);
  bpf_probe_read_kernel(&fd_int,  sizeof(int),    (char *)ctx + 104);
#elif defined(bpf_target_arm64)
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 0);
  bpf_probe_read_kernel(&fd_int,  sizeof(int),    (char *)ctx + 8);
#else
  return 0;
#endif

  if (!ssl_ptr || fd_int < 0)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  struct ssl_fd_key key;
  __builtin_memset(&key, 0, sizeof(key));
  key.tgid    = tgid;
  key.ssl_ptr = (__u64)ssl_ptr;

  struct ssl_fd_val val = {.fd = (__u32)fd_int};
  bpf_map_update_elem(&ssl_fd_map, &key, &val, BPF_ANY);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak ssl_set_fd: tgid=%u ssl=%llx fd=%d", tgid,
             (__u64)ssl_ptr, fd_int);
#endif

  return 0;
}

// -----------------------------------------------------------------------------
// SSL_do_handshake uprobe — stage 1 of BIO-based fd correlation.
//
// CPython 3.11+, Node.js, and other runtimes use BIO_new_socket(fd) +
// SSL_set_bio(ssl, bio, bio) instead of SSL_set_fd(ssl, fd). This uprobe
// captures ssl_ptr from SSL_do_handshake(SSL *ssl) and stores it in
// handshake_pending[{tgid, tid}]. During the handshake, OpenSSL internally
// calls write(fd, ClientHello) on the socket — tp_enter_write correlates
// the fd to complete the ssl_ptr → fd mapping in ssl_fd_map.
//
// SSL_do_handshake(SSL *ssl):
//   x86_64: RDI=ssl   (pt_regs offset: rdi=112)
//   ARM64:  X0=ssl    (pt_regs offset: 0)
// -----------------------------------------------------------------------------

SEC("uprobe/ssl_do_handshake")
int bpf_uprobe_ssl_do_handshake(void *ctx) {
  void *ssl_ptr;

#if defined(bpf_target_x86)
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 112);
#elif defined(bpf_target_arm64)
  bpf_probe_read_kernel(&ssl_ptr, sizeof(void *), (char *)ctx + 0);
#else
  return 0;
#endif

  if (!ssl_ptr)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;

  // If SSL_set_fd already populated ssl_fd_map, skip the handshake path.
  struct ssl_fd_key sfk;
  __builtin_memset(&sfk, 0, sizeof(sfk));
  sfk.tgid    = tgid;
  sfk.ssl_ptr = (__u64)ssl_ptr;
  if (bpf_map_lookup_elem(&ssl_fd_map, &sfk))
    return 0;

  __u32 pid = (__u32)(pid_tgid & 0xFFFFFFFF);
  struct handshake_pending_key key = {.tgid = tgid, .pid = pid};
  struct handshake_pending_val val = {.ssl_ptr = (__u64)ssl_ptr};
  bpf_map_update_elem(&handshake_pending, &key, &val, BPF_ANY);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak handshake: tgid=%u tid=%u ssl=%llx", tgid, pid,
             (__u64)ssl_ptr);
#endif

  return 0;
}

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
// Resolve host for the current SSL connection — DNS-verified path ONLY.
//
// Walks: ssl_ptr → ssl_fd_map → fd → conn_ip_map → peer_ip → dns_ip_map → hostname
//
// This is the ONLY host resolution path. SNI and HTTP Host header are app-controlled
// and trivially spoofable, so they are NOT used. If any lookup in the chain fails,
// host_value_len remains 0, and host-filtered secrets (getkloak.io/hosts) are blocked.
// Secrets without host filtering (wildcard) are unaffected — they skip the host check.
//
// For Go crypto/tls (ssl_ptr=0): returns immediately with host_value_len=0.
// Host-filtered secrets won't be rewritten until Go support is added (Phase 2).
// -----------------------------------------------------------------------------
static __always_inline void resolve_host(struct scratch_buf *scratch,
                                         __u64 ssl_ptr) {
  scratch->host_offset = 0;
  scratch->host_value_len = 0;
  __builtin_memset(scratch->host_value, 0, MAX_HOST_LEN);

  if (ssl_ptr == 0)
    return; // Go crypto/tls — no ssl_ptr, cannot verify

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  struct ssl_fd_key sfk;
  __builtin_memset(&sfk, 0, sizeof(sfk));
  sfk.tgid    = tgid;
  sfk.ssl_ptr = ssl_ptr;

  struct ssl_fd_val *sfv = bpf_map_lookup_elem(&ssl_fd_map, &sfk);
  if (!sfv)
    return;

  struct conn_ip_key cik = {.tgid = tgid, .fd = sfv->fd};
  struct conn_ip_val *civ = bpf_map_lookup_elem(&conn_ip_map, &cik);
  if (!civ)
    return;

  struct dns_ip_key dik;
  __builtin_memset(&dik, 0, sizeof(dik));
  dik.tgid = tgid;
  __builtin_memcpy(dik.ip, civ->ip, 16);

  struct dns_ip_val *div = bpf_map_lookup_elem(&dns_ip_map, &dik);
  if (div && div->host_len > 0 && div->host_len <= MAX_HOST_LEN) {
    __builtin_memcpy(scratch->host_value, div->hostname, MAX_HOST_LEN);
    scratch->host_value_len = div->host_len;
  }
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
