// go:build ignore

// tls_uprobe.c - eBPF uprobes for TLS interception in Go and OpenSSL apps.
// Uses a per-CPU array as scratch buffer (not ringbuf) to avoid verifier
// issues with ringbuf_mem pointer tracking in loops.
// Supports both x86_64 and ARM64 architectures.
// Host filtering uses DNS-verified connect-time resolution.

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
#include <bpf/bpf_endian.h>
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
// Maximum DNS packet size we can parse in BPF
#define MAX_DNS_PKT 512
// Maximum number of DNS answer records to process
#define MAX_DNS_ANSWERS 8
// Maximum DNS server IPs we can configure
#define MAX_DNS_SERVERS 4

#include "helpers.h"

// BPF Map: shadow secret prefix -> real secret value
struct secret_key {
  char prefix[SECRET_KEY_LEN];
};

struct secret_value {
  __u32 len;
  char real_secret[SECRET_MAX_LEN];
  __u32 host_len;                      // 0 = wildcard (allow all hosts)
  char allowed_host[MAX_HOST_LEN];     // e.g. "httpbin.org"
  __u32 prefix_len;                    // actual prefix length (8..42)
  char full_prefix[SECRET_PREFIX_MAX]; // full kloak:UUID prefix for verification
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
  __u32 read_len;       // bytes read into data[] (max 256, for host parsing)
  __u32 total_data_len; // full TLS write length (for bpf_loop scanning)
  __u32 host_offset;
  __u32 host_value_len; // length of extracted host value
  char host_value[MAX_HOST_LEN]; // host from DNS chain
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

// =============================================================================
// DNS-verified host filtering maps
// =============================================================================

// Per-process opt-in filter: only track DNS/connect for these TGIDs.
// Populated from userspace when attaching uprobes to a process.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);   // tgid
  __type(value, __u8);  // 1 = tracked
} tracked_tgids SEC(".maps");

// DNS-verified IP -> hostname mapping per process.
// Populated by tp_exit_recvfrom when a DNS response contains an A/AAAA
// record whose qname is in watched_hosts.
struct dns_ip_key {
  __u32 tgid;
  __u8 ip[16]; // IPv4-mapped-IPv6 or native IPv6
};

struct dns_ip_val {
  char hostname[MAX_HOST_LEN];
  __u32 host_len;
  __u32 ttl_sec;
  __u64 inserted_at;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 8192);
  __type(key, struct dns_ip_key);
  __type(value, struct dns_ip_val);
} dns_ip_map SEC(".maps");

// TCP connection fd -> peer IP per process.
// Populated by tp_exit_connect for every connect() call.
struct conn_ip_key {
  __u32 tgid;
  __u32 fd;
};

struct conn_ip_val {
  __u8 ip[16]; // IPv4-mapped-IPv6 or native IPv6
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, struct conn_ip_key);
  __type(value, struct conn_ip_val);
} conn_ip_map SEC(".maps");

// SSL pointer -> fd cache per process.
// Populated lazily in resolve_host when last_verified_fd provides an fd.
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

// Most recent DNS-verified connect fd per tgid.
// Written by tp_exit_connect when the destination IP has a dns_ip_map entry.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);   // tgid
  __type(value, __u32); // fd
} last_verified_fd SEC(".maps");

// Scratch for recvfrom enter->exit correlation: save the buffer pointer.
struct dns_pending_val {
  __u64 buf_ptr;
  __u64 sockaddr_ptr; // pointer to msghdr/sockaddr for source port check
  __u32 fd;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);   // pid_tgid
  __type(value, struct dns_pending_val);
} dns_pending SEC(".maps");

// Scratch for connect enter->exit correlation: save fd and sockaddr.
struct connect_pending_val {
  __u32 fd;
  __u8 ip[16]; // destination IP (IPv4-mapped-IPv6)
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);   // pid_tgid
  __type(value, struct connect_pending_val);
} connect_pending SEC(".maps");

// Array of configured DNS server IPs (up to 4).
// Index 0..3 hold IPv4-mapped-IPv6 addresses. Zeroed = unused slot.
struct dns_server_ip {
  __u8 ip[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, MAX_DNS_SERVERS);
  __type(key, __u32);
  __type(value, struct dns_server_ip);
} dns_config SEC(".maps");

// Per-CPU scratch buffer for DNS packet parsing (512 bytes).
struct dns_scratch_buf {
  char pkt[MAX_DNS_PKT];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct dns_scratch_buf);
} dns_scratch SEC(".maps");

// Watched hostnames: only DNS responses for these hosts are recorded.
// Populated from userspace with the unique AllowedHosts from synced secrets.
struct watched_host_key {
  char host[MAX_HOST_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, struct watched_host_key);
  __type(value, __u8);
} watched_hosts SEC(".maps");

// =============================================================================
// DNS helpers (inline, used by tracepoint programs)
// =============================================================================

// Convert an IPv4 address (4 bytes, network order) to IPv4-mapped-IPv6 (16 bytes).
static __always_inline void ipv4_to_mapped(__u8 *out16, const __u8 *ipv4) {
  __builtin_memset(out16, 0, 10);
  out16[10] = 0xff;
  out16[11] = 0xff;
  out16[12] = ipv4[0];
  out16[13] = ipv4[1];
  out16[14] = ipv4[2];
  out16[15] = ipv4[3];
}

// Check if an IP matches any configured DNS server.
static __always_inline int is_dns_server(const __u8 *ip16) {
  for (__u32 i = 0; i < MAX_DNS_SERVERS; i++) {
    __u32 idx = i;
    struct dns_server_ip *srv = bpf_map_lookup_elem(&dns_config, &idx);
    if (!srv)
      continue;

    // Check if server slot is zeroed (unused)
    __u64 lo, hi;
    __builtin_memcpy(&lo, srv->ip, 8);
    __builtin_memcpy(&hi, srv->ip + 8, 8);
    if (lo == 0 && hi == 0)
      continue;

    // Compare as 2x uint64
    __u64 a_lo, a_hi;
    __builtin_memcpy(&a_lo, ip16, 8);
    __builtin_memcpy(&a_hi, ip16 + 8, 8);
    if (a_lo == lo && a_hi == hi)
      return 1;
  }
  return 0;
}

// barrier_var prevents the compiler from eliminating the AND mask below.
// After "if (offset >= MAX_DNS_PKT) return 0", the compiler proves
// offset < 512 and would optimize away "offset & 511" as a no-op.
// The BPF verifier then sees an unbounded pointer arithmetic operation.
// This asm barrier breaks the compiler's value-range reasoning.
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var) : :)
#endif

// Skip a DNS name in compressed wire format. Returns the new offset, or 0 on error.
// Uses barrier_var + bitmask to satisfy BPF verifier bounds checking.
static __always_inline __u32 dns_skip_name(const char *pkt, __u32 pkt_len,
                                           __u32 off) {
  for (int i = 0; i < 8; i++) {
    if (off >= pkt_len || off >= MAX_DNS_PKT)
      return 0;
    barrier_var(off);
    __u8 b = (__u8)pkt[off & (MAX_DNS_PKT - 1)];
    if (b == 0)
      return off + 1;
    if ((b & 0xC0) == 0xC0)
      return off + 2;
    if ((b & 0xC0) != 0)
      return 0; // reserved bits
    __u32 next = off + 1 + (__u32)b;
    if (next > pkt_len || next > MAX_DNS_PKT)
      return 0;
    off = next;
  }
  return 0;
}

// Decode a DNS qname using a FLAT single loop (not nested).
// Nested loops (8 outer × 63 inner = 504 iterations) create multiplicative
// verifier state explosion, hitting the 1M-instruction limit. A single loop
// of MAX_HOST_LEN+8 iterations stays well within budget.
static __always_inline __u32 dns_decode_qname(const char *pkt, __u32 pkt_len,
                                              __u32 off, char *out,
                                              __u32 out_len) {
  __u32 host_len = 0;
  __u32 label_rem = 0;
  __u8 after_first = 0;

  for (__u32 i = 0; i < MAX_HOST_LEN + 8; i++) {
    if (off >= pkt_len || off >= MAX_DNS_PKT)
      break;
    barrier_var(off);
    __u8 c = (__u8)pkt[off & (MAX_DNS_PKT - 1)];
    off++;

    if (label_rem == 0) {
      if (c == 0)
        break;
      if ((c & 0xC0) != 0)
        break;
      if (c > 63)
        break;
      label_rem = (__u32)c;
      if (after_first && host_len < out_len)
        out[host_len++] = '.';
      after_first = 1;
    } else {
      label_rem--;
      if (host_len < out_len)
        out[host_len++] = c;
    }
  }
  return host_len;
}

// Process a DNS response packet: extract A/AAAA answer IPs and map them to
// the query hostname, but only if the hostname is in watched_hosts.
// `tgid` is the process that received the DNS response.
static __always_inline void process_dns_packet(const char *pkt, __u32 pkt_len,
                                               __u32 tgid) {
  // Minimum DNS header: 12 bytes
  if (pkt_len < 12)
    return;

  // Check QR bit (response) and RCODE == 0 (no error)
  __u8 flags0 = (__u8)pkt[2];
  __u8 flags1 = (__u8)pkt[3];
  if (!(flags0 & 0x80)) // QR bit must be 1 (response)
    return;
  if ((flags1 & 0x0F) != 0) // RCODE must be 0
    return;

  // Parse question count and answer count (big-endian)
  __u16 qdcount = ((__u16)(__u8)pkt[4] << 8) | (__u16)(__u8)pkt[5];
  __u16 ancount = ((__u16)(__u8)pkt[6] << 8) | (__u16)(__u8)pkt[7];

  if (qdcount < 1 || ancount < 1)
    return;

  // Decode the qname from the question section (offset 12)
  char qname[MAX_HOST_LEN];
  __builtin_memset(qname, 0, sizeof(qname));
  __u32 qname_len = dns_decode_qname(pkt, pkt_len, 12, qname, MAX_HOST_LEN);
  if (qname_len == 0 || qname_len > MAX_HOST_LEN)
    return;

  // Check if this hostname is in watched_hosts
  struct watched_host_key wk;
  __builtin_memset(&wk, 0, sizeof(wk));
  __builtin_memcpy(wk.host, qname, MAX_HOST_LEN);
  __u8 *watched = bpf_map_lookup_elem(&watched_hosts, &wk);
  if (!watched)
    return; // not a watched hostname, skip

  // Skip past the question section to get to the answer section
  __u32 off = 12;
  // Skip qname
  off = dns_skip_name(pkt, pkt_len, off);
  if (off == 0)
    return;
  // Skip QTYPE (2) + QCLASS (2)
  off += 4;
  if (off > pkt_len)
    return;

  // Parse answer records
  __u32 answers_processed = 0;
  for (int i = 0; i < MAX_DNS_ANSWERS; i++) {
    if (answers_processed >= ancount)
      break;
    if (off >= pkt_len)
      break;

    // Skip the answer name (may be compressed)
    off = dns_skip_name(pkt, pkt_len, off);
    if (off == 0 || off + 10 > pkt_len || off + 10 > MAX_DNS_PKT)
      break;

    // Read TYPE/CLASS/TTL/RDLENGTH (10 bytes) using __builtin_memcpy into
    // stack variables. This avoids per-byte pkt[m+N] accesses that the verifier
    // unrolls and fails to prove bounded after dns_skip_name.
    if (off + 10 > pkt_len || off + 10 > MAX_DNS_PKT)
      break;
    barrier_var(off);
    __u8 rr_hdr[10];
    __builtin_memcpy(rr_hdr, pkt + (off & (MAX_DNS_PKT - 1)), 10);
    __u16 rtype = ((__u16)rr_hdr[0] << 8) | (__u16)rr_hdr[1];
    __u32 ttl = ((__u32)rr_hdr[4] << 24) | ((__u32)rr_hdr[5] << 16) |
                ((__u32)rr_hdr[6] << 8) | (__u32)rr_hdr[7];
    __u16 rdlength = ((__u16)rr_hdr[8] << 8) | (__u16)rr_hdr[9];
    off += 10;

    if (off + rdlength > pkt_len || off + rdlength > MAX_DNS_PKT)
      break;

    // A record (type 1, rdlength 4)
    if (rtype == 1 && rdlength == 4) {
      if (off + 4 > MAX_DNS_PKT) break;
      barrier_var(off);
      struct dns_ip_key dik;
      __builtin_memset(&dik, 0, sizeof(dik));
      dik.tgid = tgid;
      ipv4_to_mapped(dik.ip, (__u8 *)(pkt + (off & (MAX_DNS_PKT - 1))));

      struct dns_ip_val div;
      __builtin_memset(&div, 0, sizeof(div));
      __builtin_memcpy(div.hostname, qname, MAX_HOST_LEN);
      div.host_len = qname_len;
      div.ttl_sec = ttl;
      div.inserted_at = bpf_ktime_get_ns();

      bpf_map_update_elem(&dns_ip_map, &dik, &div, BPF_ANY);
    }

    // AAAA record (type 28, rdlength 16)
    if (rtype == 28 && rdlength == 16) {
      if (off + 16 > MAX_DNS_PKT) break;
      barrier_var(off);
      struct dns_ip_key dik;
      __builtin_memset(&dik, 0, sizeof(dik));
      dik.tgid = tgid;
      __builtin_memcpy(dik.ip, pkt + (off & (MAX_DNS_PKT - 1)), 16);

      struct dns_ip_val div;
      __builtin_memset(&div, 0, sizeof(div));
      __builtin_memcpy(div.hostname, qname, MAX_HOST_LEN);
      div.host_len = qname_len;
      div.ttl_sec = ttl;
      div.inserted_at = bpf_ktime_get_ns();

      bpf_map_update_elem(&dns_ip_map, &dik, &div, BPF_ANY);

#ifdef KLOAK_DEBUG
      bpf_printk("kloak dns: tgid=%u AAAA -> %s", tgid, qname);
#endif
    }

    off += rdlength;
    answers_processed++;
  }
}

// =============================================================================
// DNS interception tracepoints (recvfrom enter/exit)
// =============================================================================

// tp/syscalls/sys_enter_recvfrom: save buffer pointer for exit handler.
// recvfrom(int fd, void *buf, size_t len, int flags, sockaddr *src_addr, socklen_t *addrlen)
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  // Only track processes we care about
  __u8 *tracked = bpf_map_lookup_elem(&tracked_tgids, &tgid);
  if (!tracked)
    return 0;

  struct dns_pending_val val = {};
  val.fd = (__u32)ctx->args[0];
  val.buf_ptr = (__u64)ctx->args[1];
  val.sockaddr_ptr = (__u64)ctx->args[4]; // src_addr

  bpf_map_update_elem(&dns_pending, &pid_tgid, &val, BPF_ANY);
  return 0;
}

// tp/syscalls/sys_exit_recvfrom: read DNS response from saved buffer.
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  struct dns_pending_val *pending = bpf_map_lookup_elem(&dns_pending, &pid_tgid);
  if (!pending) {
    return 0;
  }

  // Save values before deleting the pending entry
  __u64 buf_ptr = pending->buf_ptr;
  __u64 sockaddr_ptr = pending->sockaddr_ptr;

  bpf_map_delete_elem(&dns_pending, &pid_tgid);

  // Check return value (bytes received)
  long ret = ctx->ret;
  if (ret <= 12) // minimum DNS header size
    return 0;

  // Check source address: must be a known DNS server on port 53.
  // sockaddr_in: { sa_family(2), sin_port(2), sin_addr(4), ... }
  // sockaddr_in6: { sa_family(2), sin6_port(2), sin6_flowinfo(4), sin6_addr(16), ... }
  if (sockaddr_ptr != 0) {
    __u16 sa_family = 0;
    bpf_probe_read_user(&sa_family, sizeof(sa_family), (void *)sockaddr_ptr);

    __u16 port = 0;
    __u8 ip16[16] = {};

    if (sa_family == 2) { // AF_INET
      bpf_probe_read_user(&port, sizeof(port), (void *)(sockaddr_ptr + 2));
      __u8 ipv4[4] = {};
      bpf_probe_read_user(ipv4, 4, (void *)(sockaddr_ptr + 4));
      ipv4_to_mapped(ip16, ipv4);
    } else if (sa_family == 10) { // AF_INET6
      bpf_probe_read_user(&port, sizeof(port), (void *)(sockaddr_ptr + 2));
      bpf_probe_read_user(ip16, 16, (void *)(sockaddr_ptr + 8));
    } else {
      return 0; // unknown address family
    }

    // port is in network byte order; DNS = port 53 = 0x0035
    if (port != __bpf_htons(53))
      return 0;

    // Check if source IP is a configured DNS server
    if (!is_dns_server(ip16))
      return 0;
  }
  // If sockaddr_ptr is NULL, the caller didn't care about source —
  // this is common with connected UDP sockets. We still process it since
  // the tracked_tgids filter already limits scope.

  // Read DNS packet into per-CPU scratch buffer
  __u32 zero = 0;
  struct dns_scratch_buf *dbuf = bpf_map_lookup_elem(&dns_scratch, &zero);
  if (!dbuf)
    return 0;

  __u32 read_len = (__u32)ret;
  if (read_len > MAX_DNS_PKT)
    read_len = MAX_DNS_PKT;

  if (bpf_probe_read_user(dbuf->pkt, read_len, (void *)buf_ptr) != 0)
    return 0;

  process_dns_packet(dbuf->pkt, read_len, tgid);
  return 0;
}

// =============================================================================
// TCP connect tracepoints (connect enter/exit)
// =============================================================================

// tp/syscalls/sys_enter_connect: save fd and destination IP.
// connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_enter_connect(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  // Only track processes we care about
  __u8 *tracked = bpf_map_lookup_elem(&tracked_tgids, &tgid);
  if (!tracked)
    return 0;

  __u32 fd = (__u32)ctx->args[0];
  __u64 addr_ptr = (__u64)ctx->args[1];

  if (addr_ptr == 0)
    return 0;

  // Read sa_family
  __u16 sa_family = 0;
  bpf_probe_read_user(&sa_family, sizeof(sa_family), (void *)addr_ptr);

  struct connect_pending_val val = {};
  val.fd = fd;

  if (sa_family == 2) { // AF_INET
    __u8 ipv4[4] = {};
    bpf_probe_read_user(ipv4, 4, (void *)(addr_ptr + 4));
    ipv4_to_mapped(val.ip, ipv4);
  } else if (sa_family == 10) { // AF_INET6
    bpf_probe_read_user(val.ip, 16, (void *)(addr_ptr + 8));
  } else {
    return 0;
  }

  bpf_map_update_elem(&connect_pending, &pid_tgid, &val, BPF_ANY);
  return 0;
}

// tp/syscalls/sys_exit_connect: on success (or EINPROGRESS), record fd->IP
// and check if the IP was DNS-verified. If so, set last_verified_fd.
SEC("tracepoint/syscalls/sys_exit_connect")
int tp_exit_connect(struct trace_event_raw_sys_exit *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  struct connect_pending_val *pending =
      bpf_map_lookup_elem(&connect_pending, &pid_tgid);
  if (!pending) {
    return 0;
  }

  // Save before delete
  __u32 fd = pending->fd;
  __u8 ip[16];
  __builtin_memcpy(ip, pending->ip, 16);

  bpf_map_delete_elem(&connect_pending, &pid_tgid);

  // connect returns 0 on success, or -EINPROGRESS (-115) for non-blocking.
  long ret = ctx->ret;
  if (ret != 0 && ret != -115)
    return 0;

  // Always record fd -> IP in conn_ip_map
  struct conn_ip_key cik = {.tgid = tgid, .fd = fd};
  struct conn_ip_val civ;
  __builtin_memcpy(civ.ip, ip, 16);
  bpf_map_update_elem(&conn_ip_map, &cik, &civ, BPF_ANY);

  // Check if this IP was DNS-verified (exists in dns_ip_map for this tgid)
  struct dns_ip_key dik;
  __builtin_memset(&dik, 0, sizeof(dik));
  dik.tgid = tgid;
  __builtin_memcpy(dik.ip, ip, 16);

  struct dns_ip_val *div = bpf_map_lookup_elem(&dns_ip_map, &dik);
  if (div) {
    // DNS-verified connection! Record as last_verified_fd
    bpf_map_update_elem(&last_verified_fd, &tgid, &fd, BPF_ANY);

#ifdef KLOAK_DEBUG
    bpf_printk("kloak connect: tgid=%u fd=%u -> dns-verified host=%s", tgid, fd,
               div->hostname);
#endif
  }

  return 0;
}

// =============================================================================
// Resolve host for the current SSL/TLS connection using DNS chain.
//
// Chain: ssl_fd_map (cache) -> last_verified_fd -> conn_ip_map -> dns_ip_map
// =============================================================================
static __always_inline void resolve_host(struct scratch_buf *scratch_data,
                                         __u64 ssl_ptr) {
  scratch_data->host_offset = 0;
  scratch_data->host_value_len = 0;
  __builtin_memset(scratch_data->host_value, 0, MAX_HOST_LEN);

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);

  __u32 fd = 0;
  int found = 0;

  // Path 1: ssl_fd_map cache (OpenSSL fast path)
  if (ssl_ptr != 0) {
    struct ssl_fd_key sfk;
    __builtin_memset(&sfk, 0, sizeof(sfk));
    sfk.tgid = tgid;
    sfk.ssl_ptr = ssl_ptr;
    struct ssl_fd_val *sfv = bpf_map_lookup_elem(&ssl_fd_map, &sfk);
    if (sfv) {
      fd = sfv->fd;
      found = 1;
    }
  }

  // Path 2: last_verified_fd (works for ALL languages)
  if (!found) {
    __u32 *vfd = bpf_map_lookup_elem(&last_verified_fd, &tgid);
    if (!vfd)
      return;
    fd = *vfd;

    // Cache for next time (OpenSSL only)
    if (ssl_ptr != 0) {
      struct ssl_fd_key sfk;
      __builtin_memset(&sfk, 0, sizeof(sfk));
      sfk.tgid = tgid;
      sfk.ssl_ptr = ssl_ptr;
      struct ssl_fd_val new_sfv = {.fd = fd};
      bpf_map_update_elem(&ssl_fd_map, &sfk, &new_sfv, BPF_ANY);
    }
  }

  // fd -> conn_ip_map -> dns_ip_map -> hostname
  struct conn_ip_key cik = {.tgid = tgid, .fd = fd};
  struct conn_ip_val *civ = bpf_map_lookup_elem(&conn_ip_map, &cik);
  if (!civ)
    return;

  struct dns_ip_key dik;
  __builtin_memset(&dik, 0, sizeof(dik));
  dik.tgid = tgid;
  __builtin_memcpy(dik.ip, civ->ip, 16);

  struct dns_ip_val *div = bpf_map_lookup_elem(&dns_ip_map, &dik);
  if (div && div->host_len > 0 && div->host_len <= MAX_HOST_LEN) {
    __builtin_memcpy(scratch_data->host_value, div->hostname, MAX_HOST_LEN);
    scratch_data->host_value_len = div->host_len;
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
// Go doesn't call SSL_set_tlsext_host_name.
// resolve_host() uses the DNS chain (last_verified_fd -> conn_ip_map -> dns_ip_map).
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

  // Go doesn't use OpenSSL, no ssl_ptr — pass 0.
  // resolve_host will use last_verified_fd -> conn_ip_map -> dns_ip_map.
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

  // Look up hostname via DNS chain: ssl_fd_map -> conn_ip_map -> dns_ip_map
  resolve_host(scratch_data, (__u64)ssl_ptr);

  // Jump to Phase 2
  bpf_tail_call(ctx, &prog_array, 0);

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
