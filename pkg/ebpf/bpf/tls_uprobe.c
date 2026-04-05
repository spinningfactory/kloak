// go:build ignore

// tls_uprobe.c - eBPF uprobes for TLS interception in Go and OpenSSL apps.
// Uses a per-CPU array as scratch buffer (not ringbuf) to avoid verifier
// issues with ringbuf_mem pointer tracking in loops.
// Supports both x86_64 and ARM64 architectures.
// Host filtering uses DNS-verified connect-time resolution.

// Include arch-specific vmlinux.h (generated, committed per-arch).
#if defined(__TARGET_ARCH_x86) || defined(__x86_64__) || defined(__amd64__)
#include "vmlinux_x86.h"
#else
#include "vmlinux_arm64.h"
#endif
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
  __u8 _pad[3];
  __u8 matched_key[8]; // first 8 bytes of matched secret prefix
};

// Debug counters for diagnosing DNS interception issues.
// Index: see DBG_* constants below.
enum {
  DBG_KPROBE_ENTRY = 0,       // udp_recvmsg kprobe entered
  DBG_KPROBE_TRACKED,         // tracked_tgids hit
  DBG_KPROBE_DPORT53,         // skc_dport == 53
  DBG_KPROBE_DPORT0,          // skc_dport == 0 (unconnected)
  DBG_KPROBE_DPORT_OTHER,     // skc_dport != 53 and != 0
  DBG_KPROBE_IOV_OK,          // iov_base read successfully
  DBG_KRETPROBE_ENTRY,        // kretprobe entered (has pending)
  DBG_KRETPROBE_RET_SMALL,    // ret <= 12
  DBG_KRETPROBE_READ_FAIL,    // bpf_probe_read_user failed
  DBG_KRETPROBE_READ_OK,      // packet read into scratch
  DBG_DNS_PARSE_ENTRY,        // do_dns_parse entered
  DBG_DNS_NOT_RESPONSE,       // QR bit not set or RCODE != 0
  DBG_DNS_NO_ANSWERS,         // qdcount < 1 or ancount < 1
  DBG_DNS_QNAME_FAIL,         // qname decode failed
  DBG_DNS_NOT_WATCHED,        // hostname not in watched_hosts
  DBG_DNS_WATCHED_HIT,        // hostname IS in watched_hosts
  DBG_DNS_ANSWER_STORED,      // A/AAAA record stored in dns_ip_map
  DBG_PHASE2_ENTERED,         // phase2_rewrite entered
  DBG_RESOLVE_SSL_FD_HIT,     // ssl_fd_map cache hit
  DBG_RESOLVE_LAST_VFD_HIT,   // last_verified_fd hit
  DBG_RESOLVE_FD_SCAN_HIT,    // fd scan found DNS-verified connection
  DBG_RESOLVE_NO_FD,          // no fd found at all
  DBG_RESOLVE_NO_CONN,        // fd found but no conn_ip_map entry
  DBG_RESOLVE_NO_DNS,         // conn found but IP not in dns_ip_map
  DBG_RESOLVE_HOST_OK,        // hostname resolved successfully
  DBG_MAX,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 32); // must be >= DBG_MAX
  __type(key, __u32);
  __type(value, __u64);
} debug_counters SEC(".maps");

static __always_inline void dbg_inc(__u32 idx) {
  __u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
  if (val)
    __sync_fetch_and_add(val, 1);
}

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

// DNS-verified IP -> hostname mapping (global, not per-process).
// Populated by kretprobe_udp_recvmsg when a DNS response contains an A/AAAA
// record whose qname is in watched_hosts. Global because in containerized
// environments (k3d/Docker), DNS may be resolved by a proxy process.
struct dns_ip_key {
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

// Scratch for kprobe udp_recvmsg enter->return correlation.
// Saves the user buffer pointer from msghdr on entry so the
// kretprobe can read the DNS response after it's been copied.
struct udp_recv_pending {
  __u64 iov_base;  // user buffer (first iovec base)
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);   // pid_tgid
  __type(value, struct udp_recv_pending);
} udp_recv_scratch SEC(".maps");

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

// Per-CPU scratch buffer for DNS packet parsing.
// Also carries tgid/pkt_len for the tail-called dns_parse_packet program.
struct dns_scratch_buf {
  char pkt[MAX_DNS_PKT];
  __u32 pkt_len;
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
// Container process lifecycle tracking
// =============================================================================

// Tracked container cgroups: cgroup inode ID -> enabled.
// Populated from userspace when a container is discovered by the reconciler.
// Used by sched_process_exec/exit tracepoints to filter events to tracked containers.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u64);  // cgroup id (inode)
  __type(value, __u8); // 1 = tracked
} tracked_cgroups SEC(".maps");

// Cgroup array for bpf_current_task_under_cgroup() ancestor check.
// Index 0 holds the fd of the kubepods ancestor cgroup. The exec
// tracepoint uses this to catch ALL container execs without needing
// individual container cgroup IDs to be pre-registered.
struct {
  __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} cgroup_ancestor SEC(".maps");

// Ring buffer for process lifecycle events (exec) to notify userspace.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 1024);
} proc_events SEC(".maps");

// Event sent to userspace when a tracked process execs a new binary.
struct kloak_proc_event {
  __u32 tgid;
  __u8 type; // 1 = exec, 2 = exit
  __u8 _pad[3];
  __u64 cgroup_id;
};

// Check if a dns_ip_map entry has expired based on its TTL.
// Returns 1 if expired, 0 if still valid. TTL of 0 means never expires.
static __always_inline int dns_entry_expired(struct dns_ip_val *div) {
  if (div->ttl_sec == 0)
    return 0;
  __u64 age_ns = bpf_ktime_get_ns() - div->inserted_at;
  __u64 ttl_ns = (__u64)div->ttl_sec * 1000000000ULL;
  return age_ns > ttl_ns;
}

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



// barrier_var prevents the compiler from eliminating the AND mask below.
// After "if (offset >= MAX_DNS_PKT) return 0", the compiler proves
// offset < 512 and would optimize away "offset & 511" as a no-op.
// The BPF verifier then sees an unbounded pointer arithmetic operation.
// This asm barrier breaks the compiler's value-range reasoning.
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var) : :)
#endif

// Context for dns_skip_name bpf_loop callback.
struct skip_name_ctx {
  __u32 off;
  __u32 pkt_len;
  __u32 result; // 0 = still running, >0 = final offset (success), set to pkt_len+1 on error
};

// bpf_loop callback: skip one label of a DNS name.
static int skip_name_step(__u32 idx, void *ctx) {
  struct skip_name_ctx *sctx = (struct skip_name_ctx *)ctx;
  if (sctx->result)
    return 1; // already done

  __u32 off = sctx->off;
  if (off >= sctx->pkt_len || off >= MAX_DNS_PKT) {
    sctx->result = sctx->pkt_len + 1; // error
    return 1;
  }

  __u32 zero = 0;
  struct dns_scratch_buf *dbuf = bpf_map_lookup_elem(&dns_scratch, &zero);
  if (!dbuf) { sctx->result = sctx->pkt_len + 1; return 1; }

  barrier_var(off);
  __u8 b = (__u8)dbuf->pkt[off & (MAX_DNS_PKT - 1)];

  if (b == 0) {
    sctx->result = off + 1;
    return 1;
  }
  if ((b & 0xC0) == 0xC0) {
    sctx->result = off + 2;
    return 1;
  }
  if ((b & 0xC0) != 0) {
    sctx->result = sctx->pkt_len + 1; // reserved bits = error
    return 1;
  }
  __u32 next = off + 1 + (__u32)b;
  if (next > sctx->pkt_len || next > MAX_DNS_PKT) {
    sctx->result = sctx->pkt_len + 1;
    return 1;
  }
  sctx->off = next;
  return 0;
}

// Skip a DNS name in compressed wire format. Returns new offset, or 0 on error.
static __always_inline __u32 dns_skip_name(__u32 pkt_len, __u32 off) {
  struct skip_name_ctx sctx = { .off = off, .pkt_len = pkt_len, .result = 0 };
  bpf_loop(64, skip_name_step, &sctx, 0);
  if (sctx.result == 0 || sctx.result > pkt_len)
    return 0;
  return sctx.result;
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

// Context passed to each bpf_loop callback for DNS answer parsing.
struct dns_answer_ctx {
  __u32 off;
  __u32 pkt_len;
  __u16 ancount;
  __u32 qname_len;
  __u32 answers_processed;
  char qname[MAX_HOST_LEN];
};

// bpf_loop callback: parse one DNS answer record.
// Reads from dns_scratch per-CPU buffer (must re-lookup per frame for verifier).
static int parse_dns_answer(__u32 idx, void *ctx) {
  struct dns_answer_ctx *actx = (struct dns_answer_ctx *)ctx;

  if (actx->answers_processed >= actx->ancount)
    return 1; // stop
  if (actx->off >= actx->pkt_len)
    return 1;

  // Re-lookup per-CPU scratch buffer (verifier requires per-frame)
  __u32 zero = 0;
  struct dns_scratch_buf *dbuf = bpf_map_lookup_elem(&dns_scratch, &zero);
  if (!dbuf)
    return 1;
  const char *pkt = dbuf->pkt;
  __u32 pkt_len = actx->pkt_len;
  __u32 off = actx->off;

  // Skip the answer name (may be compressed)
  off = dns_skip_name(pkt_len, off);
  if (off == 0 || off + 10 > pkt_len || off + 10 > MAX_DNS_PKT)
    return 1;

  // Read TYPE/CLASS/TTL/RDLENGTH (10 bytes).
  if (off + 10 > pkt_len || off > 502)
    return 1;
  barrier_var(off);
  __u32 rr_base = off & (MAX_DNS_PKT - 1);
  if (rr_base + 10 > MAX_DNS_PKT)
    return 1;
  __u8 rr_hdr[10];
  for (int k = 0; k < 10; k++)
    rr_hdr[k] = (__u8)pkt[rr_base + k];
  __u16 rtype = ((__u16)rr_hdr[0] << 8) | (__u16)rr_hdr[1];
  __u32 ttl = ((__u32)rr_hdr[4] << 24) | ((__u32)rr_hdr[5] << 16) |
              ((__u32)rr_hdr[6] << 8) | (__u32)rr_hdr[7];
  __u16 rdlength = ((__u16)rr_hdr[8] << 8) | (__u16)rr_hdr[9];
  off += 10;

  if (off + rdlength > pkt_len || off + rdlength > MAX_DNS_PKT)
    return 1;

  // A record (type 1, rdlength 4)
  if (rtype == 1 && rdlength == 4) {
    if (off + 4 > MAX_DNS_PKT) return 1;
    barrier_var(off);
    __u32 a_off = off & (MAX_DNS_PKT - 1);
    if (a_off + 4 > MAX_DNS_PKT) return 1;
    struct dns_ip_key dik;
    __builtin_memset(&dik, 0, sizeof(dik));
    ipv4_to_mapped(dik.ip, (__u8 *)(pkt + a_off));

    struct dns_ip_val div;
    __builtin_memset(&div, 0, sizeof(div));
    __builtin_memcpy(div.hostname, actx->qname, MAX_HOST_LEN);
    div.host_len = actx->qname_len;
    div.ttl_sec = ttl;
    div.inserted_at = bpf_ktime_get_ns();

    bpf_map_update_elem(&dns_ip_map, &dik, &div, BPF_ANY);
    dbg_inc(DBG_DNS_ANSWER_STORED);

  }

  // AAAA record (type 28, rdlength 16)
  if (rtype == 28 && rdlength == 16) {
    if (off + 16 > MAX_DNS_PKT) return 1;
    barrier_var(off);
    __u32 aaaa_off = off & (MAX_DNS_PKT - 1);
    if (aaaa_off + 16 > MAX_DNS_PKT) return 1;
    struct dns_ip_key dik;
    __builtin_memset(&dik, 0, sizeof(dik));
    __builtin_memcpy(dik.ip, pkt + aaaa_off, 16);

    struct dns_ip_val div;
    __builtin_memset(&div, 0, sizeof(div));
    __builtin_memcpy(div.hostname, actx->qname, MAX_HOST_LEN);
    div.host_len = actx->qname_len;
    div.ttl_sec = ttl;
    div.inserted_at = bpf_ktime_get_ns();

    bpf_map_update_elem(&dns_ip_map, &dik, &div, BPF_ANY);
    dbg_inc(DBG_DNS_ANSWER_STORED);

  }

  off += rdlength;
  actx->off = off;
  actx->answers_processed++;
  return 0; // continue
}

// Tail-called DNS parser program (slot 1 in prog_array).
// Reads packet from dns_scratch_buf (per-CPU), parses the DNS response,
// and stores A/AAAA records in dns_ip_map for watched hostnames.
// Separated from kretprobe_udp_recvmsg to stay under the verifier's
// 1M instruction limit on x86_64.
// Parse DNS response from dns_scratch per-CPU buffer.
// __noinline to keep it as a single BPF subprogram, reducing verifier cost.
static __noinline void do_dns_parse(void) {
  dbg_inc(DBG_DNS_PARSE_ENTRY);
  __u32 zero = 0;
  struct dns_scratch_buf *dbuf = bpf_map_lookup_elem(&dns_scratch, &zero);
  if (!dbuf)
    return;

  const char *pkt = dbuf->pkt;
  __u32 pkt_len = dbuf->pkt_len;

  if (pkt_len < 12)
    return;

  __u8 flags0 = (__u8)pkt[2];
  __u8 flags1 = (__u8)pkt[3];
  if (!(flags0 & 0x80)) { dbg_inc(DBG_DNS_NOT_RESPONSE); return; }
  if ((flags1 & 0x0F) != 0) { dbg_inc(DBG_DNS_NOT_RESPONSE); return; }

  __u16 qdcount = ((__u16)(__u8)pkt[4] << 8) | (__u16)(__u8)pkt[5];
  __u16 ancount = ((__u16)(__u8)pkt[6] << 8) | (__u16)(__u8)pkt[7];

  if (qdcount < 1 || ancount < 1) { dbg_inc(DBG_DNS_NO_ANSWERS); return; }

  char qname[MAX_HOST_LEN];
  __builtin_memset(qname, 0, sizeof(qname));
  __u32 qname_len = dns_decode_qname(pkt, pkt_len, 12, qname, MAX_HOST_LEN);
  if (qname_len == 0 || qname_len > MAX_HOST_LEN) { dbg_inc(DBG_DNS_QNAME_FAIL); return; }

  struct watched_host_key wk;
  __builtin_memset(&wk, 0, sizeof(wk));
  __builtin_memcpy(wk.host, qname, MAX_HOST_LEN);
  __u8 *watched = bpf_map_lookup_elem(&watched_hosts, &wk);
  if (!watched) { dbg_inc(DBG_DNS_NOT_WATCHED); return; }
  dbg_inc(DBG_DNS_WATCHED_HIT);

  __u32 off = 12;
  off = dns_skip_name(pkt_len, off);
  if (off == 0)
    return;
  off += 4;
  if (off > pkt_len)
    return;

  // Parse answer records using bpf_loop
  struct dns_answer_ctx actx = {
    .off = off,
    .pkt_len = pkt_len,
    .ancount = ancount,
    .qname_len = qname_len,
    .answers_processed = 0,
  };
  __builtin_memcpy(actx.qname, qname, MAX_HOST_LEN);

  bpf_loop(MAX_DNS_ANSWERS, parse_dns_answer, &actx, 0);
}

// =============================================================================
// DNS interception via kprobe on udp_recvmsg (network-level, language-agnostic)
//
// Hooks the kernel's udp_recvmsg() which handles ALL UDP receives regardless
// of which syscall the application uses (read, recvfrom, recvmsg).
// Filters on source port 53 + configured DNS server IPs using kernel sock state.
// =============================================================================

// kprobe/udp_recvmsg: check if this is a DNS socket, save user buffer pointer.
// int udp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
//
// Uses bpf_probe_read_kernel with arch-specific pt_regs offsets (same pattern
// as the uprobe functions) since bpf2go compiles with -target bpfel/bpfeb
// which doesn't support PT_REGS_PARM* / BPF_KPROBE macros.
SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(void *ctx) {
  dbg_inc(DBG_KPROBE_ENTRY);
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  // Read arguments from pt_regs.
  // udp_recvmsg(struct sock *sk, struct msghdr *msg, ...)
  struct sock *sk = NULL;
  struct msghdr *msg = NULL;

#if defined(bpf_target_x86)
  // x86_64 C ABI: RDI=arg1(sk), RSI=arg2(msg)
  // pt_regs offsets: di=112, si=104
  bpf_probe_read_kernel(&sk, sizeof(sk), (char *)ctx + 112);
  bpf_probe_read_kernel(&msg, sizeof(msg), (char *)ctx + 104);
#elif defined(bpf_target_arm64)
  // ARM64 C ABI: X0=arg1(sk), X1=arg2(msg)
  // pt_regs offsets: regs[0]=0, regs[1]=8
  bpf_probe_read_kernel(&sk, sizeof(sk), (char *)ctx + 0);
  bpf_probe_read_kernel(&msg, sizeof(msg), (char *)ctx + 8);
#else
  return 0;
#endif

  if (!sk || !msg)
    return 0;

  // Filter for DNS traffic. For connected UDP sockets (Go, Python), skc_dport
  // is set to 53. For unconnected sockets (Node.js c-ares uses sendto), skc_dport
  // is 0 — we allow those through since tracked_tgids already limits scope, and
  // process_dns_packet validates the DNS response format.
  __be16 dport = 0;
  BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
  if (dport == __bpf_htons(53))
    dbg_inc(DBG_KPROBE_DPORT53);
  else if (dport == 0)
    dbg_inc(DBG_KPROBE_DPORT0);
  else {
    dbg_inc(DBG_KPROBE_DPORT_OTHER);
    return 0;
  }

  __u64 iov_base = 0;
  BPF_CORE_READ_INTO(&iov_base, msg, msg_iter.__ubuf_iovec.iov_base);
  if (!iov_base)
    return 0;
  dbg_inc(DBG_KPROBE_IOV_OK);

  struct udp_recv_pending val = {.iov_base = iov_base};
  bpf_map_update_elem(&udp_recv_scratch, &pid_tgid, &val, BPF_ANY);
  return 0;
}

// kretprobe/udp_recvmsg: read the DNS response from the saved user buffer.
SEC("kretprobe/udp_recvmsg")
int kretprobe_udp_recvmsg(void *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct udp_recv_pending *pending =
      bpf_map_lookup_elem(&udp_recv_scratch, &pid_tgid);
  if (!pending)
    return 0;
  dbg_inc(DBG_KRETPROBE_ENTRY);

  __u64 iov_base = pending->iov_base;
  bpf_map_delete_elem(&udp_recv_scratch, &pid_tgid);

  // Read return value from pt_regs
  long ret = 0;
#if defined(bpf_target_x86)
  bpf_probe_read_kernel(&ret, sizeof(ret), (char *)ctx + 80);
#elif defined(bpf_target_arm64)
  bpf_probe_read_kernel(&ret, sizeof(ret), (char *)ctx + 0);
#else
  return 0;
#endif

  if (ret <= 12) {
    dbg_inc(DBG_KRETPROBE_RET_SMALL);
    return 0;
  }

  __u32 zero = 0;
  struct dns_scratch_buf *dbuf = bpf_map_lookup_elem(&dns_scratch, &zero);
  if (!dbuf)
    return 0;

  __u32 read_len = (__u32)ret;
  if (read_len > MAX_DNS_PKT)
    read_len = MAX_DNS_PKT;

  if (bpf_probe_read_user(dbuf->pkt, read_len, (void *)iov_base) != 0) {
    dbg_inc(DBG_KRETPROBE_READ_FAIL);
    return 0;
  }
  dbg_inc(DBG_KRETPROBE_READ_OK);

  dbuf->pkt_len = read_len;

  do_dns_parse();
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

  // Always record fd -> IP and IP -> {tgid,fd}
  struct conn_ip_key cik = {.tgid = tgid, .fd = fd};
  struct conn_ip_val civ;
  __builtin_memcpy(civ.ip, ip, 16);
  bpf_map_update_elem(&conn_ip_map, &cik, &civ, BPF_ANY);

  // Check if this IP was already DNS-verified
  struct dns_ip_key dik;
  __builtin_memset(&dik, 0, sizeof(dik));
  __builtin_memcpy(dik.ip, ip, 16);

  struct dns_ip_val *div = bpf_map_lookup_elem(&dns_ip_map, &dik);
  if (div && !dns_entry_expired(div)) {
    // DNS-verified connection! Record as last_verified_fd
    bpf_map_update_elem(&last_verified_fd, &tgid, &fd, BPF_ANY);

#ifdef KLOAK_DEBUG
    bpf_printk("kloak connect: tgid=%u fd=%u -> dns-verified host=%s", tgid, fd,
               div->hostname);
#endif
  }

  return 0;
}

// tp/syscalls/sys_enter_close: clean up connection state when an fd is closed.
// Prevents stale conn_ip_map entries from being used after fd reuse.
// close(int fd)
SEC("tracepoint/syscalls/sys_enter_close")
int tp_enter_close(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  __u32 fd = (__u32)ctx->args[0];

  // Clean up conn_ip_map entry for this fd (no-op if fd wasn't a tracked connection)
  struct conn_ip_key cik = {.tgid = tgid, .fd = fd};
  bpf_map_delete_elem(&conn_ip_map, &cik);

  // Clean up last_verified_fd if it pointed to this fd
  __u32 *vfd = bpf_map_lookup_elem(&last_verified_fd, &tgid);
  if (vfd && *vfd == fd)
    bpf_map_delete_elem(&last_verified_fd, &tgid);

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
      dbg_inc(DBG_RESOLVE_SSL_FD_HIT);
    }
  }

  // Path 2: last_verified_fd (fast path if connect happened after DNS)
  if (!found) {
    __u32 *vfd = bpf_map_lookup_elem(&last_verified_fd, &tgid);
    if (vfd) {
      fd = *vfd;
      found = 1;
      dbg_inc(DBG_RESOLVE_LAST_VFD_HIT);

      if (ssl_ptr != 0) {
        struct ssl_fd_key sfk;
        __builtin_memset(&sfk, 0, sizeof(sfk));
        sfk.tgid = tgid;
        sfk.ssl_ptr = ssl_ptr;
        struct ssl_fd_val new_sfv = {.fd = fd};
        bpf_map_update_elem(&ssl_fd_map, &sfk, &new_sfv, BPF_ANY);
      }
    }
  }

  // If we have a cached fd, try it directly
  if (found) {
    struct conn_ip_key cik = {.tgid = tgid, .fd = fd};
    struct conn_ip_val *civ = bpf_map_lookup_elem(&conn_ip_map, &cik);
    if (!civ) { dbg_inc(DBG_RESOLVE_NO_CONN); return; }
    struct dns_ip_key dik;
    __builtin_memset(&dik, 0, sizeof(dik));
    __builtin_memcpy(dik.ip, civ->ip, 16);
    struct dns_ip_val *div = bpf_map_lookup_elem(&dns_ip_map, &dik);
    if (div && !dns_entry_expired(div) && div->host_len > 0 && div->host_len <= MAX_HOST_LEN) {
      __builtin_memcpy(scratch_data->host_value, div->hostname, MAX_HOST_LEN);
      scratch_data->host_value_len = div->host_len;
      dbg_inc(DBG_RESOLVE_HOST_OK);
    } else {
      dbg_inc(DBG_RESOLVE_NO_DNS);
    }
    return;
  }

  // Path 3: No cached fd — scan fds 3..30 in conn_ip_map for a DNS-verified IP.
  // Handles the case where connect() happened before DNS was captured.
  for (__u32 try_fd = 3; try_fd <= 30; try_fd++) {
    struct conn_ip_key cik = {.tgid = tgid, .fd = try_fd};
    struct conn_ip_val *civ = bpf_map_lookup_elem(&conn_ip_map, &cik);
    if (!civ)
      continue;
    struct dns_ip_key dik;
    __builtin_memset(&dik, 0, sizeof(dik));
    __builtin_memcpy(dik.ip, civ->ip, 16);
    struct dns_ip_val *div = bpf_map_lookup_elem(&dns_ip_map, &dik);
    if (div && !dns_entry_expired(div) && div->host_len > 0 && div->host_len <= MAX_HOST_LEN) {
      __builtin_memcpy(scratch_data->host_value, div->hostname, MAX_HOST_LEN);
      scratch_data->host_value_len = div->host_len;
      bpf_map_update_elem(&last_verified_fd, &tgid, &try_fd, BPF_ANY);
      dbg_inc(DBG_RESOLVE_FD_SCAN_HIT);
      return;
    }
  }
  dbg_inc(DBG_RESOLVE_NO_FD);
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
  __u8 matched_key[8]; // last matched secret key prefix
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

    // Check for both plaintext "kloak:" (HTTP/1.1) and HPACK Huffman
    // encoded "kloak:" (HTTP/2). Both use the same 8-byte key lookup
    // into secret_map — plaintext keys start with "kloak:" ASCII,
    // Huffman keys start with the Huffman encoding bytes.
    int matched = 0;
    if (is_kloak_prefix(&scratch_data->data[i]))
      matched = 1;
    else if (is_kloak_prefix_huffman((const unsigned char *)&scratch_data->data[i]))
      matched = 1;

    if (!matched)
      continue;

    // 8-byte key lookup. For plaintext: "kloak:" + 2 UUID chars.
    // For Huffman: first 8 bytes of Huffman-encoded shadow value.
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
    __builtin_memcpy(sctx->matched_key, key.prefix, 8);
  }
  return 0;
}

SEC("uprobe/phase2_rewrite")
int bpf_phase2_rewrite(void *ctx) {
  dbg_inc(DBG_PHASE2_ENTERED);
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
      __builtin_memcpy(event->matched_key, sctx.matched_key, 8);
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
  // No cgroup filter — Go uprobes use PID-scoped attachment because
  // Go binaries are statically linked (unique per container).

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
  // Filter by cgroup: only intercept processes in tracked containers.
  __u64 cgroup_id = bpf_get_current_cgroup_id();
  if (!bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id))
    return 0;

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

// =============================================================================
// Container process lifecycle tracepoints
// =============================================================================

// tp/sched/sched_process_exec: detect when a process in a tracked container
// execs a new binary. Notifies userspace via ring buffer to attach uprobes.
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
  // Check if the process is under the kubepods cgroup hierarchy.
  // This catches ALL container execs without needing per-container cgroup
  // tracking, eliminating the timing gap where the reconciler hasn't yet
  // registered the container's cgroup. Userspace filters by pod annotation.
  if (bpf_current_task_under_cgroup(&cgroup_ancestor, 0) != 1)
    return 0;

  __u64 cgroup_id = bpf_get_current_cgroup_id();

  __u32 tgid = ctx->pid; // pid field is the TGID in this context

  // Ensure the new process is in tracked_tgids for DNS/connect tracking
  __u8 val = 1;
  bpf_map_update_elem(&tracked_tgids, &tgid, &val, BPF_ANY);

  // Notify userspace to attach uprobes to the new binary
  struct kloak_proc_event *evt = bpf_ringbuf_reserve(&proc_events, sizeof(*evt), 0);
  if (evt) {
    evt->tgid = tgid;
    evt->type = 1; // exec
    evt->cgroup_id = cgroup_id;
    bpf_ringbuf_submit(evt, 0);
  }
  return 0;
}

// tp/sched/sched_process_exit: clean up stale map entries when a tracked
// process exits. Prevents map pollution from dead processes.
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
  __u64 cgroup_id = bpf_get_current_cgroup_id();
  __u8 *tracked = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
  if (!tracked)
    return 0;

  __u32 tgid = ctx->pid;

  // Clean up tracked_tgids
  bpf_map_delete_elem(&tracked_tgids, &tgid);

  // Clean up last_verified_fd
  bpf_map_delete_elem(&last_verified_fd, &tgid);

  // Clean up ssl_fd_map entries for this tgid.
  // We cannot iterate the LRU map in BPF, so we rely on LRU eviction
  // for ssl_fd_map and conn_ip_map entries keyed by (tgid, *).
  // The LRU will naturally evict stale entries over time.

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
