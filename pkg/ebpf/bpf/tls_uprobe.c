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
// The prescan uses bpf_loop() to scan the full SSL_write buffer in
// MAX_DATA_SIZE-byte chunks with SECRET_KEY_LEN-1 overlap, so there is no
// upper limit on the buffer size that can be scanned.
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
// Max host length for matching
#define MAX_HOST_LEN 64
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
  __u64 ssl_ptr;        // SSL* or Go *tls.Conn pointer; used by XOR path tail call
  __u32 read_len;       // bytes read into data[] (max 256, for host parsing)
  __u32 total_data_len; // full TLS write length (for bpf_loop scanning)
  __u8  chain_type;     // 0=OpenSSL/BoringSSL, CHAIN_GO_TLS=Go crypto/tls
  __u32 host_offset;
  __u32 host_value_len; // length of extracted host value
  __u32 xor_fd;         // socket fd resolved by resolve_host (for tc_pending key)
  // Multiple secret matches per SSL_write (up to 4).
  // xor_path processes one match per invocation and tail-calls back to itself.
  #define XOR_MAX_MATCHES 4
  __u32 xor_match_count;   // total matches found by pre-scan
  __u32 xor_current_match; // index of the next match to process
  struct {
    __u32 pos;                    // byte offset of kloak: prefix in data[]
    struct secret_key key;        // 8-byte key prefix
  } xor_matches[XOR_MAX_MATCHES];
  char host_value[MAX_HOST_LEN]; // host from DNS chain
  char data[MAX_DATA_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratch_buf);
} scratch SEC(".maps");

// Tail-call program array:
//   index 1 = bpf_xor_path (AES-GCM ciphertext patching path)
//   index 2 = bpf_h_extract (GHASH key H extraction on first SSL_write)
//   index 3 = bpf_go_write_path (Go plaintext patching — writes real secrets directly)
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 4); // indices 1, 2, and 3 used
  __type(key, __u32);
  __type(value, __u32);
} prog_array SEC(".maps");

// Tail-call array for tc programs:
//   index 0 = tc_ghash_update (GHASH tag recomputation in kernel skb)
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} tc_prog_array SEC(".maps");

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
  DBG_RESOLVE_SSL_FD_HIT,     // ssl_fd_map cache hit
  DBG_RESOLVE_LAST_VFD_HIT,   // last_verified_fd hit
  DBG_RESOLVE_FD_SCAN_HIT,    // fd scan found DNS-verified connection
  DBG_RESOLVE_NO_FD,          // no fd found at all
  DBG_RESOLVE_NO_CONN,        // fd found but no conn_ip_map entry
  DBG_RESOLVE_NO_DNS,         // conn found but IP not in dns_ip_map
  DBG_RESOLVE_HOST_OK,        // hostname resolved successfully
  DBG_XOR_CONN_CHECK,         // entry uprobe checked tls_conn_state
  DBG_XOR_CONN_HIT,           // tls_conn_state found + AES-GCM confirmed
  DBG_XOR_PRESCAN_MATCH,      // pre-scan found kloak: prefix
  DBG_XOR_TAILCALL,           // tail-called to xor_path
  DBG_XOR_PATH_ENTERED,       // bpf_xor_path entered
  DBG_XOR_SECRET_FOUND,       // secret_map lookup succeeded in xor_path
  DBG_XOR_DELTA_DONE,         // XOR delta computed and stored in tc_pending
  DBG_TC_ENTRY,               // tc egress program entered (any packet)
  DBG_TC_MATCH,               // tc_pending lookup matched
  DBG_TC_PATCHED,             // tc XOR patch applied to skb
  DBG_KPROBE_BRIDGE,          // kprobe successfully bridged xor_pending → tc_pending
  DBG_KPROBE_BRIDGE_NO_ENTRY, // kprobe found no xor_pending entry
  DBG_KPROBE_BRIDGE_H_FAIL,   // kprobe H extraction failed (no tc_pending written)
  DBG_MAX,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 64); // must be >= DBG_MAX
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
// Populated by the exec tracepoint for all kubepods processes.
// Sized for busy clusters with many concurrent container processes.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
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
  __uint(max_entries, 16384);
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

// =============================================================================
// TLS AES-GCM XOR-patch maps (post-encryption ciphertext patching)
//
// When the negotiated cipher is AES-GCM, the entry uprobe does NOT rewrite the
// plaintext buffer. Instead it computes XOR deltas and stores them in tc_pending.
// A tc egress program patches the ciphertext + GHASH auth tag entirely in kernel
// skb memory. The real secret never exists in user-space memory.
// =============================================================================

// Per-connection TLS state: GHASH key H and cipher suite.
// Populated by the entry uprobe on first SSL_write (reads H from SSL struct at
// a userspace-configured offset), then enriched by the controller with the
// precomputed H power table.
struct tls_conn_key {
  __u32 tgid;
  __u32 _pad;
  __u64 ssl_ptr;
};

struct tls_conn_state {
  __u8  ghash_h[16];         // GHASH key H = AES(K, 0^128)
  __u8  h_powers[16][16];    // H^(2^i) for i=0..10 (padded to 16 for bitmask bounds)
  __u16 cipher_type;        // KLOAK_CIPHER_AES_GCM or KLOAK_CIPHER_UNKNOWN
  __u8  h_powers_ready;      // 1 = userspace has pushed precomputed H powers
  __u8  _pad[1];
  __u64 wrl_ptr;             // cached first pointer in chain — changes on session recycle
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct tls_conn_key);
  __type(value, struct tls_conn_state);
} tls_conn_state SEC(".maps");

// A single XOR patch entry (one secret match within a TLS record).
struct xor_patch {
  __u32 secret_offset;      // byte offset of secret in plaintext
  __u32 secret_len;         // length of secret (1..128)
  __u8  xor_delta[SECRET_MAX_LEN]; // shadow[i] ^ real[i]
};

// Per-thread pending XOR patches. Supports multiple secrets per SSL_write.
#define XOR_MAX_PATCHES 4
struct xor_pending_val {
  __u64 ssl_ptr;
  __u32 tgid;
  __u32 patch_count;        // number of valid patches (0..XOR_MAX_PATCHES)
  struct xor_patch patches[XOR_MAX_PATCHES];
  __u8  active;
  __u8  chain_type;         // 0=OpenSSL/BoringSSL, CHAIN_GO_TLS=Go crypto/tls
  __u8  _pad[2];
  __u32 plaintext_len;      // SSL_write data length (for TLS version detection in tc)
};

// Per-thread pending XOR patches, keyed by pid_tgid.
// Written by the uprobe (xor_path), read by the tcp_sendmsg kprobe which
// bridges to tc_pending with the per-connection (dst_ip, src_port) key.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);  // pid_tgid
  __type(value, struct xor_pending_val);
} xor_pending SEC(".maps");

// Userspace-configured struct offsets for extracting TLS key material.
// Populated once per library at uprobe attach time after the controller
// detects the OpenSSL version. Supports a 4-level pointer chain:
//   SSL* + off1 → wrl* + off2 → enc_ctx* + off3 → algctx* + off4 → H (16 bytes)
// For OpenSSL 3.2+, the record layer refactoring added an extra hop.
struct tls_offsets {
  __u32 ssl_to_wrl;         // SSL* + off → OSSL_RECORD_LAYER* (pointer deref)
  __u32 wrl_to_enc_ctx;     // wrl* + off → EVP_CIPHER_CTX* (pointer deref)
  __u32 enc_ctx_to_algctx;  // enc_ctx* + off → algctx/PROV_GCM_CTX* (pointer deref)
  __u32 algctx_to_h;        // algctx* + off → H (16 bytes, direct read)
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct tls_offsets);
} tls_offset_config SEC(".maps");

// Go crypto/tls struct offsets for H extraction.
// Keyed by TGID (per-process), allowing different Go versions to coexist.
//
// H extraction chain (3 pointer dereferences + GF halving):
//   Conn + conn_to_cipher → cipher interface data_ptr (1st deref)
//     → prefixNonceAEAD/xorNonceAEAD + aead_iface_off → aead interface data_ptr (2nd deref)
//       → GCM + h2_hi_off / h2_lo_off → H×2 (two 64-bit words from productTable[224])
//
// Go's gcmAesInit assembly computes H = AES_K(0^128), byte-swaps, then doubles
// in GF(2^128) before storing in productTable at offset 224. We read the two
// 64-bit words (arch-dependent order: AMD64 PSHUFB vs ARM64 VREV64) and apply
// GF(2^128) halving to recover the standard big-endian GHASH H key.
//
// conn_to_cipher combines Conn.out offset + halfConn.cipher offset + 8 (interface data_ptr).
// aead_iface_off is the offset to the inner aead interface data_ptr within the AEAD wrapper.
#define CHAIN_GO_TLS 2

struct go_tls_offsets {
  __u32 conn_to_cipher;   // Conn* + off → halfConn.cipher interface data_ptr (combined offset)
  __u32 aead_iface_off;   // wrapper + off → inner aead interface data_ptr
  __u32 h2_hi_off;        // GCM* + off → high 64 bits of H×2 (byte-swapped, arch-dependent)
  __u32 h2_lo_off;        // GCM* + off → low 64 bits of H×2 (byte-swapped, arch-dependent)
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u32);
  __type(value, struct go_tls_offsets);
} go_tls_offset_config SEC(".maps");

// Per-CPU scratch space for XOR-path programs (bpf_xor_path + tcp_sendmsg kprobe).
// tc egress struct definitions (needed by ghash_work below and tc maps further down).
struct tc_dest_key {
  __u8  dst_ip[16]; // IPv4-mapped-IPv6 or native IPv6
  __u16 src_port;   // source port (network byte order) — unique per connection
  __u16 _pad;
  __u64 cgroup_id;  // per-container isolation
};

struct tc_pending_val {
  __u32 tgid;
  __u64 ssl_ptr;
  __u32 patch_count;
  struct xor_patch patches[XOR_MAX_PATCHES];
  __u8  active;
  __u8  _pad[3];
  __u32 plaintext_len;      // SSL_write data length (for TLS version detection)
};

// Holds all large structs and buffers that would otherwise exceed the 512-byte
// BPF stack limit, including staging areas for map updates and GF(2^128) state.
struct ghash_work {
  // Staging for map updates (avoids large structs on BPF stack)
  struct tls_conn_state staged_conn;     // for tls_conn_state map insert
  struct xor_pending_val staged_pending; // staging area for patch accumulation
  struct tc_pending_val staged_tc;       // for tc_pending map insert
  // Ciphertext patching buffers
  __u8 ct_buf[SECRET_MAX_LEN]; // Ciphertext chunk for XOR patching
  __u8 old_tag[16];            // Original auth tag from TLS record
  __u8 tag_delta[16];          // Accumulated tag correction
  __u8 new_tag[16];            // Patched auth tag
  __u8 block_delta[16];        // Per-block XOR delta
  __u8 h_pow[16];              // H^power for current block
  __u8 contrib[16];            // block_delta * H^power result
  __u8 mul_a[16];              // gf128_mul input: operand a
  __u8 mul_v[16];              // gf128_mul internal: shifting register
  __u8 mul_z[16];              // gf128_mul internal: accumulator
  __u8 hp_base[16];            // gf128_h_power internal: base
  __u8 hp_tmp[16];             // gf128_h_power internal: temporary
  // Metadata for GHASH tag recomputation (tc egress path):
  __u32 ghash_ct_len;          // ciphertext length (excluding tag)
  __u32 ghash_tgid;            // tgid for tls_conn_state lookup
  __u64 ghash_ssl_ptr;         // ssl_ptr for tls_conn_state lookup
  __u32 ghash_secret_offset;   // byte offset of secret in plaintext
  __u32 ghash_patch_len;       // length of patched region
  __u32 ghash_nonce_len;       // TLS explicit nonce length (8 for TLS 1.2, 0 for TLS 1.3)
  __u32 ghash_payload_off;     // TCP payload offset within skb
  __u8  ghash_xor_delta[SECRET_MAX_LEN]; // copy of xor_delta for block computation
  __u8  ghash_active;          // 1 = GHASH update needed
  __u8  _ghash_pad[3];
  __u32 ghash_first_block;     // first changed block index
  __u32 ghash_ct_blocks;       // total ciphertext blocks
  // h_powers_cache moved to separate h_power_entries per-CPU array map
  __u32 ghash_h_power_val;      // power value for h_power_step callback
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct ghash_work);
} ghash_scratch SEC(".maps");

// Per-CPU array of H^(2^i) power entries (16 bytes each).
// Separate map so callbacks can look up individual entries without
// array indexing into ghash_work (which the verifier can't bound).
struct h_power_entry {
  __u8 val[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 16);
  __type(key, __u32);
  __type(value, struct h_power_entry);
} h_power_entries SEC(".maps");

// =============================================================================
// tc egress: pending XOR patch map keyed by TCP 4-tuple.
// Populated by the entry uprobe, consumed by the tc egress BPF program.
// The tc program modifies kernel skb data (not user-space memory), so the
// encrypted real secret never exists in user-space memory.
// =============================================================================

// tc_pending map: keyed by (dst_ip, src_port, cgroup_id, tcp_seq).
// Each TLS record gets a unique entry (tcp_seq prevents keep-alive overwrites).
// LRU evicts stale entries from connections that closed without consuming.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct tc_dest_key);
  __type(value, struct tc_pending_val);
} tc_pending SEC(".maps");

// =============================================================================

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

// Offsets for reading fd from SSL struct's BIO (stable across OpenSSL 3.x).
// SSL_CONNECTION.wbio → BIO*, BIO.num → int fd
// Verified via pahole: identical on aarch64 and x86_64, OpenSSL 3.0-3.5.
#define SSL_WBIO_OFFSET 88  // offsetof(ssl_connection_st, wbio) for 3.2+
#define BIO_NUM_OFFSET  56  // offsetof(bio_st, num)

// Read the socket fd directly from the SSL struct's write BIO.
// Returns the fd, or 0 if the read fails.
static __always_inline __u32 ssl_read_fd(__u64 ssl_ptr) {
  if (!ssl_ptr) return 0;
  __u64 wbio = 0;
  if (bpf_probe_read_user(&wbio, 8, (void *)(ssl_ptr + SSL_WBIO_OFFSET)) < 0 || !wbio)
    return 0;
  __u32 fd = 0;
  if (bpf_probe_read_user(&fd, 4, (void *)(wbio + BIO_NUM_OFFSET)) < 0)
    return 0;
  return fd;
}

// =============================================================================
// Resolve host for the current SSL/TLS connection using DNS chain.
//
// Chain: ssl_fd_map (cache) -> BIO fd read -> last_verified_fd -> conn_ip_map -> dns_ip_map
// =============================================================================
static __always_inline void resolve_host(struct scratch_buf *scratch_data,
                                         __u64 ssl_ptr) {
  scratch_data->host_offset = 0;
  scratch_data->host_value_len = 0;
  scratch_data->xor_fd = 0;
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

  // Path 2: Read fd directly from the SSL struct's BIO.
  // This covers new connections where ssl_fd_map hasn't been populated yet
  // (e.g., raw TLS sockets, first SSL_write on a fresh connection).
  if (!found && ssl_ptr != 0) {
    __u32 bio_fd = ssl_read_fd(ssl_ptr);
    if (bio_fd > 0) {
      fd = bio_fd;
      found = 1;
      // Cache it in ssl_fd_map for subsequent SSL_writes on same connection.
      struct ssl_fd_key sfk;
      __builtin_memset(&sfk, 0, sizeof(sfk));
      sfk.tgid = tgid;
      sfk.ssl_ptr = ssl_ptr;
      struct ssl_fd_val new_sfv = {.fd = fd};
      bpf_map_update_elem(&ssl_fd_map, &sfk, &new_sfv, BPF_ANY);
      dbg_inc(DBG_RESOLVE_SSL_FD_HIT);
    }
  }

  // Path 3: last_verified_fd (fast path if connect happened after DNS)
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
    scratch_data->xor_fd = fd;
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
      scratch_data->xor_fd = try_fd;
      bpf_map_update_elem(&last_verified_fd, &tgid, &try_fd, BPF_ANY);
      dbg_inc(DBG_RESOLVE_FD_SCAN_HIT);
      return;
    }
  }
  dbg_inc(DBG_RESOLVE_NO_FD);
}

// -----------------------------------------------------------------------------
// Prescan: bpf_loop callback to find all kloak: prefixes in the SSL_write buffer.
// Scans in MAX_DATA_SIZE chunks with SECRET_KEY_LEN-1 overlap so that tokens
// straddling chunk boundaries are always detected. Match positions are stored as
// global byte offsets (relative to the start of the SSL_write buffer).
// -----------------------------------------------------------------------------

struct prescan_ctx {
  __u64 user_data_ptr;
  __u32 total_len;
};

static int prescan_chunk(__u32 chunk_idx, void *ctx) {
  struct prescan_ctx *pctx = (struct prescan_ctx *)ctx;

  __u32 offset = chunk_idx * CHUNK_STRIDE;
  if (offset >= pctx->total_len)
    return 1; // stop

  __u32 zero = 0;
  struct scratch_buf *sd = bpf_map_lookup_elem(&scratch, &zero);
  if (!sd)
    return 1;

  if (sd->xor_match_count >= XOR_MAX_MATCHES)
    return 1; // already found max matches

  __u32 read_len = pctx->total_len - offset;
  if (read_len > MAX_DATA_SIZE)
    read_len = MAX_DATA_SIZE;

  bpf_probe_read_user(sd->data, read_len,
                      (void *)(pctx->user_data_ptr + offset));

  __u32 scan_limit = read_len >= SECRET_KEY_LEN ? read_len - SECRET_KEY_LEN + 1 : 0;
  for (__u32 i = 0; i < MAX_DATA_SIZE && i < scan_limit; i++) {
    if (sd->xor_match_count >= XOR_MAX_MATCHES)
      break;

    __u32 si = i & (MAX_DATA_SIZE - 1); // verifier-friendly bitmask
    if (is_kloak_prefix(&sd->data[si]) ||
        is_kloak_prefix_huffman((const unsigned char *)&sd->data[si])) {
      __u32 idx = sd->xor_match_count;
      if (idx >= XOR_MAX_MATCHES) break;
      sd->xor_matches[idx & (XOR_MAX_MATCHES - 1)].pos = offset + i;
      __builtin_memcpy(sd->xor_matches[idx & (XOR_MAX_MATCHES - 1)].key.prefix,
                       &sd->data[si], SECRET_KEY_LEN);
      sd->xor_match_count = idx + 1;
      dbg_inc(DBG_XOR_PRESCAN_MATCH);
    }
  }

  return 0;
}

// =============================================================================
// TLS 1.3 AES-GCM XOR-patch path
//
// When the connection uses AES-GCM, the entry uprobe does NOT write the real
// secret to user memory. Instead it computes XOR deltas and stores them in
// tc_pending. A tc egress program patches the ciphertext and recomputes the
// GHASH auth tag entirely in kernel skb memory.
// =============================================================================

// Tail-called XOR-path program (index 1 in prog_array).
// Reads ssl_ptr from scratch_buf, checks for AES-GCM, computes the XOR delta,
// and stores patches in tc_pending for the tc egress program.
// Has its own verifier budget and 512-byte stack (separate from the entry uprobe).

// =============================================================================
// H extraction — tail-called on first SSL_write per connection.
// Follows 4-step pointer chain: SSL* → wrl* → enc_ctx* → algctx* → H
// Stores H in tls_conn_state. Next SSL_write uses cached state → xor_path.
// =============================================================================

SEC("uprobe/h_extract")
int bpf_h_extract(void *ctx) {
  __u32 zero = 0;
  struct scratch_buf *sd = bpf_map_lookup_elem(&scratch, &zero);
  if (!sd)
    return 0;

  __u64 ssl_ptr = sd->ssl_ptr;
  if (!ssl_ptr)
    return 0;

  struct tls_offsets *offsets = bpf_map_lookup_elem(&tls_offset_config, &zero);
  if (!offsets || offsets->ssl_to_wrl == 0)
    return 0;

  // 4-step pointer chase: SSL* → wrl* → enc_ctx* → algctx* → H
  __u64 wrl_ptr = 0;
  if (bpf_probe_read_user(&wrl_ptr, 8, (void *)(ssl_ptr + offsets->ssl_to_wrl)) < 0 || !wrl_ptr)
    return 0;
  __u64 ptr = wrl_ptr;
  if (bpf_probe_read_user(&ptr, 8, (void *)(ptr + offsets->wrl_to_enc_ctx)) < 0 || !ptr)
    return 0;
  if (bpf_probe_read_user(&ptr, 8, (void *)(ptr + offsets->enc_ctx_to_algctx)) < 0 || !ptr)
    return 0;

  // Read H directly into a stack-allocated tls_conn_state.
  // Only set ghash_h + cipher_type (rest stays zero).
  // The struct is 276 bytes but we only write 18 bytes — the rest is zero from stack init.
  struct tls_conn_state new_conn;
  __builtin_memset(&new_conn, 0, sizeof(new_conn));
  if (bpf_probe_read_user(new_conn.ghash_h, 16, (void *)(ptr + offsets->algctx_to_h)) < 0)
    return 0;

  // OpenSSL stores H as two u64 in native (little-endian) byte order.
  // GHASH expects big-endian byte order. Byte-swap each 8-byte half.
  __u64 *h64 = (__u64 *)new_conn.ghash_h;
  if (h64[0] == 0 && h64[1] == 0)
    return 0;
  h64[0] = __builtin_bswap64(h64[0]);
  h64[1] = __builtin_bswap64(h64[1]);

  // Successful H extraction implies AES-GCM (only GCM contexts have a valid H key).
  // Non-GCM ciphers (CBC, ChaCha20) don't have a GCM128_CONTEXT, so the pointer
  // chain fails or H is all-zeros — both caught above.
  new_conn.cipher_type = KLOAK_CIPHER_AES_GCM;
  new_conn.wrl_ptr = wrl_ptr;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  struct tls_conn_key ck;
  __builtin_memset(&ck, 0, sizeof(ck));
  ck.tgid = tgid;
  ck.ssl_ptr = ssl_ptr;
  bpf_map_update_elem(&tls_conn_state, &ck, &new_conn, BPF_ANY);

  dbg_inc(DBG_XOR_CONN_HIT);

  // Chain to xor_path to do the rewrite on this same SSL_write call.
  // scratch_buf already has the pre-scanned match position from the entry uprobe.
  bpf_tail_call(ctx, &prog_array, 1);

  return 0;
}

SEC("uprobe/xor_path")
int bpf_xor_path(void *ctx) {
  __u32 zero = 0;
  struct scratch_buf *sd = bpf_map_lookup_elem(&scratch, &zero);
  if (!sd)
    return 0;

  __u32 mi = sd->xor_current_match;
  if (mi >= sd->xor_match_count || mi >= XOR_MAX_MATCHES)
    goto finalize;

  // Initialize staged_pending on first invocation.
  if (mi == 0) {
    struct ghash_work *wi = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!wi) return 0;
    __builtin_memset(&wi->staged_pending, 0, sizeof(wi->staged_pending));
    wi->staged_pending.ssl_ptr = sd->ssl_ptr;
    wi->staged_pending.tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    wi->staged_pending.active = 1;
    wi->staged_pending.chain_type = sd->chain_type;
    wi->staged_pending.plaintext_len = sd->total_data_len;
  }

  dbg_inc(DBG_XOR_PATH_ENTERED);

  // Read the current match position + key. Use fixed index via bitmask for verifier.
  __u32 local_i = sd->xor_matches[mi & (XOR_MAX_MATCHES - 1)].pos;
  struct secret_key key;
  __builtin_memcpy(&key,
    &sd->xor_matches[mi & (XOR_MAX_MATCHES - 1)].key, sizeof(key));

  // Save host_value from sd before secret_map lookup invalidates it.
  __u32 sd_host_len = sd->host_value_len;
  // Host comparison will use sd->host_value via re-lookup later.

  struct secret_value *val = bpf_map_lookup_elem(&secret_map, &key);
  if (!val || val->len == 0 || val->len > SECRET_MAX_LEN)
    goto next; // Skip this match.

  // Host filtering: val is fresh, re-lookup sd for host_value.
  __u32 val_len = val->len;
  __u32 val_host_len = val->host_len;
  if (val_host_len > 0 && val_host_len < MAX_HOST_LEN) {
    if (sd_host_len == 0)
      goto next;
    // Re-lookup sd for host comparison (val stays in callee-saved reg).
    sd = bpf_map_lookup_elem(&scratch, &zero);
    if (!sd) return 0;
    if (!hosts_match(sd->host_value, val->allowed_host))
      goto next;
  }

  dbg_inc(DBG_XOR_SECRET_FOUND);

  // Compute XOR delta: shadow bytes ^ real bytes.
  __u32 delta_len = clamp_write_len(val_len);

  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 0;
  sd = bpf_map_lookup_elem(&scratch, &zero);
  if (!sd) return 0;

  // Read shadow bytes directly from user memory. This avoids depending on
  // the prescan buffer size — secrets that start near the end of the buffer
  // won't wrap around and read garbage from position 0.
  bpf_probe_read_user(w->ct_buf, SECRET_MAX_LEN,
                      (void *)(sd->user_data_ptr + local_i));

  val = bpf_map_lookup_elem(&secret_map, &key);
  if (!val) goto next;
  for (__u32 j = 0; j < SECRET_MAX_LEN && j < delta_len; j++)
    w->ct_buf[j] ^= val->real_secret[j];

  // Store patch in staged_pending.
  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 0;

  __u32 pi = w->staged_pending.patch_count;
  if (pi < XOR_MAX_PATCHES) {
    w->staged_pending.patches[pi & (XOR_MAX_PATCHES - 1)].secret_offset = local_i;
    w->staged_pending.patches[pi & (XOR_MAX_PATCHES - 1)].secret_len = val_len;
    __builtin_memcpy(w->staged_pending.patches[pi & (XOR_MAX_PATCHES - 1)].xor_delta,
                     w->ct_buf, SECRET_MAX_LEN);
    w->staged_pending.patch_count = pi + 1;
  }

next:
  // Increment current match and tail-call back to process the next one.
  sd = bpf_map_lookup_elem(&scratch, &zero);
  if (!sd) return 0;
  sd->xor_current_match = mi + 1;
  if (mi + 1 < sd->xor_match_count && mi + 1 < XOR_MAX_MATCHES) {
    bpf_tail_call(ctx, &prog_array, 1); // Tail-call back to xor_path.
  }

finalize:;
  // All matches processed. Store patches in xor_pending keyed by pid_tgid.
  // The tcp_sendmsg kprobe will bridge this to tc_pending with the per-connection
  // (dst_ip, src_port) key that tc egress can look up from the packet headers.
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct ghash_work *wf = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!wf || wf->staged_pending.patch_count == 0)
    return 0;

  // ssl_ptr, tgid, active already set during mi=0 initialization.
  bpf_map_update_elem(&xor_pending, &pid_tgid, &wf->staged_pending, BPF_ANY);
  // bpf_printk("kloak [1-UPROBE] pid=%u patches=%u", (__u32)pid_tgid, wf->staged_pending.patch_count);

  dbg_inc(DBG_XOR_DELTA_DONE);
  return 0;
}

// =============================================================================
// GHASH shared callbacks — used by tc_ghash_update for tag recomputation.
// =============================================================================

// bpf_loop callback: one iteration of GF(2^128) multiplication.
// State lives in the ghash_scratch per-CPU map (mul_a, mul_v, mul_z).
// The verifier only needs to verify one iteration, not 128.
static int gf128_mul_iter(__u32 i, void *_unused) {
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1; // stop

  __u32 byte_idx = (i >> 3) & 0xF;  // i/8 clamped to [0,15] for verifier
  __u32 bit_idx = i & 7;            // i%8 clamped to [0,7]
  if (w->mul_a[byte_idx] & ((__u8)0x80 >> bit_idx)) {
    for (int j = 0; j < 16; j++)
      w->mul_z[j] ^= w->mul_v[j];
  }
  __u8 carry = w->mul_v[15] & 1;
  for (int j = 15; j > 0; j--)
    w->mul_v[j] = (w->mul_v[j] >> 1) | (w->mul_v[j - 1] << 7);
  w->mul_v[0] >>= 1;
  if (carry)
    w->mul_v[0] ^= 0xe1;
  return 0;
}

// bpf_loop callback: copy one H^(2^i) entry from tls_conn_state to ghash_work.
// Alternates map lookups to avoid holding both pointers simultaneously.
static int copy_h_power_step(__u32 i, void *_unused) {
  if (i >= 11)
    return 1;

  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1;

  struct tls_conn_key ck;
  __builtin_memset(&ck, 0, sizeof(ck));
  ck.tgid = w->ghash_tgid;
  ck.ssl_ptr = w->ghash_ssl_ptr;
  struct tls_conn_state *conn = bpf_map_lookup_elem(&tls_conn_state, &ck);
  if (!conn)
    return 1;

  struct h_power_entry entry;

  if (i == 0) {
    // H^1 = H (copy directly from tls_conn_state.ghash_h)
    __builtin_memcpy(entry.val, conn->ghash_h, 16);
  } else {
    // H^(2^i) = (H^(2^(i-1)))^2 — read previous entry and square it.
    __u32 prev = i - 1;
    struct h_power_entry *prev_entry = bpf_map_lookup_elem(&h_power_entries, &prev);
    if (!prev_entry)
      return 1;
    __u8 prev_val[16];
    __builtin_memcpy(prev_val, prev_entry->val, 16);

    // Square via bpf_loop. Re-lookup w after each step.
    w = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!w)
      return 1;
    __builtin_memcpy(w->mul_a, prev_val, 16);
    __builtin_memset(w->mul_z, 0, 16);
    __builtin_memcpy(w->mul_v, prev_val, 16);

    bpf_loop(128, gf128_mul_iter, NULL, 0);

    w = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!w)
      return 1;
    __builtin_memcpy(entry.val, w->mul_z, 16);
  }

  bpf_map_update_elem(&h_power_entries, &i, &entry, BPF_ANY);
  return 0;
}

// bpf_loop callback: one step of square-and-multiply for H^power.
// Uses nested bpf_loop(128, gf128_mul_iter) for each multiply.
// Re-lookups w after every bpf_loop to satisfy the verifier.
static int h_power_step(__u32 bit, void *_unused) {
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w || bit >= 11)
    return 1;

  if (!(w->ghash_h_power_val & (1u << bit)))
    return 0; // Bit not set — skip this multiply.

  // Look up H^(2^bit) from separate map and copy to stack.
  struct h_power_entry *hp = bpf_map_lookup_elem(&h_power_entries, &bit);
  if (!hp)
    return 1;
  __u8 hp_val[16];
  __builtin_memcpy(hp_val, hp->val, 16);

  // Re-lookup w (invalidated by h_power_entries lookup).
  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1;

  // h_pow = h_pow * H^(2^bit)
  __builtin_memcpy(w->mul_a, w->h_pow, 16);
  __builtin_memset(w->mul_z, 0, 16);
  __builtin_memcpy(w->mul_v, hp_val, 16);

  bpf_loop(128, gf128_mul_iter, NULL, 0);

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1;
  __builtin_memcpy(w->h_pow, w->mul_z, 16);
  return 0;
}

// bpf_loop callback: process one 16-byte block for GHASH tag delta.
static int ghash_block_iter(__u32 block_idx, void *_unused) {
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1;

  __u32 b = w->ghash_first_block + block_idx;
  if (b >= w->ghash_ct_blocks)
    return 1;

  // Build 16-byte block delta.
  __builtin_memset(w->block_delta, 0, 16);
  __u32 sec_off = w->ghash_secret_offset;
  __u32 sec_end = sec_off + w->ghash_patch_len;
  for (__u32 i = 0; i < 16; i++) {
    __u32 pos = (b & 0x3FF) * 16 + i;
    if (pos >= sec_off && pos < sec_end) {
      __u32 si = (pos - sec_off) & (SECRET_MAX_LEN - 1);
      w->block_delta[i] = w->ghash_xor_delta[si];
    }
  }

  // Compute H^power via bpf_loop (no inline functions — avoids stale w).
  __u32 power = w->ghash_ct_blocks - b + 1;
  w->ghash_h_power_val = power;
  __builtin_memset(w->h_pow, 0, 16);
  w->h_pow[0] = 0x80; // GF(2^128) identity

  bpf_loop(11, h_power_step, NULL, 0);

  // Re-lookup w. h_pow now contains H^power.
  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1;

  // contribution = block_delta * H^power (flat bpf_loop, no inline).
  __builtin_memcpy(w->mul_a, w->block_delta, 16);
  __builtin_memset(w->mul_z, 0, 16);
  __builtin_memcpy(w->mul_v, w->h_pow, 16);

  bpf_loop(128, gf128_mul_iter, NULL, 0);

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 1;

  // Accumulate: tag_delta ^= contribution (mul_z)
  for (__u32 i = 0; i < 16; i++)
    w->tag_delta[i] ^= w->mul_z[i];

  return 0;
}

// bpf_loop callback: process one patch for GHASH tag recomputation.
// Replaces the unrolled for-loop over patches in tc_ghash_update to keep
// verifier complexity O(1) per patch instead of O(XOR_MAX_PATCHES).
static int ghash_patch_iter(__u32 p, void *_unused) {
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 1;

  // Skip patches that tc_egress_patch failed to apply (secret_len zeroed).
  __u32 raw_len = w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].secret_len;
  if (raw_len == 0) return 0;

  __u32 sec_off = w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].secret_offset;
  __u32 sec_len = clamp_write_len(raw_len);

  w->ghash_secret_offset = sec_off;
  w->ghash_patch_len = sec_len;
  __builtin_memcpy(w->ghash_xor_delta,
      w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].xor_delta,
      SECRET_MAX_LEN);
  w->ghash_first_block = sec_off / 16;

  __u32 num_blocks = (sec_off + sec_len - 1) / 16 - w->ghash_first_block + 1;
  if (num_blocks > 9) num_blocks = 9;

  bpf_loop(num_blocks, ghash_block_iter, NULL, 0);
  return 0;
}

// -----------------------------------------------------------------------------
// kprobe/tcp_sendmsg — Bridge xor_pending to tc_pending with per-connection key.
//
// SSL_write → encrypt → write()/send() → tcp_sendmsg (this kprobe) → kernel TCP
//
// The uprobe stores patches in xor_pending[pid_tgid]. This kprobe reads the
// source port from struct sock (first arg) and copies the entry to
// tc_pending[(dst_ip, src_port)] where tc egress can find it by packet headers.
// This gives per-connection isolation: two connections to the same IP have
// different source ports, so their entries don't collide.
// -----------------------------------------------------------------------------

SEC("kprobe/tcp_sendmsg")
int bpf_kprobe_tcp_sendmsg(void *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  struct xor_pending_val *pending = bpf_map_lookup_elem(&xor_pending, &pid_tgid);
  if (!pending || pending->patch_count == 0)
    return 0;

  // Read source port from struct sock (first argument of tcp_sendmsg).
  // tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
  void *sk;
#if defined(bpf_target_x86)
  bpf_probe_read_kernel(&sk, sizeof(void *), (char *)ctx + 112); // RDI
#elif defined(bpf_target_arm64)
  bpf_probe_read_kernel(&sk, sizeof(void *), (char *)ctx + 0);   // X0
#else
  return 0;
#endif
  if (!sk) return 0;

  // Read source port: struct sock → __sk_common.skc_num (host byte order).
  __u16 src_port_h = 0;
  bpf_probe_read_kernel(&src_port_h, sizeof(src_port_h),
                        (void *)sk + offsetof(struct sock, __sk_common.skc_num));

  // Read destination IP: struct sock → __sk_common.skc_daddr (IPv4, network order).
  __u32 daddr = 0;
  bpf_probe_read_kernel(&daddr, sizeof(daddr),
                        (void *)sk + offsetof(struct sock, __sk_common.skc_daddr));

  // Build tc_pending key: (dst_ip, src_port, cgroup_id).
  // src_port is unique per connection within a container.
  // cgroup_id isolates containers.
  struct tc_dest_key tdk = {};
  tdk.dst_ip[10] = 0xff;
  tdk.dst_ip[11] = 0xff;
  __builtin_memcpy(&tdk.dst_ip[12], &daddr, 4);
  tdk.src_port = __bpf_htons(src_port_h);
  tdk.cgroup_id = bpf_get_current_cgroup_id();

  // Save values from xor_pending before helper calls invalidate the pointer.
  __u32 zero = 0;

  pending = bpf_map_lookup_elem(&xor_pending, &pid_tgid);
  if (!pending) return 0;

  __u64 ssl_ptr = pending->ssl_ptr;
  __u32 tgid = (__u32)(pid_tgid >> 32);
  __u32 plaintext_len = pending->plaintext_len;
  __u8 chain = pending->chain_type;

  // Extract H BEFORE creating tc_pending. If H extraction fails, we must NOT
  // create tc_pending — otherwise tc_egress would XOR-patch the ciphertext
  // without being able to recompute the GHASH tag, causing "bad record MAC".
  struct tls_conn_state new_conn;
  __builtin_memset(&new_conn, 0, sizeof(new_conn));
  __u64 wrl_val = 0;

  if (chain == CHAIN_GO_TLS) {
    // Go crypto/tls: H×2 stored at productTable offset 224 (entry 14).
    // gcmAesInit computes H = AES_K(0^128), byte-swaps, doubles in GF(2^128).
    // We read the two 64-bit words and apply GF halving to recover H.
    struct go_tls_offsets *go_off = bpf_map_lookup_elem(&go_tls_offset_config, &tgid);
    if (!go_off)
      return 0; // No Go offsets — bail (fail-secure, no corruption).

    __u64 cipher_data = 0;
    if (bpf_probe_read_user(&cipher_data, 8,
        (void *)(ssl_ptr + go_off->conn_to_cipher)) < 0 || !cipher_data)
      return 0;
    __u64 gcm_ptr = 0;
    if (bpf_probe_read_user(&gcm_ptr, 8,
        (void *)(cipher_data + go_off->aead_iface_off)) < 0 || !gcm_ptr)
      return 0;

    // Read H×2 as two separate 64-bit words (arch-aware offsets from userspace).
    // h2_hi_off points to the GF "high" word (contains the GF MSB at bit 63).
    // h2_lo_off points to the GF "low" word (contains the GF LSB at bit 0).
    __u64 hi = 0, lo = 0;
    if (bpf_probe_read_user(&hi, 8, (void *)(gcm_ptr + go_off->h2_hi_off)) < 0)
      return 0;
    if (bpf_probe_read_user(&lo, 8, (void *)(gcm_ptr + go_off->h2_lo_off)) < 0)
      return 0;

    if (hi == 0 && lo == 0)
      return 0;

    // GF(2^128) halving: recover H from H×2.
    //
    // Go's gcmAesInit computes H×2 as a 128-bit GF(2^128) left shift with
    // conditional reduction. The 128-bit value V = hi * 2^64 + lo, where:
    //   - AMD64: hi = XMM[64:127], lo = XMM[0:63]
    //   - ARM64: hi = D[0], lo = D[1]
    //
    // The doubling was: V' = (V << 1) ^ (V.MSB ? poly : 0)
    //   poly = {hi: 0xC200000000000000, lo: 0x0000000000000001}
    //
    // Reduction indicator: lo.bit0. During left-shift, lo.bit0 becomes 0.
    // If reduction happened, poly.lo.bit0 = 1 is XORed in, so lo.bit0 = 1.
    // The carry from hi to lo doesn't affect lo.bit0 (it goes to lo.bit63).
    int reduced = lo & 1;
    if (reduced) {
      hi ^= 0xC200000000000000ULL;
      lo ^= 0x0000000000000001ULL;
    }
    // V is now (H << 1) without reduction. Undo the 128-bit left shift:
    // Carry from hi.bit0 → lo.bit63 (the bit that crossed the word boundary).
    __u64 carry = hi & 1;
    hi >>= 1;
    lo = (lo >> 1) | (carry << 63);
    if (reduced)
      hi |= (1ULL << 63); // Restore GF MSB that was shifted out.

    // Convert from register representation (byte-reversed per 8-byte lane
    // by PSHUFB/VREV64) to standard big-endian GHASH H.
    *(__u64 *)&new_conn.ghash_h[0] = __builtin_bswap64(hi);
    *(__u64 *)&new_conn.ghash_h[8] = __builtin_bswap64(lo);

    new_conn.cipher_type = KLOAK_CIPHER_AES_GCM;
  } else {
    // OpenSSL/BoringSSL: 4-hop pointer chain from SSL* to H.
    struct tls_offsets *offsets = bpf_map_lookup_elem(&tls_offset_config, &zero);
    if (!offsets || offsets->ssl_to_wrl == 0)
      return 0;

    __u64 ptr = 0;
    if (bpf_probe_read_user(&ptr, 8, (void *)(ssl_ptr + offsets->ssl_to_wrl)) < 0 || !ptr)
      return 0;
    wrl_val = ptr;
    if (bpf_probe_read_user(&ptr, 8, (void *)(ptr + offsets->wrl_to_enc_ctx)) < 0 || !ptr)
      return 0;
    if (bpf_probe_read_user(&ptr, 8, (void *)(ptr + offsets->enc_ctx_to_algctx)) < 0 || !ptr)
      return 0;
    if (bpf_probe_read_user(new_conn.ghash_h, 16, (void *)(ptr + offsets->algctx_to_h)) < 0)
      return 0;

    __u64 *h64 = (__u64 *)new_conn.ghash_h;
    if (h64[0] == 0 && h64[1] == 0)
      return 0;
    h64[0] = __builtin_bswap64(h64[0]);
    h64[1] = __builtin_bswap64(h64[1]);

    new_conn.cipher_type = KLOAK_CIPHER_AES_GCM;
    new_conn.wrl_ptr = wrl_val;
  }

  // H extraction succeeded — store connection state.
  struct tls_conn_key ck = {};
  ck.tgid = tgid;
  ck.ssl_ptr = ssl_ptr;
  bpf_map_update_elem(&tls_conn_state, &ck, &new_conn, BPF_ANY);

  // Now safe to create tc_pending — tc_egress can always find H.
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 0;

  pending = bpf_map_lookup_elem(&xor_pending, &pid_tgid);
  if (!pending) return 0;

  __builtin_memset(&w->staged_tc, 0, sizeof(w->staged_tc));
  w->staged_tc.tgid = tgid;
  w->staged_tc.ssl_ptr = ssl_ptr;
  w->staged_tc.active = 1;
  w->staged_tc.plaintext_len = plaintext_len;
  w->staged_tc.patch_count = pending->patch_count;
  if (w->staged_tc.patch_count > XOR_MAX_PATCHES)
    w->staged_tc.patch_count = XOR_MAX_PATCHES;
  for (__u32 p = 0; p < XOR_MAX_PATCHES && p < w->staged_tc.patch_count; p++)
    w->staged_tc.patches[p] = pending->patches[p];

  bpf_map_update_elem(&tc_pending, &tdk, &w->staged_tc, BPF_ANY);
  bpf_printk("kloak [2-KPROBE] sport=%u cg=%x", src_port_h, (__u32)tdk.cgroup_id);

  // Delete xor_pending — the entry has been bridged to tc_pending.
  bpf_map_delete_elem(&xor_pending, &pid_tgid);

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

  void *conn_ptr; // *tls.Conn receiver — used as connection ID and for H extraction
  void *data_ptr;
  __u64 data_len;

#if defined(bpf_target_x86)
  // x86_64 Go register ABI: RAX=receiver, RBX=data, RCX=len
  // pt_regs offsets: rax=80, rbx=40, rcx=88
  bpf_probe_read_kernel(&conn_ptr, sizeof(void *), (char *)ctx + 80);
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 40);
  bpf_probe_read_kernel(&data_len, sizeof(__u64), (char *)ctx + 88);
#elif defined(bpf_target_arm64)
  // ARM64 Go register ABI: R0=receiver, R1=data, R2=len
  // user_pt_regs offsets: regs[0]=0, regs[1]=8, regs[2]=16
  bpf_probe_read_kernel(&conn_ptr, sizeof(void *), (char *)ctx + 0);
  bpf_probe_read_kernel(&data_ptr, sizeof(void *), (char *)ctx + 8);
  bpf_probe_read_kernel(&data_len, sizeof(__u64), (char *)ctx + 16);
#else
  return 0;
#endif

#ifdef KLOAK_DEBUG
  __u32 pid = bpf_get_current_pid_tgid();
  bpf_printk("kloak go_tls: conn=%llx ptr=%llx len=%llu pid=%d",
             (__u64)conn_ptr, (__u64)data_ptr, data_len, pid);
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

  // resolve_host uses last_verified_fd -> conn_ip_map -> dns_ip_map for Go.
  resolve_host(scratch_data, 0);

  // Pre-scan for kloak: prefix and tail-call to xor_path.
  // Same flow as SSL_write — the downstream pipeline is generic.
  dbg_inc(DBG_XOR_CONN_CHECK);
  scratch_data->ssl_ptr = (__u64)conn_ptr; // reuse ssl_ptr field as connection ID
  scratch_data->chain_type = CHAIN_GO_TLS;
  scratch_data->xor_match_count = 0;
  scratch_data->xor_current_match = 0;

  {
    struct prescan_ctx pctx = {
      .user_data_ptr = scratch_data->user_data_ptr,
      .total_len = scratch_data->total_data_len,
    };
    __u32 num_chunks = (pctx.total_len + CHUNK_STRIDE - 1) / CHUNK_STRIDE;
    bpf_loop(num_chunks, prescan_chunk, &pctx, 0);
  }

  // H extraction is deferred to the tcp_sendmsg kprobe (same as OpenSSL).
  bpf_tail_call(ctx, &prog_array, 1);

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

  // Skip server-mode SSL connections. Server sockets are created via accept(),
  // which never populates conn_ip_map (only connect() does via tp_exit_connect).
  // Without this check, the H extraction path runs against server-mode SSL*
  // objects whose internal layout differs from client-mode, producing garbage
  // GHASH keys that corrupt outbound TLS authentication tags ("bad record MAC").
  //
  // If ssl_read_fd fails (returns 0), we cannot determine client vs server mode,
  // so we fall through and let the existing logic handle it. We only bail when
  // we have a valid fd that is positively NOT in conn_ip_map (server-mode).
  {
    __u32 bio_fd = ssl_read_fd((__u64)ssl_ptr);
    if (bio_fd != 0) {
      __u32 cur_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
      struct conn_ip_key cik = {};
      cik.tgid = cur_tgid;
      cik.fd = bio_fd;
      if (!bpf_map_lookup_elem(&conn_ip_map, &cik))
        return 0;  // server-mode: fd exists but not from connect()
    }
  }

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

  // Pre-scan for kloak: prefix BEFORE conn_state check, so both
  // h_extract and xor_path have the match position in scratch_buf.
  dbg_inc(DBG_XOR_CONN_CHECK);
  scratch_data->ssl_ptr = (__u64)ssl_ptr;
  scratch_data->chain_type = 0; // OpenSSL/BoringSSL
  scratch_data->xor_match_count = 0;
  scratch_data->xor_current_match = 0;

  // Scan the FULL SSL_write buffer for kloak: prefixes using bpf_loop.
  // Each chunk reads MAX_DATA_SIZE bytes with SECRET_KEY_LEN-1 overlap,
  // so tokens spanning chunk boundaries are always detected. Match positions
  // are stored as global offsets relative to the SSL_write buffer start.
  {
    struct prescan_ctx pctx = {
      .user_data_ptr = scratch_data->user_data_ptr,
      .total_len = scratch_data->total_data_len,
    };
    __u32 num_chunks = (pctx.total_len + CHUNK_STRIDE - 1) / CHUNK_STRIDE;
    bpf_loop(num_chunks, prescan_chunk, &pctx, 0);
  }

  // Go directly to xor_path. H extraction is deferred to the tcp_sendmsg
  // kprobe where the TLS handshake has completed and H is available.
  bpf_tail_call(ctx, &prog_array, 1);

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

  // Ensure the new process is tracked for DNS/connect and SSL_write filtering.
  __u8 val = 1;
  bpf_map_update_elem(&tracked_tgids, &tgid, &val, BPF_ANY);
  bpf_map_update_elem(&tracked_cgroups, &cgroup_id, &val, BPF_ANY);

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

// tp/sched/sched_process_exit: clean up stale map entries when any kubepods
// process exits. Uses bpf_current_task_under_cgroup (same as exec handler)
// to match all container processes — not just tracked_cgroups — so TGIDs
// added by the broad exec handler are always cleaned up.
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
  if (bpf_current_task_under_cgroup(&cgroup_ancestor, 0) != 1)
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

// =============================================================================
// tc egress: XOR-patch ciphertext + GHASH tag in kernel skb data.
//
// This runs AFTER tcp_sendmsg copies user-space data to kernel skbs.
// Modifications happen in kernel memory only — the user-space iov is untouched.
// The encrypted real secret NEVER exists in user-space memory.
// =============================================================================

SEC("tc")
int tc_egress_patch(struct __sk_buff *skb) {
  dbg_inc(DBG_TC_ENTRY);

  // Parse Ethernet header (if present)
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // Determine L3 offset. For tc, skb->protocol tells us the L3 protocol.
  // In container environments (veth), there's usually no Ethernet header
  // at the tc level — the packet starts at IP. Check skb->protocol.
  __u32 l3_off = 0;

  // Check if there's an Ethernet header
  if (skb->protocol == __bpf_htons(0x0800)) {
    // Could be raw IP or after Ethernet. Check data length.
    // For tc on veth pairs, skb typically includes Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
      return 0 /* TC_ACT_OK */;
    if (eth->h_proto == __bpf_htons(0x0800))
      l3_off = sizeof(struct ethhdr);
    // else: raw IP, l3_off stays 0
  }

  // Parse IPv4 header
  struct iphdr *ip = data + l3_off;
  if ((void *)(ip + 1) > data_end)
    return 0 /* TC_ACT_OK */;
  if (ip->protocol != 6) // Not TCP
    return 0 /* TC_ACT_OK */;

  __u32 ip_hdr_len = ip->ihl * 4;
  if (ip_hdr_len < 20)
    return 0 /* TC_ACT_OK */;

  // Parse TCP header
  struct tcphdr *tcp = data + l3_off + ip_hdr_len;
  if ((void *)(tcp + 1) > data_end)
    return 0 /* TC_ACT_OK */;

  __u32 tcp_hdr_len = tcp->doff * 4;
  if (tcp_hdr_len < 20)
    return 0 /* TC_ACT_OK */;

  // Save header fields to locals before helper calls invalidate direct pointers.
  __u16 sport = tcp->source;

  // Read the original (pre-DNAT) destination IP from the socket, not the packet.
  // For cluster services, iptables/kube-proxy DNATs the packet's dst_ip to the
  // pod IP, but the socket's skc_daddr still holds the service ClusterIP —
  // matching what the kprobe stored in tc_pending.
  __u32 daddr = ip->daddr; // fallback: packet dst_ip
  struct bpf_sock *bsk = skb->sk;
  if (bsk) {
    bsk = bpf_sk_fullsock(bsk);
    if (bsk) {
      // bpf_sock.dst_ip4 is the original connect() destination
      daddr = bsk->dst_ip4;
    }
  }

  // Build key from destination IP + source port (per-connection isolation).
  struct tc_dest_key key = {};
  key.dst_ip[10] = 0xff;
  key.dst_ip[11] = 0xff;
  __builtin_memcpy(&key.dst_ip[12], &daddr, 4);
  key.src_port = sport;
  key.cgroup_id = bpf_skb_cgroup_id(skb);

  // Check TLS application_data FIRST (cheap, no map lookup).
  __u32 payload_off = l3_off + ip_hdr_len + tcp_hdr_len;
  __u32 payload_len = __bpf_ntohs(ip->tot_len) - ip_hdr_len - tcp_hdr_len;
  if (payload_len < 5)
    return 0 /* TC_ACT_OK */;

  __u8 tls_hdr[5];
  if (bpf_skb_load_bytes(skb, payload_off, tls_hdr, 5) < 0)
    return 0 /* TC_ACT_OK */;
  bpf_printk("kloak tc tls_hdr=%x ver=%x%x plen=%u", tls_hdr[0], tls_hdr[1], tls_hdr[2], payload_len);
  // Validate TLS application_data record:
  //   byte 0: content type must be 0x17
  //   bytes 1-2: version must be 0x0301..0x0303 (TLS 1.0-1.3)
  //   bytes 3-4: record_len must be sane (> 24 for TLS 1.2 AES-GCM minimum)
  // This rejects TCP continuation segments where random ciphertext bytes
  // coincidentally start with 0x17 (1/256 without version check → ~1/5.6M with).
  if (tls_hdr[0] != 0x17 || tls_hdr[1] != 0x03 || tls_hdr[2] > 0x03)
    return 0 /* TC_ACT_OK */;

  __u16 record_len = ((__u16)tls_hdr[3] << 8) | (__u16)tls_hdr[4];
  if (record_len < 24) // minimum: 8 nonce + 0 payload + 16 tag
    return 0 /* TC_ACT_OK */;

  // Now that we know this is a valid TLS application_data record, look up
  // the pending entry. This avoids map lookups on non-TLS packets.
  struct tc_pending_val *pending = bpf_map_lookup_elem(&tc_pending, &key);
  if (!pending || !pending->active) {
    bpf_printk("kloak [3-TC] MISS sport=%u cg=%x", __bpf_ntohs(sport), (__u32)key.cgroup_id);
    return 0 /* TC_ACT_OK */;
  }
  bpf_printk("kloak [3-TC] HIT sport=%u cg=%x", __bpf_ntohs(sport), (__u32)key.cgroup_id);

  __u32 tls_total = 5 + record_len; // header + body

  // Linearize the skb so the full TLS record is in contiguous memory.
  // With GSO, the kernel may pass a large packet with non-linear fragments;
  // bpf_skb_pull_data makes it accessible to bpf_skb_load/store_bytes.
  // If the record truly spans TCP segments (separate skbs), this can't help
  // and we fail-secure (shadow goes through).
  if (payload_len < tls_total) {
    if (bpf_skb_pull_data(skb, payload_off + tls_total) < 0)
      return 0 /* TC_ACT_OK */;
    // After pull, skb->len reflects the linearized data. Re-derive payload_len.
    // skb->len is the total L3 length. Direct access pointers are invalid after
    // pull, but bpf_skb_load/store_bytes still work.
    if (skb->len < payload_off + tls_total)
      return 0 /* TC_ACT_OK */;
  }

  dbg_inc(DBG_TC_MATCH);

  // Detect TLS version from record_len vs plaintext_len:
  //   TLS 1.2: record_len = plaintext_len + 8 (nonce) + 16 (tag) = pt + 24
  //   TLS 1.3: record_len = plaintext_len + 1 (content_type) + 16 (tag) = pt + 17
  __u32 pt_len = pending->plaintext_len;
  __u32 nonce_len;
  if (pt_len > 0 && record_len == pt_len + 17)
    nonce_len = 0;  // TLS 1.3
  else
    nonce_len = 8;  // TLS 1.2 (default)
  __u32 ct_len = record_len - 16 - nonce_len;

  // Copy ALL data from pending to ghash_scratch staging area.
  // pending (tc_pending) and w (ghash_scratch) are from different maps — both
  // pointers remain valid after the second lookup.
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 0 /* TC_ACT_OK */;

  __u32 pc = pending->patch_count;
  if (pc > XOR_MAX_PATCHES) pc = XOR_MAX_PATCHES;
  w->staged_pending.patch_count = pc;
  for (__u32 p = 0; p < XOR_MAX_PATCHES && p < pc; p++)
    w->staged_pending.patches[p] = pending->patches[p];
  w->ghash_ct_len = ct_len;
  w->ghash_nonce_len = nonce_len;
  w->ghash_payload_off = payload_off;
  w->ghash_tgid = pending->tgid;
  w->ghash_ssl_ptr = pending->ssl_ptr;
  w->ghash_active = 1;

  // Mark inactive instead of deleting. Retransmits on the same connection
  // would steal a freshly-created entry if we deleted. With active=0, the
  // retransmit finds the entry but skips it. The kprobe overwrites with
  // active=1 on the next SSL_write.
  pending = bpf_map_lookup_elem(&tc_pending, &key);
  if (pending) pending->active = 0;

  // Apply patches. Zero secret_len on failure so GHASH skips unapplied patches.
  for (__u32 p = 0; p < XOR_MAX_PATCHES && p < pc; p++) {
    w = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!w) return 0 /* TC_ACT_OK */;

    __u32 sec_off = w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].secret_offset;
    __u32 sec_len = w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].secret_len;
    if (record_len < 16 + nonce_len + sec_len) {
      w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].secret_len = 0;
      continue;
    }

    __u32 patch_off = payload_off + 5 + nonce_len + sec_off;
    __u32 patch_len = clamp_write_len(sec_len);

    if (bpf_skb_load_bytes(skb, patch_off, w->ct_buf, patch_len) < 0) {
      w = bpf_map_lookup_elem(&ghash_scratch, &zero);
      if (w) w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].secret_len = 0;
      continue;
    }

    for (__u32 i = 0; i < SECRET_MAX_LEN && i < patch_len; i++)
      w->ct_buf[i] ^= w->staged_pending.patches[p & (XOR_MAX_PATCHES - 1)].xor_delta[i];

    bpf_skb_store_bytes(skb, patch_off, w->ct_buf, patch_len, 0);
    dbg_inc(DBG_TC_PATCHED);
  }

  bpf_printk("kloak [4-PATCH] sport=%u pc=%u ct=%u", __bpf_ntohs(sport), pc, ct_len);

  // Tail-call to tc GHASH program.
  bpf_tail_call(skb, &tc_prog_array, 0);
  bpf_printk("kloak [4-PATCH] TAILCALL_FAILED");
  return 0 /* TC_ACT_OK */;
}

// =============================================================================
// tc GHASH: tag recomputation in kernel skb memory.
// Uses shared GF multiply callbacks (gf128_mul_iter, h_power_step,
// ghash_block_iter, copy_h_power_step) that operate on BPF maps.
// =============================================================================

SEC("tc")
int tc_ghash_update(struct __sk_buff *skb) {
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w || !w->ghash_active)
    return 0 /* TC_ACT_OK */;
  w->ghash_active = 0;

  // Copy H power table from tls_conn_state.
  bpf_loop(11, copy_h_power_step, NULL, 0);

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 0 /* TC_ACT_OK */;

  __u32 ct_len = w->ghash_ct_len;
  __u32 nonce_len = w->ghash_nonce_len;
  __u32 payload_off = w->ghash_payload_off;
  __u32 ct_blocks = (ct_len + 15) / 16;

  // Read old tag from skb (kernel memory).
  __u32 tag_offset = payload_off + 5 + nonce_len + ct_len;
  if (bpf_skb_load_bytes(skb, tag_offset, w->old_tag, 16) < 0)
    return 0 /* TC_ACT_OK */;

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 0 /* TC_ACT_OK */;

  __builtin_memset(w->tag_delta, 0, 16);

  // Iterate ALL patches — the GHASH formula is additive:
  // tag_delta = Σ Σ (delta_block * H^power) for each patch, each block.
  // tag_delta accumulates across all ghash_block_iter calls.
  //
  // Uses bpf_loop instead of a for-loop to avoid compiler unrolling
  // XOR_MAX_PATCHES iterations. Each unrolled iteration contains nested
  // bpf_loop calls (ghash_block_iter → h_power_step → gf128_mul_iter),
  // causing the verifier to re-analyze the full callback tree per iteration
  // and exceed the 1M instruction limit on newer kernels.
  __u32 pc = w->staged_pending.patch_count;
  if (pc > XOR_MAX_PATCHES) pc = XOR_MAX_PATCHES;
  w->ghash_ct_blocks = ct_blocks;

  bpf_loop(pc, ghash_patch_iter, NULL, 0);

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 0 /* TC_ACT_OK */;

  for (__u32 i = 0; i < 16; i++)
    w->new_tag[i] = w->old_tag[i] ^ w->tag_delta[i];

  bpf_skb_store_bytes(skb, tag_offset, w->new_tag, 16, 0);

  __u32 dsum = 0;
  for (__u32 di = 0; di < 16; di++) dsum += w->tag_delta[di];
  bpf_printk("kloak [5-GHASH] tag_off=%u dsum=%u", tag_offset, dsum);

  return 0 /* TC_ACT_OK */;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
