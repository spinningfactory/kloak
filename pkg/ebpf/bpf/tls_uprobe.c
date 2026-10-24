// go:build ignore

// tls_uprobe.c - eBPF uprobes for TLS interception in Go and OpenSSL apps.
// Uses a per-CPU array as scratch buffer (not ringbuf) to avoid verifier
// issues with ringbuf_mem pointer tracking in loops.
// Supports both x86_64 and ARM64 architectures.
// Host filtering uses virtual IPs: the host of a connection is the host of
// the fake IP it connected to.

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
// BPF map key length — short key for lookup (kl:: + 4 UUID chars)
#define SECRET_KEY_LEN 8
// Max prefix bytes stored in secret_value (for future verification use)
#define SECRET_PREFIX_MAX 42
// Chunk stride for bpf_loop scanning: overlap of SECRET_KEY_LEN-1 bytes
// ensures tokens straddling chunk boundaries are always detected.
#define CHUNK_STRIDE (MAX_DATA_SIZE - (SECRET_KEY_LEN - 1)) // 249
// Max host length for matching
#define MAX_HOST_LEN 64
// Maximum DNS message size tc_dns_rewrite parses
#define MAX_DNS_PKT 512

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
  __u32 ip_len;                        // 0 = no IP filter, 16 = IPv4-mapped-IPv6
  char allowed_ip[16];                 // IPv4-mapped-IPv6 address
  __u16 port;                          // 0 = wildcard, otherwise port number (host byte order)
  __u8 protocol;                       // IPPROTO_TCP (6) = TCP, IPPROTO_UDP (17) = UDP
  __u32 prefix_len;                    // actual prefix length (8..42)
  char full_prefix[SECRET_PREFIX_MAX]; // full kl::UUID prefix for verification
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, struct secret_key);
  __type(value, struct secret_value);
} secret_map SEC(".maps");

// Per-pod secret binding: a placeholder is redeemed only by processes whose
// cgroup belongs to a pod that references the owning secret in its spec
// (Secret volume, env secretKeyRef, envFrom secretRef). Keyed by container
// cgroup and placeholder BPF key; a placeholder's HPACK-Huffman key gets its
// own entry. Written and pruned by pkg/ebpf/secret_binding.go.
struct secret_acl_key {
  __u64 cgroup_id;
  struct secret_key key;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, struct secret_acl_key);
  __type(value, __u8);
} secret_acl SEC(".maps");

// Binding mode, index 0. Enforce is the zero value, so an unconfigured map
// still enforces.
#define SECRET_BINDING_ENFORCE 0
#define SECRET_BINDING_AUDIT 1

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, __u32);
  __type(value, __u32);
} secret_binding_mode SEC(".maps");

// Per-CPU array used as scratch space for reading and scanning data.
struct scratch_buf {
  __u64 user_data_ptr;
  __u64 ssl_ptr;        // SSL* or Go *tls.Conn pointer; used by XOR path tail call
  __u32 read_len;       // bytes read into data[] (max 256, for host parsing)
  __u32 total_data_len; // full TLS write length (for bpf_loop scanning)
  __u8  chain_type;     // 0=OpenSSL/BoringSSL, CHAIN_GO_TLS=Go crypto/tls
  __u8  h_fresh;        // 1: bpf_h_extract stored this write's H in tls_conn_state
  __u8  memory_bio;     // 1: the TLS library writes to a memory BIO (see xor_pending_val)
  // Multiple secret matches per SSL_write (up to 4).
  // xor_path processes one match per invocation and tail-calls back to itself.
  #define XOR_MAX_MATCHES 4
  __u32 xor_match_count;   // total matches found by pre-scan
  __u32 xor_current_match; // index of the next match to process
  struct {
     __u32 pos;                    // byte offset of kl:: prefix in data[]
     struct secret_key key;        // 8-byte key prefix
   } xor_matches[XOR_MAX_MATCHES];
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

// Secret-binding violations reported to userspace (see secret_binding_allows).
// Only the controller's log consumes these, so a full buffer just drops events.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 1024);
} secret_binding_events SEC(".maps");

// Why a placeholder was not rewritten (secret_binding_event.reason).
#define SECRET_EVT_BINDING 0 // its pod does not reference the secret (secret_acl)
#define SECRET_EVT_SNI 1     // the connection's SNI is not the secret's host (sni_state)

// A process redeemed a placeholder it may not redeem. Must match
// secretBindingEvent in pkg/ebpf/secret_binding.go.
struct secret_binding_event {
  __u64 cgroup_id;
  __u32 tgid;
  __u8 audit;      // 1 = audit mode, the rewrite went ahead; 0 = refused
  __u8 reason;     // SECRET_EVT_*
  __u8 sni_status; // SECRET_EVT_SNI: the connection's SNI_STATUS_*
  __u8 memory_bio; // SECRET_EVT_SNI: 1 = memory-BIO writer, the socket may be another connection
  char key[8];     // placeholder BPF key (SECRET_KEY_LEN)
  char sni[MAX_HOST_LEN]; // SECRET_EVT_SNI: the connection's SNI, if any
};

// report_secret_event submits a refused (or, in audit mode, allowed)
// redemption to secret_binding_events. sni may be NULL. Ring buffer memory
// is not zeroed, so every field is written.
static __always_inline void report_secret_event(const struct secret_key *key,
                                                __u8 audit, __u8 reason,
                                                __u8 sni_status, __u8 memory_bio,
                                                const char *sni) {
  struct secret_binding_event *evt =
      bpf_ringbuf_reserve(&secret_binding_events, sizeof(*evt), 0);
  if (!evt)
    return;
  evt->cgroup_id = bpf_get_current_cgroup_id();
  evt->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  evt->audit = audit;
  evt->reason = reason;
  evt->sni_status = sni_status;
  evt->memory_bio = memory_bio;
  __builtin_memcpy(evt->key, key->prefix, sizeof(evt->key));
  if (sni)
    __builtin_memcpy(evt->sni, sni, MAX_HOST_LEN);
  else
    __builtin_memset(evt->sni, 0, MAX_HOST_LEN);
  bpf_ringbuf_submit(evt, 0);
}

// Debug counters for diagnosing the data plane.
// Index: see DBG_* constants below; debugCounterNames in uprobe.go must match.
enum {
  DBG_XOR_CONN_CHECK = 0,         // entry uprobe checked tls_conn_state
  DBG_XOR_CONN_HIT,           // tls_conn_state found + AES-GCM confirmed
  DBG_XOR_PRESCAN_MATCH,      // pre-scan found kl:: prefix
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
  DBG_EVP_INIT_ENTRY,         // EVP_CipherInit_ex entry uprobe fired (cipher init started)
  DBG_EVP_INIT_H_OK,          // EVP_CipherInit_ex uretprobe extracted non-zero H
  DBG_EVP_INIT_H_ZERO,        // EVP_CipherInit_ex uretprobe found no usable H (non-GCM / unkeyed ctx)
  DBG_EVP_INIT_CHAIN_FAIL,    // EVP_CipherInit_ex uretprobe failed at evp_ctx → algctx hop
  DBG_H_EXTRACT_CACHE_HIT,    // bpf_h_extract found H in evp_h_cache
  DBG_H_EXTRACT_CACHE_MISS,   // bpf_h_extract walked SSL→wrl→enc_ctx but cache had no entry
  DBG_KPROBE_BRIDGE_FROM_PENDING, // kprobe used H carried via xor_pending (libcrypto-hook hot path)
  DBG_KPROBE_WALK_LEGACY,     // kprobe walked SSL→wrl→enc_ctx→algctx→H (BoringSSL/cold-start path)
  DBG_H_EXTRACT_LIVE_WALK,    // bpf_h_extract derived H live from enc_ctx→algctx→H on cache miss
  DBG_BSSL_REACHED,           // kprobe entered the BoringSSL branch (tls_lib==BORINGSSL)
  DBG_BSSL_H_OK,              // BoringSSL bssl_recover_h recovered a non-zero H
  DBG_BSSL_S3_NULL,          // bssl: SSL→s3 read failed / null
  DBG_BSSL_AEAD_NULL,        // bssl: s3→aead_write_ctx read failed / null
  DBG_BSSL_RDKEY_FAIL,       // bssl: AES_KEY.rd_key read failed
  DBG_BSSL_ROUNDS_BAD,       // bssl: AES_KEY.rounds not in {9,10,12,13,14}
  DBG_BSSL_HZERO,            // bssl: recovered H was all-zero
  DBG_OSSL_GCM_GATE_FAIL,    // OpenSSL: algctx failed the gcm.key == &ks check (not a keyed GCM ctx)
  DBG_OSSL_H_FROM_HKEY1,     // OpenSSL: H recovered from the AVX-512 HashKey_1 slot (raw H field zero)
  DBG_SECRET_BINDING_DENY,   // placeholder redeemed outside its pod binding: refused
  DBG_SECRET_BINDING_AUDIT,  // same, but audit mode let the rewrite go ahead
  DBG_SNI_CAPTURED,          // first handshake record on a connection parsed into sni_state
  DBG_SNI_DENY,              // patch for a host-restricted secret refused: SNI missing / not the host
  DBG_SNI_AUDIT,             // same, but audit mode let the rewrite go ahead
  DBG_VIP_DNS_REWRITTEN,     // tc_dns_rewrite replaced a watched host's A / AAAA records with its fake IP
  DBG_VIP_DNS_UNCHANGED,     // a watched host's answer left unchanged (not every record could be read)
  DBG_VIP_CONNECT_REDIRECT,  // vip_connect4 sent a connect to a fake IP to a real address
  DBG_VIP_CONNECT_REFUSED,   // connect to a fake IP refused: unallocated, or no address recorded yet
  DBG_VIP_DNS_UNBOUND,       // a watched host's answer left unchanged: the pod has no secret for the host
  DBG_VIP_SOCK_HOST_DENY,    // patch refused at tcp_sendmsg: the socket did not connect to the secret host's fake IP
  DBG_VIP_SOCK_ADDR_DENY,    // patch refused at tcp_sendmsg: the socket's real address or port is not the secret's
  DBG_MAX,
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 128); // must be >= DBG_MAX

  __type(key, __u32);
  __type(value, __u64);
} debug_counters SEC(".maps");

static __always_inline void dbg_inc(__u32 idx) {
  __u64 *val = bpf_map_lookup_elem(&debug_counters, &idx);
  if (val)
    __sync_fetch_and_add(val, 1);
}

// secret_binding_allows reports whether the current process may redeem the
// placeholder `key`: its cgroup must be bound to the owning secret in
// secret_acl. Must run in the writing process's context (the SSL_write /
// Go Write uprobes and their tail calls). An unbound redemption is refused,
// or allowed in audit mode; either way it is reported on
// secret_binding_events so the controller can name the pod and the secret.
static __always_inline int secret_binding_allows(const struct secret_key *key) {
  struct secret_acl_key ak = {};
  ak.cgroup_id = bpf_get_current_cgroup_id();
  __builtin_memcpy(&ak.key, key, sizeof(ak.key));
  if (bpf_map_lookup_elem(&secret_acl, &ak))
    return 1;

  __u32 zero = 0;
  __u32 *mode = bpf_map_lookup_elem(&secret_binding_mode, &zero);
  int audit = mode && *mode == SECRET_BINDING_AUDIT;
  dbg_inc(audit ? DBG_SECRET_BINDING_AUDIT : DBG_SECRET_BINDING_DENY);
  report_secret_event(key, (__u8)audit, SECRET_EVT_BINDING, 0, 0, NULL);
  return audit;
}

// =============================================================================
// Process and connection tracking maps
// =============================================================================

// Per-process opt-in filter: only track these TGIDs.
// Populated by the exec tracepoint for all kubepods processes.
// Sized for busy clusters with many concurrent container processes.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u32);   // tgid
  __type(value, __u8);  // 1 = tracked
} tracked_tgids SEC(".maps");

// A 16-byte address: IPv6, or IPv4-mapped.
struct dns_ip_key {
  __u8 ip[16];
};

// TCP connection fd -> peer IP and port per process, for every connect()
// (tp_exit_connect). The SSL_write uprobe uses it to tell the connections a
// process made from those it accepted.
struct conn_ip_key {
  __u32 tgid;
  __u32 fd;
};

struct conn_ip_val {
  __u8 ip[16]; // IPv4-mapped-IPv6 or native IPv6
  __u16 port;  // destination port (network byte order)
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 16384);
  __type(key, struct conn_ip_key);
  __type(value, struct conn_ip_val);
} conn_ip_map SEC(".maps");

// Trusted DNS server IPs: tc_dns_rewrite only rewrites their answers.
// Populated from userspace (kube-dns's ClusterIPs and endpoints, and
// --trusted-dns-servers).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, struct dns_ip_key);  // 16-byte IPv4-mapped-IPv6
  __type(value, __u8);             // 1 = trusted
} trusted_dns_servers SEC(".maps");

// Flag: 1 if trusted_dns_servers whitelist is active, 0 if not configured.
// Used to distinguish "map empty = allow all" from "IP not in map = reject".
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);  // 0 = allow all, 1 = whitelist active
} dns_whitelist_enabled SEC(".maps");

// Scratch for connect enter->exit correlation: save fd, IP, and port.
struct connect_pending_val {
  __u32 fd;
  __u8 ip[16];  // destination IP (IPv4-mapped-IPv6)
  __u16 port;   // destination port (network byte order)
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);

  __type(key, __u64);   // pid_tgid
  __type(value, struct connect_pending_val);
} connect_pending SEC(".maps");

// Scratch for EVP_CipherInit_ex enter→return correlation: stash arg0
// (EVP_CIPHER_CTX *) so the uretprobe can read H from it after OpenSSL has
// finished setting up the cipher state.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);   // pid_tgid
  __type(value, __u64); // EVP_CIPHER_CTX *
} evp_init_scratch SEC(".maps");

// Cached GHASH H per (tgid, EVP_CIPHER_CTX *), populated by the uretprobe
// on EVP_CipherInit_ex. SSL_write uprobe walks SSL→wrl→enc_ctx and looks
// H up by the enc_ctx pointer — eliminates the dependency on lazy
// initialization of wrl→enc_ctx in libssl 3.5+.
struct evp_h_key {
  __u32 tgid;
  __u32 _pad;
  __u64 evp_ctx_ptr;
};
struct evp_h_val {
  __u8  ghash_h[16];
  __u16 cipher_type;        // KLOAK_CIPHER_AES_GCM (set on success)
  __u8  nonce_len;          // 0xFF — actual nonce_len comes from SSL_CONNECTION.version
  __u8  _pad[5];
};
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct evp_h_key);
  __type(value, struct evp_h_val);
} evp_h_cache SEC(".maps");

// Per-process H-extraction strategy. Written by the controller when the
// libcrypto EVP_CipherInit_ex uretprobe attaches successfully for a pid.
// Read in bpf_uprobe_ssl_write to choose between the cache-lookup path
// (LIBCRYPTO_HOOK) and the legacy kprobe-walk path (default 0).
//   0 = STRATEGY_KPROBE_WALK    — BoringSSL, static binaries, OpenSSL where
//                                 the libcrypto attach failed. Pre-existing
//                                 SSL_write→xor_path→kprobe-walks-chain flow.
//   1 = STRATEGY_LIBCRYPTO_HOOK — OpenSSL where libcrypto.so was found and
//                                 EVP_CipherInit_ex hooks are in place.
//                                 SSL_write→h_extract(cache)→xor_path→kprobe
//                                 reads H from xor_pending.
#define STRATEGY_KPROBE_WALK    0
#define STRATEGY_LIBCRYPTO_HOOK 1
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u32);   // tgid
  __type(value, __u8);  // strategy
} tls_strategy SEC(".maps");

// A watched hostname, zero-padded: the key of vip_host_ip.
struct watched_host_key {
  char host[MAX_HOST_LEN];
};

// =============================================================================
// Virtual IP host resolution (spinningfactory/kloak#327)
// =============================================================================

// Every watched host gets a fake IP from a reserved range (virtual_ip.go), and
// a fake IPv6 from the IPv6 range when one is configured. tc_dns_rewrite
// hands a pod the fake IP of the answer's family in place of the host's
// addresses, and records the real ones in vip_upstream; vip_connect4/6 send a
// connect to the fake IP to one of them. vip_host_ip and vip_ip_host are
// written only by userspace. The vip_* maps holding state (vip_host_ip,
// vip_ip_host, vip_upstream) are pinned in bpffs, so a
// controller restart keeps the fake IPs apps may have cached and where they
// lead.

// Watched host -> its fake IPs.
struct vip_host_val {
  __u8 ip4[4];  // fake IPv4, network byte order
  __u8 ip6[16]; // fake IPv6; all zero without an IPv6 range
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, struct watched_host_key);
  __type(value, struct vip_host_val);
} vip_host_ip SEC(".maps");

// Set on a fake IP whose host is no longer watched. The IP stays reserved
// for that host (and still resolves to it) for a retention period, so it is
// not handed to another host while apps may still cache it.
#define VIP_F_RETIRED 1

// Fake IP -> host.
struct vip_ip_val {
  char host[MAX_HOST_LEN]; // lowercased, zero-padded (hosts_match-comparable)
  __u32 host_len;
  __u32 flags;      // VIP_F_*
  __u64 retired_at; // unix seconds; userspace bookkeeping only
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096); // active hosts plus retired reservations
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, struct dns_ip_key); // IPv4-mapped-IPv6 or native IPv6
  __type(value, struct vip_ip_val);
} vip_ip_host SEC(".maps");

// The virtual IP ranges, written by userspace at startup. mask4 == 0 (the
// default, before that) disables tc_dns_rewrite and vip_connect4/6; an
// all-zero mask6 means no IPv6 range (AAAA answers are left unchanged).
struct vip_config_val {
  __u32 net4;     // range address, network byte order
  __u32 mask4;    // range mask, network byte order
  __u8 net6[16];  // IPv6 range address
  __u8 mask6[16]; // IPv6 range mask
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct vip_config_val);
} vip_config SEC(".maps");

static __always_inline int vip_in_range(const struct vip_config_val *cfg,
                                        __u32 ip4) {
  return cfg->mask4 && (ip4 & cfg->mask4) == cfg->net4;
}

// vip_addr_in_range reports whether ip (IPv4-mapped or IPv6) is a fake IP:
// in the virtual IP range of its family.
static __always_inline int vip_addr_in_range(const struct vip_config_val *cfg,
                                             const __u8 *ip) {
  if (vip_addr_v4mapped(ip)) {
    __u32 ip4;
    __builtin_memcpy(&ip4, ip + 12, 4);
    return vip_in_range(cfg, ip4);
  }
  return cfg->mask4 && vip_in_prefix6(cfg->net6, cfg->mask6, ip);
}

// Fake IP -> the real addresses of its host (struct vip_upstream_val in
// helpers.h), as the trusted resolvers last returned them to a pod.
// Written by tc_dns_rewrite; userspace deletes the entry of a fake IP that
// is released or handed to another host.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096); // = vip_ip_host
  __type(key, struct dns_ip_key); // fake IP, IPv4-mapped-IPv6 or IPv6
  __type(value, struct vip_upstream_val);
} vip_upstream SEC(".maps");

// Per socket: the fake IP vip_connect4/6 redirected it from, so that
// getpeername() reports the address the app connected to.
struct vip_sock_val {
  __u8 fake_ip[16]; // IPv4-mapped-IPv6 or IPv6
  __u8 real_ip[16]; // the same family as fake_ip
  __u32 port;       // bpf_sock_addr.user_port (network byte order)
};

struct {
  __uint(type, BPF_MAP_TYPE_SK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct vip_sock_val);
} vip_sock SEC(".maps");

// Socket cookie -> host of the fake IP the socket connected to. Written by
// vip_connect4/6; read at tcp_sendmsg (socket_filter_patches), which decides
// a host-restricted secret on it. Keyed by cookie, not in vip_sock: a kprobe
// can't read socket storage, and cookies are never reused. An entry goes
// when its socket connects anywhere else or closes; a socket whose entry is
// missing gets no host-restricted secret.
struct vip_sock_host_val {
  char host[MAX_HOST_LEN]; // as vip_ip_val.host
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536); // = sni_state
  __type(key, __u64);
  __type(value, struct vip_sock_host_val);
} vip_sock_host SEC(".maps");

// Socket cookie -> the address and port a TCP socket connected to, as
// vip_connect4/6 leave the connect: after their own redirect, before a
// connect hook further up the cgroup tree runs. A CNI's socket load balancer
// there (Cilium's kube-proxy replacement, on the root cgroup) replaces a
// Service's ClusterIP with a backend's, so the socket's own destination is
// the backend. socket_filter_patches checks a secret's IP and port against
// this instead, so that they mean the same with and without socket load
// balancing: the address the app connected to, as kube-proxy (which DNATs
// the packets, not the socket) leaves it. Removed when the socket closes;
// without an entry (evicted, or the socket connected before the hooks were
// attached), the socket's own destination is used.
struct vip_sock_dst_val {
  __u8 ip[16]; // IPv4-mapped or IPv6
  __u16 port;  // host byte order
  __u16 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536); // = vip_sock_host
  __type(key, __u64);
  __type(value, struct vip_sock_dst_val);
} vip_sock_dst SEC(".maps");

// The (pod IP, host) pairs tc_dns_rewrite rewrites answers for: a pod gets
// the fake IP of a host only if it references a secret restricted to that
// host (its secret_acl bindings). An all-zero host stands for every watched
// host (--secret-binding=audit, where a pod may redeem any secret). Written
// only by userspace, from the pod bindings; not pinned (rebuilt at startup).
struct vip_pod_host_key {
  __u8 pod_ip[16];         // IPv4-mapped-IPv6 or IPv6, as dns_ip_key
  char host[MAX_HOST_LEN]; // as watched_host_key
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, struct vip_pod_host_key);
  __type(value, __u8);
} vip_pod_host SEC(".maps");

// Per-CPU state of tc_dns_rewrite: the DNS message and the walks over it
// (too large for the stack). Its own: tc runs in softirq context, which can
// interrupt another program using a shared scratch buffer on the same CPU.
struct dns_rewrite_buf {
  __u8 msg[MAX_DNS_PKT];
  struct dns_question q;
  struct dns_answers a;
  struct vip_upstream_val up;
  struct vip_pod_host_key pod;
  __u8 rdata[16]; // the fake IP as an answer record holds it (A: 4 bytes)
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct dns_rewrite_buf);
} dns_rewrite_scratch SEC(".maps");

// =============================================================================
// Container process lifecycle tracking
// =============================================================================

// Tracked container cgroups: cgroup inode ID -> enabled.
// Populated from userspace when a container is discovered by the reconciler.
// Used by sched_process_exec/exit tracepoints to filter events to tracked containers.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
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
// Written by bpf_h_extract (libcrypto-hook path) and by the tcp_sendmsg
// kprobe once it has H; read by bpf_xor_path and by tc, which derives the
// H powers itself (copy_h_power_step).
struct tls_conn_key {
  __u32 tgid;
  __u32 _pad;
  __u64 ssl_ptr;
};

struct tls_conn_state {
  __u8  ghash_h[16];         // GHASH key H = AES(K, 0^128)
  __u16 cipher_type;        // KLOAK_CIPHER_AES_GCM or KLOAK_CIPHER_UNKNOWN
  __u8  nonce_len;           // 0 = TLS 1.3, 8 = TLS 1.2, 0xFF = unknown (use heuristic)
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
  struct secret_key key;    // placeholder key: tcp_sendmsg re-checks the secret's host against the SNI
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
  __u8  memory_bio;         // 1=memory BIO (Node.js, Bun): the app sends the record later, maybe after other sends
  __u8  h_valid;            // 1 if ghash_h was populated at uprobe time (libcrypto-hook path)
  __u32 plaintext_len;      // SSL_write data length (for TLS version detection in tc)
  __u64 created_at;         // bpf_ktime_get_ns() — for TTL-based cleanup (memory BIO)
  // GHASH H carried from uprobe to kprobe when the libcrypto cipher-init hook
  // populated evp_h_cache and bpf_h_extract found a hit. h_valid=0 means the
  // process is on STRATEGY_KPROBE_WALK (BoringSSL, statically-linked, or
  // libcrypto attach failed) and the kprobe must walk SSL→…→H itself.
  __u8  ghash_h[16];
  __u16 cipher_type;        // KLOAK_CIPHER_AES_GCM if h_valid=1, else KLOAK_CIPHER_UNKNOWN
  __u8  nonce_len;          // 0=TLS 1.3, 8=TLS 1.2, 0xFF=unknown
  __u8  _pad[5];
};

// Per-process pending XOR patches, keyed by tgid.
// Written by the uprobe (xor_path), read by the tcp_sendmsg kprobe which
// bridges to tc_pending with the per-connection (dst_ip, src_port) key.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);

  __type(key, __u32);  // tgid (process ID) — cross-thread visible for libuv/Node.js
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
  __u32 ssl_to_version;     // SSL_CONNECTION* + off → int version (0xFFFFFFFF=unknown)
  // ssl_to_wbio is the offset from the SSL/SSL_CONNECTION pointer to its
  // `wbio` BIO* field. Used by ssl_read_fd() to walk SSL → wbio → BIO.num
  // (the socket fd). 3.0/3.1 use struct ssl_st where wbio lives at 24;
  // 3.2+ wrapped SSL in ssl_connection_st and moved wbio to 88. Pushed by
  // pushTLSOffsets per detected OpenSSL major.minor — 0 here means
  // "unknown; ssl_read_fd should fall back to the legacy hardcoded 88".
  __u32 ssl_to_wbio;

  // tls_lib selects the H-extraction chain. The OpenSSL fields above (ssl_to_wrl
  // …) are unused when tls_lib == TLS_LIB_BORINGSSL, and the BoringSSL fields
  // below are unused when tls_lib == TLS_LIB_OPENSSL.
  __u32 tls_lib;
  // BoringSSL chain (no OSSL_RECORD_LAYER indirection):
  //   SSL* + bssl_ssl_to_s3       → SSL3_STATE*     (pointer deref)
  //        + bssl_s3_to_aead      → SSLAEADContext* (pointer deref, aead_write_ctx)
  //        + bssl_aead_to_aeskey  → AES_KEY.rd_key  (direct read of round keys)
  // BoringSSL persists no raw H — only the AES round-key schedule — so the
  // walk lands on AES_KEY and the data plane recomputes H = AES_encrypt(0).
  // AES_KEY.rounds sits BSSL_AESKEY_ROUNDS_OFF (240) past rd_key.
  __u32 bssl_ssl_to_s3;
  __u32 bssl_s3_to_aead;
  __u32 bssl_aead_to_aeskey;

  // OpenSSL provider GCM context (algctx) layout used by ossl_read_gcm_h.
  // Appended last so every field above keeps its offset; 0 = not calibrated.
  //   ossl_algctx_to_gcm_key:    algctx + off → GCM128_CONTEXT.key (AES_KEY*)
  //   ossl_algctx_to_ks:         algctx + off → PROV_AES_GCM_CTX.ks, which every
  //                              keyed GCM ctx points gcm.key at (self-pointer)
  //   ossl_algctx_to_vaes_hkey1: algctx + off → GCM128_CONTEXT.Htable[15], where
  //                              the AVX-512 GCM path stores HashKey_1 instead
  //                              of writing the raw H field (issue #275)
  __u32 ossl_algctx_to_gcm_key;
  __u32 ossl_algctx_to_ks;
  __u32 ossl_algctx_to_vaes_hkey1;
};

#define TLS_LIB_OPENSSL 0
#define TLS_LIB_BORINGSSL 1
#define BSSL_AESKEY_ROUNDS_OFF 240  // AES_KEY: uint32_t rd_key[60]; uint32_t rounds;
#define BSSL_AES_RDKEY_BYTES 240    // (AES_MAXNR+1)*16 = 15*16

// An offsets entry is uncalibrated (push not yet seen / wrong key) when neither
// the OpenSSL chain (ssl_to_wrl) nor the BoringSSL chain (bssl_ssl_to_s3) is
// populated. Used to gate the per-binary offset lookup + its exe_inode=0
// fallback in the kprobe H-walk.
#define OFFSETS_UNCALIBRATED(o)                                                 \
  ((o)->ssl_to_wrl == 0 &&                                                      \
   !((o)->tls_lib == TLS_LIB_BORINGSSL && (o)->bssl_ssl_to_s3 != 0))

// ossl_read_gcm_h results. Only RAW and HKEY1 yield a usable H.
#define OSSL_H_READ_FAIL 0 // a probe read faulted
#define OSSL_H_ZERO      1 // no H available (raw field zero, no recovery path)
#define OSSL_H_NOT_GCM   2 // definite gate mismatch: not a keyed GCM context
#define OSSL_H_RAW       3 // H read from GCM128_CONTEXT.H
#define OSSL_H_HKEY1     4 // H recovered from the AVX-512 HashKey_1 slot
#define OSSL_H_OK(r) ((r) >= OSSL_H_RAW)

// ossl_read_gcm_h reads the GHASH subkey H for an OpenSSL provider GCM
// context, writing it to h as the 16-byte big-endian GHASH string.
//
// Gate: every keyed OpenSSL GCM context has gcm.key pointing at its own
// PROV_AES_GCM_CTX.ks (CRYPTO_gcm128_init / vaes_gcm_setkey). Garbage at the
// H offset of a non-GCM context (AES-CTR DRBG, ChaCha20, …) or of a context
// not keyed yet cannot satisfy that self-pointer. Uncalibrated gate offsets
// fall back to the legacy heuristic (raw H non-zero ⇒ GCM).
//
// H source: OpenSSL's generic and AES-NI GCM paths write GCM128_CONTEXT.H at
// key setup. On x86-64 CPUs with AVX-512 + VAES + VPCLMULQDQ, OpenSSL ≥ 3.1
// uses vaes_gcm instead: vaes_gcm_setkey zeroes the GCM128_CONTEXT and
// ossl_aes_gcm_init_avx512 only fills Htable, storing
// HashKey_1 = (bswap128(H) << 1) ^ (MSB ? POLY : 0) in Htable[15] — so the raw
// H field is always zero there. That slot is inverted with gf128_halve_to_h.
// arm64 GCM paths always write raw H, so a zero there means an unknown
// implementation and fails closed.
//
// Always inline, and h is the caller's buffer (no locals beyond scalars):
// bpf_h_extract is a tail-call program and the tcp_sendmsg kprobe is close to
// the 512-byte stack limit, so neither can afford a BPF-to-BPF call frame.
static __always_inline int ossl_read_gcm_h(__u64 algctx,
                                           const struct tls_offsets *o,
                                           __u64 h[2]) {
  int gated = o->ossl_algctx_to_gcm_key != 0 && o->ossl_algctx_to_ks != 0;
  if (gated) {
    if (bpf_probe_read_user(&h[0], 8, (void *)(algctx + o->ossl_algctx_to_gcm_key)) < 0)
      return OSSL_H_READ_FAIL;
    if (h[0] != algctx + o->ossl_algctx_to_ks) {
      dbg_inc(DBG_OSSL_GCM_GATE_FAIL);
      return OSSL_H_NOT_GCM;
    }
  }

  if (bpf_probe_read_user(h, 16, (void *)(algctx + o->algctx_to_h)) < 0)
    return OSSL_H_READ_FAIL;
  if (h[0] | h[1]) {
    // GCM128_CONTEXT.H holds H as native u64 halves; GHASH wants big-endian.
    h[0] = __builtin_bswap64(h[0]);
    h[1] = __builtin_bswap64(h[1]);
    return OSSL_H_RAW;
  }

#if defined(bpf_target_x86)
  if (gated && o->ossl_algctx_to_vaes_hkey1 != 0) {
    if (bpf_probe_read_user(h, 16, (void *)(algctx + o->ossl_algctx_to_vaes_hkey1)) < 0)
      return OSSL_H_READ_FAIL;
    if (h[0] | h[1]) {
      gf128_halve_to_h(h[0], h[1], (__u8 *)h);
      dbg_inc(DBG_OSSL_H_FROM_HKEY1);
      return OSSL_H_HKEY1;
    }
  }
#endif
  return OSSL_H_ZERO;
}

// Per-CPU scratch for reading BoringSSL's AES round-key schedule off the BPF
// stack (240 bytes would otherwise crowd the kprobe stack frame).
struct aes_scratch_buf {
  __u8 rd_key[BSSL_AES_RDKEY_BYTES];
};
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct aes_scratch_buf);
} aes_scratch SEC(".maps");

// Diagnostic capture for the BoringSSL H-walk (read by the controller). Records
// the last walk's pointers + the rounds value read at the configured offset,
// plus a scan that reports the offset where a valid AES round count (10/12/14)
// actually sits — so a wrong AEADToAESKey on a given build/arch is visible
// without local reproduction. Only written in KLOAK_DEBUG builds; otherwise it
// stays zero and the controller logs nothing for it.
struct bssl_probe_val {
  __u64 ssl;
  __u64 s3;
  __u64 aead;
  __u32 cfg_off;       // configured aead_to_aeskey
  __u32 raw_rounds;    // rounds read at aead + cfg_off + 240
  __u32 good_off;      // scanned offset where rounds ∈ {9,10,12,13,14} (0 if none)
  __u32 good_rounds;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bssl_probe_val);
} bssl_probe SEC(".maps");

// bssl_recover_h walks the BoringSSL chain SSL → s3 → aead_write_ctx → AES_KEY
// and recomputes the GHASH subkey H = AES_encrypt(0), writing 16 bytes to
// h_out. Returns 1 on success, 0 on any failure.
//
// Deliberately __noinline: the AES round function plus the 240-byte round-key
// read need their own stack frame. Inlining this into the already stack-heavy
// bpf_kprobe_tcp_sendmsg blows the 512-byte BPF stack limit; a BPF-to-BPF call
// gives it a separate frame. Offsets are passed by value (not the map-value
// pointer) to keep the verifier's job simple.
static __attribute__((noinline)) int bssl_recover_h(__u64 ssl_ptr, __u32 ssl_to_s3,
                                                    __u32 s3_to_aead,
                                                    __u32 aead_to_aeskey,
                                                    __u8 *h_out) {
  __u64 s3 = 0, aead = 0;
  if (bpf_probe_read_user(&s3, 8, (void *)(ssl_ptr + ssl_to_s3)) < 0 || !s3) {
    dbg_inc(DBG_BSSL_S3_NULL);
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [BSSL] s3 read fail ssl=%llx off=%u", ssl_ptr, ssl_to_s3);
#endif
    return 0;
  }
  if (bpf_probe_read_user(&aead, 8, (void *)(s3 + s3_to_aead)) < 0 || !aead) {
    dbg_inc(DBG_BSSL_AEAD_NULL);
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [BSSL] aead read fail s3=%llx off=%u", s3, s3_to_aead);
#endif
    return 0;
  }

  __u32 zk = 0;
  struct aes_scratch_buf *ab = bpf_map_lookup_elem(&aes_scratch, &zk);
  if (!ab)
    return 0;

  __u64 aeskey = aead + aead_to_aeskey;
  if (bpf_probe_read_user(ab->rd_key, BSSL_AES_RDKEY_BYTES, (void *)aeskey) < 0) {
    dbg_inc(DBG_BSSL_RDKEY_FAIL);
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [BSSL] rd_key read fail aead=%llx off=%u", aead, aead_to_aeskey);
#endif
    return 0;
  }
  __u32 rounds = 0;
  if (bpf_probe_read_user(&rounds, 4, (void *)(aeskey + BSSL_AESKEY_ROUNDS_OFF)) < 0) {
    dbg_inc(DBG_BSSL_RDKEY_FAIL);
    return 0;
  }

  // Diagnostic: record the walk + scan for where a valid AES round count
  // actually sits (the SSLAEADContext is the heap object `aead` points to;
  // scan a window of offsets within it). Helps pin AEADToAESKey per build/arch.
  // KLOAK_DEBUG builds only (the e2e and nightly images): the scan is dead
  // weight in the stack-heavy tcp_sendmsg kprobe otherwise.
#ifdef KLOAK_DEBUG
  {
    __u32 zero = 0;
    struct bssl_probe_val *pv = bpf_map_lookup_elem(&bssl_probe, &zero);
    if (pv) {
      pv->ssl = ssl_ptr;
      pv->s3 = s3;
      pv->aead = aead;
      pv->cfg_off = aead_to_aeskey;
      pv->raw_rounds = rounds;
      pv->good_off = 0;
      pv->good_rounds = 0;
      for (__u32 off = 16; off <= 400; off += 8) {
        __u32 r = 0;
        if (bpf_probe_read_user(&r, 4, (void *)(aead + off + BSSL_AESKEY_ROUNDS_OFF)) < 0)
          continue;
        if (r == 10 || r == 9 || r == 12 || r == 14 || r == 13) {  // 9/13 = x86 AES-NI nr-1
          pv->good_off = off;
          pv->good_rounds = r;
          break;
        }
      }
    }
  }
#endif

  // aes_recover_h validates rounds ∈ {10,14} and writes H to h_out in place.
  if (!aes_recover_h(ab->rd_key, rounds, h_out)) {
    dbg_inc(DBG_BSSL_ROUNDS_BAD);
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [BSSL] aes_recover_h fail rounds=%u", rounds);
#endif
    return 0;
  }

  __u64 *bh = (__u64 *)h_out;
  if (bh[0] == 0 && bh[1] == 0) {
    dbg_inc(DBG_BSSL_HZERO);
    return 0;
  }
#ifdef KLOAK_DEBUG
  bpf_printk("kloak [BSSL] H ok rounds=%u h0=%llx h1=%llx", rounds, bh[0], bh[1]);
#endif
  return 1;
}

// Shared key for per-binary TLS config maps (see tls_offset_config and
// go_tls_offset_config below). Keyed by (cgroup_id, exe_inode) rather than
// tgid for two reasons:
//   1. cgroup_id survives PID namespace mismatches in nested setups
//      (kind, k3d) where BPF's bpf_get_current_pid_tgid() returns
//      root-NS PIDs while userspace sees its own NS PIDs.
//   2. exe_inode distinguishes different binaries running inside the same
//      cgroup (e.g. a shell that exec's an app, or one binary spawning
//      another). Without it, the last-pushed offsets would overwrite
//      earlier ones and corrupt TLS for the first binary.
struct tls_binary_key {
  __u64 cgroup_id;
  __u64 exe_inode;
};

// Per-binary OpenSSL/BoringSSL offsets for the XOR-patch path. Per-binary
// keying lets different OpenSSL versions coexist on the same node (e.g.,
// Node.js with statically linked BoringSSL + curl with system OpenSSL 3.0).
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct tls_binary_key);
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
  __u32 conn_vers_off;    // Conn* + off → uint16 negotiated TLS version (e.g. 0x0303, 0x0304)
};

// Per-binary Go crypto/tls offsets. Shares the tls_binary_key struct with
// tls_offset_config — see the commentary there for the rationale.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, struct tls_binary_key);
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
  __u32 write_seq;          // TCP write_seq at time of tcp_sendmsg — identifies the exact segment
};

// Holds all large structs and buffers that would otherwise exceed the 512-byte
// BPF stack limit, including staging areas for map updates and GF(2^128) state.
struct ghash_work {
  // Staging for map updates (avoids large structs on BPF stack)
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
  // Connection key + record position for deferred tag patching (multi-segment records).
  struct tc_dest_key ghash_conn_key;
  __u32 ghash_pkt_seq;           // TCP seq of this segment
  __u32 ghash_record_tcp_off;    // TLS record start offset within TCP payload (0 if first record)
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct ghash_work);
} ghash_scratch SEC(".maps");

// Per-CPU scratch for the tls_conn_state that bpf_kprobe_tcp_sendmsg builds
// before committing it to the tls_conn_state map. Kept off the kprobe's
// stack, which together with the bpf-to-bpf call into bssl_recover_h is the
// deepest frame chain in this file (512-byte verifier limit).
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct tls_conn_state);
} conn_state_scratch SEC(".maps");

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

// Deferred GHASH tag delta for TLS records that span multiple TCP segments.
// When the ciphertext is patched in segment 1 but the auth tag is in a later
// segment, the precomputed tag correction is stored here and applied when the
// segment containing the tag arrives.
struct tc_tag_val {
  __u8  tag_delta[16];    // precomputed GHASH correction: new_tag = old_tag ^ delta
  __u32 tag_tcp_seq;      // TCP seq number of the byte where the auth tag starts
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 4096);
  __type(key, struct tc_dest_key);
  __type(value, struct tc_tag_val);
} tc_tag_pending SEC(".maps");

// =============================================================================
// Address helpers
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

// dns_server_trusted reports whether DNS answers from ip (IPv4-mapped-IPv6
// or IPv6) are believed: any server while no trusted_dns_servers whitelist
// is configured, otherwise only the listed ones.
static __always_inline int dns_server_trusted(const __u8 *ip) {
  __u32 flag_key = 0;
  __u8 *enabled = bpf_map_lookup_elem(&dns_whitelist_enabled, &flag_key);
  if (!enabled || *enabled != 1)
    return 1;
  struct dns_ip_key key = {};
  __builtin_memcpy(key.ip, ip, 16);
  return bpf_map_lookup_elem(&trusted_dns_servers, &key) != NULL;
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
    // Port is at offset 2 in sockaddr_in (after sa_family)
    __u16 port_be = 0;
    bpf_probe_read_user(&port_be, sizeof(port_be), (void *)(addr_ptr + 2));
    val.port = port_be;
  } else if (sa_family == 10) { // AF_INET6
    bpf_probe_read_user(val.ip, 16, (void *)(addr_ptr + 8));
    // Port is at offset 2 in sockaddr_in6
    __u16 port_be = 0;
    bpf_probe_read_user(&port_be, sizeof(port_be), (void *)(addr_ptr + 2));
    val.port = port_be;
  } else {
    return 0;
  }

  bpf_map_update_elem(&connect_pending, &pid_tgid, &val, BPF_ANY);
  return 0;
}

// tp/syscalls/sys_exit_connect: on success (or EINPROGRESS), record fd->IP.
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
  __u16 port = pending->port;
  __builtin_memcpy(ip, pending->ip, 16);

  bpf_map_delete_elem(&connect_pending, &pid_tgid);

  // connect returns 0 on success, or -EINPROGRESS (-115) for non-blocking.
  long ret = ctx->ret;
  if (ret != 0 && ret != -115)
    return 0;

  struct conn_ip_key cik = {.tgid = tgid, .fd = fd};
  struct conn_ip_val civ;
  __builtin_memcpy(civ.ip, ip, 16);
  civ.port = port;
  bpf_map_update_elem(&conn_ip_map, &cik, &civ, BPF_ANY);
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
  return 0;
}

// Fallback wbio offset used only when tls_offset_config has no entry for
// the current binary yet (cold path very early in a process's lifetime,
// before pushTLSOffsets has run). Matches OpenSSL 3.2+ ssl_connection_st.
// 3.0/3.1 resolve their own (smaller) wbio offset at runtime — keeping
// the fallback at 88 preserves the pre-fix behavior for callers that
// happen to be on 3.2+ but raced the userspace push.
#define SSL_WBIO_OFFSET_FALLBACK 88
// offsetof(bio_st, num). Confirmed identical on OpenSSL 3.0.13 and 3.5
// via pahole + empirical SSL_set_bio + pointer-scan; the bio_st layout
// hasn't been reshuffled across 3.x. If a future release does move
// `num`, lift this into tls_offsets the same way ssl_to_wbio is now.
#define BIO_NUM_OFFSET  56

// resolve_wbio_offset returns the SSL → wbio field offset for the
// calling process's libssl, derived from the per-binary tls_offset_config
// pushed by pushTLSOffsets. Falls back to the hardcoded 3.2+ value if
// the map has no entry yet (race with userspace push) so existing 3.2+
// workloads keep working even on the cold path.
static __always_inline __u32 resolve_wbio_offset(void) {
  struct tls_binary_key bk = {};
  bk.cgroup_id = bpf_get_current_cgroup_id();
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  bk.exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
  struct tls_offsets *off = bpf_map_lookup_elem(&tls_offset_config, &bk);
  if (off && off->ssl_to_wbio != 0) return off->ssl_to_wbio;
  bk.exe_inode = 0;
  off = bpf_map_lookup_elem(&tls_offset_config, &bk);
  if (off && off->ssl_to_wbio != 0) return off->ssl_to_wbio;
  return SSL_WBIO_OFFSET_FALLBACK;
}

// Read the socket fd directly from the SSL struct's write BIO.
// Returns the fd, or 0 if the read fails.
static __always_inline __u32 ssl_read_fd(__u64 ssl_ptr) {
  if (!ssl_ptr) return 0;
  __u32 wbio_off = resolve_wbio_offset();
  __u64 wbio = 0;
  if (bpf_probe_read_user(&wbio, 8, (void *)(ssl_ptr + wbio_off)) < 0 || !wbio)
    return 0;
  __u32 fd = 0;
  if (bpf_probe_read_user(&fd, 4, (void *)(wbio + BIO_NUM_OFFSET)) < 0)
    return 0;
  return fd;
}

// -----------------------------------------------------------------------------
// Prescan: bpf_loop callback to find all kl:: prefixes in the SSL_write buffer.
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
// libcrypto EVP_CipherInit_ex hooks — capture H at the canonical moment
// OpenSSL keys the cipher. Cached by (tgid, EVP_CIPHER_CTX *), looked up
// later by bpf_h_extract during SSL_write. Eliminates the dependency on
// libssl 3.5+'s lazy wrl→enc_ctx initialization, since by the time the
// uretprobe fires, OpenSSL has fully set up the EVP_CIPHER_CTX.
// =============================================================================

SEC("uprobe/evp_cipher_init")
int bpf_uprobe_evp_cipher_init(void *ctx) {
  __u64 cgroup_id = bpf_get_current_cgroup_id();
  if (!bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id))
    return 0;

  __u64 evp_ctx_ptr = 0;
#if defined(bpf_target_x86)
  bpf_probe_read_kernel(&evp_ctx_ptr, sizeof(evp_ctx_ptr), (char *)ctx + 112); // RDI
#elif defined(bpf_target_arm64)
  bpf_probe_read_kernel(&evp_ctx_ptr, sizeof(evp_ctx_ptr), (char *)ctx + 0);   // X0
#else
  return 0;
#endif
  if (!evp_ctx_ptr)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&evp_init_scratch, &pid_tgid, &evp_ctx_ptr, BPF_ANY);
  dbg_inc(DBG_EVP_INIT_ENTRY);
  return 0;
}

SEC("uretprobe/evp_cipher_init")
int bpf_uretprobe_evp_cipher_init(void *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u64 *evp_ctx_p = bpf_map_lookup_elem(&evp_init_scratch, &pid_tgid);
  if (!evp_ctx_p)
    return 0;
  __u64 evp_ctx_ptr = *evp_ctx_p;
  bpf_map_delete_elem(&evp_init_scratch, &pid_tgid);

  // Look up offsets — we need enc_ctx_to_algctx + the GCM H offsets read by
  // ossl_read_gcm_h. The EVP_CIPHER_CTX layout is the same internal struct
  // that the kprobe walks through to today, so the existing offsets table
  // covers it.
  struct tls_binary_key bk = {};
  bk.cgroup_id = bpf_get_current_cgroup_id();
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  bk.exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
  struct tls_offsets *offsets = bpf_map_lookup_elem(&tls_offset_config, &bk);
  if (!offsets || offsets->enc_ctx_to_algctx == 0) {
    bk.exe_inode = 0;
    offsets = bpf_map_lookup_elem(&tls_offset_config, &bk);
    if (!offsets || offsets->enc_ctx_to_algctx == 0) {
      dbg_inc(DBG_EVP_INIT_CHAIN_FAIL);
      return 0;
    }
  }

  // Walk EVP_CIPHER_CTX → algctx → H.
  __u64 algctx = 0;
  if (bpf_probe_read_user(&algctx, 8,
                          (void *)(evp_ctx_ptr + offsets->enc_ctx_to_algctx)) < 0 ||
      !algctx) {
    dbg_inc(DBG_EVP_INIT_CHAIN_FAIL);
    return 0;
  }

  struct evp_h_key key = {};
  key.tgid = (__u32)(pid_tgid >> 32);
  key.evp_ctx_ptr = evp_ctx_ptr;

  __u64 h[2] = {0, 0};
  int src = ossl_read_gcm_h(algctx, offsets, h);
  if (!OSSL_H_OK(src)) {
    dbg_inc(src == OSSL_H_READ_FAIL ? DBG_EVP_INIT_CHAIN_FAIL : DBG_EVP_INIT_H_ZERO);
    // A definite gate mismatch means this ctx is not (or no longer) a keyed
    // GCM context — the key-less first init of a cipher switch, or an
    // EVP_CIPHER_CTX* reused for another cipher. Drop any H cached for the
    // pointer so h_extract cannot serve a stale value. Read failures and
    // uncalibrated offsets prove nothing, so they leave the cache alone.
    if (src == OSSL_H_NOT_GCM)
      bpf_map_delete_elem(&evp_h_cache, &key);
    return 0;
  }

  struct evp_h_val val;
  __builtin_memset(&val, 0, sizeof(val));
  __builtin_memcpy(val.ghash_h, h, 16);
  val.cipher_type = KLOAK_CIPHER_AES_GCM;
  val.nonce_len = 0xFF; // actual nonce_len is determined per-connection in h_extract.

  bpf_map_update_elem(&evp_h_cache, &key, &val, BPF_ANY);
  dbg_inc(DBG_EVP_INIT_H_OK);
  return 0;
}

// =============================================================================
// H extraction — tail-called on first SSL_write per connection (libcrypto-hook
// path only; STRATEGY_KPROBE_WALK skips this and goes straight to xor_path).
// Walks SSL → wrl → enc_ctx and looks up cached H by enc_ctx pointer.
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

  struct tls_binary_key bk = {};
  bk.cgroup_id = bpf_get_current_cgroup_id();
  struct task_struct *h_task = (struct task_struct *)bpf_get_current_task();
  bk.exe_inode = BPF_CORE_READ(h_task, mm, exe_file, f_inode, i_ino);
  struct tls_offsets *offsets = bpf_map_lookup_elem(&tls_offset_config, &bk);
  if (!offsets || offsets->ssl_to_wrl == 0) {
    bk.exe_inode = 0;
    offsets = bpf_map_lookup_elem(&tls_offset_config, &bk);
    if (!offsets || offsets->ssl_to_wrl == 0) {
      dbg_inc(DBG_H_EXTRACT_CACHE_MISS);
      return 0;
    }
  }

  // Walk SSL → wrl → enc_ctx (no further). H is read at cipher-init time
  // by bpf_uretprobe_evp_cipher_init and looked up here by enc_ctx pointer.
  __u64 enc_ctx = 0;
  if (offsets->wrl_to_enc_ctx > 0) {
    __u64 wrl = 0;
    if (bpf_probe_read_user(&wrl, 8, (void *)(ssl_ptr + offsets->ssl_to_wrl)) < 0 || !wrl) {
      dbg_inc(DBG_H_EXTRACT_CACHE_MISS);
      return 0;
    }
    if (bpf_probe_read_user(&enc_ctx, 8, (void *)(wrl + offsets->wrl_to_enc_ctx)) < 0 || !enc_ctx) {
      dbg_inc(DBG_H_EXTRACT_CACHE_MISS);
      return 0;
    }
  } else {
    if (bpf_probe_read_user(&enc_ctx, 8, (void *)(ssl_ptr + offsets->ssl_to_wrl)) < 0 || !enc_ctx) {
      dbg_inc(DBG_H_EXTRACT_CACHE_MISS);
      return 0;
    }
  }

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = (__u32)(pid_tgid >> 32);
  struct evp_h_key key = {};
  key.tgid = tgid;
  key.evp_ctx_ptr = enc_ctx;
  struct evp_h_val *cached = bpf_map_lookup_elem(&evp_h_cache, &key);

  // H source: prefer the value captured at EVP_CipherInit_ex time (fast
  // path). On a cache miss the handshake completed before kloak's libcrypto
  // uretprobe attached (cold-start race), or the enc_ctx was rebuilt (e.g.
  // TLS 1.3 KeyUpdate). Letting the write go out unmodified would
  // permanently break rewriting on a keep-alive connection whose enc_ctx is
  // never re-initialised under our hook — so instead we derive H live from
  // the same enc_ctx → algctx → H chain the uretprobe and the kprobe-walk
  // fallback use. The cache is therefore a pure optimisation, not a
  // correctness dependency.
  // 8-byte-aligned backing store: ossl_read_gcm_h operates on it as __u64, so
  // an under-aligned __u8[16] could trip strict-alignment arches or the BPF
  // verifier. It is also that routine's only scratch space — this tail-call
  // program has no stack to spare.
  __u64 ghash_h64[2] = {0};
  __u8 *ghash_h = (__u8 *)ghash_h64;
  __u8 cipher_type;
  if (cached) {
    __builtin_memcpy(ghash_h, cached->ghash_h, 16);
    cipher_type = cached->cipher_type;
    dbg_inc(DBG_H_EXTRACT_CACHE_HIT);
  } else {
    __u64 algctx = 0;
    if (bpf_probe_read_user(&algctx, 8,
                            (void *)(enc_ctx + offsets->enc_ctx_to_algctx)) < 0 ||
        !algctx) {
      dbg_inc(DBG_H_EXTRACT_CACHE_MISS);
      return 0;
    }
    // Same H source as the uretprobe and the kprobe walk, including the
    // AVX-512 HashKey_1 recovery — so a VAES context whose raw H field is
    // zero is still rewritable on a cache miss.
    if (!OSSL_H_OK(ossl_read_gcm_h(algctx, offsets, ghash_h64))) {
      dbg_inc(DBG_H_EXTRACT_CACHE_MISS);
      return 0;
    }
    cipher_type = KLOAK_CIPHER_AES_GCM;

    // Backfill the cache so subsequent writes on this enc_ctx take the
    // fast path. nonce_len is resolved per-connection below, so the cached
    // entry keeps the sentinel.
    struct evp_h_val backfill;
    __builtin_memset(&backfill, 0, sizeof(backfill));
    __builtin_memcpy(backfill.ghash_h, ghash_h, 16);
    backfill.cipher_type = KLOAK_CIPHER_AES_GCM;
    backfill.nonce_len = 0xFF;
    bpf_map_update_elem(&evp_h_cache, &key, &backfill, BPF_ANY);
    dbg_inc(DBG_H_EXTRACT_LIVE_WALK);
  }

  // Determine nonce_len from SSL_CONNECTION.version (per-connection, not
  // per-EVP_CIPHER_CTX). 0xFFFFFFFF means we don't have a known offset
  // for this libssl version → fall back to plaintext_len heuristic in tc.
  __u8 nonce_len = 0xFF;
  if (offsets->ssl_to_version != 0xFFFFFFFF) {
    __u32 ssl_ver = 0;
    bpf_probe_read_user(&ssl_ver, 4, (void *)(ssl_ptr + offsets->ssl_to_version));
    nonce_len = (ssl_ver >= 0x0304) ? 0 : 8;
  }

  struct tls_conn_state new_conn;
  __builtin_memset(&new_conn, 0, sizeof(new_conn));
  __builtin_memcpy(new_conn.ghash_h, ghash_h, 16);
  new_conn.cipher_type = cipher_type;
  new_conn.nonce_len = nonce_len;

  struct tls_conn_key ck;
  __builtin_memset(&ck, 0, sizeof(ck));
  ck.tgid = tgid;
  ck.ssl_ptr = ssl_ptr;
  bpf_map_update_elem(&tls_conn_state, &ck, &new_conn, BPF_ANY);

  // CACHE_HIT / LIVE_WALK already counted above per H source.
  dbg_inc(DBG_XOR_CONN_HIT);

  sd = bpf_map_lookup_elem(&scratch, &zero);
  if (!sd)
    return 0;
  sd->h_fresh = 1;
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
    return 0; // No matches to process — bail without touching stale staged_pending.

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
    wi->staged_pending.memory_bio = sd->memory_bio;
    wi->staged_pending.created_at = bpf_ktime_get_ns();

    // For OpenSSL/BoringSSL, if h_extract just populated tls_conn_state
    // (libcrypto-hook path), carry H through xor_pending so the kprobe
    // doesn't need to re-walk the chain. Otherwise h_valid stays 0 and the
    // kprobe walks the chain itself: an entry it stored for an earlier write
    // may belong to an earlier connection, whose SSL object this one reuses
    // (same ssl_ptr, another key). Go's H derivation is shaped differently
    // and stays in the kprobe.
    if (sd->chain_type != CHAIN_GO_TLS && sd->h_fresh) {
      struct tls_conn_key ck = {};
      ck.tgid = wi->staged_pending.tgid;
      ck.ssl_ptr = sd->ssl_ptr;
      struct tls_conn_state *conn = bpf_map_lookup_elem(&tls_conn_state, &ck);
      if (conn && conn->cipher_type == KLOAK_CIPHER_AES_GCM) {
        __builtin_memcpy(wi->staged_pending.ghash_h, conn->ghash_h, 16);
        wi->staged_pending.cipher_type = conn->cipher_type;
        wi->staged_pending.nonce_len = conn->nonce_len;
        wi->staged_pending.h_valid = 1;
      }
    }
  }

  dbg_inc(DBG_XOR_PATH_ENTERED);

  // Read the current match position + key. Use fixed index via bitmask for verifier.
  __u32 local_i = sd->xor_matches[mi & (XOR_MAX_MATCHES - 1)].pos;
  struct secret_key key;
  __builtin_memcpy(&key,
    &sd->xor_matches[mi & (XOR_MAX_MATCHES - 1)].key, sizeof(key));

  // The host, IP and port restrictions are checked on the socket the record
  // leaves on, at tcp_sendmsg (socket_filter_patches).
  struct secret_value *val = bpf_map_lookup_elem(&secret_map, &key);
  if (!val || val->len == 0 || val->len > SECRET_MAX_LEN)
    goto next; // Skip this match.

  __u32 val_len = val->len;

  // Pod binding last, so a violation is reported only when it is the sole
  // reason this placeholder is not rewritten. sd, w and val are re-looked-up
  // below, so the helper's map accesses don't matter here.
  if (!secret_binding_allows(&key))
    goto next;

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
    __builtin_memcpy(&w->staged_pending.patches[pi & (XOR_MAX_PATCHES - 1)].key,
                     &key, sizeof(key));
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

  // All matches processed. Store patches in xor_pending keyed by tgid (process ID).
  // Uses tgid instead of pid_tgid so the tcp_sendmsg kprobe can find it even if
  // the socket write happens on a different thread (e.g., Node.js/libuv).
  __u32 store_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

  struct ghash_work *wf = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!wf || wf->staged_pending.patch_count == 0)
    return 0;

  // ssl_ptr, tgid, active already set during mi=0 initialization.
  bpf_map_update_elem(&xor_pending, &store_tgid, &wf->staged_pending, BPF_ANY);
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

  gf128_mul_step(w->mul_a, w->mul_v, w->mul_z, i);
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
  ghash_block_delta(w->ghash_xor_delta, b, w->ghash_secret_offset,
                    w->ghash_patch_len, w->block_delta);

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

// =============================================================================
// SNI check (spinningfactory/kloak#328)
//
// A secret restricted to a hostname is only rewritten on a connection whose
// first ClientHello named that host. The destination-IP check alone lets a
// compromised pod open TLS to a verified IP of the host (a CDN or cloud load
// balancer edge) with the SNI of another tenant on the same front end, which
// then routes the real value to that tenant.
//
// bpf_kprobe_tcp_sendmsg_sni parses the first handshake record written on
// each TCP connection into sni_state; tp_inet_sock_set_state clears the entry
// when a socket starts a new connection or closes, so a reused struct sock
// never inherits an old SNI. The bridge kprobe (bpf_kprobe_tcp_sendmsg) drops
// patches whose secret host is not the SNI of the socket they would leave on.
// =============================================================================

struct sni_state_val {
  __u32 status; // SNI_STATUS_* (helpers.h)
  __u32 len;    // host length when status == SNI_STATUS_SEEN
  char sni[MAX_HOST_LEN]; // lowercased, zero-padded (hosts_match-comparable)
};

// struct sock * -> SNI of the first ClientHello on that connection. A
// missing (never seen, or evicted) entry refuses host-restricted patches.
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, struct sni_state_val);
} sni_state SEC(".maps");

struct sni_scratch_buf {
  __u8 buf[TLS_SNI_BUF_LEN]; // copy of the ClientHello prefix
  struct sni_state_val st;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct sni_scratch_buf);
} sni_scratch SEC(".maps");

// SNI check mode, index 0. Enforce is the zero value, so an unconfigured map
// still enforces.
#define SNI_CHECK_ENFORCE 0
#define SNI_CHECK_AUDIT 1

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, __u32);
  __type(value, __u32);
} sni_check_mode SEC(".maps");

// iov_iter before Linux 6.4 named the iovec array `iov` (now `__iov`).
struct iov_iter___pre_6_4 {
  const struct iovec *iov;
} __attribute__((preserve_access_index));

// sendmsg_first_buf returns the user address and length of the first
// contiguous chunk of a tcp_sendmsg payload: the whole buffer for write() /
// send() (ITER_UBUF), the first iovec for writev() / sendmsg() (ITER_IOVEC).
// A ClientHello is written in one piece by every TLS stack kloak supports.
static __always_inline int sendmsg_first_buf(struct msghdr *msg, __u64 *base,
                                             __u64 *len) {
  if (!bpf_core_field_exists(msg->msg_iter.iter_type))
    return -1; // < 5.14: no stable iter_type; the check fails closed
  __u8 type = BPF_CORE_READ(msg, msg_iter.iter_type);
  __u64 count = BPF_CORE_READ(msg, msg_iter.count);
  __u64 skip = BPF_CORE_READ(msg, msg_iter.iov_offset);

  if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF) &&
      type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
    *base = (__u64)BPF_CORE_READ(msg, msg_iter.ubuf) + skip;
    *len = count;
    return 0;
  }
  if (type != bpf_core_enum_value(enum iter_type, ITER_IOVEC))
    return -1;

  const struct iovec *iov;
  if (bpf_core_field_exists(msg->msg_iter.__iov)) {
    iov = BPF_CORE_READ(msg, msg_iter.__iov);
  } else {
    struct iov_iter___pre_6_4 *it = (void *)&msg->msg_iter;
    iov = BPF_CORE_READ(it, iov);
  }
  if (!iov)
    return -1;
  __u64 iov_base = (__u64)BPF_CORE_READ(iov, iov_base);
  __u64 iov_len = BPF_CORE_READ(iov, iov_len);
  if (skip >= iov_len)
    return -1;
  *base = iov_base + skip;
  *len = iov_len - skip;
  if (*len > count)
    *len = count;
  return 0;
}

// kprobe/tcp_sendmsg: record the SNI of the first handshake record each
// connection writes. Runs before any SSL_write on that connection, so the
// bridge kprobe below always finds it.
//
// The first TLS handshake record decides: anything that starts with
// 0x16 0x03 and is not a parseable ClientHello leaves the connection
// unusable for host-restricted secrets. Plaintext before it (STARTTLS-style
// protocols) is ignored. A later valid ClientHello (after a
// HelloRetryRequest) that names another host or carries ECH marks the
// connection SNI_STATUS_MISMATCH.
SEC("kprobe/tcp_sendmsg")
int bpf_kprobe_tcp_sendmsg_sni(void *ctx) {
  __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  if (!bpf_map_lookup_elem(&tracked_tgids, &tgid))
    return 0;

  // tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
  struct sock *sk = NULL;
  struct msghdr *msg = NULL;
#if defined(bpf_target_x86)
  bpf_probe_read_kernel(&sk, sizeof(sk), (char *)ctx + 112); // RDI
  bpf_probe_read_kernel(&msg, sizeof(msg), (char *)ctx + 104); // RSI
#elif defined(bpf_target_arm64)
  bpf_probe_read_kernel(&sk, sizeof(sk), (char *)ctx + 0); // X0
  bpf_probe_read_kernel(&msg, sizeof(msg), (char *)ctx + 8); // X1
#else
  return 0;
#endif
  if (!sk || !msg)
    return 0;

  __u64 base = 0, len = 0;
  if (sendmsg_first_buf(msg, &base, &len) < 0 || len < 2)
    return 0;
  __u8 hdr[2] = {};
  if (bpf_probe_read_user(hdr, sizeof(hdr), (void *)base) < 0)
    return 0;
  if (hdr[0] != TLS_CT_HANDSHAKE || hdr[1] != 0x03)
    return 0;

  __u64 sk_key = (__u64)sk;
  struct sni_state_val *cur = bpf_map_lookup_elem(&sni_state, &sk_key);
  __u32 cur_status = cur ? cur->status : SNI_STATUS_NONE;
  if (cur_status != SNI_STATUS_NONE && cur_status != SNI_STATUS_SEEN)
    return 0; // already decided, and not by a valid ClientHello

  __u32 zero = 0;
  struct sni_scratch_buf *s = bpf_map_lookup_elem(&sni_scratch, &zero);
  if (!s)
    return 0;
  __u32 n = len > TLS_SNI_BUF_LEN ? TLS_SNI_BUF_LEN : (__u32)len;
  if (bpf_probe_read_user(s->buf, n, (void *)base) < 0)
    return 0;
  __builtin_memset(&s->st, 0, sizeof(s->st));
  __u32 host_len = 0;
  __u32 status = tls_parse_sni(s->buf, n, s->st.sni, &host_len);

  if (cur_status == SNI_STATUS_SEEN) {
    // Only a fully valid ClientHello can change a decided connection: an
    // encrypted TLS 1.2 handshake record (Finished) also starts with
    // 0x16 0x03, and the server would reject a malformed second ClientHello.
    int other = status == SNI_STATUS_ECH ||
                (status == SNI_STATUS_SEEN && !hosts_match(cur->sni, s->st.sni));
    if (other) {
      cur = bpf_map_lookup_elem(&sni_state, &sk_key);
      if (cur)
        cur->status = SNI_STATUS_MISMATCH;
    }
    return 0;
  }

  if (status == SNI_NOT_CLIENT_HELLO)
    status = SNI_STATUS_MALFORMED; // a handshake record, but not a ClientHello
  s->st.status = status;
  s->st.len = host_len;
  bpf_map_update_elem(&sni_state, &sk_key, &s->st, BPF_ANY);
  dbg_inc(DBG_SNI_CAPTURED);
  return 0;
}

// tracepoint/sock/inet_sock_set_state: forget a socket's SNI when it starts
// a new connection (SYN_SENT, before any data) or closes, so a reused
// struct sock address never inherits another connection's SNI. On close,
// also forget the host its connect recorded (vip_sock_host): a TCP socket
// can connect again after a failed connect, without going through
// vip_connect4 if the hooks are detached at that moment.
SEC("tracepoint/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  if (ctx->protocol != IPPROTO_TCP)
    return 0;
  if (ctx->newstate != TCP_SYN_SENT && ctx->newstate != TCP_CLOSE)
    return 0;
  __u64 sk_key = (__u64)ctx->skaddr;
  bpf_map_delete_elem(&sni_state, &sk_key);
  if (ctx->newstate == TCP_CLOSE) {
    __u64 cookie = BPF_CORE_READ((struct sock *)ctx->skaddr, __sk_common.skc_cookie.counter);
    if (cookie) {
      bpf_map_delete_elem(&vip_sock_host, &cookie);
      bpf_map_delete_elem(&vip_sock_dst, &cookie);
    }
  }
  return 0;
}

// sock_dst_addr reads the destination of sk into out (16 bytes, network byte
// order): IPv6, or IPv4-mapped for an IPv4 peer, from an AF_INET socket or
// an AF_INET6 one connected to a v4-mapped address (whose packets are IPv4).
// This is the address tc_egress_patch keys on (bpf_sock dst_ip4 / dst_ip6).
static __always_inline void sock_dst_addr(struct sock *sk, __u8 *out) {
  if (BPF_CORE_READ(sk, __sk_common.skc_family) == 10) { // AF_INET6
    bpf_core_read(out, 16, &sk->__sk_common.skc_v6_daddr);
    if (!vip_addr_v4mapped(out))
      return;
  }
  __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  ipv4_to_mapped(out, (const __u8 *)&daddr);
}

// socket_filter_patches drops, from ghash_scratch.staged_tc, the patches
// whose secret may not leave on `sk`, the socket the patched record will
// leave on:
//   - a secret restricted to a hostname that is not the socket's SNI;
//   - a secret whose host, IP or port restriction the socket does not meet:
//     the host of the fake IP it connected to (vip_sock_host), and the
//     address and port it connected to (vip_sock_dst, else its own
//     destination, sock_dst_addr). bpf_xor_path leaves these restrictions
//     to this check.
// Refused patches are removed, not zeroed: tc treats secret_len 0 as a full
// SECRET_MAX_LEN patch (clamp_write_len). Returns the number of patches kept.
//
// Deliberately __noinline: its own stack frame, away from the bridge
// kprobe's, which is close to the 512-byte limit.
static __attribute__((noinline)) __u32 socket_filter_patches(__u64 sk_key,
                                                            __u8 memory_bio) {
  __u32 zero = 0;
  __u32 *mode = bpf_map_lookup_elem(&sni_check_mode, &zero);
  __u8 audit = mode && *mode == SNI_CHECK_AUDIT;

  struct sock *sk = (struct sock *)sk_key;
  __u8 daddr16[16];
  sock_dst_addr(sk, daddr16);
  __u64 cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
  __u16 dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
  struct vip_sock_dst_val *dst =
      cookie ? bpf_map_lookup_elem(&vip_sock_dst, &cookie) : NULL;
  if (dst) {
    __builtin_memcpy(daddr16, dst->ip, 16);
    dport = dst->port;
  }

  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 0;
  __u32 pc = w->staged_tc.patch_count;
  if (pc > XOR_MAX_PATCHES)
    pc = XOR_MAX_PATCHES;

  __u32 kept = 0;
  for (__u32 p = 0; p < XOR_MAX_PATCHES; p++) {
    if (p >= pc)
      break;
    w = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!w)
      return 0;
    struct secret_key key;
    __builtin_memcpy(&key, &w->staged_tc.patches[p & (XOR_MAX_PATCHES - 1)].key,
                     sizeof(key));

    int keep = 1;
    struct secret_value *val = bpf_map_lookup_elem(&secret_map, &key);
    if (!val) {
      keep = 0; // secret removed since the uprobe staged it
    } else {
      struct vip_sock_host_val *sh =
          cookie ? bpf_map_lookup_elem(&vip_sock_host, &cookie) : NULL;
      int why = vip_socket_check(sh ? sh->host : NULL, val->host_len,
                                 val->allowed_host, val->ip_len,
                                 (const __u8 *)val->allowed_ip, daddr16,
                                 val->port, dport);
      if (why != VIP_SOCK_OK) {
        dbg_inc(why == VIP_SOCK_DENY_HOST ? DBG_VIP_SOCK_HOST_DENY
                                          : DBG_VIP_SOCK_ADDR_DENY);
        keep = 0;
      }
    }
    if (keep && val && val->host_len > 0 && val->host_len < MAX_HOST_LEN) {
      struct sni_state_val *st = bpf_map_lookup_elem(&sni_state, &sk_key);
      __u32 status = st ? st->status : SNI_STATUS_NONE;
      if (status == SNI_STATUS_SEEN && !hosts_match(st->sni, val->allowed_host))
        status = SNI_STATUS_MISMATCH;
      if (status != SNI_STATUS_SEEN) {
        dbg_inc(audit ? DBG_SNI_AUDIT : DBG_SNI_DENY);
        report_secret_event(&key, audit, SECRET_EVT_SNI, (__u8)status,
                            memory_bio, st ? st->sni : NULL);
        keep = audit;
      }
    }
    if (!keep)
      continue;

    w = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!w)
      return 0;
    if (kept != p)
      w->staged_tc.patches[kept & (XOR_MAX_PATCHES - 1)] =
          w->staged_tc.patches[p & (XOR_MAX_PATCHES - 1)];
    kept++;
  }

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return 0;
  w->staged_tc.patch_count = kept;
  return kept;
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
  __u32 tgid = (__u32)(pid_tgid >> 32);

  struct xor_pending_val *pending = bpf_map_lookup_elem(&xor_pending, &tgid);
  if (!pending || pending->patch_count == 0) {
    dbg_inc(DBG_KPROBE_BRIDGE_NO_ENTRY);
    return 0;
  }

  // TTL cleanup: for memory BIO apps, xor_pending persists across tcp_sendmsg
  // calls. Delete stale entries older than 2 seconds to bound kprobe overhead.
  // 2s is generous — the encrypt→writev gap is typically <10ms.
  if (pending->memory_bio &&
      bpf_ktime_get_ns() - pending->created_at > 2000000000ULL) {
    bpf_map_delete_elem(&xor_pending, &tgid);
    return 0;
  }

#ifdef KLOAK_DEBUG
  bpf_printk("kloak [2-KPROBE] FOUND xor_pending tgid=%u patches=%u ssl=%llx",
             tgid, pending->patch_count, pending->ssl_ptr);
#endif

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

  // Build tc_pending key: (dst_ip, src_port, cgroup_id).
  // dst_ip is the socket's destination, IPv6 or IPv4-mapped.
  // src_port is unique per connection within a container.
  // cgroup_id isolates containers.
  struct tc_dest_key tdk = {};
  sock_dst_addr((struct sock *)sk, tdk.dst_ip);
  tdk.src_port = __bpf_htons(src_port_h);
  tdk.cgroup_id = bpf_get_current_cgroup_id();

  // Save values from xor_pending before helper calls invalidate the pointer.
  __u32 zero = 0;

  pending = bpf_map_lookup_elem(&xor_pending, &tgid);
  if (!pending) return 0;

  __u64 ssl_ptr = pending->ssl_ptr;
  __u32 plaintext_len = pending->plaintext_len;
  __u8 chain = pending->chain_type;

  // Filter the patches first: a write none of whose patches may leave on
  // this socket must not reach the H extraction below, which stores the
  // connection's H in tls_conn_state for the next writes with this ssl_ptr
  // (an SSL object reused by a later connection would inherit it).
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 0;

  pending = bpf_map_lookup_elem(&xor_pending, &tgid);
  if (!pending) return 0;

  // Read TCP write_seq to identify the exact segment in tc_egress.
  // tcp_sendmsg appends data starting at write_seq. The tc_egress program
  // checks that tcp->seq falls within this range before patching.
  // Use BPF_CORE_READ for kernel version portability (tcp_sock layout varies).
  __u32 wseq = 0;
  BPF_CORE_READ_INTO(&wseq, (struct tcp_sock *)sk, write_seq);

  __u8 is_membio = pending->memory_bio;

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

  // SNI and host / IP / port check: keep only patches
  // whose secret may leave on this socket. xor_pending itself is untouched,
  // so a memory-BIO write refused on another connection's tcp_sendmsg is
  // still bridged on its own.
  if (socket_filter_patches((__u64)sk, is_membio) == 0) {
    if (!is_membio)
      bpf_map_delete_elem(&xor_pending, &tgid);
    return 0;
  }
  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 0;

  pending = bpf_map_lookup_elem(&xor_pending, &tgid);
  if (!pending) return 0;

  // Extract H BEFORE creating tc_pending. If H extraction fails, we must NOT
  // create tc_pending — otherwise tc_egress would XOR-patch the ciphertext
  // without being able to recompute the GHASH tag, causing "bad record MAC".
  // new_conn lives in a per-CPU scratch map, not on the stack — see
  // conn_state_scratch. BPF programs run with preemption disabled, so the
  // per-CPU slot cannot be re-entered while this kprobe is executing.
  struct tls_conn_state *new_conn = bpf_map_lookup_elem(&conn_state_scratch, &zero);
  if (!new_conn) return 0;
  __builtin_memset(new_conn, 0, sizeof(*new_conn));

  if (chain == CHAIN_GO_TLS) {
    // Go crypto/tls: H×2 stored at productTable offset 224 (entry 14).
    // gcmAesInit computes H = AES_K(0^128), byte-swaps, doubles in GF(2^128).
    // We read the two 64-bit words and apply GF halving to recover H.
    // Look up Go offsets by (cgroup_id, exe_inode) — see tls_binary_key
    // rationale near the map declaration.
    struct tls_binary_key gk = {};
    gk.cgroup_id = bpf_get_current_cgroup_id();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    gk.exe_inode = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
    struct go_tls_offsets *go_off = bpf_map_lookup_elem(&go_tls_offset_config, &gk);
    if (!go_off) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE-GO] H-fail: no offsets cgid=%llx ino=%llu tgid=%u",
                 gk.cgroup_id, gk.exe_inode, tgid);
#endif
      dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
      return 0;
    }

    __u64 cipher_data = 0;
    long r_cd = bpf_probe_read_user(&cipher_data, 8,
        (void *)(ssl_ptr + go_off->conn_to_cipher));
    if (r_cd < 0 || !cipher_data) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE-GO] H-fail: cipher_data r=%ld val=%llx off=%u",
                 r_cd, cipher_data, go_off->conn_to_cipher);
#endif
      dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
      return 0;
    }
    __u64 gcm_ptr = 0;
    long r_gp = bpf_probe_read_user(&gcm_ptr, 8,
        (void *)(cipher_data + go_off->aead_iface_off));
    if (r_gp < 0 || !gcm_ptr) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE-GO] H-fail: gcm_ptr r=%ld val=%llx off=%u",
                 r_gp, gcm_ptr, go_off->aead_iface_off);
#endif
      dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
      return 0;
    }

    // Read H×2 as two separate 64-bit words (arch-aware offsets from userspace).
    // h2_hi_off points to the GF "high" word (contains the GF MSB at bit 63).
    // h2_lo_off points to the GF "low" word (contains the GF LSB at bit 0).
    __u64 hi = 0, lo = 0;
    long r_hi = bpf_probe_read_user(&hi, 8, (void *)(gcm_ptr + go_off->h2_hi_off));
    long r_lo = bpf_probe_read_user(&lo, 8, (void *)(gcm_ptr + go_off->h2_lo_off));
    if (r_hi < 0 || r_lo < 0) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE-GO] H-fail: h2 read r_hi=%ld r_lo=%ld", r_hi, r_lo);
#endif
      dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
      return 0;
    }

    if (hi == 0 && lo == 0) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE-GO] H-fail: hi=0 lo=0 gcm=%llx hi_off=%u lo_off=%u",
                 gcm_ptr, go_off->h2_hi_off, go_off->h2_lo_off);
#endif
      dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
      return 0;
    }
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [2-KPROBE-GO] H-ok hi=%llx lo=%llx", hi, lo);
#endif

    // Go's gcmAesInit stores H×2: V' = (V << 1) ^ (V.MSB ? poly : 0), with
    // the 128-bit value V = hi * 2^64 + lo where
    //   - AMD64: hi = XMM[64:127], lo = XMM[0:63]
    //   - ARM64: hi = D[0], lo = D[1]
    // gf128_halve_to_h undoes the doubling and emits big-endian GHASH H.
    gf128_halve_to_h(lo, hi, new_conn->ghash_h);

    new_conn->cipher_type = KLOAK_CIPHER_AES_GCM;

    // Read negotiated TLS version from Conn.vers for nonce_len determination.
    // TLS 1.3 (0x0304) has no explicit nonce; TLS 1.2 (0x0303) has 8-byte nonce.
    __u16 go_tls_ver = 0;
    if (go_off->conn_vers_off > 0)
      bpf_probe_read_user(&go_tls_ver, 2, (void *)(ssl_ptr + go_off->conn_vers_off));
    new_conn->nonce_len = (go_tls_ver >= 0x0304) ? 0 : 8;
  } else if (pending->h_valid && pending->cipher_type == KLOAK_CIPHER_AES_GCM) {
    // Libcrypto-hook hot path: H was captured at EVP_CipherInit_ex time and
    // carried through xor_pending. No chain walk needed. (h_extract already
    // looked up evp_h_cache and tls_conn_state has the same H — but we copy
    // from pending here so the kprobe doesn't depend on tls_conn_state still
    // being there for the same (tgid, ssl_ptr).)
    __builtin_memcpy(new_conn->ghash_h, pending->ghash_h, 16);
    new_conn->cipher_type = pending->cipher_type;
    new_conn->nonce_len = pending->nonce_len;
    dbg_inc(DBG_KPROBE_BRIDGE_FROM_PENDING);
  } else {
    // STRATEGY_KPROBE_WALK path (BoringSSL, statically-linked OpenSSL, or
    // OpenSSL where libcrypto attach failed / cipher_init fired before
    // kloak attached). Walk SSL → wrl → enc_ctx → algctx → H exactly as on
    // main today. This is the same code that has been shipping; no changes.
    dbg_inc(DBG_KPROBE_WALK_LEGACY);
    struct tls_binary_key bk = {};
    bk.cgroup_id = bpf_get_current_cgroup_id();
    struct task_struct *ssl_task = (struct task_struct *)bpf_get_current_task();
    bk.exe_inode = BPF_CORE_READ(ssl_task, mm, exe_file, f_inode, i_ino);
    struct tls_offsets *offsets = bpf_map_lookup_elem(&tls_offset_config, &bk);
    if (!offsets || OFFSETS_UNCALIBRATED(offsets)) {
      bk.exe_inode = 0;
      offsets = bpf_map_lookup_elem(&tls_offset_config, &bk);
      if (!offsets || OFFSETS_UNCALIBRATED(offsets)) {
#ifdef KLOAK_DEBUG
        bpf_printk("kloak [2-KPROBE] H-fail: no offsets cgid=%llx",
                   bk.cgroup_id);
#endif
        dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
        return 0;
      }
    }

    if (offsets->tls_lib == TLS_LIB_BORINGSSL) {
      // BoringSSL: recover H via the AES round-key schedule in a separate
      // BPF-to-BPF subprogram (its own stack frame — see bssl_recover_h). The
      // AES output is the raw subkey in the same byte layout the OpenSSL branch
      // produces AFTER its bswap, so no bswap here.
      dbg_inc(DBG_BSSL_REACHED);
      if (!bssl_recover_h(ssl_ptr, offsets->bssl_ssl_to_s3,
                          offsets->bssl_s3_to_aead, offsets->bssl_aead_to_aeskey,
                          new_conn->ghash_h)) {
        dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
        return 0;
      }
      dbg_inc(DBG_BSSL_H_OK);
      new_conn->cipher_type = KLOAK_CIPHER_AES_GCM;
      if (offsets->ssl_to_version != 0xFFFFFFFF) {
        __u32 ssl_ver = 0;
        bpf_probe_read_user(&ssl_ver, 4, (void *)(ssl_ptr + offsets->ssl_to_version));
        new_conn->nonce_len = (ssl_ver >= 0x0304) ? 0 : 8;
      } else {
        new_conn->nonce_len = 0xFF;
      }
      goto h_ready;
    }

    __u64 ptr = 0;
    if (offsets->wrl_to_enc_ctx > 0) {
      __u64 wrl = 0;
      if (bpf_probe_read_user(&wrl, 8, (void *)(ssl_ptr + offsets->ssl_to_wrl)) < 0 || !wrl) {
#ifdef KLOAK_DEBUG
        bpf_printk("kloak [2-KPROBE] H-fail: 4hop wrl null ssl=%llx off=%u", ssl_ptr, offsets->ssl_to_wrl);
#endif
        return 0;
      }
      if (bpf_probe_read_user(&ptr, 8, (void *)(wrl + offsets->wrl_to_enc_ctx)) < 0 || !ptr) {
#ifdef KLOAK_DEBUG
        bpf_printk("kloak [2-KPROBE] H-fail: 4hop enc_ctx null wrl=%llx off=%u", wrl, offsets->wrl_to_enc_ctx);
#endif
        return 0;
      }
    } else {
      if (bpf_probe_read_user(&ptr, 8, (void *)(ssl_ptr + offsets->ssl_to_wrl)) < 0 || !ptr) {
#ifdef KLOAK_DEBUG
        __u32 ver = 0;
        bpf_probe_read_user(&ver, 4, (void *)ssl_ptr);
        __u64 wbio = 0;
        bpf_probe_read_user(&wbio, 8, (void *)(ssl_ptr + 24));
        bpf_printk("kloak [2-KPROBE] H-fail: enc_write_ctx null ssl=%llx off=%u ver=0x%x wbio=%llx", ssl_ptr, offsets->ssl_to_wrl, ver, wbio);
#endif
        return 0;
      }
    }
    if (bpf_probe_read_user(&ptr, 8, (void *)(ptr + offsets->enc_ctx_to_algctx)) < 0 || !ptr) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE] H-fail: algctx null");
#endif
      return 0;
    }
    // new_conn lives in the per-CPU conn_state_scratch map, so its ghash_h
    // doubles as ossl_read_gcm_h's scratch without touching this program's
    // stack (already close to the 512-byte limit with bssl_recover_h).
    int h_src = ossl_read_gcm_h(ptr, offsets, (__u64 *)new_conn->ghash_h);
    if (!OSSL_H_OK(h_src)) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [2-KPROBE] H-fail: src=%d algctx=%llx off=%u",
                 h_src, ptr, offsets->algctx_to_h);
#endif
      dbg_inc(DBG_KPROBE_BRIDGE_H_FAIL);
      return 0;
    }

    new_conn->cipher_type = KLOAK_CIPHER_AES_GCM;

    if (offsets->ssl_to_version != 0xFFFFFFFF) {
      __u32 ssl_ver = 0;
      bpf_probe_read_user(&ssl_ver, 4, (void *)(ssl_ptr + offsets->ssl_to_version));
      new_conn->nonce_len = (ssl_ver >= 0x0304) ? 0 : 8;
    } else {
      new_conn->nonce_len = 0xFF;
    }
  }

h_ready:;
  // H extraction succeeded — store connection state (only if H changed).
  struct tls_conn_key ck = {};
  ck.tgid = tgid;
  ck.ssl_ptr = ssl_ptr;
  struct tls_conn_state *existing = bpf_map_lookup_elem(&tls_conn_state, &ck);
  if (!existing ||
      ((__u64 *)existing->ghash_h)[0] != ((__u64 *)new_conn->ghash_h)[0] ||
      ((__u64 *)existing->ghash_h)[1] != ((__u64 *)new_conn->ghash_h)[1]) {
    bpf_map_update_elem(&tls_conn_state, &ck, new_conn, BPF_ANY);
  }

  // Now safe to create tc_pending — tc_egress can always find H.
  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w) return 0;

  // For memory BIO apps: write_seq from this tcp_sendmsg may not match the
  // segment that carries the TLS data (SSL_write and writev are decoupled).
  // Disable seq check so tc_egress matches by TLS header + record validation.
  // For socket BIO apps: write_seq is always correct (synchronous call chain).
  w->staged_tc.write_seq = is_membio ? 0 : wseq;

  bpf_map_update_elem(&tc_pending, &tdk, &w->staged_tc, BPF_ANY);
  dbg_inc(DBG_KPROBE_BRIDGE);
#ifdef KLOAK_DEBUG
  bpf_printk("kloak [2-KPROBE] sport=%u cg=%x membio=%u", src_port_h, (__u32)tdk.cgroup_id, is_membio);
#endif

  // For socket BIO apps: delete xor_pending — the first kprobe hit is the
  // correct one (SSL_write → tcp_sendmsg is synchronous).
  // For memory BIO apps: keep xor_pending alive — multiple tcp_sendmsg calls
  // may fire before the one carrying the TLS data. tc_egress uses TLS header
  // validation to skip wrong records.
  if (!is_membio)
    bpf_map_delete_elem(&xor_pending, &tgid);

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

  // crypto/tls writes each record to its net.Conn within Write, so the
  // record leaves on the next tcp_sendmsg, as with a socket BIO.
  scratch_data->memory_bio = 0;

  // Pre-scan for kl:: prefix and tail-call to xor_path.
  // Same flow as SSL_write — the downstream pipeline is generic.
  dbg_inc(DBG_XOR_CONN_CHECK);
  scratch_data->ssl_ptr = (__u64)conn_ptr; // reuse ssl_ptr field as connection ID
  scratch_data->chain_type = CHAIN_GO_TLS;
  scratch_data->h_fresh = 0;
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
  __u32 bio_fd = ssl_read_fd((__u64)ssl_ptr);
  if (bio_fd != 0) {
    __u32 cur_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct conn_ip_key cik = {};
    cik.tgid = cur_tgid;
    cik.fd = bio_fd;
    if (!bpf_map_lookup_elem(&conn_ip_map, &cik))
      return 0;  // server-mode: fd exists but not from connect()
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

  // A socket BIO holds the connection's fd (a client socket, checked above);
  // a memory BIO (Node.js, Bun) holds none.
  scratch_data->memory_bio = bio_fd == 0;

  // Pre-scan for kl:: prefix BEFORE conn_state check, so both
  // h_extract and xor_path have the match position in scratch_buf.
  dbg_inc(DBG_XOR_CONN_CHECK);
  scratch_data->ssl_ptr = (__u64)ssl_ptr;
  scratch_data->chain_type = 0; // OpenSSL/BoringSSL
  scratch_data->h_fresh = 0;
  scratch_data->xor_match_count = 0;
  scratch_data->xor_current_match = 0;

  // Scan the FULL SSL_write buffer for kl:: prefixes using bpf_loop.
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

  // Route by per-process H-extraction strategy. STRATEGY_LIBCRYPTO_HOOK
  // (set by the controller when EVP_CipherInit_ex hooks attached for this
  // pid's libcrypto.so) goes through h_extract → cache lookup → xor_path.
  // STRATEGY_KPROBE_WALK (default — BoringSSL, statically-linked, or
  // libcrypto attach failed) goes straight to xor_path; the tcp_sendmsg
  // kprobe then walks SSL→…→H itself, exactly as on main today.
  __u32 cur_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  __u8 *strat = bpf_map_lookup_elem(&tls_strategy, &cur_tgid);
  if (strat && *strat == STRATEGY_LIBCRYPTO_HOOK) {
    bpf_tail_call(ctx, &prog_array, 2);
  } else {
    bpf_tail_call(ctx, &prog_array, 1);
  }

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

// tp/sched/sched_process_exit: clean up stale map entries when any process
// exits. Unlike the exec handler, this does NOT gate on cgroup_ancestor
// because during container teardown the process may already be moved out
// of the kubepods cgroup hierarchy before the exit tracepoint fires.
// Unconditional deletes are safe — if the key doesn't exist, it's a no-op.
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
  __u32 tgid = ctx->pid;

  // Clean up tracked_tgids (no-op if not tracked)
  bpf_map_delete_elem(&tracked_tgids, &tgid);

  // We cannot iterate the LRU map in BPF, so we rely on LRU eviction for
  // conn_ip_map entries keyed by (tgid, *). The LRU will naturally evict
  // stale entries over time.

  return 0;
}

// =============================================================================
// tc egress: XOR-patch ciphertext + GHASH tag in kernel skb data.
//
// This runs AFTER tcp_sendmsg copies user-space data to kernel skbs.
// Modifications happen in kernel memory only — the user-space iov is untouched.
// The encrypted real secret NEVER exists in user-space memory.
// =============================================================================

// The verdict of the tc programs for a packet they let through (patched or
// not): TC_ACT_UNSPEC hands it to the next program on the hook (TCX_NEXT
// with TCX, the next filter with cls_bpf), such as a CNI's (Cilium's on the
// pod's host-side veth); TC_ACT_OK would end the chain there. With no
// program after, the packet passes.
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif
#define TC_PASS TC_ACT_UNSPEC

// Max non-application_data records (CCS / handshake / alert) skipped at the
// start of a segment before the first application_data record. 4 covers a
// TLS 1.2 client's ClientKeyExchange + CCS + Finished and a TLS 1.3 client's
// CCS + Finished with headroom.
#define TC_MAX_LEADING_RECORDS 4
// Max records examined after the first application_data record when looking
// for the one carrying the staged SSL_write.
#define TC_MAX_SCAN_RECORDS 4

SEC("tc")
int tc_egress_patch(struct __sk_buff *skb) {
  dbg_inc(DBG_TC_ENTRY);

  // Parse Ethernet header (if present)
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // Determine L3 offset. For tc, skb->protocol tells us the L3 protocol
  // (IPv4 or IPv6). On veth pairs the skb typically starts with an Ethernet
  // header; raw IP devices have none.
  __u16 l3_proto = skb->protocol;
  if (l3_proto != __bpf_htons(0x0800) && l3_proto != __bpf_htons(0x86DD))
    return TC_PASS;
  __u32 l3_off = 0;
  {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
      return TC_PASS;
    if (eth->h_proto == l3_proto)
      l3_off = sizeof(struct ethhdr);
    // else: raw IP, l3_off stays 0
  }

  // Parse the IP header, and key on the connection's original (pre-DNAT)
  // destination, read from the socket rather than the packet: for cluster
  // services, iptables/kube-proxy DNATs the packet's destination to the pod
  // IP, but the socket still holds the service ClusterIP, which is what the
  // kprobe stored in tc_pending (sock_dst_addr).
  // The packet's destination is read first and the socket's after the
  // bpf_sk_fullsock call: otherwise the compiler may merge the two loads into
  // one through a selected pointer, which the verifier refuses on a socket.
  struct tc_dest_key key = {};
  struct bpf_sock *bsk = skb->sk;
  __u32 ip_hdr_len;
  __u32 l4_len; // TCP header and payload
  if (l3_proto == __bpf_htons(0x0800)) {
    struct iphdr *ip = data + l3_off;
    if ((void *)(ip + 1) > data_end)
      return TC_PASS;
    if (ip->protocol != 6) // Not TCP
      return TC_PASS;
    ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20)
      return TC_PASS;
    l4_len = __bpf_ntohs(ip->tot_len) - ip_hdr_len;
    __u32 daddr = ip->daddr; // fallback: the packet's
    if (bsk) {
      bsk = bpf_sk_fullsock(bsk);
      // bpf_sock.dst_ip4 is the original connect() destination
      if (bsk)
        daddr = bsk->dst_ip4;
    }
    ipv4_to_mapped(key.dst_ip, (const __u8 *)&daddr);
  } else {
    struct ipv6hdr *ip6 = data + l3_off;
    if ((void *)(ip6 + 1) > data_end)
      return TC_PASS;
    // TCP right after the fixed header: a Linux TCP socket sends no
    // extension headers of its own.
    if (ip6->nexthdr != 6)
      return TC_PASS;
    ip_hdr_len = sizeof(struct ipv6hdr);
    l4_len = __bpf_ntohs(ip6->payload_len);
    __builtin_memcpy(key.dst_ip, &ip6->daddr, 16); // fallback: the packet's
    if (bsk) {
      bsk = bpf_sk_fullsock(bsk);
      if (bsk) {
        __u32 *d = (__u32 *)key.dst_ip;
        d[0] = bsk->dst_ip6[0];
        d[1] = bsk->dst_ip6[1];
        d[2] = bsk->dst_ip6[2];
        d[3] = bsk->dst_ip6[3];
      }
    }
  }

  // Parse TCP header
  struct tcphdr *tcp = data + l3_off + ip_hdr_len;
  if ((void *)(tcp + 1) > data_end)
    return TC_PASS;

  __u32 tcp_hdr_len = tcp->doff * 4;
  if (tcp_hdr_len < 20)
    return TC_PASS;

  // Save header fields to locals before helper calls invalidate direct pointers.
  __u16 sport = tcp->source;
  __u32 pkt_seq = __bpf_ntohl(tcp->seq);

  // Key: destination IP + source port (per-connection isolation).
  key.src_port = sport;
  key.cgroup_id = bpf_skb_cgroup_id(skb);

  __u32 payload_off = l3_off + ip_hdr_len + tcp_hdr_len;
  __u32 payload_len = l4_len - tcp_hdr_len;

  // --- Deferred tag patching for multi-segment TLS records ---
  // When a TLS record spans multiple TCP segments, the ciphertext is patched
  // in the first segment but the auth tag (last 16 bytes) is in a later one.
  // Check if this segment contains a deferred tag patch.
  {
    struct tc_tag_val *tag = bpf_map_lookup_elem(&tc_tag_pending, &key);
    if (tag) {
      __u32 tag_seq = tag->tag_tcp_seq;
      __u32 pkt_end = pkt_seq + payload_len;
      // Check if the tag's byte position falls within this segment.
      if (pkt_seq <= tag_seq && tag_seq + 16 <= pkt_end) {
        __u32 tag_off = payload_off + (tag_seq - pkt_seq);
        __u8 old_tag[16], new_tag[16];
        if (bpf_skb_load_bytes(skb, tag_off, old_tag, 16) >= 0) {
          for (__u32 i = 0; i < 16; i++)
            new_tag[i] = old_tag[i] ^ tag->tag_delta[i];
          bpf_skb_store_bytes(skb, tag_off, new_tag, 16, 0);
#ifdef KLOAK_DEBUG
          bpf_printk("kloak [5-TAG-DEFERRED] seq=%u off=%u", tag_seq, tag_off);
#endif
        }
        bpf_map_delete_elem(&tc_tag_pending, &key);
      }
      // Whether we patched or not, return — this segment is a continuation,
      // not a new TLS record. Don't process it further.
      return TC_PASS;
    }
  }

  // Check TLS record framing (cheap, no map lookup).
  if (payload_len < 5)
    return TC_PASS;

  // Offset of the TCP payload; ghash_record_tcp_off below is relative to it.
  __u32 tcp_payload_start = payload_off;

  // Locate the first application_data record in the segment. A TLS stack may
  // flush non-application records in the same write as the first
  // application_data record — a TLS 1.3 client sends ChangeCipherSpec +
  // encrypted Finished + its first application write as one segment (Bun
  // >= 1.4.1 does this) — so skip leading CCS / handshake / alert records.
  // Every header must still validate as a record boundary (version + per-type
  // length bounds, see tls_record_hdr_kind), which rejects TCP continuation
  // segments whose ciphertext bytes happen to resemble a header.
  __u8 tls_hdr[5];
  __u32 record_len = 0;
  int rec_kind = TLS_REC_INVALID;
  for (__u32 i = 0; i <= TC_MAX_LEADING_RECORDS; i++) {
    if (bpf_skb_load_bytes(skb, payload_off, tls_hdr, 5) < 0)
      return TC_PASS;
#ifdef KLOAK_DEBUG
    bpf_printk("kloak tc tls_hdr=%x ver=%x%x plen=%u", tls_hdr[0], tls_hdr[1], tls_hdr[2], payload_len);
#endif
    rec_kind = tls_record_hdr_kind(tls_hdr, &record_len);
    if (rec_kind != TLS_REC_SKIPPABLE)
      break;
    payload_off += 5 + record_len;
  }
  if (rec_kind != TLS_REC_APPDATA)
    return TC_PASS;

  // Now that we know this is a valid TLS application_data record, look up
  // the pending entry. This avoids map lookups on non-TLS packets.
  struct tc_pending_val *pending = bpf_map_lookup_elem(&tc_pending, &key);
  if (!pending || !pending->active) {
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [3-TC] MISS sport=%u cg=%x", __bpf_ntohs(sport), (__u32)key.cgroup_id);
#endif
    return TC_PASS;
  }

  // TCP sequence check: only patch the segment that contains the password data.
  // write_seq was captured in the kprobe at the moment the password was queued
  // into the TCP send buffer. Skip segments from earlier writes (e.g., TLS
  // Finished, StartupMessage) that share the same connection key.
  if (pending->write_seq > 0) {
    __u32 pkt_end = pkt_seq + payload_len;
    // write_seq points to the START of the password TLS record in the stream.
    // The segment must contain this offset: pkt_seq <= write_seq < pkt_end.
    if (pkt_seq > pending->write_seq || pkt_end <= pending->write_seq) {
#ifdef KLOAK_DEBUG
      bpf_printk("kloak [3-TC] SEQ-SKIP pkt=%u ws=%u", pkt_seq, pending->write_seq);
#endif
      return TC_PASS; // wrong segment — keep tc_pending active
    }
  }

#ifdef KLOAK_DEBUG
  bpf_printk("kloak [3-TC] HIT sport=%u cg=%x", __bpf_ntohs(sport), (__u32)key.cgroup_id);
#endif

  dbg_inc(DBG_TC_MATCH);

#ifdef KLOAK_DEBUG
  bpf_printk("kloak [3-TC] DIAG plen=%u rlen=%u skblen=%u po=%u", payload_len, record_len, skb->len, payload_off);
#endif

  // --- Determine nonce_len from tls_conn_state (authoritative) ---
  // TLS 1.3 has no explicit nonce (nonce_len=0); TLS 1.2 has 8-byte nonce.
  // The nonce_len was set during H extraction from the connection struct
  // (Go Conn.vers or OpenSSL SSL_CONNECTION.version). TLS libraries without a
  // known version offset (OpenSSL versions without ssl_to_version, BoringSSL
  // in Bun) store 0xFF; the record-length match below then decides.
  __u32 nonce_len = TLS_NONCE_UNKNOWN;
  {
    struct tls_conn_key ck = {};
    ck.tgid = pending->tgid;
    ck.ssl_ptr = pending->ssl_ptr;
    struct tls_conn_state *conn = bpf_map_lookup_elem(&tls_conn_state, &ck);
    if (conn && conn->nonce_len != TLS_NONCE_UNKNOWN)
      nonce_len = conn->nonce_len;
  }

  // --- Find the record that carries the staged SSL_write ---
  // A segment may hold several application_data records (in TLS 1.3 the
  // encrypted Finished is application_data on the wire too), so the first one
  // is not necessarily ours. The record whose length exactly fits
  // plaintext_len (under the known nonce_len, or either TLS 1.2/1.3 layout
  // when unknown) is the one to patch, and its layout fixes nonce_len.
  __u32 pt_len = pending->plaintext_len;
  __u32 matched_nonce = 0;
  int matched = tls_appdata_reclen_match(record_len, pt_len, nonce_len, &matched_nonce);
  if (!matched && pt_len > 0) {
    __u32 scan_off = payload_off + 5 + record_len;
    for (__u32 i = 0; i < TC_MAX_SCAN_RECORDS; i++) {
      __u8 hdr[5];
      if (bpf_skb_load_bytes(skb, scan_off, hdr, 5) < 0) break;
      __u32 rlen = 0;
      int kind = tls_record_hdr_kind(hdr, &rlen);
      if (kind == TLS_REC_INVALID) break;
      if (kind == TLS_REC_APPDATA &&
          tls_appdata_reclen_match(rlen, pt_len, nonce_len, &matched_nonce)) {
        payload_off = scan_off;
        record_len = rlen;
        matched = 1;
        break;
      }
      scan_off += 5 + rlen;
    }
  }
  if (matched)
    nonce_len = matched_nonce;
  else if (nonce_len == TLS_NONCE_UNKNOWN)
    // No exact fit (e.g. an SSL_write larger than one record): keep the first
    // application_data record and assume TLS 1.2, as before.
    // TODO: derive nonce_len for TLS libraries without an ssl_to_version
    // offset (BoringSSL/Bun) instead of guessing, so large writes on TLS 1.3
    // are patched with the right layout.
    nonce_len = 8;

  // Ensure record is large enough for the nonce + tag. For TLS 1.2 (nonce_len=8),
  // minimum is 24; for TLS 1.3 (nonce_len=0), minimum is 17. Without this check,
  // the subtraction underflows for small records with the wrong nonce_len.
  if (record_len < 16 + nonce_len)
    return TC_PASS;

  __u32 ct_len = record_len - 16 - nonce_len;

  // Copy ALL data from pending to ghash_scratch staging area.
  // pending (tc_pending) and w (ghash_scratch) are from different maps — both
  // pointers remain valid after the second lookup.
  __u32 zero = 0;
  struct ghash_work *w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return TC_PASS;

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
  w->ghash_conn_key = key;
  w->ghash_pkt_seq = pkt_seq;
  w->ghash_record_tcp_off = payload_off - tcp_payload_start;

  // Apply patches. Zero secret_len on failure so GHASH skips unapplied patches.
  // Track whether any patch was actually applied — only deactivate tc_pending
  // if at least one patch succeeded. For multi-segment TLS records, the first
  // segment may have a record too small for the secret; we must NOT consume
  // tc_pending so the real record's segment can match later.
  __u32 patches_applied = 0;
  for (__u32 p = 0; p < XOR_MAX_PATCHES && p < pc; p++) {
    w = bpf_map_lookup_elem(&ghash_scratch, &zero);
    if (!w) return TC_PASS;

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
    patches_applied++;
  }

  // Only deactivate tc_pending if at least one patch was applied.
  // If no patches applied (record too small or patch offset beyond segment),
  // keep tc_pending active so the correct segment can match later.
  if (patches_applied > 0) {
    pending = bpf_map_lookup_elem(&tc_pending, &key);
    if (pending) pending->active = 0;
  } else {
    // No patches applied — don't proceed to GHASH (nothing changed).
    return TC_PASS;
  }

#ifdef KLOAK_DEBUG
  bpf_printk("kloak [4-PATCH] sport=%u pc=%u ct=%u applied=%u", __bpf_ntohs(sport), pc, ct_len, patches_applied);
#endif

  // Tail-call to tc GHASH program.
  bpf_tail_call(skb, &tc_prog_array, 0);
#ifdef KLOAK_DEBUG
  bpf_printk("kloak [4-PATCH] TAILCALL_FAILED");
#endif
  return TC_PASS;
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
    return TC_PASS;
  w->ghash_active = 0;

  // Copy H power table from tls_conn_state.
  bpf_loop(11, copy_h_power_step, NULL, 0);

  w = bpf_map_lookup_elem(&ghash_scratch, &zero);
  if (!w)
    return TC_PASS;

  __u32 ct_len = w->ghash_ct_len;
  __u32 nonce_len = w->ghash_nonce_len;
  __u32 payload_off = w->ghash_payload_off;
  __u32 ct_blocks = (ct_len + 15) / 16;

  // Tag offset within the skb (if the tag is in this segment).
  __u32 tag_offset = payload_off + 5 + nonce_len + ct_len;

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
    return TC_PASS;

  // Try to read the old tag from the current segment.
  if (bpf_skb_load_bytes(skb, tag_offset, w->old_tag, 16) >= 0) {
    // Tag is in this segment — apply delta inline (common case for socket BIOs
    // and small TLS records that fit in one segment).
    for (__u32 i = 0; i < 16; i++)
      w->new_tag[i] = w->old_tag[i] ^ w->tag_delta[i];
    bpf_skb_store_bytes(skb, tag_offset, w->new_tag, 16, 0);
#ifdef KLOAK_DEBUG
    __u32 dsum = 0;
    for (__u32 di = 0; di < 16; di++) dsum += w->tag_delta[di];
    bpf_printk("kloak [5-GHASH] tag_off=%u dsum=%u", tag_offset, dsum);
#endif
  } else {
    // Tag is in a later segment (TLS record spans multiple TCP segments).
    // Store the precomputed tag delta so tc_egress can apply it when the
    // segment containing the tag arrives.
    // tag_tcp_seq = pkt_seq + record_tcp_off + 5 + nonce_len + ct_len
    // record_tcp_off accounts for forward-scanned records that don't start
    // at byte 0 of the TCP payload (coalesced TLS records).
    struct tc_tag_val tv;
    __builtin_memcpy(tv.tag_delta, w->tag_delta, 16);
    tv.tag_tcp_seq = w->ghash_pkt_seq + w->ghash_record_tcp_off + 5 + nonce_len + ct_len;
    bpf_map_update_elem(&tc_tag_pending, &w->ghash_conn_key, &tv, BPF_ANY);
#ifdef KLOAK_DEBUG
    bpf_printk("kloak [5-GHASH] DEFERRED tag_seq=%u", tv.tag_tcp_seq);
#endif
  }

  return TC_PASS;
}

// =============================================================================
// Virtual IP host resolution (spinningfactory/kloak#327)
//
// tc_dns_rewrite runs at tc ingress on the pod's own interface, inside the pod
// netns: past the CNI (which may deliver with bpf_redirect_peer and skip the
// host side of the veth), before the pod's sockets. It replaces every A
// record of a trusted resolver's answer for a watched host with the host's
// fake IP, and every AAAA record with its fake IPv6 (when an IPv6 range is
// configured), if the pod has a secret for the host (vip_pod_host), and
// records the real addresses in vip_upstream. vip_connect4 / vip_connect6
// (cgroup connect4/6 on the kubepods cgroup) send a connect to a fake IP to
// one of them, before any CNI socket load balancer sees it (connect6 also
// takes the v4-mapped form of a fake IPv4); vip_getpeername4/6 report the
// fake IP back to the app.
//
// Host attribution is the socket's: vip_connect4/6 record, per socket
// cookie, the host of the fake IP it connected to (vip_sock_host), and the
// tcp_sendmsg kprobe checks a secret's host, IP and port against the socket
// the record leaves on (socket_filter_patches).
// A connection that did not go through a fake IP (a hardcoded or
// unrewritten address) gets no host-restricted secret. The socket and the
// packets carry the real address, which the tcp_sendmsg kprobe and
// tc_egress_patch key on as before.
// =============================================================================

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

// vip_rewrite_addr overwrites the address of an A (six = 0, 4 bytes) or AAAA
// (six = 1, 16 bytes) record at skb offset `at` with `to` (was `from`; both
// hold the address in their first 4 or 16 of 16 bytes) and updates the UDP
// checksum at csum_off. odd: `at` is an odd number of bytes past the UDP
// header. has_csum: the datagram carries a checksum (UDP over IPv4 may send
// 0).
static __always_inline long vip_rewrite_addr(struct __sk_buff *skb, __u32 at,
                                             __u32 csum_off, int odd,
                                             int has_csum, const __u8 *from,
                                             const __u8 *to, int six) {
  // No BPF_F_RECOMPUTE_CSUM with a checksum: the checksum field moves by the
  // opposite of the payload change, so a CHECKSUM_COMPLETE skb->csum stays
  // right.
  __u64 flags = has_csum ? 0 : BPF_F_RECOMPUTE_CSUM;
  long err = six ? bpf_skb_store_bytes(skb, at, to, 16, flags)
                 : bpf_skb_store_bytes(skb, at, to, 4, flags);
  if (err || !has_csum)
    return err;
  __u32 words = six ? 4 : 1;
  for (__u32 k = 0; k < 4; k++) {
    if (k >= words)
      break;
    __u32 f, t;
    __builtin_memcpy(&f, from + 4 * k, 4);
    __builtin_memcpy(&t, to + 4 * k, 4);
    if (odd) {
      f = csum_odd_bytes(f);
      t = csum_odd_bytes(t);
    }
    err = bpf_l4_csum_replace(skb, csum_off, f, t,
                              BPF_F_MARK_MANGLED_0 | sizeof(__u32));
    if (err)
      return err;
  }
  return 0;
}

// vip_record_addr returns a record's address (A: its 4 bytes) as a 16-byte
// address in out: IPv4-mapped for an A record.
static __always_inline void vip_record_addr(const struct dns_addr_record *r,
                                            int six, __u8 *out) {
  if (six)
    __builtin_memcpy(out, r->ip, 16);
  else
    ipv4_to_mapped(out, r->ip);
}

// bpf_loop callbacks driving the DNS walks of helpers.h over the message in
// dns_rewrite_scratch (looked up again per callback for the verifier).
static int dns_question_cb(__u32 idx, void *ctx) {
  __u32 zero = 0;
  struct dns_rewrite_buf *buf = bpf_map_lookup_elem(&dns_rewrite_scratch, &zero);
  if (!buf)
    return 1;
  return dns_question_step(&buf->q, buf->msg);
}

static int dns_answers_cb(__u32 idx, void *ctx) {
  __u32 zero = 0;
  struct dns_rewrite_buf *buf = bpf_map_lookup_elem(&dns_rewrite_scratch, &zero);
  if (!buf)
    return 1;
  return dns_answers_step(&buf->a, buf->msg);
}

SEC("tc")
int tc_dns_rewrite(struct __sk_buff *skb) {
  __u32 zero = 0;
  struct vip_config_val *cfg = bpf_map_lookup_elem(&vip_config, &zero);
  if (!cfg || !cfg->mask4)
    return TC_PASS;
  __u16 l3_proto = skb->protocol;
  if (l3_proto != __bpf_htons(0x0800) && l3_proto != __bpf_htons(0x86DD))
    return TC_PASS;

  // Ethernet header if present (see tc_egress_patch).
  __u32 l3_off = 0;
  __u16 h_proto = 0;
  if (bpf_skb_load_bytes(skb, 12, &h_proto, sizeof(h_proto)) == 0 &&
      h_proto == l3_proto)
    l3_off = sizeof(struct ethhdr);

  struct dns_rewrite_buf *buf = bpf_map_lookup_elem(&dns_rewrite_scratch, &zero);
  if (!buf)
    return TC_PASS;
  // The answer's source (the resolver) and destination (the pod), as 16-byte
  // addresses.
  __u8 src[16];
  struct vip_pod_host_key *pk = &buf->pod;
  __u32 l4_off;
  if (l3_proto == __bpf_htons(0x0800)) {
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, l3_off, &ip, sizeof(ip)))
      return TC_PASS;
    if (ip.version != 4 || ip.protocol != IPPROTO_UDP)
      return TC_PASS;
    // A fragment carries only part of the message (MF or a fragment offset).
    if (ip.frag_off & __bpf_htons(0x3FFF))
      return TC_PASS;
    __u32 ihl = ip.ihl * 4;
    if (ihl < sizeof(struct iphdr))
      return TC_PASS;
    l4_off = l3_off + ihl;
    ipv4_to_mapped(src, (const __u8 *)&ip.saddr);
    ipv4_to_mapped(pk->pod_ip, (const __u8 *)&ip.daddr);
  } else {
    struct ipv6hdr ip6;
    if (bpf_skb_load_bytes(skb, l3_off, &ip6, sizeof(ip6)))
      return TC_PASS;
    // UDP right after the fixed header: a message behind extension headers,
    // a fragment header included, is left unchanged.
    if (ip6.version != 6 || ip6.nexthdr != IPPROTO_UDP)
      return TC_PASS;
    l4_off = l3_off + sizeof(struct ipv6hdr);
    __builtin_memcpy(src, &ip6.saddr, 16);
    __builtin_memcpy(pk->pod_ip, &ip6.daddr, 16);
  }

  struct udphdr udp;
  if (bpf_skb_load_bytes(skb, l4_off, &udp, sizeof(udp)))
    return TC_PASS;
  if (udp.source != __bpf_htons(53))
    return TC_PASS;

  if (!dns_server_trusted(src))
    return TC_PASS;

  // A message larger than the copy buffer could hold records past it: left
  // unchanged.
  // 64-bit with the two checks kept apart: as a __u32, or merged into one
  // range check, the bounds end up on a copy and the verifier rejects the
  // variable-length copy below.
  __u64 udp_len = __bpf_ntohs(udp.len);
  if (udp_len < sizeof(struct udphdr) + 12)
    return TC_PASS;
  barrier_var(udp_len);
  if (udp_len > sizeof(struct udphdr) + MAX_DNS_PKT)
    return TC_PASS;
  __u32 msg_len = udp_len - sizeof(struct udphdr);

  __u32 msg_off = l4_off + sizeof(struct udphdr);
  if (bpf_skb_load_bytes(skb, msg_off, buf->msg, msg_len))
    return TC_PASS;

  struct dns_question *q = &buf->q;
  __builtin_memset(q, 0, sizeof(*q));
  dns_question_begin(q, buf->msg, msg_len);
  if (q->status == DNS_SCAN_RUNNING)
    bpf_loop(DNS_QNAME_STEPS, dns_question_cb, NULL, 0);
  if (dns_question_end(q) != DNS_SCAN_OK)
    return TC_PASS;
  // An A question gets the host's fake IPv4, an AAAA question its fake IPv6.
  __u32 qtype = q->qtype;
  int six = qtype == DNS_TYPE_AAAA;
  if (!six && qtype != DNS_TYPE_A)
    return TC_PASS;
  // q->qname is laid out as a watched_host_key.
  struct vip_host_val *hv = bpf_map_lookup_elem(&vip_host_ip, q->qname);
  if (!hv)
    return TC_PASS;
  struct dns_ip_key fk = {}; // the fake IP, as vip_upstream's key
  if (six)
    __builtin_memcpy(fk.ip, hv->ip6, 16);
  else
    ipv4_to_mapped(fk.ip, hv->ip4);
  // No fake IP of the question's family (an all-zero ip6: no IPv6 range),
  // or one the range no longer holds: the answer is left unchanged.
  if (!vip_addr_in_range(cfg, fk.ip))
    return TC_PASS;

  // Only for a pod with a secret for the host (the answer's destination is
  // the pod's address): any other pod keeps the real addresses, and gets
  // no host-restricted secret.
  __builtin_memcpy(pk->host, q->qname, MAX_HOST_LEN);
  if (!bpf_map_lookup_elem(&vip_pod_host, pk)) {
    __builtin_memset(pk->host, 0, MAX_HOST_LEN);
    if (!bpf_map_lookup_elem(&vip_pod_host, pk)) {
      dbg_inc(DBG_VIP_DNS_UNBOUND);
      return TC_PASS;
    }
  }

  struct dns_answers *a = &buf->a;
  __builtin_memset(a, 0, sizeof(*a));
  dns_answers_begin(a, msg_len, q->answers_off, q->ancount, qtype);
  bpf_loop(DNS_SCAN_STEPS, dns_answers_cb, NULL, 0);
  if (dns_answers_end(a) != DNS_SCAN_OK) {
    // The app gets the real addresses, and no host-restricted secret.
    dbg_inc(DBG_VIP_DNS_UNCHANGED);
    return TC_PASS;
  }
  __u32 n = a->n_recs;
  if (n == 0)
    return TC_PASS; // e.g. no address of the question's family

  // Record the real addresses before handing out the fake IP, so a connect
  // that follows the answer finds them.
  struct vip_upstream_val *up = &buf->up;
  struct vip_upstream_val *cur = bpf_map_lookup_elem(&vip_upstream, &fk);
  if (cur)
    __builtin_memcpy(up, cur, sizeof(*up));
  else
    __builtin_memset(up, 0, sizeof(*up));
  __u64 now = bpf_ktime_get_boot_ns();
  int recorded = 0;
  __u8 real[16];
  for (__u32 i = 0; i < DNS_MAX_ADDR_RECORDS; i++) {
    if (i >= n)
      break;
    vip_record_addr(&a->recs[i], six, real);
    // Already a fake IP (the program ran twice on this packet): not an
    // upstream.
    if (vip_addr_in_range(cfg, real))
      continue;
    // RFC 2181: a TTL with the top bit set means 0.
    __u64 ttl = a->recs[i].ttl > 0x7FFFFFFF ? 0 : a->recs[i].ttl;
    vip_upstream_record(up, real, now + ttl * 1000000000ULL);
    recorded = 1;
  }
  if (!recorded)
    return TC_PASS;
  if (bpf_map_update_elem(&vip_upstream, &fk, up, BPF_ANY))
    return TC_PASS; // nowhere to redirect to: leave the real addresses

  // The record data to write: the fake IPv6, or the fake IPv4's 4 bytes.
  if (six)
    __builtin_memcpy(buf->rdata, fk.ip, 16);
  else
    __builtin_memcpy(buf->rdata, &fk.ip[12], 4);
  int has_csum = udp.check != 0;
  __u32 csum_off = l4_off + offsetof(struct udphdr, check);
  for (__u32 i = 0; i < DNS_MAX_ADDR_RECORDS; i++) {
    if (i >= n)
      break;
    vip_record_addr(&a->recs[i], six, real);
    if (vip_addr_in_range(cfg, real))
      continue;
    // The message starts 8 bytes (even) past the UDP header.
    if (vip_rewrite_addr(skb, msg_off + a->recs[i].off, csum_off,
                         a->recs[i].off & 1, has_csum, a->recs[i].ip,
                         buf->rdata, six)) {
      // Part of the answer may already hold the fake IP: drop it rather
      // than deliver a mix; the resolver retries.
      return TC_ACT_SHOT;
    }
  }
  dbg_inc(DBG_VIP_DNS_REWRITTEN);
#ifdef KLOAK_DEBUG
  bpf_printk("kloak [vip] dns rewrite host=%s records=%u fake=%pI6", q->qname,
             n, fk.ip);
#endif
  return TC_PASS;
}

// vip_redirect decides where a connect to dst (IPv4-mapped or IPv6) goes:
// -1 leaves it alone (not a fake IP), 0 refuses it, 1 sends it to real (an
// address of dst's family) and records the socket's fake IP for
// getpeername.
static __always_inline int vip_redirect(struct bpf_sock_addr *ctx,
                                        const __u8 *dst, __u8 *real) {
  __u32 zero = 0;
  struct vip_config_val *cfg = bpf_map_lookup_elem(&vip_config, &zero);
  if (!cfg || !vip_addr_in_range(cfg, dst))
    return -1;

  // From here on the connect either goes to a real address or fails: the
  // range is unrouted, a connect left on the fake IP would only time out.
  struct dns_ip_key k = {};
  __builtin_memcpy(k.ip, dst, 16);
  struct vip_upstream_val *up = NULL;
  struct vip_ip_val *ih = bpf_map_lookup_elem(&vip_ip_host, &k);
  if (ih)
    up = bpf_map_lookup_elem(&vip_upstream, &k);
  if (!ih || !up ||
      !vip_upstream_pick(up, bpf_ktime_get_boot_ns(), bpf_get_prandom_u32(), real) ||
      vip_addr_v4mapped(real) != vip_addr_v4mapped(dst)) {
    dbg_inc(DBG_VIP_CONNECT_REFUSED);
    return 0;
  }

  // The host this socket's secrets are checked against (vip_sock_host).
  // Without the entry it gets no host-restricted secret, but still connects.
  __u64 cookie = bpf_get_socket_cookie(ctx);
  bpf_map_update_elem(&vip_sock_host, &cookie, ih->host, BPF_ANY);

  struct bpf_sock *sk = ctx->sk;
  if (sk) {
    struct vip_sock_val *sv =
        bpf_sk_storage_get(&vip_sock, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
    if (sv) {
      __builtin_memcpy(sv->fake_ip, dst, 16);
      __builtin_memcpy(sv->real_ip, real, 16);
      sv->port = ctx->user_port;
    }
  }
  dbg_inc(DBG_VIP_CONNECT_REDIRECT);
  return 1;
}

// vip_peer_fake copies to fake the fake IP a socket connected to, and sets
// the port getpeername reports to the one the app connected to, if the
// socket's last connect went to a fake IP (vip_forget_host clears it
// otherwise). Returns 0 when it did not. The address getpeername reports
// (peer) is not checked: a socket load balancer acting after vip_redirect
// (Cilium's) replaces the real address it chose with a backend's. peer is
// only used to keep the family: a fake IPv4 for an IPv4 peer.
static __always_inline int vip_peer_fake(struct bpf_sock_addr *ctx,
                                         const __u8 *peer, __u8 *fake) {
  struct bpf_sock *sk = ctx->sk;
  if (!sk)
    return 0;
  struct vip_sock_val *sv = bpf_sk_storage_get(&vip_sock, sk, 0, 0);
  if (!sv || vip_addr_v4mapped(sv->fake_ip) != vip_addr_v4mapped(peer))
    return 0;
  __builtin_memcpy(fake, sv->fake_ip, 16);
  ctx->user_port = sv->port;
  return 1;
}

// vip_forget_host drops what a socket's earlier connect to a fake IP
// recorded (its host, and the fake IP getpeername reports), when it connects
// anywhere but a fake IP: a TCP socket can connect again after a failed
// connect, a UDP socket at any time.
static __always_inline void vip_forget_host(struct bpf_sock_addr *ctx) {
  __u64 cookie = bpf_get_socket_cookie(ctx);
  bpf_map_delete_elem(&vip_sock_host, &cookie);
  struct bpf_sock *sk = ctx->sk;
  if (sk)
    bpf_sk_storage_delete(&vip_sock, sk);
}

// vip_record_dst records where a TCP socket connects (vip_sock_dst): dst
// (IPv4-mapped or IPv6) and the connect's port.
static __always_inline void vip_record_dst(struct bpf_sock_addr *ctx,
                                           const __u8 *dst) {
  if (ctx->type != 1) // SOCK_STREAM
    return;
  struct vip_sock_dst_val v = {};
  __builtin_memcpy(v.ip, dst, 16);
  v.port = __bpf_ntohs((__u16)ctx->user_port);
  __u64 cookie = bpf_get_socket_cookie(ctx);
  bpf_map_update_elem(&vip_sock_dst, &cookie, &v, BPF_ANY);
}

// bpf_sock_addr's user_ip6 as a 16-byte address, read word by word (the
// context allows 4-byte loads of it).
static __always_inline void vip_user_ip6(const struct bpf_sock_addr *ctx,
                                         __u32 *out) {
  out[0] = ctx->user_ip6[0];
  out[1] = ctx->user_ip6[1];
  out[2] = ctx->user_ip6[2];
  out[3] = ctx->user_ip6[3];
}

static __always_inline void vip_set_user_ip6(struct bpf_sock_addr *ctx,
                                             const __u32 *ip) {
  ctx->user_ip6[0] = ip[0];
  ctx->user_ip6[1] = ip[1];
  ctx->user_ip6[2] = ip[2];
  ctx->user_ip6[3] = ip[3];
}

SEC("cgroup/connect4")
int vip_connect4(struct bpf_sock_addr *ctx) {
  __u32 dst4 = ctx->user_ip4;
  __u8 dst[16], real[16];
  ipv4_to_mapped(dst, (const __u8 *)&dst4);
  int r = vip_redirect(ctx, dst, real);
  if (r == 1) {
    __u32 real4;
    __builtin_memcpy(&real4, &real[12], 4);
    ctx->user_ip4 = real4;
    vip_record_dst(ctx, real);
  } else {
    vip_forget_host(ctx);
    if (r < 0)
      vip_record_dst(ctx, dst);
  }
  return r != 0; // 0: EPERM
}

// An AF_INET6 socket connects to an IPv6 address, or to an IPv4 address
// through its v4-mapped form (::ffff:a.b.c.d; Java does by default): both
// go through the connect6 hook, not connect4.
SEC("cgroup/connect6")
int vip_connect6(struct bpf_sock_addr *ctx) {
  __u32 dst[4], real[4];
  vip_user_ip6(ctx, dst);
  int r = vip_redirect(ctx, (const __u8 *)dst, (__u8 *)real);
  if (r == 1) {
    vip_set_user_ip6(ctx, real);
    vip_record_dst(ctx, (const __u8 *)real);
  } else {
    vip_forget_host(ctx);
    if (r < 0)
      vip_record_dst(ctx, (const __u8 *)dst);
  }
  return r != 0;
}

SEC("cgroup/getpeername4")
int vip_getpeername4(struct bpf_sock_addr *ctx) {
  __u32 peer4 = ctx->user_ip4;
  __u8 peer[16], fake[16];
  ipv4_to_mapped(peer, (const __u8 *)&peer4);
  if (vip_peer_fake(ctx, peer, fake)) {
    __u32 fake4;
    __builtin_memcpy(&fake4, &fake[12], 4);
    ctx->user_ip4 = fake4;
  }
  return 1;
}

SEC("cgroup/getpeername6")
int vip_getpeername6(struct bpf_sock_addr *ctx) {
  __u32 peer[4], fake[4];
  vip_user_ip6(ctx, peer);
  if (vip_peer_fake(ctx, (const __u8 *)peer, (__u8 *)fake))
    vip_set_user_ip6(ctx, fake);
  return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
