// go:build ignore

// redirect.c - eBPF program for redirecting HTTPS traffic to localhost
//
// This program attaches to cgroup connect4/connect6 hooks and redirects
// outbound port 443 connections to localhost:15001 where Envoy listens.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// Constants
#define AF_INET 2
#define AF_INET6 10
#define HTTPS_PORT 443
#define ENVOY_PORT 15001

// Legacy map definition for BTF-less loading
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
};

// Map to track which cgroup IDs should have traffic redirected
struct bpf_map_def SEC("maps") tracked_cgroups = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u8),
    .max_entries = 10240,
};

// Map to store original destination for each connection
// Key: socket cookie, Value: original destination
struct orig_dst {
  __u32 ip4;
  __u16 port;
  __u8 family;
  __u8 pad;
};

struct bpf_map_def SEC("maps") original_dst = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),
    .value_size = sizeof(struct orig_dst),
    .max_entries = 65535,
};

// Check if this cgroup should have traffic redirected
static __always_inline int is_tracked(__u64 cgroup_id) {
  __u8 *enabled = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
  return enabled != NULL && *enabled == 1;
}

// IPv4 connect hook
SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx) {
  // Only intercept TCP connections to port 443
  if (ctx->protocol != IPPROTO_TCP) {
    return 1; // Allow
  }

  __u16 dst_port = bpf_ntohs(ctx->user_port);
  if (dst_port != HTTPS_PORT) {
    return 1; // Allow
  }

  // Check if this cgroup is tracked
  __u64 cgroup_id = bpf_get_current_cgroup_id();
  if (!is_tracked(cgroup_id)) {
    return 1; // Allow - not a tracked pod
  }

  // Exclude Envoy sidecar (UID 1337)
  __u32 uid = bpf_get_current_uid_gid();
  if (uid == 1337) {
    return 1; // Allow Envoy traffic
  }

  // Store original destination
  __u64 cookie = bpf_get_socket_cookie(ctx);
  struct orig_dst dst = {
      .ip4 = ctx->user_ip4,
      .port = dst_port,
      .family = AF_INET,
  };
  bpf_map_update_elem(&original_dst, &cookie, &dst, BPF_ANY);

  // Redirect to localhost:15001
  ctx->user_ip4 = bpf_htonl(0x7f000001); // 127.0.0.1
  ctx->user_port = bpf_htons(ENVOY_PORT);

  bpf_printk("kloak: redirected %pI4:%d -> 127.0.0.1:%d", &dst.ip4, dst_port,
             ENVOY_PORT);

  return 1; // Allow (with modified destination)
}

// IPv6 connect hook (simplified - redirects to IPv6 localhost)
SEC("cgroup/connect6")
int cgroup_connect6(struct bpf_sock_addr *ctx) {
  // Only intercept TCP connections to port 443
  if (ctx->protocol != IPPROTO_TCP) {
    return 1;
  }

  __u16 dst_port = bpf_ntohs(ctx->user_port);
  if (dst_port != HTTPS_PORT) {
    return 1;
  }

  // Check if this cgroup is tracked
  __u64 cgroup_id = bpf_get_current_cgroup_id();
  if (!is_tracked(cgroup_id)) {
    return 1;
  }

  // For IPv6, we store the last 4 bytes as "ip4" for simplicity
  __u64 cookie = bpf_get_socket_cookie(ctx);
  struct orig_dst dst = {
      .ip4 = ctx->user_ip6[3], // Last 32 bits
      .port = dst_port,
      .family = AF_INET6,
  };
  bpf_map_update_elem(&original_dst, &cookie, &dst, BPF_ANY);

  // Redirect to IPv4-mapped localhost (::ffff:127.0.0.1) so the kernel
  // routes to 127.0.0.1 where Envoy listens on 0.0.0.0:15001.
  // Using ::1 would fail because Envoy only binds IPv4.
  ctx->user_ip6[0] = 0;
  ctx->user_ip6[1] = 0;
  ctx->user_ip6[2] = bpf_htonl(0x0000FFFF);
  ctx->user_ip6[3] = bpf_htonl(0x7F000001);
  ctx->user_port = bpf_htons(ENVOY_PORT);

  return 1;
}

char LICENSE[] SEC("license") = "GPL";
