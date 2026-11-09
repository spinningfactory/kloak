// go:build ignore

// dispatch_v1.c - the entry trampolines every kloak uprobe is attached to
// (spinningfactory/kloak#107).
//
// A uprobe link can't be moved to another program (link.Update is not
// supported for perf-event links), so the uprobes don't run the TLS
// pipeline's entry programs directly: each runs one of these trampolines,
// which tail-calls the entry program in its kloak_dispatch slot. The
// trampolines and kloak_dispatch are pinned once per node, and the pipeline's
// programs are put in the slots: a controller that loads another build only
// fills the slots again, and every call runs exactly one entry program.
// Clearing the slots turns every kloak uprobe into a no-op.
//
// This is a frozen ABI. Pinned uprobes of a running node reference these
// programs, so the slots, the program types and kloak_dispatch's layout must
// never change: a change is a dispatch_v2, with a one-time re-attach of every
// uprobe.

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__) || defined(__amd64__)
#include "vmlinux_x86.h"
#else
#include "vmlinux_arm64.h"
#endif
#include <bpf/bpf_helpers.h>

// Slots of kloak_dispatch (dispatchSlot* in pins.go).
#define KLOAK_DISPATCH_SSL_WRITE 0     // bpf_uprobe_ssl_write
#define KLOAK_DISPATCH_GO_TLS_WRITE 1  // bpf_uprobe_go_tls_write
#define KLOAK_DISPATCH_EVP_INIT 2      // bpf_uprobe_evp_cipher_init
#define KLOAK_DISPATCH_EVP_INIT_RET 3  // bpf_uretprobe_evp_cipher_init

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 8); // 4 used; room for entry kinds a later pipeline adds
  __type(key, __u32);
  __type(value, __u32);
} kloak_dispatch SEC(".maps");

// An empty slot makes the tail call fail: the uprobe then does nothing.
// Program names stay within the kernel's 15 characters, for bpftool.

SEC("uprobe/dispatch_ssl_write")
int kloak_ssl_write(void *ctx) {
  bpf_tail_call(ctx, &kloak_dispatch, KLOAK_DISPATCH_SSL_WRITE);
  return 0;
}

SEC("uprobe/dispatch_go_tls_write")
int kloak_go_write(void *ctx) {
  bpf_tail_call(ctx, &kloak_dispatch, KLOAK_DISPATCH_GO_TLS_WRITE);
  return 0;
}

SEC("uprobe/dispatch_evp_init")
int kloak_evp_init(void *ctx) {
  bpf_tail_call(ctx, &kloak_dispatch, KLOAK_DISPATCH_EVP_INIT);
  return 0;
}

SEC("uretprobe/dispatch_evp_init_ret")
int kloak_evp_ret(void *ctx) {
  bpf_tail_call(ctx, &kloak_dispatch, KLOAK_DISPATCH_EVP_INIT_RET);
  return 0;
}

// The same license as tls_uprobe.c, whose programs these tail-call.
char LICENSE[] SEC("license") = "Dual BSD/GPL";
