#!/usr/bin/env bash
# Wrapper around `bpf2go` invoked from this package's //go:generate directive.
#
# Why a script instead of inlining the bpf2go command in //go:generate:
# Go's variable substitution for //go:generate directives matches `${VAR...}`
# greedily and does NOT understand the shell `${VAR:-default}` form — it
# replaces the whole `${KLOAK_TARGET_ARCH:-arm64}` token with empty, then sh
# only sees an empty `ARCH=` assignment. Result: clang gets `-D__TARGET_ARCH_`
# (suffix missing), so neither `bpf_target_x86` nor `bpf_target_arm64` ends up
# defined and the SSL_write / Go-TLS / EVP_CipherInit uprobes' arch-specific
# register-read blocks silently dead-strip to a `return 0`. Empirically: kloak's
# data plane on every aarch64 dev build (and any path that hit this directive
# without the env var explicitly set) was bailing at uprobe entry, never
# reaching the prescan / xor path. CI worked-by-accident because it set the
# env var explicitly but Go still mangled the cflags string.
#
# A wrapper script bypasses Go's directive substitution entirely: sh runs the
# command with full shell semantics, including `${KLOAK_TARGET_ARCH:-arm64}`.
set -euo pipefail

# Default to arm64 to match macOS / Apple Silicon dev environments. CI sets
# this to x86 explicitly. Any new arch goes here.
ARCH="${KLOAK_TARGET_ARCH:-arm64}"
case "$ARCH" in
    x86|arm64) ;;
    *)
        echo "generate.sh: unsupported KLOAK_TARGET_ARCH=$ARCH (expected x86 or arm64)" >&2
        exit 1
        ;;
esac

# -tags linux constrains the generated _bpfel.go / _bpfeb.go to linux builds
# so macOS unit tests still compile (cilium/ebpf is Linux-only). See PR #217.
exec go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang \
    -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_${ARCH}" \
    -tags linux \
    tlsuprobe \
    bpf/tls_uprobe.c -- -I../ebpf
