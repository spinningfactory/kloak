# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Kloak

Kloak is a Kubernetes eBPF HTTPS interceptor that transparently replaces secret placeholders with real values at runtime. Applications never see actual secrets — they use hashed shadow values (`kl::<UUID>`) that get rewritten in-kernel via eBPF uprobes before TLS transmission.

## Build & Test Commands

```bash
make build              # Build the kloak binary to bin/
make test               # Run all tests (go test -v ./...)
make build-linux        # Cross-compile for Linux (uses Lima VM on macOS)
make test-linux         # Run tests inside Lima VM (needed for eBPF tests)
make docker-build       # Build Docker image
make generate-ebpf      # Regenerate eBPF Go bindings (requires Lima on macOS)
make generate-vmlinux   # Regenerate vmlinux.h from kernel BTF
make clean              # Remove build artifacts and generated eBPF files
```

Run a single test: `go test -v -run TestName ./pkg/some_package/`

## eBPF Development on macOS

eBPF code requires Linux. On macOS, Kloak uses Lima VMs (`lima.yaml` config):

```bash
make lima-start         # Create/start the Lima VM
make lima-shell         # Shell into VM for manual work
make lima-stop          # Stop the VM
```

The `generate-ebpf` and `test-linux` targets auto-start Lima via `lima-ensure`.

eBPF C source is in `pkg/ebpf/bpf/tls_uprobe.c`. Generated Go bindings (`tlsuprobe_bpfel.go`, `tlsuprobe_bpfeb.go`) are produced by `go generate` using `bpf2go` from `cilium/ebpf`. The `//go:generate` directive is in `pkg/ebpf/uprobe.go`.

## Architecture

The binary (`cmd/kloak/main.go`) has two subcommands via cobra:

- **`kloak controller`** — runs as a DaemonSet per node. Starts two reconcilers and optionally the eBPF uprobe manager:
  - `SecretReconciler` (`pkg/controller/secret_reconciler.go`) — watches Secrets labeled `getkloak.io/enabled=true`, creates shadow secrets (`<name>-kloak`) with UUID placeholders length-matched to originals, and stores hash→real-value mappings in `storage.Storage`.
  - `Reconciler` (`pkg/controller/reconciler.go`) — watches Pods annotated `getkloak.io/enabled=true`, discovers container cgroup IDs, and attaches eBPF TLS uprobes to container processes.
  - `TLSUprobeManager` (`pkg/ebpf/uprobe.go`) — loads eBPF programs, attaches uprobes to `crypto/tls.(*Conn).Write` (Go) or `SSL_write`/`SSL_write_ex` (OpenSSL/libssl — scans `/proc/<pid>/maps` to locate `libssl.so`), syncs secrets into the BPF map, and polls the ring buffer for rewrite events. Uses a two-phase tail-call design: phase 1 intercepts the TLS write, phase 2 performs the in-kernel rewrite via a `ProgArray` tail call. Also on startup, generates TLS certs for the webhook and patches the `CABundle` in the `MutatingWebhookConfiguration`.

- **`kloak webhook`** — mutating admission webhook. `Handler` (`pkg/webhook/handler.go`) intercepts pod creation, checks enablement (pod annotation → namespace label → owner workload labels, following ReplicaSet → Deployment chains), and rewrites Secret volume references to point to shadow secrets. `pkg/webhook/cert.go` generates self-signed RSA-2048 certs stored in the `kloak-webhook-certs` secret.

### Data Flow

1. Secret labeled `getkloak.io/enabled=true` → SecretReconciler creates shadow secret with `kl::<UUID>` values (padded/truncated to match original length)
2. Pod created → webhook rewrites volume mounts from original secret to shadow secret
3. Pod starts → controller detects pod, finds container cgroup, attaches TLS uprobes
4. App writes TLS data containing `kl::<UUID>` → eBPF uprobe intercepts, looks up real secret in BPF map, rewrites in-kernel before transmission

### Key Interfaces

- `storage.Storage` (`pkg/storage/storage.go`) — hash-to-value store interface with `Store`, `Lookup`, `Delete`, `List` methods. `Entry` holds `Value` string + `AllowedHosts []string`. Currently only in-memory (`pkg/storage/memory.go`).
- `pkg/cgroups/` — platform-specific cgroup utilities (Linux-only implementation + stub for other OS).

### Labels & Annotations

- `getkloak.io/enabled=true` — enable on secrets (label), pods (annotation), namespaces (label), or workloads (label/annotation)
- `getkloak.io/hosts=<host>` — restrict which host a secret can be sent to. Accepts a single hostname, a single IP, or `*` (any). A comma-separated list is **not** supported yet — the validating webhook rejects it and the data plane would treat it as one bogus hostname (see spinningfactory/kloak#102 for multi-host support)
- `getkloak.io/managed=true` — marks shadow secrets created by Kloak

## Project Layout

- `cmd/kloak/` — CLI entry point and subcommand wiring (`controller.go`, `webhook.go`)
- `cmd/ebpftest/` — standalone eBPF test utility
- `pkg/controller/` — Kubernetes reconcilers (pod + secret)
- `pkg/ebpf/` — eBPF program loading, uprobe attachment, BPF map sync
- `pkg/ebpf/bpf/` — eBPF C source and vmlinux.h
- `pkg/webhook/` — admission webhook handler and cert generation
- `pkg/storage/` — secret storage interface and implementations
- `pkg/cgroups/` — cgroup path resolution and inode lookup (Linux-only impl + stub)
- `charts/kloak/` — Helm chart for deploying Kloak (controller DaemonSet, webhook Deployment, RBAC, values.yaml)
- `examples/` — demo applications (Go, Node.js, Python)

/memory I want a production ready code and not things that are specific to the demo, while we can sometime prioritize making the demo work we need
always to add a todo to make things more generic and fix them