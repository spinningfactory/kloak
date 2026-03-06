# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Kloak

Kloak is a Kubernetes eBPF HTTPS interceptor that transparently replaces secret placeholders with real values at runtime. Applications never see actual secrets — they use hashed shadow values (`kloak:<UUID>`) that get rewritten in-kernel via eBPF uprobes before TLS transmission.

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
  - `TLSUprobeManager` (`pkg/ebpf/uprobe.go`) — loads eBPF programs, attaches uprobes to `crypto/tls.(*Conn).Write` (Go) or `SSL_write` (OpenSSL/libssl), syncs secrets into the BPF map, and polls the ring buffer for rewrite events.

- **`kloak webhook`** — mutating admission webhook. `Handler` (`pkg/webhook/handler.go`) intercepts pod creation, checks enablement (pod annotation → namespace label → owner workload labels), and rewrites Secret volume references to point to shadow secrets. Cert management is in `pkg/webhook/cert.go`.

### Data Flow

1. Secret labeled `getkloak.io/enabled=true` → SecretReconciler creates shadow secret with `kloak:<UUID>` values (padded/truncated to match original length)
2. Pod created → webhook rewrites volume mounts from original secret to shadow secret
3. Pod starts → controller detects pod, finds container cgroup, attaches TLS uprobes
4. App writes TLS data containing `kloak:<UUID>` → eBPF uprobe intercepts, looks up real secret in BPF map, rewrites in-kernel before transmission

### Key Interfaces

- `storage.Storage` (`pkg/storage/storage.go`) — hash-to-value store interface. Currently only in-memory (`pkg/storage/memory.go`).
- `pkg/cgroups/` — platform-specific cgroup utilities (Linux-only implementation + stub for other OS).

### Labels & Annotations

- `getkloak.io/enabled=true` — enable on secrets (label), pods (annotation), namespaces (label), or workloads (label/annotation)
- `getkloak.io/hosts=host1,host2` — restrict which hosts a secret can be sent to
- `getkloak.io/managed=true` — marks shadow secrets created by Kloak

## Project Layout

- `cmd/kloak/` — CLI entry point and subcommand wiring
- `pkg/controller/` — Kubernetes reconcilers (pod + secret)
- `pkg/ebpf/` — eBPF program loading, uprobe attachment, BPF map sync
- `pkg/ebpf/bpf/` — eBPF C source and vmlinux.h
- `pkg/webhook/` — admission webhook handler and cert generation
- `pkg/storage/` — secret storage interface and implementations
- `pkg/cgroups/` — cgroup path resolution and inode lookup
- `config/manifests/` — Kubernetes deployment manifests (controller, webhook, RBAC)
- `config/overlays/` — Kustomize overlays (dev, prod, k3s)
