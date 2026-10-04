# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is Kloak

Kloak is a Kubernetes eBPF TLS interceptor that keeps real secrets out of application pods. Applications only see random shadow placeholders (`kl::…`, exactly the same length as the real value). When an app sends a placeholder over TLS, eBPF uprobes on the TLS write path detect it, and after the TLS library has encrypted the record, a tc program XOR-patches the AES-GCM ciphertext so it decrypts to the real value, then recomputes the GCM tag. Nothing ever writes to user-space memory (there is no `bpf_probe_write_user`), so the real secret never exists inside the pod.

## Build & Test Commands

```bash
make build              # Build the kloak binary to bin/
make test               # Run all Go tests (go test -v ./...)
make test-bpf-helpers   # Userspace unit tests for pkg/ebpf/bpf/helpers.h (gcc, no BPF needed)
make build-linux        # Cross-compile for Linux (uses Lima VM on macOS)
make test-linux         # Run tests inside Lima VM (needed for eBPF tests)
make docker-build       # Build Docker image
make generate-ebpf      # Regenerate eBPF Go bindings (requires Lima on macOS)
make clean              # Remove build artifacts and generated eBPF files
make e2e-k3s            # e2e suite against a local k3s cluster (see Makefile for k3d/Lima variants)
```

Run a single test: `go test -v -run TestName ./pkg/some_package/`

eBPF e2e tests are behind a build tag: `go test -v -tags=e2e_ebpf -run TestEBPFBunHostFiltering ./test/e2e/` (needs a cluster with kloak + demo images; see `.github/workflows/ci.yml`).

## eBPF Development

eBPF code requires Linux. On macOS, Kloak uses Lima VMs (`lima.yaml` config):

```bash
make lima-start         # Create/start the Lima VM
make lima-shell         # Shell into VM for manual work
make lima-stop          # Stop the VM
```

The `generate-ebpf` and `test-linux` targets auto-start Lima via `lima-ensure`.

- C source: `pkg/ebpf/bpf/tls_uprobe.c`. Pure logic that can be unit-tested in userspace (GF(2^128), AES, HTTP/HPACK parsing, TLS record framing) lives in `pkg/ebpf/bpf/helpers.h` (compiled as BPF when `__BPF__` is defined, as plain C otherwise) with tests in `helpers_test.c`. Put new pure helpers there.
- Bindings (`tlsuprobe_bpfel.go` / `tlsuprobe_bpfeb.go` + `.o`) are generated, not committed. `//go:generate bash ./generate.sh` in `pkg/ebpf/uprobe.go` runs `bpf2go` with `-D__TARGET_ARCH_${KLOAK_TARGET_ARCH:-arm64}`. CI and the Dockerfile set `KLOAK_TARGET_ARCH=x86` for amd64. Building with `BPF_DEBUG=1` defines `KLOAK_DEBUG`, which enables the `bpf_printk` trace markers (`kloak [3-TC] …`) used by the e2e failure dumps.
- `tls_uprobe.c` includes the committed `vmlinux_x86.h` / `vmlinux_arm64.h`, selected by `__TARGET_ARCH_*`. `make generate-vmlinux` dumps the host kernel's BTF to `bpf/vmlinux.h`.
- Every BPF change must pass the kernel verifier for both arches, with and without `KLOAK_DEBUG`. `tc_egress_patch` and the `tcp_sendmsg` kprobe are close to the 512-byte stack limit, which is why large state lives in the per-CPU `ghash_scratch` map and helpers are `__always_inline`.

## Architecture

The binary (`cmd/kloak/`) has these cobra subcommands:

- **`kloak controller`** runs as a DaemonSet (hostPID) on every node.
  - `SecretReconciler` (`pkg/controller/secret_reconciler.go`) watches Secrets labeled `getkloak.io/enabled=true` and creates shadow secrets (`<name>-kloak`, labeled `getkloak.io/managed=true`). Shadow values come from `pkg/secrets/shadow.go`: `kl::` plus a random tail of the same length as the real value, with the same HPACK Huffman bit length (so HTTP/2 rewrites need no padding). The first 8 bytes are the BPF lookup key, so values shorter than 8 bytes are rejected.
  - `Reconciler` (`pkg/controller/reconciler.go`) watches Pods with the **annotation** `getkloak.io/enabled=true` (stamped by the webhook), discovers container cgroup IDs, and calls `TLSUprobeManager.AttachTLS`.
  - `TLSUprobeManager` (`pkg/ebpf/uprobe.go`, enabled with `--enable-ebpf`) loads the BPF objects, attaches probes per process, syncs secrets into BPF maps (`pkg/ebpf/sync.go`, fed by a `secrets.Source`), and attaches the tc patch program.
- **`kloak webhook`** runs as a Deployment.
  - `/mutate-pods` (`pkg/webhook/handler.go`): enabled when the pod has the **label** `getkloak.io/enabled=true`, or failing that its namespace has it. There is no workload-owner inheritance. It rewrites Secret volumes and `secretKeyRef` / `envFrom` references to shadow secrets, fails closed if a shadow doesn't exist yet, and stamps the pod annotation `getkloak.io/enabled=true` for the controller.
  - `/validate-secrets` (`pkg/webhook/secret_validator.go`): rejects kloak-enabled Secrets that the data plane can't handle. That covers multi-host or invalid `getkloak.io/hosts` (max 63 bytes), values < 8 or > 128 bytes, values no same-length shadow can match (`secrets.CanShadow`), and invalid `getkloak.io/port` (`PORT` or `PORT/tcp|udp`).
  - The serving cert lives in the `kloak-webhook-certs` secret and is provisioned by the Helm chart (`certificates.mode`: `auto` self-signs at install and sets `caBundle`; `certManager` uses cert-manager CA injection; `provided` uses your own). `pkg/webhook/cert.go` (`EnsureWebhookCerts`) can generate one and patch `CABundle`, but nothing calls it outside tests today.
- **`kloak secrets validate <file>`** validates a YAML secrets file (`pkg/secrets/yaml`) offline. **`kloak version`** prints the release tag and commit.

### Data plane (all runtimes take the same path)

1. **Attach** (`AttachTLS`), tried in order:
   - Go `crypto/tls.(*Conn).Write`.
   - Bun single-executables: `DetectBun` finds the embedded `bun/X.Y.Z`, then attaches at a pre-computed `SSL_write` file offset from `bunOffsetTable` (the binary is symbol-stripped).
   - `SSL_write` / `SSL_write_ex` in the main executable (statically linked OpenSSL such as Node.js, or BoringSSL), then in every TLS shared library found in the container's filesystem.
   - Per library and version, struct offsets for the TLS chain are pushed into `tls_offset_config` (`openssl_offsets.go`, `boringssl_offsets.go`, `go_tls_offsets.go`, `bun_offsets.go`).
2. **Uprobe** (`bpf_uprobe_ssl_write` / `bpf_uprobe_go_tls_write`): resolves the destination (`resolve_host`: BIO fd → `last_verified_fd` → `conn_ip_map` → `dns_ip_map`), prescans the plaintext for `kl::`, and tail-calls `prog_array` slot 1 (`bpf_xor_path`), or slot 2 (`bpf_h_extract`) for processes whose libcrypto `EVP_CipherInit_ex` hook is attached.
3. **`bpf_xor_path`**: for each placeholder found in `secret_map`, checks the secret's host / IP / port policy. On a match it stages `shadow XOR real` in `xor_pending`. On a mismatch nothing is staged and the placeholder goes out unchanged.
4. **`tcp_sendmsg` kprobe**: obtains the GHASH key H, either from the libcrypto hook or by walking the library's structs (OpenSSL GCM context; Go `gcmAsm` H×2; BoringSSL has no stored H, so `H = AES_K(0)` is recomputed from the AES key schedule). It moves the patch to `tc_pending`, keyed by (dst IP, src port, cgroup ID). Memory-BIO apps (Node, Bun) can't be matched by write sequence, so tc matches by TLS record framing instead.
5. **tc** (`tc_egress_patch` → tail call `tc_ghash_update`): attached at **ingress on the host side of the pod's veth** (`attachTCEgress`), so in-pod `CAP_NET_RAW` capture never sees patched ciphertext. It finds the record carrying the write (segments can coalesce CCS / Finished / several app-data records), XOR-patches the ciphertext, and recomputes the GCM tag. Attach uses TCX on Linux ≥ 6.6, otherwise a clsact qdisc + cls_bpf filter (`--tc-attach-mode=auto|tcx|clsact`, `pkg/ebpf/tc_attach.go`, `tc_mode.go`).

Supporting probes: kprobe/kretprobe on `udp_recvmsg` (DNS answers for watched hosts → `dns_ip_map`), `sys_enter/exit_connect` and `sys_enter_close` tracepoints (`conn_ip_map`, `last_verified_fd`), and `sched_process_exec/exit` (process lifecycle).

Only AES-128/256-GCM records (TLS 1.2 and 1.3) are patched. GnuTLS and Go BoringCrypto are not supported (their e2e cases are skipped).

### Key Interfaces

- `secrets.Source` (`pkg/secrets/secrets.go`): `Snapshot(ctx) ([]secrets.Secret, error)`, the boundary between control plane and data plane. `secrets.Secret` carries `Real`, `Shadow`, `Host` / `IP`, `Port`, `Protocol`. The Kubernetes implementation is `pkg/secrets/k8s`; `pkg/secrets/yaml` backs `kloak secrets validate`.
- `pkg/cgroups/`: cgroup path resolution and inode lookup (Linux implementation + stub for other OSes).

### Labels & Annotations

- `getkloak.io/enabled=true`: a label on Secrets (creates a shadow), Namespaces and Pods (webhook scope). The webhook adds it as a Pod **annotation**, which is what the controller watches.
- `getkloak.io/hosts=<host>` (annotation on the Secret): restricts which host a secret can be sent to. Accepts a single hostname, a single IP, or `*` (any). A comma-separated list is **not** supported yet. The validating webhook rejects it, and the data plane would treat it as one bogus hostname (see spinningfactory/kloak#102 for multi-host support).
- `getkloak.io/port=<port>` (annotation on the Secret): restricts the destination port.
- `getkloak.io/managed=true`: marks shadow secrets created by Kloak.

### Version tracking

TLS struct layouts and Bun `SSL_write` offsets change between releases. `tools/{openssl,boringssl,go-tls,bun}-offsets/` discover them and commit results under `results/`. The `*-versions-nightly.yml` workflows diff discovery against the committed results, run e2e against recent versions, and open PRs adding new versions (e.g. `tools/bun-offsets/apply-new-versions.sh` inserts rows into `bunOffsetTable`). When a nightly fails, compare the latest passing and failing versions before assuming the offsets are wrong.

## Project Layout

- `cmd/kloak/`: CLI entry point and subcommands (`controller.go`, `webhook.go`, `secrets*.go`, `version.go`)
- `cmd/ebpftest/`: standalone eBPF test utility
- `pkg/controller/`: Kubernetes reconcilers (pod + secret)
- `pkg/ebpf/`: probe attachment, BPF map sync, tc attach, per-library offset tables
- `pkg/ebpf/bpf/`: eBPF C source, `helpers.h` + tests, per-arch vmlinux headers
- `pkg/secrets/`: `Source` interface, shadow generator, k8s and YAML sources
- `pkg/webhook/`: mutating pod webhook, validating secret webhook, cert generation
- `pkg/cgroups/`, `pkg/logging/`: cgroup utilities, logging helpers
- `tools/*-offsets/`: offset discovery tooling and committed results
- `charts/kloak/`: Helm chart (controller DaemonSet, webhook Deployment, webhook configurations, RBAC, optional demo)
- `examples/`: demo applications (Go, Node.js, Python, Bun, BoringSSL, GnuTLS, raw TLS) used by the e2e tests
- `test/e2e/`: end-to-end tests

## Engineering standards

Write production-ready code, not code specific to the demo. When we prioritize making the demo work, always add a TODO to make it generic and fix it later.
