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

The BPF tests (`pkg/ebpf`, loading the objects, `BPF_PROG_RUN`, cgroup hooks, network namespaces, bpffs pins) skip without root; CI's `Test` job runs every test binary as root (`go test -exec "sudo -E"`) and fails if the objects don't load. Locally on Linux: `go test -exec "sudo -E" ./pkg/ebpf/`.

The `Kernels` workflow (`.github/workflows/kernels.yml`) runs `pkg/ebpf` on every kernel series still maintained upstream from 5.17 up (the list is read from github.com/cilium/ci-kernels on every run, so nothing to bump on a release), x86 and arm64 (load tests only: GitHub's arm64 runners have no KVM, so the VM is emulated), with and without `BPF_DEBUG`. `TestVerifierBudget` loads each program on its own and fails above 500K verified instructions (half the kernel's limit). It runs on PRs and pushes that change `BPF_PATHS` (`pkg/ebpf/`, `go.mod`/`go.sum`, the workflow), and daily on main; a PR gets a comment (`.github/scripts/kernel-report.py`) with each kernel's result and the verifier costs compared to the base branch's latest run. Require `Kernels / All kernels`, which passes when the kernels were skipped. On another kernel locally (Linux host, `go install lmb.io/vimto@v0.4.0`): `vimto -kernel ghcr.io/cilium/ci-kernels:6.6 -- go test ./pkg/ebpf/` (`.vimto.toml` runs it as root; `VIMTO_DISABLE_KVM=true` without KVM). Those kernels have no clsact or cls_bpf, so the clsact attach tests skip there.

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
  - `Reconciler` (`pkg/controller/reconciler.go`) watches Pods with the **annotation** `getkloak.io/enabled=true` (stamped by the webhook), discovers container cgroup IDs, binds them to the secrets the pod spec references (`k8s.PodSecretRefs` → `TLSUprobeManager.BindPodSecrets`), and calls `TLSUprobeManager.AttachTLS`.
  - `SecretSyncReconciler` (`pkg/controller/secret_sync.go`) calls `TLSUprobeManager.SyncSecrets` when an enabled or shadow Secret is created, changed or deleted, once at start, and every 5 min (`DefaultSecretResyncPeriod`). Every event maps to the same request, so a burst folds into one sync, and a failed sync is retried with backoff.
  - `TLSUprobeManager` (`pkg/ebpf/uprobe.go`, enabled with `--enable-ebpf`) loads the BPF objects, attaches probes per process, syncs secrets into BPF maps (`SyncSecrets`, `pkg/ebpf/sync.go`, fed by a `secrets.Source`), and attaches the tc patch program.
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
2. **Uprobe** (`bpf_uprobe_ssl_write` / `bpf_uprobe_go_tls_write`): prescans the plaintext for `kl::`, and tail-calls `prog_array` slot 1 (`bpf_xor_path`), or slot 2 (`bpf_h_extract`) for processes whose libcrypto `EVP_CipherInit_ex` hook is attached.
3. **`bpf_xor_path`**: for each placeholder found in `secret_map`, checks the per-pod binding (`secret_acl`, keyed by the writer's cgroup and the placeholder key: a pod may only redeem secrets its spec references). On a match it stages `shadow XOR real` in `xor_pending`. On a mismatch nothing is staged and the placeholder goes out unchanged; a binding refusal is also reported on `secret_binding_events` and logged by the controller (`--secret-binding=enforce|audit`).
4. **`tcp_sendmsg` kprobe**: drops patches for secrets restricted to a hostname unless the socket's first ClientHello named that host (`socket_filter_patches`, `sni_state`, `--sni-check=enforce|audit`, spinningfactory/kloak#328), and patches whose secret's host, IP or port restriction the socket does not meet (see virtual IPs below). Refused patches are removed, not zeroed (tc treats `secret_len` 0 as a full-length patch). It then obtains the GHASH key H, either from the libcrypto hook or by walking the library's structs (OpenSSL GCM context; Go `gcmAsm` H×2; BoringSSL has no stored H, so `H = AES_K(0)` is recomputed from the AES key schedule). It moves the patch to `tc_pending`, keyed by (dst IP, src port, cgroup ID), the dst IP being the socket's destination (`sock_dst_addr`: IPv6, or IPv4-mapped). Memory-BIO apps (Node, Bun) can't be matched by write sequence, so tc matches by TLS record framing instead: an `SSL_write` whose BIO holds no fd is a memory-BIO write (`memory_bio`), while Go `crypto/tls` writes each record to its socket within `Write`.
5. **tc** (`tc_egress_patch` → tail call `tc_ghash_update`): attached at **ingress on the host side of the pod's veth** (`attachTCEgress`), so in-pod `CAP_NET_RAW` capture never sees patched ciphertext. It takes IPv4 and IPv6 packets, finds the record carrying the write (segments can coalesce CCS / Finished / several app-data records), XOR-patches the ciphertext, and recomputes the GCM tag. Attach uses TCX on Linux ≥ 6.6, otherwise a clsact qdisc + cls_bpf filter (`--tc-attach-mode=auto|tcx|clsact`, `pkg/ebpf/tc_attach.go`, `tc_mode.go`). A CNI may have its own programs on the same hook (Cilium on the pod's veth): kloak's attach first (TCX head, cls_bpf priority 1), so a CNI redirect cannot hide packets from them, and pass every packet on with `TC_ACT_UNSPEC` (`TCX_NEXT`), never ending the chain. TCX programs run before the clsact chain, which only runs if they return `TCX_NEXT`: on a node where the CNI attaches with TCX (Cilium on Linux ≥ 6.6), kloak must too (`auto` or `tcx`).

Supporting probes: a second `tcp_sendmsg` kprobe (`bpf_kprobe_tcp_sendmsg_sni`) that parses each connection's first handshake record into `sni_state` (keyed by `struct sock *`; parser `tls_parse_sni` in `helpers.h`), the `sock/inet_sock_set_state` tracepoint that clears it on SYN_SENT / CLOSE, `sys_enter/exit_connect` and `sys_enter_close` tracepoints (`conn_ip_map`, which the `SSL_write` uprobe uses to skip server-side connections: their fd was never connected), and `sched_process_exec/exit` (process lifecycle).

Host resolution uses virtual IPs (spinningfactory/kloak#327; it replaced DNS snooping of `udp_recvmsg`, which kept a node-wide IP → host map). The controller gives every watched host a stable fake IP from each range of `--virtual-ip-range` (an IPv4 range and an optional IPv6 one, default `198.18.0.0/15,2001:2::/48`; `planVirtualIPRanges` / `planVirtualIPs` in `pkg/ebpf/virtual_ip.go`), kept in `vip_host_ip` / `vip_ip_host`. `tc_dns_rewrite` (tc ingress on the pod's own interface, inside the pod netns; attached while the container runtime creates the pod's sandbox, which waits for it, through NRI (`NRIPlugin` and `Reconciler.PrepareSandbox` in `pkg/controller`, `--nri-socket`, containerd 2.0+ / CRI-O 1.30+), or without NRI by the pod reconciler as soon as it finds a Pending pod's sandbox process, which leaves a short window before its containers start; `AttachPodDNSRewrite` / `AttachPodDNSRewriteNetns` also return the pod's addresses, read in its netns) replaces the A records of a trusted resolver's answer (over IPv4 or IPv6) for a watched host with its fake IP, and the AAAA records with its fake IPv6 (left unchanged without an IPv6 range), and records the real addresses in `vip_upstream`. It does so only for a pod that references a secret restricted to the host: `vip_pod_host` holds (pod IP, host) pairs derived from the pod bindings (`vipPodHosts`; with `--secret-binding=audit`, every watched host), and other pods keep the real addresses. `vip_connect4` / `vip_connect6` (cgroup connect4/6 on the kubepods cgroup; connect6 also takes the v4-mapped form of a fake IPv4) redirect a connect to a fake IP to one of them, or refuse it (EPERM) when none is known, and record the fake IP's host for the socket (`vip_sock_host`, keyed by socket cookie, dropped when the socket connects elsewhere or closes); `vip_getpeername4/6` report the fake IP back, whatever address a socket load balancer acting after them gave the socket. They also record, for every TCP socket, the address and port it connected to (`vip_sock_dst`): a CNI's socket load balancer on the root cgroup (Cilium's kube-proxy replacement) runs after them and replaces a Service's ClusterIP with a backend's, so IP and port restrictions are checked against that recorded address, as with kube-proxy. Only answers from trusted resolvers are rewritten: kube-dns's ClusterIPs and its endpoints' addresses (where answers come from under socket load balancing), kept current by `TrustedDNSReconciler` (`pkg/controller/trusted_dns.go`), plus `--trusted-dns-servers`. Host attribution is the socket's: the `tcp_sendmsg` kprobe checks a secret's host, IP and port on the socket the record leaves on (`socket_filter_patches`, `vip_socket_check`): the recorded host, the address and port the socket connected to. A connection that did not go through a fake IP gets no host-restricted secret. The DNS walks, upstream slots and the socket check are pure helpers in `helpers.h`. The controller refuses to start if a range overlaps a node address, pod or service CIDR, or node route, IPv4 or IPv6 (`cmd/kloak/virtual_ip.go`). The state maps (`vip_host_ip`, `vip_ip_host`, `vip_upstream`) are pinned under `/sys/fs/bpf/kloak` so a restart keeps them, and their layouts outlive the controller: if one of their structs changes, `prepareVirtualIPPins` drops the old pin and hosts are reallocated.

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
