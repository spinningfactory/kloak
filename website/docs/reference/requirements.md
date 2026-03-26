# System Requirements

Kloak uses eBPF uprobes with advanced features that require specific kernel and Kubernetes versions. This page details the minimum requirements and tested configurations.

## Kernel Requirements

### Minimum: Linux 5.17+

Kloak requires Linux kernel **5.17 or later**. The hard dependency is the `bpf_loop` helper function, which was introduced in kernel 5.17. This helper is used in the eBPF rewrite program to iterate over the TLS write buffer scanning for `kloak:` prefixes.

::: danger
Kernels older than 5.17 will fail to load the eBPF programs. The controller will log a verifier error and the pod reconciler will not be able to attach uprobes.
:::

### Recommended: Linux 6.1+

Kernel **6.1+** is recommended for production use. Kloak has been tested most extensively on 6.1+ kernels, which include:

- Improved BPF verifier performance and memory limits
- Better BTF (BPF Type Format) support
- Ring buffer reliability improvements
- Stable uprobe behavior across process lifecycle

### Required Kernel Features

The following kernel configuration options must be enabled (they are enabled by default on all major distributions):

| Config Option | Purpose |
|---|---|
| `CONFIG_BPF` | Base BPF support |
| `CONFIG_BPF_SYSCALL` | BPF system call |
| `CONFIG_BPF_JIT` | JIT compilation for BPF programs |
| `CONFIG_UPROBES` | User-space probes (uprobe attachment) |
| `CONFIG_KPROBES` | Kernel probes (kprobe on `udp_recvmsg` for DNS capture) |
| `CONFIG_TRACEPOINTS` | Tracepoints (connect/close tracking) |
| `CONFIG_BPF_EVENTS` | BPF-based event tracing |
| `CONFIG_DEBUG_INFO_BTF` | BTF type information for CO-RE |

Verify BTF availability on a node:

```bash
ls /sys/kernel/btf/vmlinux
```

If the file exists, BTF is available and Kloak can use CO-RE (Compile Once, Run Everywhere) to adapt to the running kernel.

## Kubernetes Requirements

### Minimum: Kubernetes 1.28+

Kloak requires Kubernetes **1.28 or later**. Key dependencies:

- **Mutating Admission Webhooks v1** -- stable since Kubernetes 1.16, but Kloak uses `admissionReviewVersions: ["v1"]` features stabilized in later versions
- **Namespace selectors on webhooks** -- used to target only `getkloak.io/enabled=true` namespaces
- **Pod Security Standards** -- Kloak's controller DaemonSet requires `privileged` security context, which is properly supported in 1.28+

### RBAC Requirements

The Kloak controller service account requires the following cluster-level permissions:

```yaml
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["mutatingwebhookconfigurations"]
  verbs: ["get", "update", "patch"]
```

## Supported Linux Distributions

### Fully Tested

| Distribution | Kernel Version | Status | Notes |
|---|---|---|---|
| Ubuntu 22.04 LTS (HWE kernel) | 5.19 - 6.5 | Tested | HWE kernel required (default 5.15 is too old) |
| Ubuntu 24.04 LTS | 6.8+ | Tested | Works out of the box |
| Amazon Linux 2023 | 6.1+ | Tested | Default kernel is compatible |
| K3s on Ubuntu | 5.17+ | Tested | Used in development and CI |

### Expected to Work

| Distribution | Kernel Version | Status | Notes |
|---|---|---|---|
| Debian 12 (Bookworm) | 6.1 | Expected | Default kernel meets requirements |
| Fedora 38+ | 6.2+ | Expected | Modern kernels |
| Arch Linux | Rolling (6.x) | Expected | Always current |
| RHEL 9.2+ | 5.14 (with backports) | Verify | May have `bpf_loop` backported; test before production |
| Rocky Linux 9.2+ | 5.14 (with backports) | Verify | Same kernel as RHEL |

::: warning
**Ubuntu 22.04 default kernel (5.15) is NOT compatible.** You must install the HWE (Hardware Enablement) kernel:
```bash
sudo apt install linux-generic-hwe-22.04
```
This upgrades to kernel 5.19+ which includes `bpf_loop`.
:::

::: warning
**RHEL/Rocky 9.x kernels report as 5.14** but may include backported BPF features. Test `bpf_loop` availability before deploying:
```bash
# Check if bpf_loop is available
bpftool feature probe kernel | grep bpf_loop
```
:::

## Cloud Provider Notes

### Amazon EKS

| EKS Version | Node AMI | Kernel | Status |
|---|---|---|---|
| 1.28+ | Amazon Linux 2023 AMI | 6.1+ | Supported |
| 1.28+ | Amazon Linux 2 AMI | 5.10 | Not supported (kernel too old) |
| 1.28+ | Bottlerocket | 5.15 - 6.1 | Verify kernel version |
| 1.28+ | Ubuntu 22.04 EKS AMI | 5.15 | Not supported without HWE |
| 1.28+ | Ubuntu 24.04 EKS AMI | 6.8 | Supported |

::: tip
For EKS, use the **Amazon Linux 2023** node AMI. It ships with kernel 6.1+ and includes full BTF support. Amazon Linux 2 uses kernel 5.10 which is too old.
:::

**EKS-specific configuration:**
- EKS manages the control plane, so the webhook configuration must reference the in-cluster service
- Security groups must allow traffic on port 443 from the API server to the webhook service
- If using managed node groups, ensure the AMI includes BTF (`/sys/kernel/btf/vmlinux`)

### Google GKE

| GKE Channel | Node OS | Kernel | Status |
|---|---|---|---|
| Regular/Stable | Container-Optimized OS (COS) | 5.15 - 6.1 | Verify kernel version |
| Rapid | Container-Optimized OS (COS) | 6.1+ | Likely supported |
| Any | Ubuntu node images | 5.15 - 6.8 | Depends on image version |

::: warning
**GKE with COS:** Container-Optimized OS may not include full BTF support in older versions. Check `/sys/kernel/btf/vmlinux` on a node. Consider using Ubuntu-based node images for guaranteed compatibility.
:::

**GKE-specific notes:**
- GKE Autopilot does **not** support privileged DaemonSets, which Kloak requires. Use GKE Standard.
- If using Workload Identity, ensure the controller service account has no restrictive policies blocking eBPF syscalls.

### Azure AKS

| AKS Version | Node OS | Kernel | Status |
|---|---|---|---|
| 1.28+ | Ubuntu 22.04 | 5.15 | Not supported without HWE |
| 1.28+ | Azure Linux (Mariner) | 5.15 - 6.2 | Verify kernel version |
| 1.28+ | Ubuntu 24.04 (preview) | 6.8 | Supported |

::: tip
AKS node images are updated frequently. Check the kernel version on your nodes:
```bash
kubectl get nodes -o wide  # Check KERNEL-VERSION column
```
:::

**AKS-specific notes:**
- Azure Linux (formerly CBL-Mariner) ships kernel 5.15 by default in some versions. Verify `bpf_loop` availability.
- AKS with Kata Containers / confidential nodes: not supported (nested BPF).

## Resource Requirements

### Controller DaemonSet (per node)

| Resource | Request | Limit | Notes |
|---|---|---|---|
| CPU | 10m | 500m | eBPF attachment is CPU-light; reconciliation is the main consumer |
| Memory | 64Mi | 512Mi | BPF maps + in-memory secret store |

### Webhook Deployment

| Resource | Request | Limit | Notes |
|---|---|---|---|
| CPU | 10m | 500m | Admission requests are fast (JSON patch generation) |
| Memory | 64Mi | 128Mi | Stateless; only caches Kubernetes client objects |

### Kernel Resources

| Resource | Size | Notes |
|---|---|---|
| BPF map: `secret_map` | Scales with number of secrets | ~212 bytes per entry (8B key + 204B value) |
| BPF map: `dns_ip_map` | Scales with resolved DNS entries | LRU, max 1024 entries |
| BPF map: `conn_ip_map` | Scales with active TCP connections | ~24 bytes per entry |
| BPF map: `watched_hosts` | Scales with unique host filters | ~36 bytes per entry |
| Ring buffer: `tls_events` | Fixed size (configurable) | Default 256KB |
| eBPF programs | ~80KB total | Two TLS programs (phase 1 + phase 2) + DNS kprobe + connect/close tracepoints |

## Verification Checklist

Run these checks on a node to verify Kloak compatibility:

```bash
# 1. Kernel version (must be 5.17+)
uname -r

# 2. BTF availability
ls -la /sys/kernel/btf/vmlinux

# 3. BPF filesystem
mount | grep bpf

# 4. bpf_loop support
bpftool feature probe kernel 2>/dev/null | grep bpf_loop || \
  echo "bpftool not available; check kernel version >= 5.17"

# 5. Uprobe support
ls /sys/kernel/debug/tracing/uprobe_events 2>/dev/null && \
  echo "Uprobes available" || echo "Uprobes not available (check CONFIG_UPROBES)"
```

::: tip
If `bpftool` is not installed, the simplest check is the kernel version: any 5.17+ kernel from a major distribution will have all required features enabled.
:::
