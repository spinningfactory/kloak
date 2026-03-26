# Configuration

This page covers all configuration options for the Kloak controller and webhook, namespace and workload enablement, and production resource tuning.

## Controller Flags

The controller runs as a DaemonSet on every node. It manages secret reconciliation, TLS certificate generation, and eBPF uprobe attachment.

| Flag | Default | Description |
|---|---|---|
| `--metrics-bind-address` | `:8080` | Address for the Prometheus metrics endpoint. Set to `0` to disable metrics serving. |
| `--health-probe-bind-address` | `:8081` | Address for health (`/healthz`) and readiness (`/readyz`) probe endpoints. |
| `--leader-elect` | `false` | Enable leader election for the controller manager. Useful when running multiple replicas, though the DaemonSet typically runs one pod per node. |
| `--enable-ebpf` | `false` | Enable eBPF TLS uprobe loading and attachment. Requires Linux with `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and `CAP_SYS_RESOURCE`. |
| `--cgroup-path` | `/sys/fs/cgroup` | Path to the cgroup v2 filesystem. When running in a container with a host mount, this is typically `/host/sys/fs/cgroup`. |
| `--cert-mode` | `auto` | Certificate management mode. See [Certificate Modes](#certificate-modes) below. |

### Certificate Modes

The `--cert-mode` flag controls how TLS certificates for the mutating webhook are provisioned:

**`auto` (default)** -- The controller generates a self-signed RSA-2048 CA and server certificate on startup, stores them in the `kloak-webhook-certs` secret, and patches the `MutatingWebhookConfiguration` with the CA bundle. This is the recommended mode for most deployments.

**`provided`** -- The controller skips certificate generation entirely and expects the `kloak-webhook-certs` secret to already exist in the `kloak-system` namespace. Use this mode when integrating with cert-manager or another certificate provider.

::: tip Using cert-manager
When using `--cert-mode=provided`, create a `Certificate` resource targeting the `kloak-webhook-certs` secret in the `kloak-system` namespace. The secret must contain `tls.crt` and `tls.key` keys. You will also need to manually set the `caBundle` on the `MutatingWebhookConfiguration`, or use cert-manager's `cainjector`.
:::

### Environment Variables

The controller also reads these environment variables (set automatically by the DaemonSet manifest):

| Variable | Description |
|---|---|
| `NODE_NAME` | The Kubernetes node name. Used to filter pod watches so each controller instance only manages pods on its own node. Populated from `spec.nodeName` via the downward API. |
| `POD_NAMESPACE` | The namespace where the controller is running (typically `kloak-system`). Used for locating the webhook certificate secret. Populated from `metadata.namespace` via the downward API. |

## Webhook Flags

The webhook runs as a Deployment and serves the mutating admission endpoint.

| Flag | Default | Description |
|---|---|---|
| `--health-probe-bind-address` | `:8081` | Address for health and readiness probe endpoints. |
| `--cert-dir` | `/certs` | Directory containing the TLS certificate and key files (`tls.crt`, `tls.key`). Mounted from the `kloak-webhook-certs` secret. |

The webhook listens on port `9443` for admission requests. The `Service` fronting the webhook maps port `443` to this target port.

## Enablement Model

Kloak uses a layered opt-in model. Nothing is intercepted unless explicitly enabled.

### Secret Enablement

Label any secret to have Kloak create a shadow copy:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-secret
  labels:
    getkloak.io/enabled: "true"      # Required: triggers shadow secret creation
    getkloak.io/hosts: "api.example.com"  # Optional: restrict allowed destinations
type: Opaque
stringData:
  token: "my-real-token-value"
```

When the `SecretReconciler` detects this label, it creates `my-secret-kloak` with UUID placeholders length-matched to each key's value.

### Namespace Enablement

Label a namespace to activate webhook interception for all pods created in it:

```bash
kubectl label namespace my-namespace getkloak.io/enabled=true
```

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
  labels:
    getkloak.io/enabled: "true"
```

::: warning Required for webhook activation
The `MutatingWebhookConfiguration` uses a `namespaceSelector` with `getkloak.io/enabled: "true"`. Pods in unlabeled namespaces will **not** be intercepted by the webhook, even if the pod itself has the annotation.
:::

### Pod Enablement

Annotate individual pods (or their parent Deployment/StatefulSet/DaemonSet templates) to enable secret rewriting:

```yaml{6-7}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    metadata:
      annotations:
        getkloak.io/enabled: "true"
    spec:
      containers:
        - name: app
          # ...
```

### Enablement Inheritance

The webhook checks enablement in the following order, stopping at the first match:

1. **Pod annotation** -- `getkloak.io/enabled: "true"` on the pod itself.
2. **Namespace label** -- `getkloak.io/enabled: "true"` on the pod's namespace.
3. **Owner workload labels** -- The webhook follows the pod's `ownerReferences` chain (Pod -> ReplicaSet -> Deployment) and checks for `getkloak.io/enabled: "true"` on the owning workload.

If none of these are set to `"true"`, the pod passes through without mutation.

### Host Filtering

The `getkloak.io/hosts` label on a secret controls which TLS destinations receive the real value:

```yaml
labels:
  getkloak.io/hosts: "api.example.com"                    # Single host
  getkloak.io/hosts: "api.example.com,cdn.example.com"    # Multiple hosts
```

When a TLS write is intercepted, the eBPF program resolves the destination hostname via the DNS-verified trust chain (DNS capture → connection tracking → host resolution). If the resolved hostname does not match the allowed hosts list, the placeholder is **not** replaced -- the remote server receives the harmless `kloak:...` UUID. See the [Host Filtering guide](/guides/host-filtering) for details.

Omitting `getkloak.io/hosts` allows the secret to be sent to any destination.

## Resource Limits

### Default Resources (Base Manifests)

The base manifests include conservative resource defaults suitable for development and testing:

**Controller (DaemonSet):**
```yaml
resources:
  requests:
    cpu: 10m
    memory: 64Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

**Webhook (Deployment):**
```yaml
resources:
  requests:
    cpu: 10m
    memory: 64Mi
  limits:
    cpu: 500m
    memory: 128Mi
```

### Production Resources

The production overlay (`config/overlays/prod`) increases the controller's resource allocation:

**Controller (Production):**
```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: "1"
    memory: 512Mi
```

::: tip Sizing for your workload
The controller's memory usage scales with the number of secrets being tracked and the number of pods being monitored on each node. For clusters with hundreds of secrets, consider increasing the memory limit to `1Gi`. The eBPF programs themselves have minimal overhead once loaded.
:::

### Custom Resource Overrides

Create a Kustomize overlay to set your own resource limits:

```yaml
# my-overlay/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - https://github.com/getkloak/kloak/config/overlays/prod

patches:
  - patch: |-
      - op: replace
        path: /spec/template/spec/containers/0/resources
        value:
          limits:
            cpu: "2"
            memory: 1Gi
          requests:
            cpu: 250m
            memory: 256Mi
    target:
      kind: DaemonSet
      name: kloak-controller
```

## Ports Reference

| Component | Port | Purpose |
|---|---|---|
| Controller | 8080 | Prometheus metrics |
| Controller | 8081 | Health and readiness probes |
| Controller | 8090 | HTTP secret store (internal) |
| Controller | 9090 | gRPC sync (internal) |
| Webhook | 8081 | Health and readiness probes |
| Webhook | 9443 | Admission webhook endpoint (TLS) |

## Security Context

The controller requires elevated privileges for eBPF operations. The manifest sets:

```yaml
securityContext:
  privileged: true
  runAsUser: 0
  runAsGroup: 0
  appArmorProfile:
    type: Unconfined
  capabilities:
    add:
      - BPF
      - NET_ADMIN
      - SYS_ADMIN
      - SYS_RESOURCE
```

The controller also requires `hostPID: true` at the pod level to access container process cgroups and attach uprobes via `/proc/<pid>/maps`.

The webhook does **not** require any elevated privileges and runs with default security settings.

## Volume Mounts (Controller)

The controller DaemonSet mounts three host paths:

| Mount Path | Host Path | Access | Purpose |
|---|---|---|---|
| `/host/sys/fs/cgroup` | `/sys/fs/cgroup` | Read-write | Cgroup v2 filesystem for resolving container cgroup IDs |
| `/sys/fs/bpf` | `/sys/fs/bpf` | Read-write | BPF filesystem for pinning eBPF maps and programs |
| `/sys/kernel/btf` | `/sys/kernel/btf` | Read-only | Kernel BTF (BPF Type Format) data for CO-RE (Compile Once, Run Everywhere) |
