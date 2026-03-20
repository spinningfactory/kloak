# Labels and Annotations Reference

Kloak uses Kubernetes labels and annotations to control which secrets are protected, which pods are intercepted, and which hosts are allowed for secret transmission.

## Overview

| Name | Type | Applies To | Description |
|---|---|---|---|
| `getkloak.io/enabled` | Label | Secret | Enables Kloak protection for this secret. Triggers shadow secret creation. |
| `getkloak.io/enabled` | Annotation | Secret | Alternative to label. Enables Kloak protection for this secret. |
| `getkloak.io/enabled` | Annotation | Pod | Enables eBPF uprobe attachment for this pod. Set explicitly or injected by webhook. |
| `getkloak.io/enabled` | Label | Namespace | Enables Kloak for all pods in this namespace. The webhook only processes pods in labeled namespaces. |
| `getkloak.io/enabled` | Label or Annotation | Deployment, DaemonSet, StatefulSet | Enables Kloak for all pods owned by this workload. |
| `getkloak.io/hosts` | Label | Secret | Comma-separated list of allowed TLS destination hostnames. |
| `getkloak.io/managed` | Label | Secret (shadow) | Automatically set by Kloak on shadow secrets. Do not set manually. |
| `getkloak.io/owner` | Label | Secret (shadow) | Name of the original secret. Automatically set by Kloak. Do not set manually. |

## Detailed Reference

### `getkloak.io/enabled`

Controls whether Kloak processes a resource. The value must be exactly `"true"` (string).

#### On Secrets (Label or Annotation)

When set on a Secret, the SecretReconciler:

1. Creates a shadow secret named `<secret-name>-kloak` with `kloak:<UUID>` placeholder values
2. Stores the UUID-to-real-value mapping in the in-memory store
3. Sets up an `OwnerReference` so the shadow is garbage collected when the original is deleted

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-api-key
  labels:
    getkloak.io/enabled: "true"
type: Opaque
data:
  key: bXktc2VjcmV0LXZhbHVl
```

::: tip
Both labels and annotations are checked (`secret.Labels["getkloak.io/enabled"] == "true" || secret.Annotations["getkloak.io/enabled"] == "true"`). Use labels for consistency with the other Kloak resources.
:::

To disable protection, remove the label:

```bash
kubectl label secret my-api-key getkloak.io/enabled- -n my-namespace
```

The shadow secret will be automatically deleted and storage mappings cleaned up.

#### On Pods (Annotation)

When set on a Pod, the controller's Pod Reconciler:

1. Detects the pod on the local node
2. Resolves the container PID via cgroup
3. Attaches eBPF TLS uprobes to the process

```yaml
metadata:
  annotations:
    getkloak.io/enabled: "true"
```

::: warning
You typically do not need to set this annotation manually. The webhook automatically injects it when it mutates a pod. Set it explicitly only if you want to bypass the webhook's enablement check logic.
:::

#### On Namespaces (Label)

When set on a Namespace, two things happen:

1. **Webhook activation:** The `MutatingWebhookConfiguration` has a `namespaceSelector` that only matches namespaces with this label. Pods in unlabeled namespaces are never processed by the webhook.

2. **Inheritance:** All pods created in this namespace are treated as Kloak-enabled, even without an explicit pod annotation. The webhook checks the namespace label as a fallback.

```bash
kubectl label namespace my-app getkloak.io/enabled=true
```

::: danger
Labeling a namespace enables Kloak for **every** pod in that namespace. Make sure all applications in the namespace are compatible (see [Supported Runtimes](../guides/supported-runtimes.md)). Pods using unsupported TLS stacks will fail to have uprobes attached, which is logged as an error but does not block the pod.
:::

#### On Workloads (Label or Annotation)

When set on a Deployment, DaemonSet, or StatefulSet, the webhook follows the owner reference chain to determine enablement:

```
Pod → ReplicaSet → Deployment    (label or annotation checked at each level)
Pod → DaemonSet                  (label or annotation checked)
Pod → StatefulSet                (label or annotation checked)
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    getkloak.io/enabled: "true"  # All pods from this Deployment get Kloak
```

### `getkloak.io/hosts`

Restricts which TLS destination hostnames are allowed to receive the real secret value. Applied as a **label** on Secrets.

**Type:** Label
**Applies to:** Secret
**Format:** Comma-separated hostnames (no wildcards, no ports)

```yaml
metadata:
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.stripe.com"
```

Multiple hosts:

```yaml
metadata:
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.stripe.com,dashboard.stripe.com"
```

**Behavior:**
- If the label is **present**: only connections to the specified hostname(s) receive the real value. All other destinations see the `kloak:<UUID>` placeholder.
- If the label is **absent** or empty: the secret is allowed for all destinations (wildcard).

::: warning
Currently, only the first hostname in the comma-separated list is enforced in the eBPF map. This is due to the single `AllowedHost` field in the BPF value struct. Support for multiple hosts per secret entry is planned.
:::

::: tip
Hostnames are matched exactly (case-sensitive, no wildcards). Use the exact hostname your application connects to. For example, use `api.stripe.com`, not `*.stripe.com` or `stripe.com`.
:::

**Hostname length limit:** 32 characters. Hostnames longer than 32 characters are truncated in the BPF map.

### `getkloak.io/managed`

Automatically applied by Kloak to shadow secrets. Indicates that the secret is managed by Kloak and should not be manually edited.

**Type:** Label
**Applies to:** Secret (shadow)
**Value:** `"true"`

```yaml
# Automatically set -- do not create manually
metadata:
  name: my-api-key-kloak
  labels:
    getkloak.io/managed: "true"
    getkloak.io/owner: "my-api-key"
```

::: danger
Do not manually create or modify secrets with `getkloak.io/managed=true`. They are fully managed by the SecretReconciler and will be overwritten on the next reconciliation cycle.
:::

### `getkloak.io/owner`

Automatically applied by Kloak to shadow secrets. Contains the name of the original secret that this shadow was created from.

**Type:** Label
**Applies to:** Secret (shadow)
**Value:** Name of the original secret

This label is informational and used for operational visibility (e.g., listing which shadow secrets exist for a given original).

## Enablement Precedence

The webhook checks for enablement in the following order. The first match wins:

1. **Pod annotation** `getkloak.io/enabled: "true"` -- most specific
2. **Namespace label** `getkloak.io/enabled: "true"` -- applies to all pods in namespace
3. **Owner workload** label or annotation -- follows ReplicaSet -> Deployment chain
4. If none match, the pod is **not** processed by Kloak

```
Pod annotation?  ──yes──▶  Enabled
       │ no
       ▼
Namespace label? ──yes──▶  Enabled
       │ no
       ▼
Owner workload?  ──yes──▶  Enabled
       │ no
       ▼
                           Not enabled
```

## Quick Reference

### Enable Kloak for a secret:
```bash
kubectl label secret my-secret getkloak.io/enabled=true -n my-namespace
```

### Enable Kloak for a namespace:
```bash
kubectl label namespace my-namespace getkloak.io/enabled=true
```

### Add host filtering:
```bash
kubectl label secret my-secret getkloak.io/hosts=api.stripe.com -n my-namespace
```

### Disable Kloak for a secret:
```bash
kubectl label secret my-secret getkloak.io/enabled- -n my-namespace
```

### Check if a pod was mutated:
```bash
kubectl get pod <pod-name> -n my-namespace -o jsonpath='{.metadata.annotations.getkloak\.io/enabled}'
```

### List all shadow secrets:
```bash
kubectl get secrets -l getkloak.io/managed=true --all-namespaces
```

### Find the shadow for a specific secret:
```bash
kubectl get secrets -l getkloak.io/owner=my-secret -n my-namespace
```
