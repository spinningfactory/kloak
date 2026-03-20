# Installation

This guide walks you through deploying Kloak into your Kubernetes cluster. The entire process takes about two minutes.

## Prerequisites

Before installing Kloak, make sure your environment meets the following requirements:

| Requirement | Minimum Version | Notes |
|---|---|---|
| Kubernetes | 1.28+ | Any conformant distribution (EKS, GKE, AKS, k3s, etc.) |
| Linux kernel | 5.17+ | Required on worker nodes for `bpf_loop` support |
| kubectl | 1.28+ | Configured with cluster access |
| cgroup v2 | Enabled | Most modern distributions enable this by default |

::: tip Checking your kernel version
Run the following on your worker nodes to verify kernel compatibility:
```bash
uname -r
```
The output should show `5.17` or higher (e.g., `6.1.0-18-amd64`).
:::

::: warning eBPF requires privileged access
The Kloak controller runs as a privileged DaemonSet with `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, and `CAP_SYS_RESOURCE`. This is required to load eBPF programs and attach uprobes to container processes. Review the [RBAC manifests](https://github.com/getkloak/kloak/blob/main/config/manifests/rbac.yaml) to understand the exact permissions granted.
:::

## Deploy with Kustomize

Kloak ships with production-ready Kustomize overlays. Deploy the entire stack (namespace, RBAC, controller DaemonSet, webhook Deployment) in a single command:

```bash
kubectl apply -k https://github.com/getkloak/kloak/config/overlays/prod
```

This creates the `kloak-system` namespace and deploys two components:

- **kloak-controller** -- A DaemonSet that runs on every node. It watches secrets, creates shadow copies, manages TLS certificates for the webhook, and loads eBPF programs to intercept TLS writes.
- **kloak-webhook** -- A Deployment that runs the mutating admission webhook. It intercepts pod creation and rewrites secret volume references to point to Kloak shadow secrets.

## Verify the Installation

Check that all Kloak pods are running:

```bash
kubectl get pods -n kloak-system
```

You should see output similar to:

```
NAME                             READY   STATUS    RESTARTS   AGE
kloak-controller-abcde           1/1     Running   0          45s
kloak-webhook-6f7b8c9d10-xyz12   1/1     Running   0          40s
```

Wait for both pods to reach `Running` status. The webhook pod has an init container that waits for the controller to generate TLS certificates, so it may take a few extra seconds.

You can also verify the components are healthy with rollout status:

```bash
kubectl rollout status daemonset/kloak-controller -n kloak-system --timeout=120s
kubectl rollout status deployment/kloak-webhook -n kloak-system --timeout=120s
```

### Verify the Webhook

Confirm that the mutating webhook configuration was created and has a valid CA bundle:

```bash
kubectl get mutatingwebhookconfiguration kloak-mutating-webhook
```

The controller automatically generates TLS certificates and patches the webhook's `caBundle` field on startup. No manual certificate management is needed.

## Customizing the Image

The production overlay defaults to `ghcr.io/your-org/kloak:v1.0.0`. To use your own registry or tag, create a custom Kustomize overlay:

```yaml
# my-overlay/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - https://github.com/getkloak/kloak/config/overlays/prod

images:
  - name: ghcr.io/your-org/kloak
    newName: your-registry.example.com/kloak
    newTag: v1.2.3
```

Then deploy with:

```bash
kubectl apply -k my-overlay/
```

## Uninstall

To remove Kloak and all its resources from your cluster:

```bash
kubectl delete -k https://github.com/getkloak/kloak/config/overlays/prod
```

This removes the controller, webhook, RBAC roles, and the `kloak-system` namespace. Shadow secrets created by Kloak in application namespaces are **not** automatically deleted. To clean those up:

```bash
kubectl delete secrets -l getkloak.io/managed=true --all-namespaces
```

::: warning
Removing Kloak while applications are running means pods will continue to see the shadow secret values (`kloak:<UUID>` placeholders) until they are restarted with the original secrets. Plan your rollback accordingly.
:::

## Next Steps

- Follow the [Quick Start](./quick-start.md) to protect your first secret in under five minutes.
- Review [Configuration](./configuration.md) for controller and webhook tuning options.
