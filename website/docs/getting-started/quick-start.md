# Quick Start

Protect your first Kubernetes secret with Kloak in under five minutes. By the end of this guide, your application will read harmless placeholder values from its mounted secrets, while the real credentials are injected transparently at the kernel level during TLS transmission.

## What You Will Build

```
                    Your App                         Network
               +--------------+               +----------------+
  Reads from   |              |   TLS write   |                |
  mounted vol  | kloak:a1b2.. | ------------> | REAL-API-KEY   |
               | (shadow)     |   eBPF rewrites in-kernel      |
               +--------------+               +----------------+
```

Your application sees `kloak:a1b2c3d4-...` in its secret files. When it sends that value over a TLS connection, Kloak's eBPF program intercepts the write and substitutes the real secret before it hits the wire. The application never handles the actual credential.

## Prerequisites

- A running Kubernetes cluster with [Kloak installed](./installation.md)
- `kubectl` configured and pointed at your cluster

## Step 1: Enable a Namespace

Kloak's webhook only intercepts pods in namespaces that opt in. Label your target namespace:

```bash
kubectl create namespace kloak-demo
kubectl label namespace kloak-demo getkloak.io/enabled=true
```

::: tip Why namespace-level enablement?
The mutating webhook uses a `namespaceSelector` to limit its scope. Only namespaces with the `getkloak.io/enabled=true` label trigger pod mutation. This prevents Kloak from interfering with system namespaces or workloads that don't need secret protection.
:::

## Step 2: Create a Secret

Create a standard Kubernetes secret and label it for Kloak:

```yaml{7-8}
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-api-credentials
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.example.com"
type: Opaque
stringData:
  api-key: "sk-live-REAL-SECRET-KEY-12345"
```

```bash
kubectl apply -f secret.yaml -n kloak-demo
```

Two things happen when you apply this:

1. Kloak's `SecretReconciler` detects the `getkloak.io/enabled=true` label.
2. It creates a shadow secret called `my-api-credentials-kloak` containing a UUID placeholder (`kloak:<UUID>`) that is length-matched to the original value.

Verify the shadow secret was created:

```bash
kubectl get secrets -n kloak-demo
```

```
NAME                          TYPE     DATA   AGE
my-api-credentials            Opaque   1      10s
my-api-credentials-kloak      Opaque   1      8s
```

Inspect the shadow value:

```bash
kubectl get secret my-api-credentials-kloak -n kloak-demo \
  -o jsonpath='{.data.api-key}' | base64 -d
```

You will see something like `kloak:a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d` -- a harmless placeholder that matches the byte length of your real secret.

## Step 3: Deploy an Application

Create a simple deployment that mounts the secret and sends it in an HTTP header:

```yaml{12-13,24-25}
# app.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo-app
  labels:
    app: demo-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: demo-app
  template:
    metadata:
      labels:
        app: demo-app
      annotations:
        getkloak.io/enabled: "true"
    spec:
      containers:
        - name: app
          image: curlimages/curl:latest
          command:
            - sh
            - -c
            - |
              while true; do
                SECRET=$(cat /etc/secrets/api-key)
                echo "Secret value seen by app: $SECRET"
                echo "---"
                echo "Making HTTPS request to api.example.com..."
                curl -sk -H "Authorization: Bearer $SECRET" \
                  https://httpbin.org/headers
                echo ""
                sleep 10
              done
          volumeMounts:
            - name: api-secret
              mountPath: /etc/secrets
              readOnly: true
      volumes:
        - name: api-secret
          secret:
            secretName: my-api-credentials
```

```bash
kubectl apply -f app.yaml -n kloak-demo
```

::: warning Note the volume reference
The deployment references `secretName: my-api-credentials` (the **original** secret). Kloak's webhook automatically rewrites this to `my-api-credentials-kloak` (the shadow secret) when the pod is created. You never need to change your manifests.
:::

## Step 4: Verify It Works

Wait for the pod to start:

```bash
kubectl rollout status deployment/demo-app -n kloak-demo --timeout=60s
```

Now check the application logs:

```bash
kubectl logs -l app=demo-app -n kloak-demo --tail=30
```

You should see two key things:

**1. The app reads the shadow value (not the real secret):**
```
Secret value seen by app: kloak:a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
```

**2. The HTTPS response from httpbin.org shows the real secret was sent:**
```json
{
  "headers": {
    "Authorization": "Bearer sk-live-REAL-SECRET-KEY-12345",
    "Host": "httpbin.org"
  }
}
```

The application never saw the real secret, but the TLS-encrypted request carried it. Kloak's eBPF uprobe replaced the placeholder with the real value inside the kernel, right before TLS encryption.

## Step 5: Verify Webhook Mutation

Confirm that the pod was mutated to use the shadow secret:

```bash
kubectl get pod -l app=demo-app -n kloak-demo -o jsonpath='{.items[0].spec.volumes}' | jq .
```

```json
[
  {
    "name": "api-secret",
    "secret": {
      "secretName": "my-api-credentials-kloak"
    }
  }
]
```

Notice the `secretName` was changed from `my-api-credentials` to `my-api-credentials-kloak` by the webhook.

## How Host Filtering Works

In Step 2, you added the label `getkloak.io/hosts: "api.example.com"`. This tells Kloak to only replace the placeholder when the TLS connection is headed to `api.example.com`.

If the application tries to send the same placeholder to a different host, Kloak will **not** substitute the real value -- the destination receives the harmless `kloak:...` UUID instead. This prevents secrets from being exfiltrated to unauthorized endpoints.

To allow multiple hosts, use a comma-separated list:

```yaml
labels:
  getkloak.io/hosts: "api.example.com,api.staging.example.com"
```

To allow a secret to be sent to any host, omit the `getkloak.io/hosts` label entirely.

## Clean Up

```bash
kubectl delete namespace kloak-demo
```

## Next Steps

- Learn about all available flags and tuning options in the [Configuration](./configuration.md) guide.
- Read about the [architecture](/architecture/overview) to understand how eBPF uprobes intercept TLS writes.
