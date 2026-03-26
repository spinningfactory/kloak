# Protecting Secrets with Kloak

This guide walks you through protecting your first Kubernetes Secret with Kloak. By the end, your application will never see actual secret values -- it will only see harmless `kloak:<UUID>` placeholders that get replaced with real values in-kernel by eBPF, just before TLS transmission.

## How It Works

When you label a Secret with `getkloak.io/enabled=true`, Kloak's SecretReconciler automatically:

1. Creates a **shadow secret** named `<original>-kloak` containing `kloak:<UUID>` placeholder values
2. Length-matches each placeholder to the original value (padding or truncating as needed)
3. Stores the UUID-to-real-value mapping in an in-memory store synced to the eBPF map

Your application mounts and reads the shadow secret -- it only ever sees the UUID placeholders. When the application writes data over TLS, the eBPF uprobe intercepts the write, scans for known `kloak:` prefixes, and rewrites them with the real secret values before the encrypted payload leaves the kernel.

## Step 1: Label Your Secret

Start with a standard Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: api-credentials
  labels:
    getkloak.io/enabled: "true"        # Enable Kloak protection
    getkloak.io/hosts: "api.stripe.com" # Optional: restrict to specific hosts
type: Opaque
data:
  api-key: c2stbGl2ZS1rZXktMTIzNDU2Nzg5MA==  # sk-live-key-1234567890
```

Apply it:

```bash
kubectl apply -f secret.yaml -n my-app
```

Within seconds, Kloak creates a shadow secret:

```bash
$ kubectl get secrets -n my-app
NAME                   TYPE     DATA   AGE
api-credentials        Opaque   1      5s
api-credentials-kloak  Opaque   1      5s
```

Inspect the shadow secret to see the placeholder:

```bash
$ kubectl get secret api-credentials-kloak -n my-app -o jsonpath='{.data.api-key}' | base64 -d
kloak:a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

::: tip
The shadow secret has an `OwnerReference` pointing to the original. If you delete the original secret, Kubernetes garbage collection automatically cleans up the shadow.
:::

::: warning
Secret values must be at least 8 bytes long (the length of `kloak:` plus 2 UUID characters). Shorter values cannot be reliably intercepted by the eBPF program.
:::

## Step 2: Enable Kloak on Your Pod

Kloak needs to know which pods should have eBPF uprobes attached. You have three options, checked in this order:

### Option A: Pod Annotation (Most Specific)

```yaml
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
          image: my-app:latest
          volumeMounts:
            - name: api-creds
              mountPath: /etc/secrets/api
              readOnly: true
      volumes:
        - name: api-creds
          secret:
            secretName: api-credentials  # Reference the ORIGINAL secret name
```

### Option B: Namespace Label (Enables All Pods in Namespace)

```bash
kubectl label namespace my-app getkloak.io/enabled=true
```

When a namespace is labeled, every pod created in that namespace is automatically processed by Kloak -- no per-pod annotations needed.

### Option C: Workload Label (Deployment, DaemonSet, StatefulSet)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    getkloak.io/enabled: "true"  # All pods from this Deployment get Kloak
```

Kloak follows the owner reference chain: Pod -> ReplicaSet -> Deployment. If any level has the label or annotation, the pod is enabled.

::: tip
Always reference the **original** secret name in your volume definition, not the shadow. The webhook automatically rewrites the volume to mount the shadow secret instead.
:::

## Step 3: How the Webhook Mutates Your Pod

When a pod is created in a namespace labeled with `getkloak.io/enabled=true`, the Kloak mutating webhook intercepts the admission request and:

1. Checks if Kloak is enabled (pod annotation, namespace label, or workload label)
2. Scans all Secret volumes in the pod spec
3. For each secret that has `getkloak.io/enabled=true`, rewrites `secretName` from `api-credentials` to `api-credentials-kloak`
4. Adds the `getkloak.io/enabled: "true"` annotation to the pod (so the controller can detect it)

You can verify the mutation worked:

```bash
# Check the pod annotation
$ kubectl get pod -l app=my-app -n my-app -o jsonpath='{.items[0].metadata.annotations.getkloak\.io/enabled}'
true

# Check which secret is actually mounted
$ kubectl get pod -l app=my-app -n my-app -o jsonpath='{.items[0].spec.volumes[0].secret.secretName}'
api-credentials-kloak
```

## Step 4: Verify the eBPF Rewrite

The best way to verify Kloak is working is to send a request to an echo service like [httpbin.org](https://httpbin.org) that reflects your headers back:

### Create the Secret

```bash
kubectl create secret generic api-credentials \
    --from-literal=api-key="sk-live-key-1234567890" \
    -n my-app --dry-run=client -o yaml | \
    kubectl label -f - getkloak.io/enabled="true" getkloak.io/hosts="httpbin.org" --local -o yaml | \
    kubectl apply -f -
```

### Deploy a Test App

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: curl-test
  namespace: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: curl-test
  template:
    metadata:
      labels:
        app: curl-test
      annotations:
        getkloak.io/enabled: "true"
    spec:
      containers:
        - name: curl
          image: curlimages/curl:latest
          command: ["sh", "-c"]
          args:
            - |
              while true; do
                SECRET=$(cat /etc/secrets/api/api-key)
                echo "App sees: $SECRET"
                echo "---"
                curl -s https://httpbin.org/headers \
                  -H "X-Api-Key: $SECRET" | python3 -m json.tool
                echo "---"
                sleep 10
              done
          volumeMounts:
            - name: api-creds
              mountPath: /etc/secrets/api
              readOnly: true
      volumes:
        - name: api-creds
          secret:
            secretName: api-credentials
```

### Check the Logs

```bash
kubectl logs -l app=curl-test -n my-app
```

You should see output like:

```
App sees: kloak:a1b2c3d4-e5f6-7890-abcd-ef1234567890
---
{
  "headers": {
    "Host": "httpbin.org",
    "X-Api-Key": "sk-live-key-1234567890"
  }
}
---
```

The application reads `kloak:a1b2c3d4-...` from the mounted secret, but httpbin.org receives `sk-live-key-1234567890` -- the real value was substituted in-kernel by the eBPF uprobe before TLS encryption.

::: danger
If you see the `kloak:` UUID in the httpbin response, the eBPF rewrite did not trigger. Common causes:
- The controller pod is not running or not ready on the node
- The eBPF map has not synced yet (wait 10-15 seconds after pod startup)
- The secret value is shorter than 8 bytes
- The DNS resolution for the target host was not captured (check controller logs for DNS debug counters)
:::

## What Happens Under the Hood

Here is the complete lifecycle of a protected secret:

```
1. You create Secret with getkloak.io/enabled=true
   │
2. SecretReconciler creates shadow secret (api-credentials-kloak)
   │  Each value: "kloak:<UUID>" padded to match original length
   │  Mapping stored: UUID → real value + allowed hosts
   │
3. Pod is created referencing the original secret
   │
4. Webhook intercepts admission, rewrites volume: api-credentials → api-credentials-kloak
   │
5. Pod starts, reads shadow secret → sees "kloak:a1b2c3d4-..."
   │
6. Controller detects pod, finds PID via cgroup, attaches eBPF uprobes
   │
7. App calls SSL_write() / tls.Conn.Write() with data containing "kloak:..."
   │
8. eBPF uprobe fires:
   ├─ Phase 1: Scans TLS write buffer for "kloak:" prefix (8-byte key lookup)
   └─ Phase 2 (tail call): Verifies full prefix, checks host filter, rewrites in-place
   │
9. Real secret value leaves the kernel encrypted via TLS
   └─ The application process never had access to the real value
```

## Updating Secrets

When you update the original secret, Kloak automatically:

1. Detects the change via the SecretReconciler watch
2. Reuses existing UUIDs where possible (to keep shadow values stable)
3. Generates new UUIDs for new keys or length-changed values
4. Updates the shadow secret and the in-memory storage
5. Syncs the new mappings to the eBPF map (within 5 seconds)

No pod restart is required -- the eBPF map is updated live.

::: tip
Shadow secrets preserve UUIDs across updates when the value length stays the same. This means your application does not see a "change" in the mounted file unless a key is added, removed, or its length changes.
:::

## Cleaning Up

To stop protecting a secret, remove the label:

```bash
kubectl label secret api-credentials getkloak.io/enabled- -n my-app
```

The SecretReconciler will automatically delete the shadow secret and clean up the storage mappings. Running pods will continue to see the old shadow values until restarted.
