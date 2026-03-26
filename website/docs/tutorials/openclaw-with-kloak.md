# Deploy OpenClaw with Kloak

This tutorial walks you through deploying [OpenClaw](https://github.com/openclaw/openclaw) on Kubernetes with all LLM API keys protected by Kloak. By the end, your OpenClaw instance will have zero knowledge of your real API keys -- they exist only in eBPF kernel memory and are injected transparently at the TLS boundary.

## What You Will Build

```
OpenClaw Pod                          LLM Providers
+-------------------------+
| Gateway Container       |
|                         |     TLS write          +------------------+
| ANTHROPIC_API_KEY=      |  ------------------>   | api.anthropic.com|
|   kloak:a1b2c3d4-...   |  eBPF rewrites with    | (real key sent)  |
|                         |  real key in-kernel     +------------------+
| OPENAI_API_KEY=         |  ------------------>   +------------------+
|   kloak:e5f6a7b8-...   |                        | api.openai.com   |
|                         |                        | (real key sent)  |
+-------------------------+                        +------------------+
```

Your OpenClaw gateway reads `kloak:<UUID>` placeholders from its environment. When it makes API calls to Anthropic, OpenAI, or other providers, Kloak's eBPF uprobe intercepts the TLS write and substitutes the real keys -- scoped to the correct provider host.

## Prerequisites

- A running Kubernetes cluster (1.28+, Linux kernel 5.17+) with [Kloak installed](/getting-started/installation)
- `kubectl` configured and pointed at your cluster
- API keys for at least one LLM provider (Anthropic, OpenAI, or Google Gemini)

## Step 1: Create the Namespace

Create a namespace for OpenClaw and enable Kloak:

```bash
kubectl create namespace openclaw
kubectl label namespace openclaw getkloak.io/enabled=true
```

## Step 2: Create Kloak-Protected Secrets

Create separate secrets for each LLM provider, each with a host filter that restricts where the key can be sent. This is the key security property -- even if OpenClaw is compromised, each API key can only be sent to its intended provider.

### Anthropic API Key

```yaml
# anthropic-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: anthropic-api-key
  namespace: openclaw
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.anthropic.com"
type: Opaque
stringData:
  ANTHROPIC_API_KEY: "sk-ant-your-real-anthropic-key-here"
```

### OpenAI API Key

```yaml
# openai-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: openai-api-key
  namespace: openclaw
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.openai.com"
type: Opaque
stringData:
  OPENAI_API_KEY: "sk-your-real-openai-key-here"
```

### Google Gemini API Key (optional)

```yaml
# gemini-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: gemini-api-key
  namespace: openclaw
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "generativelanguage.googleapis.com"
type: Opaque
stringData:
  GEMINI_API_KEY: "your-real-gemini-key-here"
```

### Gateway Token

The gateway token is used for authenticating clients to the OpenClaw gateway. Since this is not sent to an external API (it is verified locally by OpenClaw), it does not need host filtering:

```yaml
# gateway-token-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: openclaw-gateway-token
  namespace: openclaw
  labels:
    getkloak.io/enabled: "true"
    # No getkloak.io/hosts -- this token is verified locally,
    # not sent over TLS to an external host.
    # Kloak still protects it from appearing in app memory.
type: Opaque
stringData:
  OPENCLAW_GATEWAY_TOKEN: "your-long-random-gateway-token-here"
```

Apply all secrets:

```bash
kubectl apply -f anthropic-secret.yaml
kubectl apply -f openai-secret.yaml
kubectl apply -f gemini-secret.yaml       # if using Gemini
kubectl apply -f gateway-token-secret.yaml
```

Verify shadow secrets were created:

```bash
kubectl get secrets -n openclaw
```

```
NAME                             TYPE     DATA   AGE
anthropic-api-key                Opaque   1      5s
anthropic-api-key-kloak          Opaque   1      5s
openai-api-key                   Opaque   1      5s
openai-api-key-kloak             Opaque   1      5s
gemini-api-key                   Opaque   1      5s
gemini-api-key-kloak             Opaque   1      5s
openclaw-gateway-token           Opaque   1      5s
openclaw-gateway-token-kloak     Opaque   1      5s
```

Each `-kloak` shadow secret contains a `kloak:<UUID>` placeholder that matches the byte length of your real key.

## Step 3: Create the OpenClaw ConfigMap

OpenClaw needs a configuration file and optionally agent instructions:

```yaml
# openclaw-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: openclaw-config
  namespace: openclaw
data:
  openclaw.json: |
    {
      "gateway": {
        "port": 18789,
        "host": "0.0.0.0"
      }
    }
  AGENTS.md: |
    You are a helpful AI assistant running on a Kloak-protected Kubernetes cluster.
    Your API keys are secured by eBPF -- you never see the real credentials.
```

```bash
kubectl apply -f openclaw-config.yaml
```

## Step 4: Create the PersistentVolumeClaim

OpenClaw stores conversation history and state on disk:

```yaml
# openclaw-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: openclaw-data
  namespace: openclaw
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

```bash
kubectl apply -f openclaw-pvc.yaml
```

## Step 5: Deploy OpenClaw

Deploy OpenClaw with secrets mounted as environment variables. Note that all `secretKeyRef` references point to the **original** secret names -- Kloak's webhook automatically rewrites them to the shadow secrets:

```yaml
# openclaw-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw
  namespace: openclaw
  labels:
    app: openclaw
spec:
  replicas: 1
  selector:
    matchLabels:
      app: openclaw
  template:
    metadata:
      labels:
        app: openclaw
      annotations:
        getkloak.io/enabled: "true"
    spec:
      initContainers:
        - name: init-config
          image: busybox:1.36
          command:
            - sh
            - -c
            - |
              mkdir -p /home/node/.openclaw
              cp /config/openclaw.json /home/node/.openclaw/openclaw.json
              cp /config/AGENTS.md /home/node/.openclaw/AGENTS.md
              chown -R 1000:1000 /home/node/.openclaw
          volumeMounts:
            - name: data
              mountPath: /home/node/.openclaw
            - name: config
              mountPath: /config
              readOnly: true
      containers:
        - name: gateway
          image: ghcr.io/openclaw/openclaw:slim
          ports:
            - containerPort: 18789
              name: gateway
          env:
            - name: HOME
              value: /home/node
            - name: OPENCLAW_CONFIG_DIR
              value: /home/node/.openclaw
            - name: NODE_ENV
              value: production
            # Gateway auth token
            - name: OPENCLAW_GATEWAY_TOKEN
              valueFrom:
                secretKeyRef:
                  name: openclaw-gateway-token
                  key: OPENCLAW_GATEWAY_TOKEN
            # LLM provider keys -- all protected by Kloak
            - name: ANTHROPIC_API_KEY
              valueFrom:
                secretKeyRef:
                  name: anthropic-api-key
                  key: ANTHROPIC_API_KEY
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: openai-api-key
                  key: OPENAI_API_KEY
                  optional: true
            - name: GEMINI_API_KEY
              valueFrom:
                secretKeyRef:
                  name: gemini-api-key
                  key: GEMINI_API_KEY
                  optional: true
          volumeMounts:
            - name: data
              mountPath: /home/node/.openclaw
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: "1"
              memory: 1Gi
          readinessProbe:
            httpGet:
              path: /health
              port: gateway
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: gateway
            initialDelaySeconds: 15
            periodSeconds: 30
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: openclaw-data
        - name: config
          configMap:
            name: openclaw-config
```

```bash
kubectl apply -f openclaw-deployment.yaml
```

## Step 6: Expose the Gateway

Create a Service for internal cluster access:

```yaml
# openclaw-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: openclaw
  namespace: openclaw
spec:
  selector:
    app: openclaw
  ports:
    - port: 18789
      targetPort: gateway
      name: gateway
```

```bash
kubectl apply -f openclaw-service.yaml
```

For local development, port-forward to access the gateway:

```bash
kubectl port-forward -n openclaw svc/openclaw 18789:18789
```

## Step 7: Verify Kloak Protection

### Check the Pod Was Mutated

Verify Kloak's webhook rewrote the secret references:

```bash
kubectl get pod -l app=openclaw -n openclaw -o jsonpath='{.items[0].metadata.annotations}' | jq .
```

You should see `getkloak.io/enabled: "true"` in the annotations.

### Check What the App Sees

Exec into the pod and inspect the environment:

```bash
kubectl exec -n openclaw deploy/openclaw -- env | grep -E "API_KEY|GATEWAY_TOKEN"
```

```
ANTHROPIC_API_KEY=kloak:a1b2c3d4-e5f6-7890-abcd-ef1234567890
OPENAI_API_KEY=kloak:b2c3d4e5-f6a7-8901-bcde-f12345678901
GEMINI_API_KEY=kloak:c3d4e5f6-a7b8-9012-cdef-123456789012
OPENCLAW_GATEWAY_TOKEN=kloak:d4e5f6a7-b8c9-0123-defa-234567890123
```

The application only sees `kloak:<UUID>` placeholders -- the real keys are never in process memory.

### Check Controller Logs

Verify the eBPF uprobes were attached and secrets synced:

```bash
kubectl logs -n kloak-system -l app.kubernetes.io/component=controller --tail=50 | grep -E "Attached|Synced"
```

You should see uprobe attachment for the OpenClaw process and secret sync events with `hostLen > 0` (confirming host filtering is active).

### Test an API Call

Use OpenClaw to make a real API call and verify it works:

```bash
# Port-forward if not already done
kubectl port-forward -n openclaw svc/openclaw 18789:18789 &

# Send a test message (adjust the gateway token to match your real token)
curl -s http://localhost:18789/api/v1/chat \
  -H "Authorization: Bearer your-long-random-gateway-token-here" \
  -H "Content-Type: application/json" \
  -d '{"message": "Say hello in one sentence.", "model": "claude-sonnet-4-20250514"}' | jq .
```

If you get a successful response from Claude, Kloak is working -- the `kloak:<UUID>` placeholder was transparently replaced with your real Anthropic API key at the eBPF level before TLS encryption.

## How Host Filtering Protects You

The security power of this setup comes from per-secret host filtering. Here is what happens for each API key:

| Secret | Allowed Host | What Happens |
|---|---|---|
| `anthropic-api-key` | `api.anthropic.com` | Key is rewritten only for TLS connections to Anthropic |
| `openai-api-key` | `api.openai.com` | Key is rewritten only for TLS connections to OpenAI |
| `gemini-api-key` | `generativelanguage.googleapis.com` | Key is rewritten only for TLS connections to Google |
| `openclaw-gateway-token` | *(no filter)* | Token is rewritten for any connection (local auth only) |

**Attack scenario prevented:** If an attacker exploits a vulnerability in OpenClaw (e.g., prompt injection leading to SSRF), they could try to make OpenClaw send API keys to `evil.attacker.com`. With Kloak's host filtering:

1. The attacker triggers a request to `evil.attacker.com` carrying the Anthropic key placeholder
2. Kloak's eBPF program resolves the destination via the DNS-verified trust chain
3. `evil.attacker.com` does not match `api.anthropic.com`
4. The placeholder is **not** rewritten -- the attacker receives `kloak:a1b2c3d4-...` (useless)

## Troubleshooting

### OpenClaw Fails to Start

Check if the shadow secrets exist:

```bash
kubectl get secrets -n openclaw | grep kloak
```

If missing, verify the original secrets have the `getkloak.io/enabled=true` label:

```bash
kubectl get secret anthropic-api-key -n openclaw --show-labels
```

### API Calls Return Authentication Errors

1. **Check controller logs** for eBPF attachment:
   ```bash
   kubectl logs -n kloak-system -l app.kubernetes.io/component=controller --tail=100
   ```

2. **Verify DNS capture** is working (the controller logs debug counters):
   ```bash
   kubectl logs -n kloak-system -l app.kubernetes.io/component=controller | grep "dns"
   ```

3. **Check the host filter** matches the actual API endpoint. For example, if Anthropic changes their API domain, the host filter would block the rewrite. Verify with:
   ```bash
   kubectl exec -n openclaw deploy/openclaw -- nslookup api.anthropic.com
   ```

### Gateway Token Not Working

The gateway token is verified locally by OpenClaw, not sent over TLS. If clients cannot authenticate, check that the shadow secret was mounted:

```bash
kubectl get pod -l app=openclaw -n openclaw \
  -o jsonpath='{.items[0].spec.containers[0].env}' | jq '.[] | select(.name == "OPENCLAW_GATEWAY_TOKEN")'
```

The `secretKeyRef.name` should show the `-kloak` suffix (rewritten by the webhook).

## Clean Up

```bash
kubectl delete namespace openclaw
```

## Next Steps

- Read the [Host Filtering guide](/guides/host-filtering) to understand the DNS-verified trust chain in depth
- Learn about [Supported Runtimes](/guides/supported-runtimes) -- OpenClaw (Node.js/BoringSSL) is fully supported
- Review the [Architecture Overview](/architecture/overview) for the full eBPF data flow
