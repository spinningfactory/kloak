# Host Filtering

Host filtering is Kloak's mechanism for restricting which TLS destinations can receive a secret's real value. Even if an attacker gains code execution inside your container, they cannot exfiltrate secrets to unauthorized hosts -- the eBPF program will refuse to perform the rewrite.

## Why Host Filtering Matters

Without host filtering, any outbound TLS connection from a Kloak-enabled pod could receive the real secret value. Consider this scenario:

1. Your application sends an API key to `api.stripe.com` in the `Authorization` header
2. An attacker exploits an SSRF vulnerability and makes your app send the same header to `evil.attacker.com`
3. Without host filtering, the eBPF uprobe rewrites the `kloak:` placeholder for **both** destinations

With host filtering enabled, the eBPF program checks the TLS connection's destination hostname. If it does not match the allowed list, the placeholder is **not** rewritten -- the remote server receives the harmless `kloak:<UUID>` string instead of your real secret.

::: danger
Without host filtering, Kloak protects secrets from being visible in application memory, but does not prevent network-level exfiltration. Always configure `getkloak.io/hosts` for production secrets.
:::

## Configuring Host Filtering

Add the `getkloak.io/hosts` label to your Secret with a comma-separated list of allowed hostnames:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: stripe-api-key
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.stripe.com"
type: Opaque
data:
  api-key: c2stbGl2ZS1rZXktMTIzNDU2  # sk-live-key-123456
```

Or using `kubectl`:

```bash
kubectl create secret generic stripe-api-key \
    --from-literal=api-key="sk-live-key-123456" \
    -n payments --dry-run=client -o yaml | \
    kubectl label -f - \
        getkloak.io/enabled="true" \
        getkloak.io/hosts="api.stripe.com" \
        --local -o yaml | \
    kubectl apply -f -
```

### Multiple Allowed Hosts

Separate multiple hostnames with commas:

```yaml
metadata:
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.stripe.com,api.stripe.com:443"
```

::: warning
Currently, only the **first** host in the comma-separated list is enforced in the eBPF map (due to the single `AllowedHost` field in the BPF value struct). Support for multiple hosts per secret is planned.
:::

### No Host Filter (Wildcard)

If the `getkloak.io/hosts` label is omitted, the secret is allowed for **all** hosts:

```yaml
metadata:
  labels:
    getkloak.io/enabled: "true"
    # No getkloak.io/hosts = wildcard, rewrite for any destination
```

This is equivalent to `AllowedHosts: ["*"]` internally.

## How Host Resolution Works

The eBPF program needs to know the hostname of the TLS connection to enforce filtering. Kloak uses two mechanisms depending on the TLS library:

### SNI-Based Resolution (OpenSSL / BoringSSL)

For applications using OpenSSL or BoringSSL (Python, Node.js, Go+BoringSSL, and any dynamically linked application), Kloak captures the hostname from the **SNI (Server Name Indication)** extension:

1. The application calls `SSL_set_tlsext_host_name(ssl, "api.stripe.com")` before the TLS handshake
2. Kloak's eBPF uprobe on this function captures the hostname and stores it in a per-connection BPF map (`conn_hosts`)
3. When `SSL_write` is called later, the eBPF program looks up the cached hostname for that SSL connection pointer
4. The hostname is compared against the secret's `AllowedHost` field

::: tip
SNI capture happens **once** per connection, before the handshake. It is the most reliable method because the hostname is set explicitly by the TLS library.
:::

For OpenSSL specifically, `SSL_set_tlsext_host_name` is actually a macro that expands to `SSL_ctrl(ssl, 55, 0, name)`. Kloak attaches uprobes to both `SSL_set_tlsext_host_name` (for BoringSSL where it is a real function) and `SSL_ctrl` (for OpenSSL) to catch both variants.

### HTTP Host Header Fallback (Go crypto/tls)

Go's standard `crypto/tls` package does not use OpenSSL. Since Go handles SNI internally without a hookable function call, Kloak falls back to scanning the TLS write buffer for the HTTP `Host:` header:

1. Go's `net/http` writes the full HTTP request (including headers) through `tls.(*Conn).Write`
2. The eBPF uprobe scans the write buffer for `Host: ` followed by the hostname
3. The extracted hostname is used for the host filter check

This fallback works well for HTTP/1.1 traffic but has limitations:

::: warning
**HTTP/2 is not supported for Go host resolution.** Go defaults to HTTP/2 via ALPN negotiation, which uses binary HPACK-encoded headers that the eBPF scanner cannot parse. Force HTTP/1.1 in your Go client:

```go
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            NextProtos: []string{"http/1.1"},
        },
        ForceAttemptHTTP2: false,
    },
}
```
:::

### Resolution Priority

| TLS Library | Host Resolution Method | Reliability |
|---|---|---|
| OpenSSL (libssl.so) | SNI via `SSL_ctrl` | High -- captured before handshake |
| BoringSSL | SNI via `SSL_set_tlsext_host_name` | High -- captured before handshake |
| Go `crypto/tls` | HTTP `Host:` header scan | Medium -- HTTP/1.1 only |

## Practical Examples

### Example 1: Stripe API Key (Single Host)

Only allow the secret to be sent to Stripe's API:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: stripe-key
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.stripe.com"
type: Opaque
data:
  key: c2stbGl2ZS0xMjM0NTY3ODkw  # sk-live-1234567890
```

**Result:**
- Request to `https://api.stripe.com/v1/charges` -- secret is rewritten with real value
- Request to `https://evil.example.com/steal` -- secret remains as `kloak:<UUID>`

### Example 2: Two Secrets, Different Hosts

A common pattern: one secret for an allowed API, another restricted to a different host:

```bash
# Secret allowed for httpbin.org
kubectl create secret generic secret-allowed \
    --from-literal=api-key="REAL-ALLOWED-KEY-12345" \
    -n demo --dry-run=client -o yaml | \
    kubectl label -f - getkloak.io/enabled="true" getkloak.io/hosts="httpbin.org" --local -o yaml | \
    kubectl apply -f -

# Secret only allowed for example.com
kubectl create secret generic secret-blocked \
    --from-literal=api-key="REAL-BLOCKED-KEY-67890" \
    -n demo --dry-run=client -o yaml | \
    kubectl label -f - getkloak.io/enabled="true" getkloak.io/hosts="example.com" --local -o yaml | \
    kubectl apply -f -
```

When the application sends both secrets to `httpbin.org`:

```
X-Secret-Allowed: REAL-ALLOWED-KEY-12345    # Replaced -- host matches
X-Secret-Blocked: kloak:b2c3d4e5-f6a7-...  # NOT replaced -- host mismatch
```

### Example 3: SNI-Based Filtering (Non-HTTP)

Host filtering works even for non-HTTP TLS protocols, as long as the application sets the SNI hostname:

```python
import ssl
import socket

ctx = ssl.create_default_context()
with socket.create_connection(("api.stripe.com", 443)) as sock:
    # wrap_socket calls SSL_set_tlsext_host_name("api.stripe.com")
    # which the eBPF uprobe captures for host filtering
    with ctx.wrap_socket(sock, server_hostname="api.stripe.com") as tls:
        tls.sendall(b"secret data containing kloak:UUID here")
```

## Verifying Host Filtering

### Check Controller Logs

The controller logs show when secrets are synced to the eBPF map, including the host restriction:

```bash
kubectl logs -n kloak-system -l app.kubernetes.io/component=controller | grep "Synced secret"
```

Output:

```
Synced secret into eBPF map  hash="kloak:a1b2c3d4-..."  hostLen=15
```

A `hostLen` greater than 0 confirms host filtering is active. A `hostLen` of 0 means wildcard (all hosts allowed).

### Test with httpbin

Deploy the demo application and check the response:

```bash
kubectl logs -l app=demo-python -n kloak-demo -c demo-app | grep -A5 "headers"
```

You should see the allowed secret replaced with the real value and the blocked secret still showing the `kloak:` UUID.

## Security Considerations

- **Hostname is checked at TLS write time**, not at connection time. If an application reuses a TLS connection for multiple logical requests, all writes on that connection use the same cached hostname.
- **Hostname length is limited to 32 bytes** in the BPF map. Hostnames longer than 32 characters are truncated. This covers the vast majority of real-world API endpoints.
- **Wildcard matching is not supported.** You must specify exact hostnames. `*.stripe.com` will not work -- use `api.stripe.com` explicitly.
- **Host filtering is enforced in-kernel by eBPF.** Application code cannot bypass it, even with arbitrary code execution in the container.
