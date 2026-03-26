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

Kloak uses **DNS-verified host filtering** — a language-agnostic approach that works identically for all TLS runtimes (Go, Python, Node.js, Rust, etc.) without depending on SNI or HTTP headers.

### DNS-Verified Trust Chain

The eBPF program builds a chain of trust from DNS resolution to TLS write:

1. **DNS Capture** — A kprobe on the kernel's `udp_recvmsg` function intercepts all DNS responses on the node. For hostnames listed in `getkloak.io/hosts` labels (the `watched_hosts` set), the resolved A/AAAA record IPs are stored in `dns_ip_map` with their TTL.

2. **Connection Tracking** — Tracepoints on `sys_enter_connect` and `sys_exit_connect` record every TCP connection's file descriptor → destination IP mapping in `conn_ip_map`. If the destination IP exists in `dns_ip_map`, the fd is cached in `last_verified_fd` for that process.

3. **Host Resolution at TLS Write Time** — When `SSL_write` or `crypto/tls.Write` is called, the `resolve_host()` function chains: `last_verified_fd` → `conn_ip_map[{tgid, fd}]` → `dns_ip_map[ip]` to determine the hostname of the current TLS connection.

4. **Secret Filtering** — The resolved hostname is compared against the secret's `allowed_host`. Match → secret is rewritten. Mismatch → placeholder sent as-is.

5. **TTL Enforcement** — DNS entries include a TTL from the original DNS response. Expired entries are skipped on lookup, forcing re-verification through fresh DNS responses.

6. **Connection Cleanup** — A tracepoint on `sys_enter_close` removes `conn_ip_map` entries when file descriptors are closed, preventing stale mappings from being used after fd reuse.

::: tip
This approach is **language-agnostic** — it works the same way for Go, Python, Node.js, and any OpenSSL/BoringSSL-based runtime. No SNI capture or HTTP header parsing is needed.
:::

### Host Resolution Flow

| Runtime | TLS Hook | Host Resolution Method |
|---|---|---|
| Python (OpenSSL) | `SSL_write` uprobe | DNS-verified via `udp_recvmsg` kprobe |
| Node.js (BoringSSL) | `SSL_write` uprobe | DNS-verified via `udp_recvmsg` kprobe |
| Go (crypto/tls) | `crypto/tls.(*Conn).Write` uprobe | DNS-verified via `udp_recvmsg` kprobe |
| Rust, Ruby, PHP, curl | `SSL_write` / `SSL_write_ex` uprobe | DNS-verified via `udp_recvmsg` kprobe |

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

### Example 3: Raw TLS Filtering (Non-HTTP)

Host filtering works even for non-HTTP TLS protocols. The DNS resolution of the hostname is what enables host verification — no HTTP headers or SNI capture required:

```python
import ssl
import socket

ctx = ssl.create_default_context()
# DNS resolution of "api.stripe.com" is captured by the kprobe
# and stored in dns_ip_map for host verification
with socket.create_connection(("api.stripe.com", 443)) as sock:
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

- **Host verification is DNS-based.** The trust chain depends on the integrity of DNS responses. DNS spoofing could potentially trick the host filter. Use DNSSEC or trusted DNS resolvers to mitigate this.
- **DNS entries have TTL enforcement.** Expired entries are skipped, forcing re-verification through fresh DNS responses. This limits the window for stale IP → hostname mappings.
- **Hostname length is limited to 32 bytes** in the BPF map. Hostnames longer than 32 characters are truncated. This covers the vast majority of real-world API endpoints.
- **Wildcard matching is not supported.** You must specify exact hostnames. `*.stripe.com` will not work -- use `api.stripe.com` explicitly.
- **Host filtering is enforced in-kernel by eBPF.** Application code cannot bypass it, even with arbitrary code execution in the container.
- **DNS and connection tracking are global** on the node. All DNS responses and TCP connections are monitored (filtered by `watched_hosts` for DNS). This is necessary for containerized environments where DNS proxies may handle resolution in a different process context.
