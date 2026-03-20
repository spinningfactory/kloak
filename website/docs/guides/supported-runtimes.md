# Supported Runtimes

Kloak works by attaching eBPF uprobes to TLS library functions in your application's process. The specific functions targeted depend on which TLS library your application uses. This guide covers what works, what does not, and what to watch out for in each runtime.

## Detection Strategy

When Kloak's controller detects a new pod, it resolves the container's PID and probes the process in this order:

1. **Go `crypto/tls`** -- Looks for the `crypto/tls.(*Conn).Write` symbol in the binary
2. **OpenSSL / BoringSSL (statically linked)** -- Looks for `SSL_write` and `SSL_write_ex` symbols in the main executable
3. **OpenSSL / BoringSSL (dynamically linked)** -- Scans `/proc/<pid>/maps` for shared libraries matching `libssl.so*`, `libboringssl.so*`, or `libcrypto.so*`, then probes those for `SSL_write`/`SSL_write_ex`

The first successful attachment wins. For SNI-based host filtering, Kloak also attaches uprobes to `SSL_set_tlsext_host_name` (BoringSSL) and `SSL_ctrl` (OpenSSL).

## Go (crypto/tls)

**Status:** Fully supported

Go applications using the standard `crypto/tls` package are intercepted via a uprobe on `crypto/tls.(*Conn).Write`. Since Go statically links the TLS implementation into the binary, no shared library scanning is needed.

### How It Works

```
App calls http.Client.Do(req)
  → net/http serializes headers + body
  → tls.(*Conn).Write(plaintext)
  → eBPF uprobe fires, scans for kloak: prefix
  → Real secret injected before encryption
```

### Host Resolution

Go does not use OpenSSL, so SNI capture is not available. Instead, Kloak scans the TLS write buffer for the HTTP `Host:` header to determine the destination hostname.

### Important: Force HTTP/1.1

Go defaults to HTTP/2 via ALPN negotiation. HTTP/2 uses binary HPACK-encoded headers that the eBPF scanner cannot parse. You must force HTTP/1.1:

```go
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            NextProtos: []string{"http/1.1"}, // Force HTTP/1.1
        },
        ForceAttemptHTTP2: false,
    },
}
```

::: warning
If you do not force HTTP/1.1, Go will negotiate HTTP/2 and the eBPF uprobe will not be able to scan the compressed headers. Secret replacement will silently fail for HTTP/2 connections.
:::

### Limitations

- **HTTP/2 is not supported.** Headers are HPACK-compressed and cannot be scanned.
- **Non-HTTP protocols** using `tls.Conn.Write` directly will have secrets rewritten, but host filtering falls back to allowing all hosts (no `Host:` header to extract).
- **Connection pooling:** Go's `http.Transport` reuses TLS connections. If a connection is established before the eBPF map is populated, that connection's writes will not match any secrets. Use a startup delay or disable connection reuse for the first request.

## Python (OpenSSL)

**Status:** Fully supported

Python's `ssl` module wraps OpenSSL via `libssl.so`. Kloak attaches uprobes to `SSL_write` in the dynamically linked library.

### How It Works

```
App calls requests.get("https://api.example.com", headers={"Authorization": secret})
  → urllib3 → ssl.SSLSocket.write()
  → OpenSSL SSL_write() in libssl.so
  → eBPF uprobe fires, scans for kloak: prefix
  → Real secret injected before encryption
```

### Host Resolution

Python's `ssl.wrap_socket(sock, server_hostname="api.example.com")` calls `SSL_set_tlsext_host_name` under the hood, which triggers `SSL_ctrl(ssl, 55, 0, hostname)` in OpenSSL. Kloak's eBPF uprobe on `SSL_ctrl` captures the hostname for host filtering.

```python
import requests

# The requests library sets SNI automatically -- no special config needed
response = requests.get(
    "https://api.stripe.com/v1/charges",
    headers={"Authorization": f"Bearer {secret}"},
)
```

::: tip
Python applications work out of the box with Kloak. No HTTP version forcing is needed because Python's `requests` and `urllib3` libraries use HTTP/1.1 by default.
:::

### SNI for Non-HTTP Protocols

Even raw TLS sockets work with host filtering, as long as `server_hostname` is set:

```python
import ssl
import socket

ctx = ssl.create_default_context()
with socket.create_connection(("api.example.com", 8443)) as sock:
    with ctx.wrap_socket(sock, server_hostname="api.example.com") as tls:
        tls.sendall(payload_containing_secret)  # eBPF rewrites here
```

## Node.js (OpenSSL)

**Status:** Fully supported

Node.js uses OpenSSL for TLS, linked as a shared library in most distributions (or statically in some builds). Kloak attaches to `SSL_write` in `libssl.so` or in the Node.js binary itself.

### How It Works

```
App calls https.request() or fetch()
  → Node TLS module → OpenSSL SSL_write()
  → eBPF uprobe fires, scans for kloak: prefix
  → Real secret injected before encryption
```

### Host Resolution

Node.js sets the SNI hostname automatically when making HTTPS requests. Kloak captures this via the `SSL_ctrl` uprobe.

```javascript
const https = require('https');

const options = {
  hostname: 'api.stripe.com',
  path: '/v1/charges',
  headers: {
    'Authorization': `Bearer ${secret}`,
  },
};

https.request(options, (res) => {
  // Response handling
});
```

::: tip
Like Python, Node.js works with Kloak out of the box. The SNI hostname is set automatically by the `https` module.
:::

## Go + BoringSSL

**Status:** Fully supported

Some Go applications use BoringSSL instead of the standard `crypto/tls` -- for example, applications built with `GOEXPERIMENT=boringcrypto` or those linking against BoringSSL for FIPS compliance. Kloak detects this and attaches to `SSL_write` in the main executable or in the linked BoringSSL shared library.

### How It Works

When Kloak probes the binary:

1. The standard Go `crypto/tls.(*Conn).Write` symbol is not found (or is a wrapper)
2. Kloak falls back to checking for `SSL_write` / `SSL_write_ex` in the binary
3. If found (statically linked BoringSSL), uprobes are attached directly

For dynamically linked BoringSSL:

1. Kloak scans `/proc/<pid>/maps` for `libboringssl.so*` or `libssl.so*`
2. Attaches `SSL_write` uprobes to the shared library

### Host Resolution

BoringSSL exports `SSL_set_tlsext_host_name` as a real function (unlike OpenSSL where it is a macro). Kloak attaches a uprobe directly to this function for reliable SNI capture.

## Any OpenSSL-Linked Binary

**Status:** Supported

Any application that dynamically links against `libssl.so` is automatically supported. This includes:

- **Ruby** (OpenSSL via `openssl` gem)
- **PHP** (OpenSSL via `php-openssl` extension)
- **Rust** (when using `openssl` or `native-tls` crates with system OpenSSL)
- **C/C++** applications using OpenSSL directly
- **Java** (when using native TLS via JNI, though most Java apps use the JVM's built-in TLS)

Kloak scans `/proc/<pid>/maps` for any library matching `libssl.so*`, `libboringssl.so*`, or `libcrypto.so*` and attaches uprobes automatically.

## What Is NOT Supported

### Pure Go Without HTTP

If a Go application uses `tls.Conn.Write` directly (not through `net/http`), Kloak can still rewrite secrets. However, **host filtering will not work** because there is no HTTP `Host:` header to extract. The secret will be rewritten for any destination.

### HTTP/2 with Go

Go's default HTTP/2 uses HPACK binary header compression. The eBPF scanner sees compressed bytes and cannot locate the `kloak:` prefix in the header values. Secrets will not be rewritten.

::: danger
This is a silent failure -- no error is logged. Always force HTTP/1.1 for Go applications that send secrets in HTTP headers over TLS.
:::

### Custom TLS Stacks

Applications that implement their own TLS handshake and encryption (without using OpenSSL, BoringSSL, or Go's `crypto/tls`) are not supported. The eBPF uprobes have no known function to attach to.

Examples of unsupported stacks:
- **Java's built-in JSSE** (TLS is implemented in pure Java, not via native OpenSSL)
- **GnuTLS** (different API: `gnutls_record_send` instead of `SSL_write`)
- **mbedTLS** (different API: `mbedtls_ssl_write`)
- **s2n-tls** (AWS's TLS library, different API)

::: tip
If your application uses an unsupported TLS stack, you may still benefit from Kloak's shadow secret mechanism. The application will read `kloak:<UUID>` values, but they will be sent as-is without in-kernel rewriting. You would need a sidecar proxy or application-level integration to perform the substitution.
:::

### Statically Linked Go Binaries Without Symbol Table

If a Go binary is compiled with `-ldflags="-s -w"` (stripped symbols), the `crypto/tls.(*Conn).Write` symbol may not be resolvable. Kloak will fail to attach the uprobe and log an error. Ensure your Go binaries retain symbol tables in production images used with Kloak.

## Runtime Compatibility Matrix

| Runtime | TLS Library | eBPF Hook | Host Filtering | HTTP/2 | Notes |
|---|---|---|---|---|---|
| Go | crypto/tls | `tls.(*Conn).Write` | HTTP Host header | No | Force HTTP/1.1 |
| Go + BoringSSL | BoringSSL | `SSL_write` | SNI capture | N/A | FIPS compliance builds |
| Python | OpenSSL (libssl) | `SSL_write` | SNI capture | Yes | Works out of the box |
| Node.js | OpenSSL (libssl) | `SSL_write` | SNI capture | Yes | Works out of the box |
| Ruby | OpenSSL (libssl) | `SSL_write` | SNI capture | Yes | Via system OpenSSL |
| Rust | OpenSSL (libssl) | `SSL_write` | SNI capture | Yes | When using native-tls |
| C/C++ | OpenSSL (libssl) | `SSL_write` | SNI capture | Yes | Direct OpenSSL usage |
| Java (JSSE) | JVM built-in | -- | -- | -- | Not supported |
| Any (GnuTLS) | GnuTLS | -- | -- | -- | Not supported |
