# Supported Runtimes

Kloak works by attaching eBPF uprobes to TLS library functions in your application's process. The specific functions targeted depend on which TLS library your application uses. This guide covers what works, what does not, and what to watch out for in each runtime.

## Detection Strategy

When Kloak's controller detects a new pod, it resolves the container's PID and probes the process in this order:

1. **Go `crypto/tls`** -- Looks for the `crypto/tls.(*Conn).Write` symbol in the binary
2. **OpenSSL / BoringSSL (statically linked)** -- Looks for `SSL_write` and `SSL_write_ex` symbols in the main executable
3. **OpenSSL / BoringSSL (dynamically linked)** -- Scans `/proc/<pid>/maps` for shared libraries matching `libssl.so*`, `libboringssl.so*`, or `libcrypto.so*`, then probes those for `SSL_write`/`SSL_write_ex`

The first successful attachment wins. Host filtering uses DNS-verified resolution which works identically for all runtimes.

## Host Filtering

Host filtering works the same way for **all** supported runtimes. It does not depend on the TLS library or protocol (HTTP/1.1, HTTP/2, or raw TLS).

Kloak uses **DNS-verified host filtering**: a kprobe on the kernel's `udp_recvmsg` captures DNS responses, and connect tracepoints track TCP connections. At TLS write time, the destination hostname is resolved through this chain. See the [Host Filtering guide](/guides/host-filtering) for details.

::: tip
Unlike SNI-based approaches, DNS-verified filtering works for HTTP/2, raw TLS sockets, and any protocol. No application-level changes are needed.
:::

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

### Limitations

- **Connection pooling:** Go's `http.Transport` reuses TLS connections. The DNS-verified host is cached on first successful resolution, so subsequent writes on the same connection use the cached hostname.
- **Stripped binaries:** If compiled with `-ldflags="-s -w"`, the `crypto/tls.(*Conn).Write` symbol may not be resolvable. Ensure your Go binaries retain symbol tables.

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

```python
import requests

# Works out of the box -- no special configuration needed
response = requests.get(
    "https://api.stripe.com/v1/charges",
    headers={"Authorization": f"Bearer {secret}"},
)
```

::: tip
Python applications work out of the box with Kloak. No HTTP version forcing or special TLS configuration is needed.
:::

## Node.js (BoringSSL)

**Status:** Fully supported

Node.js statically links BoringSSL into its binary. Kloak attaches to `SSL_write` and `SSL_write_ex` in the main executable.

### How It Works

```
App calls https.request() or fetch()
  → Node TLS module → BoringSSL SSL_write()
  → eBPF uprobe fires, scans for kloak: prefix
  → Real secret injected before encryption
```

```javascript
const https = require('https');

// Works out of the box
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
| Go | crypto/tls | `tls.(*Conn).Write` | DNS-verified | Yes | Works out of the box |
| Go + BoringSSL | BoringSSL | `SSL_write` | DNS-verified | Yes | FIPS compliance builds |
| Python | OpenSSL (libssl) | `SSL_write` | DNS-verified | Yes | Works out of the box |
| Node.js | BoringSSL | `SSL_write` | DNS-verified | Yes | Works out of the box |
| Ruby | OpenSSL (libssl) | `SSL_write` | DNS-verified | Yes | Via system OpenSSL |
| Rust | OpenSSL (libssl) | `SSL_write` | DNS-verified | Yes | When using native-tls |
| C/C++ | OpenSSL (libssl) | `SSL_write` | DNS-verified | Yes | Direct OpenSSL usage |
| Java (JSSE) | JVM built-in | -- | -- | -- | Not supported |
| Any (GnuTLS) | GnuTLS | -- | -- | -- | Not supported |
