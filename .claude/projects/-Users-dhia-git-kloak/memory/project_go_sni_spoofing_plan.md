---
name: Go TLS SNI spoofing prevention plan
description: Plan to enable DNS-based SNI spoofing prevention for Go crypto/tls via Handshake uprobe thread correlation
type: project
---

Go crypto/tls passes ssl_ptr=0 to resolve_host, so the IP-verified DNS chain (Path 1) is skipped entirely. The missing link is tls.Conn → fd.

**Why:** Go's tls.Conn never calls OpenSSL's SSL_set_fd, so ssl_fd_map is never populated. The fd is buried in Go struct internals (tls.Conn.conn → net.TCPConn → netFD → poll.FD → Sysfd) with version-dependent offsets.

**Solution: Handshake uprobe + thread correlation**

1. Uprobe `crypto/tls.(*Conn).Handshake` → fires on thread T, captures receiver pointer. Store `handshake_pending[{tgid, tid}] = receiver`.
2. Tracepoint `sys_enter_write` → fires on same thread T during ClientHello write. If `handshake_pending[{tgid, tid}]` present, store `go_tls_fd[{tgid, receiver}] = fd`.
3. At `go_tls_write` time → look up `go_tls_fd[{tgid, receiver}]` → fd → conn_ip_map → ip → dns_ip_map → hostname. Full chain verified.

Works because Handshake always precedes application Write, and goroutines are pinned to OS threads during syscalls.

**Fallback: /proc scanning**
- `/proc/<pid>/fd/<N>` → `socket:[inode]` (fd → inode)
- `/proc/<pid>/net/tcp6` → inode, rem_addr (inode → remote_ip)
- Controller already reads /proc for maps/resolv.conf, natural extension
- Useful when Handshake symbol not found (stripped binaries, CGO)

**How to apply:** This is Phase 2 work. Current TestEBPFSNISpoofingPrevention is skipped pending this. TestEBPFSNISpoofingPreventionOpenSSL covers the OpenSSL path which works today.
