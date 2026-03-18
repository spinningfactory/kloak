"""
Demo: SNI-based host filtering for non-HTTP TLS protocols.

Tests that Kloak's eBPF uprobes capture the hostname from
SSL_set_tlsext_host_name (SNI) and use it for host-based secret filtering,
even when the TLS payload is NOT HTTP (no Host header to fall back on).

Architecture:
  1. A TLS echo server runs on localhost:8443 (self-signed cert)
  2. A TLS client connects with server_hostname="httpbin.org" (sets SNI)
  3. The client sends raw (non-HTTP) data containing the secret
  4. The echo server sends it back
  5. If eBPF rewrote the secret (SNI matched), the echo contains the real value

The allowed secret (hosts=httpbin.org) should be rewritten because SNI = httpbin.org.
The blocked secret (hosts=example.com) should NOT be rewritten.
"""

import os
import socket
import ssl
import subprocess
import sys
import threading
import time

CERT_PATH = "/tmp/cert.pem"
KEY_PATH = "/tmp/key.pem"
LISTEN_PORT = 8443


def generate_self_signed_cert():
    """Generate a self-signed certificate for the local echo server."""
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_PATH, "-out", CERT_PATH,
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    print(f"Generated self-signed cert at {CERT_PATH}")


def echo_server():
    """TLS echo server that returns whatever it receives."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN_PORT))
    srv.listen(5)
    while True:
        conn, _ = srv.accept()
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            data = tls_conn.recv(4096)
            if data:
                tls_conn.sendall(data)
            tls_conn.shutdown(socket.SHUT_RDWR)
            tls_conn.close()
        except Exception:
            try:
                conn.close()
            except Exception:
                pass


def load_secret(env_var, default):
    """Load a secret from a file path specified by an environment variable."""
    path = os.getenv(env_var)
    if path and os.path.exists(path):
        with open(path) as f:
            value = f.read().strip()
        print(f"Loaded secret from {path}")
        return value
    return default


def send_and_echo(secret_allowed, secret_blocked, sni_host):
    """Connect to local echo server with SNI, send secrets, return echo."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Python's wrap_socket calls SSL_set_tlsext_host_name(sni_host)
    # which the eBPF uprobe intercepts and caches for host filtering.
    with socket.create_connection(("127.0.0.1", LISTEN_PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni_host) as tls:
            payload = f"ALLOWED={secret_allowed}\nBLOCKED={secret_blocked}\n"
            tls.sendall(payload.encode())
            return tls.recv(4096).decode()


def main():
    key_allowed = load_secret("SECRET_ALLOWED_FILE", "allowed-default-key")
    key_blocked = load_secret("SECRET_BLOCKED_FILE", "blocked-default-key")
    sni_host = os.getenv("SNI_HOST", "httpbin.org")
    interval = int(os.getenv("REQUEST_INTERVAL", "5"))

    print("=" * 60)
    print("Kloak Demo: SNI Host Filtering (non-HTTP)")
    print("=" * 60)
    print(f"SNI hostname: {sni_host}")
    print(f"Secret Allowed: {key_allowed[:30]}...")
    print(f"Secret Blocked: {key_blocked[:30]}...")
    print("=" * 60)
    sys.stdout.flush()

    generate_self_signed_cert()

    # Start echo server in background
    t = threading.Thread(target=echo_server, daemon=True)
    t.start()
    time.sleep(1)
    print("Echo server started on port", LISTEN_PORT)

    # Wait for Kloak eBPF to attach
    startup_delay = int(os.getenv("STARTUP_DELAY", "15"))
    print(f"Waiting {startup_delay}s for eBPF attachment...")
    sys.stdout.flush()
    time.sleep(startup_delay)

    count = 0
    while True:
        count += 1
        try:
            echo = send_and_echo(key_allowed, key_blocked, sni_host)
            print(f"\n--- Request #{count} (SNI={sni_host}) ---")
            print(f"Echo: {echo.strip()}")
            sys.stdout.flush()
        except Exception as e:
            print(f"\n--- Request #{count} ---")
            print(f"Error: {e}")
            sys.stdout.flush()
        time.sleep(interval)


if __name__ == "__main__":
    main()
