"""
Demo: DNS-verified host filtering with raw TLS sockets (non-HTTP).

Tests that Kloak's eBPF DNS-verified host filtering works at the TCP level
with raw TLS sockets — no HTTP library involved.

Architecture:
  1. A TLS echo server runs as a sidecar (port 8443, self-signed cert)
  2. The client resolves the K8s Service name via DNS (populates dns_ip_map)
  3. The client connects to the Service IP and sends raw TLS data with secrets
  4. The echo server returns the data — if eBPF rewrote it, the echo shows real values

The allowed secret (hosts=<service-name>) should be rewritten because the
connection target was DNS-verified via the Service name.
The blocked secret (hosts=example.com) should NOT be rewritten.
"""

import os
import socket
import ssl
import sys
import time

LISTEN_PORT = 8443


def load_secret(env_var, default):
    """Load a secret from a file path specified by an environment variable."""
    path = os.getenv(env_var)
    if path and os.path.exists(path):
        with open(path) as f:
            value = f.read().strip()
        print(f"Loaded secret from {path}")
        return value
    return default


def send_and_echo(host, secret_allowed, secret_blocked):
    """Connect to echo server via DNS name, send secrets, return echo."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Resolve the service name via DNS, then connect.
    # This DNS lookup populates dns_ip_map, and the connect() to the
    # resolved IP sets last_verified_fd for host-based filtering.
    with socket.create_connection((host, LISTEN_PORT)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            payload = f"ALLOWED={secret_allowed}\nBLOCKED={secret_blocked}\n"
            tls.sendall(payload.encode())
            return tls.recv(16384).decode()


def main():
    key_allowed = load_secret("SECRET_ALLOWED_FILE", "allowed-default-key")
    key_blocked = load_secret("SECRET_BLOCKED_FILE", "blocked-default-key")
    target_host = os.environ.get("TARGET_HOST", "tls")
    interval = int(os.getenv("REQUEST_INTERVAL", "5"))

    print("=" * 60)
    print("Kloak Demo: Raw TLS Echo (DNS-Verified Host Filtering)")
    print("=" * 60)
    print(f"Target: {target_host}:{LISTEN_PORT}")
    print(f"Secret Allowed: {key_allowed[:30]}...")
    print(f"Secret Blocked: {key_blocked[:30]}...")
    print("=" * 60)
    sys.stdout.flush()

    # Wait for the echo server sidecar to start (cert generation + listen)
    print("Waiting for echo server sidecar to be ready...")
    sys.stdout.flush()
    for attempt in range(30):
        try:
            import socket
            s = socket.create_connection((target_host, LISTEN_PORT), timeout=1)
            s.close()
            print("Echo server is ready.")
            sys.stdout.flush()
            break
        except (ConnectionRefusedError, OSError):
            time.sleep(1)

    count = 0
    while True:
        count += 1
        try:
            echo = send_and_echo(target_host, key_allowed, key_blocked)
            print(f"\n--- Request #{count} (target={target_host}) ---")
            print(f"Echo: {echo.strip()}")
            sys.stdout.flush()
        except Exception as e:
            print(f"\n--- Request #{count} ---")
            print(f"Error: {e}")
            sys.stdout.flush()
        time.sleep(interval)


if __name__ == "__main__":
    main()
