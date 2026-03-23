"""
Demo: DNS-based SNI spoofing prevention.

Tests that Kloak's eBPF DNS interception prevents secret rewriting when the
TLS connection's peer IP was NOT DNS-resolved to the allowed hostname.

Architecture:
  Two Kubernetes Services back the same TLS echo server (this pod):
    svc-spoof-allowed → ClusterIP_A   (the hostname the secret is allowed for)
    svc-spoof-other   → ClusterIP_B   (a different hostname, same backing pod)

LEGITIMATE path:
  App DNS-resolves svc-spoof-allowed → IP_A, connects to IP_A with SNI=svc-spoof-allowed.
  eBPF chain: ssl_ptr → fd → IP_A → dns_ip_map → "svc-spoof-allowed..." == allowed_host → REWRITE

SPOOF path:
  App DNS-resolves svc-spoof-other → IP_B, connects to IP_B but sets SNI=svc-spoof-allowed.
  eBPF chain: ssl_ptr → fd → IP_B → dns_ip_map → "svc-spoof-other..." ≠ allowed_host → NO REWRITE

Output markers for e2e test polling:
  LEGIT_REWRITTEN       — legitimate path correctly rewrote the secret
  LEGIT_NOT_REWRITTEN   — legitimate path did not rewrite (eBPF not active yet)
  SPOOF_NOT_REWRITTEN   — spoofing correctly blocked ✓
  SPOOF_REWRITTEN       — spoofing NOT blocked (security failure!) ✗
"""

import os
import socket
import ssl
import subprocess
import sys
import threading
import time

CERT_PATH   = "/tmp/cert.pem"
KEY_PATH    = "/tmp/key.pem"
LISTEN_PORT = 8443


def generate_self_signed_cert():
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_PATH, "-out", CERT_PATH,
            "-days", "1", "-nodes", "-subj", "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )


def echo_server():
    """TLS echo server: reflects whatever the client sends."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(10)
    while True:
        conn, _ = srv.accept()
        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            data = tls_conn.recv(16384)
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
    path = os.getenv(env_var)
    if path and os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return default


def resolve_to_ip(hostname):
    """DNS-resolve hostname → first IPv4 address.

    glibc's stub resolver sends a UDP DNS query to CoreDNS. The UDP response
    triggers Kloak's eBPF tp_exit_recvfrom handler, which records:
        dns_ip_map[{tgid, ClusterIP}] = hostname
    This is the first link in the DNS-verification chain.
    """
    infos = socket.getaddrinfo(hostname, LISTEN_PORT, socket.AF_INET)
    return infos[0][4][0]


def send_and_echo(target_ip, sni_host, payload):
    """Open a TLS connection to target_ip with SNI=sni_host, send payload, return echo.

    Python's wrap_socket calls:
      SSL_set_fd(ssl, fd)                  → eBPF captures ssl_fd_map[ssl_ptr] = fd
      SSL_set_tlsext_host_name(ssl, host)  → eBPF captures conn_hosts[ssl_ptr] = host (SNI cache)

    The connect() syscall to target_ip also fires tp_enter/exit_connect, recording:
      conn_ip_map[{tgid, fd}] = target_ip

    At SSL_write time, Kloak resolves the host via the authoritative DNS chain:
      ssl_ptr → ssl_fd_map → fd → conn_ip_map → target_ip → dns_ip_map → actual_hostname
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target_ip, LISTEN_PORT), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni_host) as tls:
            tls.sendall(payload.encode())
            return tls.recv(16384).decode()


def main():
    secret      = load_secret("SECRET_FILE", "no-secret-mounted")
    allowed_svc = os.getenv("ALLOWED_SVC", "svc-spoof-allowed.kloak-e2e.svc.cluster.local")
    other_svc   = os.getenv("OTHER_SVC",   "svc-spoof-other.kloak-e2e.svc.cluster.local")
    interval    = int(os.getenv("REQUEST_INTERVAL", "5"))

    print("=" * 60)
    print("Kloak Demo: DNS SNI Spoofing Prevention")
    print("=" * 60)
    print(f"Allowed service: {allowed_svc}")
    print(f"Other service:   {other_svc}")
    print(f"Secret (shadow): {secret[:30]}...")
    print("=" * 60)
    sys.stdout.flush()

    generate_self_signed_cert()
    threading.Thread(target=echo_server, daemon=True).start()
    time.sleep(1)
    print("Echo server started on port", LISTEN_PORT, flush=True)

    startup_delay = int(os.getenv("STARTUP_DELAY", "15"))
    print(f"Waiting {startup_delay}s for eBPF attachment...", flush=True)
    time.sleep(startup_delay)

    count = 0
    while True:
        count += 1
        print(f"\n--- Request #{count} ---", flush=True)
        try:
            # DNS-resolve both services, populating eBPF dns_ip_map for both ClusterIPs.
            ip_allowed = resolve_to_ip(allowed_svc)
            ip_other   = resolve_to_ip(other_svc)
            print(f"DNS: {allowed_svc[:40]} → {ip_allowed}", flush=True)
            print(f"DNS: {other_svc[:40]} → {ip_other}", flush=True)

            # --- LEGITIMATE path ---
            # Connect to ClusterIP_A (resolved for allowed_svc) with SNI = allowed_svc.
            # eBPF: conn_ip=IP_A → dns_ip_map → allowed_svc == allowed_host → REWRITE expected.
            legit_echo = send_and_echo(ip_allowed, allowed_svc, secret)
            if "kloak:" in legit_echo:
                print("LEGIT_NOT_REWRITTEN", flush=True)
            else:
                print("LEGIT_REWRITTEN", flush=True)

            # --- SPOOF path ---
            # Connect to ClusterIP_B (resolved for other_svc) but set SNI = allowed_svc.
            # eBPF: conn_ip=IP_B → dns_ip_map → other_svc ≠ allowed_host → NO REWRITE expected.
            spoof_echo = send_and_echo(ip_other, allowed_svc, secret)
            if "kloak:" in spoof_echo:
                print("SPOOF_NOT_REWRITTEN", flush=True)
            else:
                print("SPOOF_REWRITTEN", flush=True)

        except Exception as e:
            print(f"Error: {e}", flush=True)

        time.sleep(interval)


if __name__ == "__main__":
    main()
