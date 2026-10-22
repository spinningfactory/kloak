"""Minimal TLS echo server. Returns whatever it receives."""

import socket
import ssl
import sys

# Cert is pre-generated at Docker build time by the Dockerfile so there is no
# runtime subprocess dependency and no interaction with LD_LIBRARY_PATH.
CERT_PATH = "/app/cert.pem"
KEY_PATH = "/app/key.pem"
LISTEN_PORT = 8443


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)

    # IPv4 and IPv6 (dual-stack clusters), or IPv4 alone where the pod has
    # no IPv6.
    if socket.has_dualstack_ipv6():
        try:
            srv = socket.create_server(("", LISTEN_PORT), family=socket.AF_INET6,
                                       backlog=5, reuse_port=False, dualstack_ipv6=True)
        except OSError:
            srv = socket.create_server(("0.0.0.0", LISTEN_PORT), backlog=5)
    else:
        srv = socket.create_server(("0.0.0.0", LISTEN_PORT), backlog=5)
    print(f"TLS echo server listening on :{LISTEN_PORT}", flush=True)

    while True:
        conn, addr = srv.accept()
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


if __name__ == "__main__":
    main()
