"""Minimal TLS echo server. Returns whatever it receives."""

import socket
import ssl
import subprocess
import sys

CERT_PATH = "/tmp/cert.pem"
KEY_PATH = "/tmp/key.pem"
LISTEN_PORT = 8443


def generate_self_signed_cert():
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_PATH, "-out", CERT_PATH,
            "-days", "365", "-nodes", "-subj", "/CN=echo-tls",
        ],
        check=True,
        capture_output=True,
    )
    print(f"Generated self-signed cert at {CERT_PATH}", flush=True)


def main():
    generate_self_signed_cert()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(5)
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
