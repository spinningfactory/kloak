"""Minimal TLS echo server. Returns whatever it receives."""

import os
import socket
import ssl
import subprocess
import sys

CERT_PATH = "/tmp/cert.pem"
KEY_PATH = "/tmp/key.pem"
LISTEN_PORT = 8443


def generate_self_signed_cert():
    # Strip LD_LIBRARY_PATH so the system openssl binary uses its own matched
    # libraries (Debian bookworm's 3.0.x), not the custom build loaded via
    # LD_LIBRARY_PATH. The custom libcrypto is compiled with --openssldir=
    # /opt/openssl/ssl which has no openssl.cnf (make install_sw skips it),
    # causing openssl req to fail.  Python's _ssl module still picks up the
    # custom OpenSSL for the TLS server itself — LD_LIBRARY_PATH is still set
    # in the process environment, only the cert-generation subprocess is
    # isolated.
    # TODO: replace subprocess cert generation with the cryptography library
    # so this image has no dependency on the system openssl CLI.
    env = os.environ.copy()
    env.pop("LD_LIBRARY_PATH", None)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_PATH, "-out", CERT_PATH,
            "-days", "365", "-nodes", "-subj", "/CN=echo-tls",
        ],
        check=True,
        capture_output=True,
        env=env,
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
