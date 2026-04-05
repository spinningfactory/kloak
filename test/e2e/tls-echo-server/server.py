#!/usr/bin/env python3
"""TLS echo server for kloak e2e cipher suite tests.

Uses Python's ssl module (backed by OpenSSL) for full cipher suite support,
including ECDHE-RSA, ECDHE-ECDSA, and all TLS 1.3 cipher suites.
The Go stdlib TLS stack cannot reliably negotiate ECDHE-RSA ciphers when
both certificate types are present; OpenSSL handles this correctly.
"""

import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile


def generate_cert(tmpdir, name, key_args):
    """Generate a self-signed certificate using the openssl CLI."""
    san = "subjectAltName=DNS:tls-echo-server,DNS:localhost,IP:127.0.0.1"
    key_path = os.path.join(tmpdir, f"{name}.key")
    cert_path = os.path.join(tmpdir, f"{name}.crt")
    result = subprocess.run(
        [
            "openssl", "req", "-x509", *key_args, "-nodes",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-subj", "/CN=tls-echo-server",
            "-addext", san,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"cert generation failed ({name}): {result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"Generated {name} certificate: {cert_path}", flush=True)
    return cert_path, key_path


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """Echoes request headers and TLS connection metadata as JSON."""

    def log_message(self, format, *args):
        pass  # suppress default per-request access log

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if self.path == "/echo":
            headers = {k: v for k, v in self.headers.items()}
            cipher_info = self.request.cipher()
            body = json.dumps({
                "headers": headers,
                "tls_version": self.request.version() or "unknown",
                "cipher": cipher_info[0] if cipher_info else "unknown",
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            # Content-Length lets curl determine response end without waiting
            # for connection close, avoiding curl exit 56 (CURLE_RECV_ERROR)
            # from Python's unclean TLS shutdown.
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Generate both RSA and ECDSA certificates. OpenSSL stores them in
        # separate per-key-type slots in the SSL_CTX, so the server can
        # negotiate ECDHE-RSA-* ciphers (using RSA cert) and ECDHE-ECDSA-*
        # ciphers (using ECDSA cert) on the same listener.
        rsa_cert, rsa_key = generate_cert(
            tmpdir, "rsa", ["-newkey", "rsa:2048"])
        ecdsa_cert, ecdsa_key = generate_cert(
            tmpdir, "ecdsa", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"])

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Load RSA cert first, then ECDSA. Python's ssl module passes each
        # call to SSL_CTX_use_certificate / SSL_CTX_use_PrivateKey which
        # OpenSSL routes to the correct per-key-type slot, so both survive.
        ctx.load_cert_chain(certfile=rsa_cert, keyfile=rsa_key)
        ctx.load_cert_chain(certfile=ecdsa_cert, keyfile=ecdsa_key)

        # TLS version range (configurable via env for debugging).
        ver_map = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
        ctx.minimum_version = ver_map.get(
            os.environ.get("TLS_MIN_VERSION", "1.2"), ssl.TLSVersion.TLSv1_2)
        ctx.maximum_version = ver_map.get(
            os.environ.get("TLS_MAX_VERSION", "1.3"), ssl.TLSVersion.TLSv1_3)

        # Explicitly enable the TLS 1.2 GCM ciphers kloak supports.
        # Without this, Alpine's OpenSSL default policy may exclude them.
        # TLS 1.3 ciphers (AES-128-GCM, AES-256-GCM) are always available
        # and cannot be restricted via set_ciphers() in Python.
        cipher_str = os.environ.get(
            "TLS_CIPHER_SUITES",
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES256-GCM-SHA384",
        )
        ctx.set_ciphers(cipher_str)

        print(f"TLS version range: {ctx.minimum_version.name} - {ctx.maximum_version.name}", flush=True)
        print(f"Cipher list: {cipher_str}", flush=True)

        server = http.server.HTTPServer(("", 8443), EchoHandler)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

        print("TLS echo server (OpenSSL) listening on :8443", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
