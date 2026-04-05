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


def generate_certs(tmpdir):
    """Generate RSA and ECDSA self-signed certificates using openssl CLI."""
    san = "subjectAltName=DNS:tls-echo-server,DNS:localhost,IP:127.0.0.1"
    configs = [
        ("rsa", ["-newkey", "rsa:2048"]),
        ("ecdsa", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]),
    ]
    certs = {}
    for name, key_args in configs:
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
        certs[name] = (cert_path, key_path)
        print(f"Generated {name} certificate")
    return certs


class EchoHandler(http.server.BaseHTTPRequestHandler):
    """Echoes request headers and TLS connection metadata as JSON."""

    def log_message(self, format, *args):
        """Suppress default per-request logging."""
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if self.path == "/echo":
            headers = {k: v for k, v in self.headers.items()}
            cipher_info = self.request.cipher()
            tls_version = self.request.version()
            body = json.dumps({
                "headers": headers,
                "tls_version": tls_version or "unknown",
                "cipher": cipher_info[0] if cipher_info else "unknown",
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())
            return

        self.send_response(404)
        self.end_headers()


def main():
    with tempfile.TemporaryDirectory() as tmpdir:
        certs = generate_certs(tmpdir)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Load both certificate types. OpenSSL selects the appropriate one
        # based on the negotiated cipher suite (RSA cert for ECDHE-RSA,
        # ECDSA cert for ECDHE-ECDSA).
        ctx.load_cert_chain(certs["rsa"][0], certs["rsa"][1])
        ctx.load_cert_chain(certs["ecdsa"][0], certs["ecdsa"][1])

        # TLS version range (configurable via env).
        ver_map = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
        min_ver = os.environ.get("TLS_MIN_VERSION", "1.2")
        max_ver = os.environ.get("TLS_MAX_VERSION", "1.3")
        ctx.minimum_version = ver_map.get(min_ver, ssl.TLSVersion.TLSv1_2)
        ctx.maximum_version = ver_map.get(max_ver, ssl.TLSVersion.TLSv1_3)

        # Optional cipher suite override (OpenSSL cipher string format).
        cipher_str = os.environ.get("TLS_CIPHER_SUITES")
        if cipher_str:
            ctx.set_ciphers(cipher_str)
            print(f"Configured ciphers: {cipher_str}")

        server = http.server.HTTPServer(("", 8443), EchoHandler)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

        print("TLS echo server (OpenSSL) listening on :8443", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
