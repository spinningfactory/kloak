"""Minimal TLS echo server. Returns whatever it receives."""

import socket
import ssl
import sys

# Cert is pre-generated at Docker build time by the Dockerfile so there is no
# runtime subprocess dependency and no interaction with LD_LIBRARY_PATH.
CERT_PATH = "/app/cert.pem"
KEY_PATH = "/app/key.pem"
LISTEN_PORT = 8443


# The client (app.py) sends one message of MESSAGE_LINES newline-terminated
# lines and waits for its echo. A message larger than a TLS record (16 KiB
# of plaintext) arrives in several records, and one recv returns one record
# at most: read until the whole message is in, the client closes, or it
# stops sending for READ_TIMEOUT seconds (a single-threaded server must not
# wait on one connection forever).
MESSAGE_LINES = 2
MAX_MESSAGE = 4 << 20
READ_TIMEOUT = 5


def read_message(tls_conn):
    buf = b""
    try:
        while buf.count(b"\n") < MESSAGE_LINES and len(buf) < MAX_MESSAGE:
            data = tls_conn.recv(65536)
            if not data:
                break
            buf += data
    except socket.timeout:
        pass
    return buf


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
            conn.settimeout(READ_TIMEOUT)
            tls_conn = ctx.wrap_socket(conn, server_side=True)
            data = read_message(tls_conn)
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
