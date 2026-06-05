ARG OPENSSL_VERSION=3.5.0

# Stage 1: build OpenSSL from source as shared libraries. Mirrors
# tools/openssl-offsets/Dockerfile so the demo runs against the exact
# libssl version under test.
FROM debian:bookworm-slim AS openssl-builder
ARG OPENSSL_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /tmp/openssl-src \
    && curl -fsSL \
    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    | tar xz -C /tmp/openssl-src --strip-components=1
WORKDIR /tmp/openssl-src
RUN ./Configure \
    --prefix=/opt/openssl \
    --openssldir=/opt/openssl/ssl \
    shared \
    no-tests \
    && make -j"$(nproc)" build_sw \
    && make install_sw

# Stage 2: Python demo image using our custom OpenSSL via LD_LIBRARY_PATH.
# Python's _ssl extension is linked against SONAME libssl.so.3; all
# OpenSSL 3.x share that SONAME and maintain binary ABI compatibility,
# so LD_LIBRARY_PATH causes Python to load our custom build without
# recompiling Python itself.
FROM python:3.11-slim
COPY --from=openssl-builder /opt/openssl /opt/openssl
ENV LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib

# curl for health probes.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pre-generate the TLS echo server cert at build time so echo_server.py needs
# no subprocess at runtime and is unaffected by LD_LIBRARY_PATH. The custom
# openssl binary uses its own matched libraries (RPATH-linked to /opt/openssl)
# and is independent of the Debian system openssl.
# The 10-year expiry is intentional — this cert is for local demo use only.
RUN /opt/openssl/bin/openssl req -x509 -newkey rsa:2048 \
    -keyout /app/key.pem -out /app/cert.pem \
    -days 3650 -nodes -subj "/CN=echo-tls"

COPY app.py echo_server.py ./
CMD ["python", "-u", "app.py"]
