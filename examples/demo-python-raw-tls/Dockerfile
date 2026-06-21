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
# Python's _ssl extension is linked against SONAME libssl.so.3 and loads our
# custom build via LD_LIBRARY_PATH without recompiling Python.
#
# IMPORTANT: pin to -bookworm (OpenSSL 3.0.x). OpenSSL 3.x symbol versioning is
# only forward-compatible: an _ssl built against the base image's OpenSSL can
# load a *newer* libcrypto, but NOT an older one (the older lib lacks the
# OPENSSL_3.x.0 symbol versions -> "version `OPENSSL_3.x.0' not found" at
# `import ssl` -> the container crash-loops). The default `python:3.11-slim`
# tag moved to Debian trixie (OpenSSL 3.5.x), which broke every tested version
# below 3.5. Bookworm's 3.0.x base loads all currently-tracked versions
# (3.0.21 … 3.5.7 and newer) via forward compatibility.
FROM python:3.11-slim-bookworm
COPY --from=openssl-builder /opt/openssl /opt/openssl
ENV LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib

# Point BOTH the standard library paths at our custom OpenSSL so the container
# has exactly one OpenSSL version everywhere — the one the app actually uses.
#
# This matters for kloak's version detection. The kloak controller scans the
# standard lib roots (/usr/lib/<triplet>, /usr/local/lib) and keys its uprobe
# offsets off the *version of libcrypto it finds there*. If we only symlinked
# /usr/local/lib and left the base image's system libcrypto in place, kloak
# would detect the base's version (bookworm = 3.0.20) and push 3.0 (3-hop)
# offsets, while the app's TLS runs through our custom build (e.g. 3.5.0, a
# 4-hop layout) — so the GCM-H walk fails and nothing gets rewritten. By
# overwriting the system libssl/libcrypto links too, every path resolves to the
# same custom inode and kloak detects the correct version.
#
# Links are relative so they resolve correctly when the controller reads them
# via /proc/<pid>/root. Python's _ssl (built against the base's older OpenSSL)
# loads the newer custom lib fine by forward compatibility.
# TODO(kloak): discover libraries from /proc/<pid>/maps instead of fixed scan
# roots so any install prefix works without this symlink workaround.
RUN mkdir -p /usr/local/lib && \
    libdir="$([ -d /opt/openssl/lib64 ] && echo lib64 || echo lib)" && \
    triplet="$(uname -m)-linux-gnu" && \
    for f in libssl.so.3 libcrypto.so.3; do \
      ln -sf "../../../opt/openssl/${libdir}/$f" "/usr/local/lib/$f" && \
      ln -sf "../../../opt/openssl/${libdir}/$f" "/usr/lib/${triplet}/$f"; \
    done

# curl for health probes.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pre-generate the TLS echo server cert at build time so echo_server.py needs
# no subprocess at runtime and is unaffected by LD_LIBRARY_PATH. The custom
# openssl binary uses its own matched libraries (RPATH-linked to /opt/openssl)
# and is independent of the Debian system openssl.
# The 10-year expiry is intentional — this cert is for local demo use only.
RUN OPENSSL_CONF=/dev/null /opt/openssl/bin/openssl req -x509 -newkey rsa:2048 \
    -keyout /app/key.pem -out /app/cert.pem \
    -days 3650 -nodes -subj "/CN=echo-tls"

COPY app.py echo_server.py ./
CMD ["python", "-u", "app.py"]
