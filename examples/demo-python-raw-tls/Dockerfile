ARG OPENSSL_VERSION=3.5.0

# Which Python the demo runs on:
#   system: python:3.11-slim-bookworm, whose _ssl loads the custom OpenSSL in
#           place of Debian's. Works for OpenSSL 3.x only (see runtime-system).
#   source: CPython built from source against the custom OpenSSL. Needed for
#           OpenSSL 4.x and later: no prebuilt Python image links libssl.so.4.
ARG PYTHON_RUNTIME=system

# CPython release for PYTHON_RUNTIME=source. OpenSSL 4 removed APIs that older
# releases still need: 3.11 doesn't compile _ssl against it, and 3.14's _ssl
# fails to import (undefined symbol TLSv1_method).
ARG PYTHON_VERSION=3.15.2

# Stage 1: build OpenSSL from source as shared libraries. Mirrors
# tools/openssl-offsets/Dockerfile so the demo runs against the exact
# libssl version under test. --libdir=lib keeps the libraries in one place on
# every arch (OpenSSL defaults to lib64 on x86_64).
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
    --libdir=lib \
    shared \
    no-tests \
    && make -j"$(nproc)" build_sw \
    && make install_sw

# Stage 2 (PYTHON_RUNTIME=system): Python demo image using our custom OpenSSL
# via LD_LIBRARY_PATH. Python's _ssl extension is linked against SONAME
# libssl.so.3 and loads our custom build via LD_LIBRARY_PATH without
# recompiling Python.
#
# IMPORTANT: pin to -bookworm (OpenSSL 3.0.x). OpenSSL 3.x symbol versioning is
# only forward-compatible: an _ssl built against the base image's OpenSSL can
# load a *newer* libcrypto, but NOT an older one (the older lib lacks the
# OPENSSL_3.x.0 symbol versions -> "version `OPENSSL_3.x.0' not found" at
# `import ssl` -> the container crash-loops). The default `python:3.11-slim`
# tag moved to Debian trixie (OpenSSL 3.5.x), which broke every tested version
# below 3.5. Bookworm's 3.0.x base loads all currently-tracked versions
# (3.0.21 … 3.5.7 and newer) via forward compatibility.
FROM python:3.11-slim-bookworm AS runtime-system
COPY --from=openssl-builder /opt/openssl /opt/openssl
ENV LD_LIBRARY_PATH=/opt/openssl/lib

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
    triplet="$(uname -m)-linux-gnu" && \
    for f in libssl.so.3 libcrypto.so.3; do \
      ln -sf "../../../opt/openssl/lib/$f" "/usr/local/lib/$f" && \
      ln -sf "../../../opt/openssl/lib/$f" "/usr/lib/${triplet}/$f"; \
    done

# curl for health probes.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Stage 2 (PYTHON_RUNTIME=source): CPython built against the custom OpenSSL.
FROM debian:bookworm-slim AS python-builder
ARG PYTHON_VERSION
# No libssl-dev: _ssl and _hashlib must link the custom OpenSSL, not Debian's.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=openssl-builder /opt/openssl /opt/openssl
RUN mkdir -p /tmp/python-src \
    && curl -fsSL "https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz" \
    | tar xz -C /tmp/python-src --strip-components=1
WORKDIR /tmp/python-src
# The test suite, static library and debug symbols only take room in the image.
RUN ./configure \
    --prefix=/usr/local \
    --with-openssl=/opt/openssl \
    --with-openssl-rpath=auto \
    --without-ensurepip \
    --disable-test-modules \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /usr/local/lib/python3*/test \
    && find /usr/local/lib -name 'libpython*.a' -delete \
    && strip --strip-unneeded "/usr/local/bin/python${PYTHON_VERSION%.*}" \
       /usr/local/lib/python3*/lib-dynload/*.so \
    && ln -s python3 /usr/local/bin/python

# debian:bookworm-slim ships no libssl/libcrypto, so the custom OpenSSL is the
# only one in the image. kloak still has to find it in one of the lib roots it
# scans, so link it into /usr/local/lib (same TODO as runtime-system).
FROM debian:bookworm-slim AS runtime-source
COPY --from=openssl-builder /opt/openssl /opt/openssl
COPY --from=python-builder /usr/local /usr/local
ENV LD_LIBRARY_PATH=/opt/openssl/lib
RUN cd /opt/openssl/lib && \
    for f in libssl.so.* libcrypto.so.*; do \
      ln -sf "../../../opt/openssl/lib/$f" "/usr/local/lib/$f"; \
    done

FROM runtime-${PYTHON_RUNTIME}
ARG OPENSSL_VERSION
ARG PYTHON_RUNTIME

# Fail the build, not the pod, when Python can't run on the OpenSSL under test
# (e.g. OpenSSL 4.x with PYTHON_RUNTIME=system), or runs on another one.
RUN python -c 'import ssl, sys; print(ssl.OPENSSL_VERSION); sys.exit(ssl.OPENSSL_VERSION.split()[1] != sys.argv[1])' \
    "${OPENSSL_VERSION}" \
    || { echo "Python can't use OpenSSL ${OPENSSL_VERSION} with PYTHON_RUNTIME=${PYTHON_RUNTIME}; OpenSSL 4.x and later need PYTHON_RUNTIME=source" >&2; exit 1; }

WORKDIR /app

# Pre-generate the TLS echo server cert at build time so echo_server.py needs
# no subprocess at runtime. The custom openssl binary loads the custom
# libraries through LD_LIBRARY_PATH, and OPENSSL_CONF=/dev/null keeps it off
# any system openssl.cnf.
# The 10-year expiry is intentional — this cert is for local demo use only.
RUN OPENSSL_CONF=/dev/null /opt/openssl/bin/openssl req -x509 -newkey rsa:2048 \
    -keyout /app/key.pem -out /app/cert.pem \
    -days 3650 -nodes -subj "/CN=echo-tls"

COPY app.py echo_server.py ./
CMD ["python", "-u", "app.py"]
