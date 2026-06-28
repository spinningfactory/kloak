# BoringSSL raw-TLS demo client for kloak e2e.
#
# Builds BoringSSL as SHARED libraries (symbols retained — this is the
# dynamically-linked, symbol-bearing BoringSSL case kloak attaches to by the
# SSL_write symbol) from the same release tag the offset table is calibrated
# against, then links the raw-TLS client against them.
#
# Keep BORINGSSL_VERSION in lockstep with the seed tag in
# tools/boringssl-offsets/results/ and pkg/ebpf/boringssl_offsets.go so the
# runtime struct layout matches the discovered offsets.
ARG BORINGSSL_VERSION=0.20260616.0

FROM ubuntu:24.04 AS builder
ARG BORINGSSL_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git golang-go perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone --depth=1 --branch "${BORINGSSL_VERSION}" \
    https://github.com/google/boringssl boringssl

WORKDIR /tmp/boringssl
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
    && cmake --build build --target ssl crypto -j"$(nproc)"

# Collect the shared libs into a known location.
RUN mkdir -p /boring-libs \
    && find build -name 'libssl.so' -exec cp {} /boring-libs/ \; \
    && find build -name 'libcrypto.so' -exec cp {} /boring-libs/ \;

WORKDIR /app
COPY main.c .
RUN gcc -O2 -o demo-app main.c \
    -I/tmp/boringssl/include \
    -L/boring-libs -Wl,-rpath,/usr/lib \
    -lssl -lcrypto -lpthread

# Runtime: install ONLY libstdc++6 (BoringSSL's libssl/libcrypto are C++ and
# need it). Deliberately NOT ca-certificates — it pulls in the system OpenSSL
# (libssl3), and a container holding both OpenSSL and BoringSSL makes kloak's
# detection pick OpenSSL first (it scans the system libcrypto.so.3 and never
# reaches the bundled BoringSSL). The client uses SSL_VERIFY_NONE, so no CA
# bundle is required. The resulting image has exactly one TLS stack: BoringSSL.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/demo-app /app/demo-app
COPY --from=builder /boring-libs/libssl.so /usr/lib/libssl.so
COPY --from=builder /boring-libs/libcrypto.so /usr/lib/libcrypto.so
# Remove the system OpenSSL shared objects (pulled in transitively by the base
# image). A container holding both OpenSSL and BoringSSL makes kloak's detection
# pick OpenSSL first — it scans the system libcrypto.so.3 and never reaches the
# bundled BoringSSL. demo-app links only the BoringSSL /usr/lib/*.so, so the
# system ones are unused at runtime. This leaves exactly one TLS stack.
RUN rm -f /usr/lib/*/libssl.so.3* /usr/lib/*/libcrypto.so.3* && ldconfig
WORKDIR /app
CMD ["./demo-app"]
