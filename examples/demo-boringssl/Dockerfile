FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates golang perl \
    && rm -rf /var/lib/apt/lists/*

# Build BoringSSL from source.
# TODO: Pin to a specific commit to ensure struct offsets in
# pkg/ebpf/openssl_offsets.go match this build. Currently uses HEAD which
# may drift from the offsets discovered by tools/boringssl-offsets/.
WORKDIR /tmp
RUN git clone --depth=1 https://boringssl.googlesource.com/boringssl
WORKDIR /tmp/boringssl
RUN mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON .. \
    && make -j$(nproc) ssl crypto

# Build the demo app linked against BoringSSL
WORKDIR /app
COPY main.c .
# Find and copy shared libs to a known location for the runtime stage.
RUN find /tmp/boringssl/build -name 'libssl.so*' -o -name 'libcrypto.so*' | head -10 > /tmp/libpaths.txt \
    && cat /tmp/libpaths.txt \
    && mkdir -p /tmp/boring-libs \
    && find /tmp/boringssl/build -name 'libssl.so' -exec cp {} /tmp/boring-libs/ \; \
    && find /tmp/boringssl/build -name 'libcrypto.so' -exec cp {} /tmp/boring-libs/ \;

RUN gcc -o demo-app main.c \
    -I/tmp/boringssl/include \
    -L/tmp/boring-libs \
    -Wl,-rpath,/usr/lib \
    -lssl -lcrypto -lpthread -lstdc++

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/demo-app /app/demo-app
COPY --from=builder /tmp/boring-libs/libssl.so /usr/lib/libssl.so
COPY --from=builder /tmp/boring-libs/libcrypto.so /usr/lib/libcrypto.so
RUN ldconfig
WORKDIR /app
CMD ["./demo-app"]
