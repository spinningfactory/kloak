FROM golang:1.25 AS go-boring

# Build a minimal Go binary with BoringCrypto to get the exact BoringSSL
# snapshot that Go bundles. This ensures offset discovery matches what
# kloak encounters in production Go+BoringCrypto workloads.
WORKDIR /app
RUN echo 'package main; import "C"; import "crypto/tls"; func main() { _ = tls.NewListener }' > main.go \
    && go mod init example.com/boringssltest \
    && GOEXPERIMENT=boringcrypto CGO_ENABLED=1 go build -gcflags='-N -l' -o boring-test main.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git ca-certificates golang perl \
    dwarfdump binutils file \
    && rm -rf /var/lib/apt/lists/*

# Also install pahole if available
RUN apt-get update && apt-get install -y --no-install-recommends dwarves 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# Clone BoringSSL and build with debug symbols for struct inspection
WORKDIR /tmp
RUN git clone --depth=1 https://boringssl.googlesource.com/boringssl

WORKDIR /tmp/boringssl
RUN mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0" .. \
    && make -j$(nproc) ssl crypto

# Copy the Go BoringCrypto binary for comparison
COPY --from=go-boring /app/boring-test /tmp/boring-test

COPY extract_offsets.sh /tmp/extract_offsets.sh
RUN chmod +x /tmp/extract_offsets.sh

ENTRYPOINT ["/tmp/extract_offsets.sh"]
