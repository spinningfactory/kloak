# BoringSSL struct-offset discovery image.
#
# Builds a given BoringSSL release tag from source with debug info (-g -O0)
# and runs extract_offsets.sh (pahole/DWARF) to emit the kloak TLS struct
# offsets as JSON. Mirrors tools/openssl-offsets/Dockerfile.
#
# BoringSSL is a rolling git repo with no semver ABI guarantee; we key the
# offset table off its published release tags (0.YYYYMMDD.0).
ARG BORINGSSL_VERSION=0.20260616.0

FROM ubuntu:24.04

ARG BORINGSSL_VERSION

# build-essential + cmake + golang to build BoringSSL's ssl/crypto targets;
# dwarves provides pahole; git to fetch the tagged source.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git golang-go perl ca-certificates dwarves \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN git clone --depth=1 --branch "${BORINGSSL_VERSION}" \
    https://github.com/google/boringssl boringssl

WORKDIR /tmp/boringssl
# Debug build, no optimization, keep object files for pahole. Only the ssl
# and crypto libraries are needed (skip the Rust pki bindings / tests).
RUN cmake -B build -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0" \
    && cmake --build build --target ssl crypto -j"$(nproc)"

COPY extract_offsets.sh /tmp/extract_offsets.sh
RUN chmod +x /tmp/extract_offsets.sh

ENV BORINGSSL_VERSION=${BORINGSSL_VERSION}
ENTRYPOINT ["/tmp/extract_offsets.sh"]
