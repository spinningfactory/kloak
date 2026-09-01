# eBPF + Go build stage.
# Runs on the BUILD platform (host arch) regardless of target platform.
# Cross-compiles both eBPF objects and Go binary for the target.
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Generate eBPF Go wrappers (bpf2go runs on host arch, targets BPF bytecode).
# Then overwrite .o files with direct clang (bpf2go's strip corrupts them).
# Map TARGETARCH (amd64, arm64) to kernel arch defines.
# When BPF_DEBUG=1, define KLOAK_DEBUG so the in-kernel bpf_printk markers in
# tls_uprobe.c are compiled in. Their output streams to
# /sys/kernel/tracing/trace_pipe and is captured by the e2e job.
ARG TARGETARCH
ARG TARGETOS
ARG BPF_DEBUG=0
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      ARCH_DEFINE=__TARGET_ARCH_x86; \
      export KLOAK_TARGET_ARCH=x86; \
    else \
      ARCH_DEFINE=__TARGET_ARCH_${TARGETARCH}; \
      export KLOAK_TARGET_ARCH=${TARGETARCH}; \
    fi && \
    if [ "$BPF_DEBUG" = "1" ]; then \
      DEBUG_DEFINE=-DKLOAK_DEBUG; \
    else \
      DEBUG_DEFINE=; \
    fi && \
    cd pkg/ebpf && go generate && \
    clang -O2 -g -Wall -Werror -D${ARCH_DEFINE} ${DEBUG_DEFINE} \
      -target bpfel -c bpf/tls_uprobe.c -o tlsuprobe_bpfel.o && \
    clang -O2 -g -Wall -Werror -D${ARCH_DEFINE} ${DEBUG_DEFINE} \
      -target bpfeb -c bpf/tls_uprobe.c -o tlsuprobe_bpfeb.o

# Cross-compile Go binary for the target platform (no CGO, pure Go).
# When COVER=1, build with `-cover` for integration test coverage and
# `-tags cover` to pull in cmd/kloak/coverage_flush_cover.go, which
# explicitly flushes covcounters at shutdown via runtime/coverage.
# Production builds (COVER=0) leave that file out — the no-op default in
# coverage_flush.go is used and the binary contains no runtime/coverage
# import.
ARG COVER=0
# VERSION is the release tag baked into the binary so `kloak version`
# can report it. release.yml sets this from the git tag; local builds
# leave it as the default and the binary advertises itself as "dev".
# The commit hash is auto-discovered via runtime/debug.ReadBuildInfo,
# so no extra build-arg is needed for that.
ARG VERSION=dev
RUN if [ "$COVER" = "1" ]; then \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -cover -covermode=atomic -tags cover \
          -ldflags "-X main.version=${VERSION}" \
          -o /kloak ./cmd/kloak; \
    else \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -ldflags "-X main.version=${VERSION}" \
          -o /kloak ./cmd/kloak; \
    fi

# Runtime stage — uses the target platform.
FROM alpine:3.24

RUN apk add --no-cache ca-certificates

COPY --from=builder /kloak /kloak

# Coverage output directory (used when built with COVER=1)
RUN mkdir -p /tmp/coverage

RUN adduser -D -u 65532 kloak
USER 65532

ENTRYPOINT ["/kloak"]
