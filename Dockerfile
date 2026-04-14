# eBPF + Go build stage.
# Runs on the BUILD platform (host arch) regardless of target platform.
# Cross-compiles both eBPF objects and Go binary for the target.
FROM --platform=$BUILDPLATFORM golang:1.25 AS builder

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
ARG TARGETARCH
ARG TARGETOS
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      ARCH_DEFINE=__TARGET_ARCH_x86; \
      export KLOAK_TARGET_ARCH=x86; \
    else \
      ARCH_DEFINE=__TARGET_ARCH_${TARGETARCH}; \
      export KLOAK_TARGET_ARCH=${TARGETARCH}; \
    fi && \
    cd pkg/ebpf && go generate && \
    clang -O2 -g -Wall -Werror -D${ARCH_DEFINE} \
      -target bpfel -c bpf/tls_uprobe.c -o tlsuprobe_bpfel.o && \
    clang -O2 -g -Wall -Werror -D${ARCH_DEFINE} \
      -target bpfeb -c bpf/tls_uprobe.c -o tlsuprobe_bpfeb.o

# Cross-compile Go binary for the target platform (no CGO, pure Go).
# When COVER=1, build with -cover for integration test coverage collection.
ARG COVER=0
RUN if [ "$COVER" = "1" ]; then \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -cover -covermode=atomic -o /kloak ./cmd/kloak; \
    else \
      CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -o /kloak ./cmd/kloak; \
    fi

# Runtime stage — uses the target platform.
FROM alpine:3.23

RUN apk add --no-cache ca-certificates

COPY --from=builder /kloak /kloak

# Coverage output directory (used when built with COVER=1)
RUN mkdir -p /tmp/coverage

RUN adduser -D -u 65532 kloak
USER 65532

ENTRYPOINT ["/kloak"]
