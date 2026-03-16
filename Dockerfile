# eBPF generation stage (Debian-based for proper libbpf + clang support)
FROM golang:1.25 AS ebpf-gen

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Map Docker TARGETARCH (amd64, arm64) to kernel arch names (x86, arm64).
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      export KLOAK_TARGET_ARCH=x86; \
    else \
      export KLOAK_TARGET_ARCH=${TARGETARCH}; \
    fi && \
    cd pkg/ebpf && go generate && \
    echo "--- bpf2go generated .o (may be broken) ---" && \
    llvm-objdump -d tlsuprobe_bpfel.o 2>/dev/null | head -5

# Overwrite with directly compiled .o files (bpf2go's llvm-strip corrupts them).
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      ARCH_DEFINE=__TARGET_ARCH_x86; \
    else \
      ARCH_DEFINE=__TARGET_ARCH_${TARGETARCH}; \
    fi && \
    clang -O2 -g -Wall -Werror -D${ARCH_DEFINE} \
      -target bpfel -c pkg/ebpf/bpf/tls_uprobe.c \
      -o pkg/ebpf/tlsuprobe_bpfel.o && \
    clang -O2 -g -Wall -Werror -D${ARCH_DEFINE} \
      -target bpfeb -c pkg/ebpf/bpf/tls_uprobe.c \
      -o pkg/ebpf/tlsuprobe_bpfeb.o && \
    echo "--- direct clang .o (correct) ---" && \
    llvm-objdump -d pkg/ebpf/tlsuprobe_bpfel.o 2>/dev/null | head -5

# Build stage (Alpine for small image)
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Copy correctly generated eBPF files from the ebpf-gen stage
COPY --from=ebpf-gen /app/pkg/ebpf/tlsuprobe_bpfel.go pkg/ebpf/
COPY --from=ebpf-gen /app/pkg/ebpf/tlsuprobe_bpfel.o  pkg/ebpf/
COPY --from=ebpf-gen /app/pkg/ebpf/tlsuprobe_bpfeb.go pkg/ebpf/
COPY --from=ebpf-gen /app/pkg/ebpf/tlsuprobe_bpfeb.o  pkg/ebpf/

RUN CGO_ENABLED=0 go build -o /kloak ./cmd/kloak

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /kloak /kloak

RUN adduser -D -u 65532 kloak
USER 65532

ENTRYPOINT ["/kloak"]
