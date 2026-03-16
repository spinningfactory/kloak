# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies (clang/llvm for eBPF compilation)
RUN apk add --no-cache make git clang llvm libbpf-dev

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Generate eBPF bindings for the build platform.
# Map Docker TARGETARCH (amd64, arm64) to kernel arch names (x86, arm64).
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      export KLOAK_TARGET_ARCH=x86; \
    else \
      export KLOAK_TARGET_ARCH=${TARGETARCH}; \
    fi && \
    cd pkg/ebpf && go generate

# Build single binary
RUN CGO_ENABLED=0 go build -o /kloak ./cmd/kloak

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binary
COPY --from=builder /kloak /kloak

# Run as non-root (UID 65532 = nonroot, matches K8s manifest)
RUN adduser -D -u 65532 kloak
USER 65532

ENTRYPOINT ["/kloak"]
