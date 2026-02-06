# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache make git

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

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
