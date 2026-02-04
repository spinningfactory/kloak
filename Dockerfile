# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache make git

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN make build

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy binary
COPY --from=builder /app/bin/bouncer /app/bouncer

# Run as non-root
RUN adduser -D -u 1000 bouncer
USER bouncer

ENTRYPOINT ["/app/bouncer"]
