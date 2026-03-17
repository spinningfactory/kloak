FROM golang:1.25 AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
# Build with BoringSSL (GOEXPERIMENT=boringcrypto links BoringSSL instead of Go's crypto/tls)
RUN GOEXPERIMENT=boringcrypto CGO_ENABLED=1 GOOS=linux go build -o demo-app main.go

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/demo-app .
CMD ["./demo-app"]
