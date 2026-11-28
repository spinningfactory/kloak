ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
# Not stripped: kloak attaches its Go crypto/tls uprobe by symbol.
RUN CGO_ENABLED=0 GOOS=linux go build -o kloak-lossy-tls main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/kloak-lossy-tls .
EXPOSE 8443
ENTRYPOINT ["./kloak-lossy-tls"]
