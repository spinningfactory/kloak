ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o echo main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/echo .
EXPOSE 8443
ENTRYPOINT ["./echo"]
