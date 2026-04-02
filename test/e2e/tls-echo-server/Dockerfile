FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go build -o /tls-echo-server main.go

FROM alpine:3.21
COPY --from=builder /tls-echo-server /tls-echo-server
EXPOSE 8443
ENTRYPOINT ["/tls-echo-server"]
