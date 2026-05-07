ARG GO_VERSION=1.26
FROM golang:${GO_VERSION} AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o demo-app main.go

FROM alpine:latest
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=builder /app/demo-app .
CMD ["./demo-app"]
