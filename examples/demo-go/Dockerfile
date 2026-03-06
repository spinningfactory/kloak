FROM golang:1.22 AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o demo-app main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/demo-app .
CMD ["./demo-app"]
