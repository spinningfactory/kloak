FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev libgnutls28-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY main.c .
RUN gcc -o demo-app main.c -lgnutls -Wall

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgnutls30 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/demo-app .
CMD ["./demo-app"]
