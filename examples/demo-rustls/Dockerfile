# Stage 1: Build librustls from source
FROM rust:bookworm AS rustls-builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN git clone --depth 1 --branch v0.14.1 https://github.com/rustls/rustls-ffi.git .
RUN cargo build --release --locked
RUN mkdir -p /opt/rustls/lib /opt/rustls/include && \
    find target/release -name 'librustls.so' -exec cp {} /opt/rustls/lib/ \; && \
    find . -name 'rustls.h' -path '*/src/*' -exec cp {} /opt/rustls/include/ \;

# Stage 2: Build the C demo
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY --from=rustls-builder /opt/rustls/include/rustls.h /usr/include/
COPY --from=rustls-builder /opt/rustls/lib/librustls.so /usr/lib/
RUN ldconfig
WORKDIR /app
COPY main.c .
RUN gcc -o demo-app main.c -lrustls -Wall

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=rustls-builder /opt/rustls/lib/librustls.so /usr/lib/
COPY --from=builder /app/demo-app /app/demo-app
RUN ldconfig
WORKDIR /app
CMD ["./demo-app"]
