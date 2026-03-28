FROM rust:bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/demo-rust-ureq-openssl /app/demo-app
WORKDIR /app
CMD ["./demo-app"]
