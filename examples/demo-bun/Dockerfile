FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y curl unzip ca-certificates && rm -rf /var/lib/apt/lists/*

# Use the Bun profile build so the SSL_write file offset in bunOffsetTable
# matches the running binary. Profile builds use identical optimisation flags
# to production but retain the symbol table (the production binary is stripped).
# The ARG lets the nightly workflow pin to the version under test.
ARG BUN_VERSION=1.3.14
ARG TARGETARCH=amd64

RUN set -e; \
    case "$TARGETARCH" in \
      amd64|x86_64) BUN_ARCH="x64" ;; \
      arm64|aarch64) BUN_ARCH="aarch64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL \
      "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-${BUN_ARCH}-profile.zip" \
      -o /tmp/bun.zip \
    && unzip -j /tmp/bun.zip "bun-linux-${BUN_ARCH}-profile/bun-profile" -d /usr/local/bin/ \
    && mv /usr/local/bin/bun-profile /usr/local/bin/bun \
    && rm /tmp/bun.zip \
    && chmod +x /usr/local/bin/bun

WORKDIR /app
COPY *.ts .

# Default entry point — override CMD in the deployment to run main-claude.ts.
CMD ["/usr/local/bin/bun", "run", "main.ts"]
