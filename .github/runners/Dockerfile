# Custom GitHub Actions runner image for kloak E2E tests.
# Pre-installs all dependencies so CI jobs only need to:
#   1. Generate eBPF bindings
#   2. Start k3s (background, no systemd)
#   3. Build + import images
#   4. Run tests
#
# Build & push:
#   docker build -t ghcr.io/spinningfactory/kloak-runner:latest .github/runners/
#   docker push ghcr.io/spinningfactory/kloak-runner:latest
#
# Then update the ARC values to use this image instead of
# ghcr.io/actions/actions-runner:latest.

FROM ghcr.io/actions/actions-runner:latest

USER root

# ── System packages: eBPF toolchain + Docker + Helm ──
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev \
      ca-certificates curl gnupg lsb-release \
      make gcc git \
    && rm -rf /var/lib/apt/lists/*

# Docker CE (daemon + CLI)
RUN curl -fsSL https://get.docker.com | sh \
    && rm -rf /var/lib/apt/lists/*

# Helm
RUN curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ── Go ──
ARG GO_VERSION=1.25.3
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

# ── k3s binary (installed, not started — started at job runtime) ──
RUN curl -sfL https://get.k3s.io | INSTALL_K3S_SKIP_START=true INSTALL_K3S_SKIP_ENABLE=true sh -

# Pre-warm Go module cache for faster builds
COPY go.mod go.sum /tmp/kloak/
RUN cd /tmp/kloak && go mod download && rm -rf /tmp/kloak

USER runner
