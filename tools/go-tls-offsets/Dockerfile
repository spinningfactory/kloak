# Builds the go-tls-offsets fixture binary against a chosen Go version, then
# runs the discovery tool against it. ENTRYPOINT prints the JSON output to
# stdout — the workflow captures that to tools/go-tls-offsets/results/.
#
# Used by .github/workflows/go-tls-offsets.yml (on-demand) and
# .github/workflows/go-versions-nightly.yml (scheduled / version watcher).
#
# Mirrors the shape of tools/openssl-offsets/Dockerfile.

# GO_VERSION is the version the fixture is COMPILED WITH (drives the struct
# layout the tool will discover). DISCOVERY_GO_VERSION is the toolchain that
# builds the discovery binary itself — it must satisfy the parent kloak
# module's `go 1.26.0` directive, so it's pinned independently.
ARG GO_VERSION=1.26
ARG DISCOVERY_GO_VERSION=1.26

# ─── Stage 1: build the fixture with the target Go version (DWARF retained)
FROM golang:${GO_VERSION} AS fixture-builder
WORKDIR /src
COPY fixture/ ./
# No -ldflags="-s -w" — we need DWARF for offset extraction.
RUN CGO_ENABLED=0 GOOS=linux go build -o /fixture .

# ─── Stage 2: build the discovery tool with a modern Go toolchain
# (independent of GO_VERSION — older images would fail on `go 1.26.0`).
FROM golang:${DISCOVERY_GO_VERSION} AS discoverer
WORKDIR /src
COPY main.go ./
RUN go build -o /go-tls-offsets .

# ─── Stage 3: minimal runtime image
FROM debian:bookworm-slim
COPY --from=discoverer /go-tls-offsets /go-tls-offsets
COPY --from=fixture-builder /fixture /fixture
ENTRYPOINT ["/go-tls-offsets", "/fixture"]
