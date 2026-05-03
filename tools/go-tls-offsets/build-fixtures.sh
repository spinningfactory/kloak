#!/usr/bin/env bash
# Build the go-tls-offsets fixture binary against every supported Go version
# × architecture. Outputs ELF binaries to pkg/ebpf/testdata/go-tls-fixtures/
# for the table-driven DWARF tests in pkg/ebpf/go_tls_offsets_test.go.
#
# Containers spin once per (version, arch) cell during fixture generation,
# never per test. The tests themselves read the resulting ELF files from
# disk in milliseconds.
#
# Usage:
#   tools/go-tls-offsets/build-fixtures.sh           # all versions, both arches
#   GO_VERSIONS="1.21 1.22" tools/go-tls-offsets/build-fixtures.sh   # subset
#
# Requirements: Docker with buildx, qemu-user-static for cross-arch builds.

set -euo pipefail

cd "$(dirname "$0")/../.."

OUT="pkg/ebpf/testdata/go-tls-fixtures"
mkdir -p "$OUT"

VERSIONS=(${GO_VERSIONS:-1.20 1.21 1.22 1.23 1.24 1.25 1.26})
ARCHES=(${GO_ARCHES:-amd64 arm64})

for v in "${VERSIONS[@]}"; do
  for a in "${ARCHES[@]}"; do
    out="$OUT/go-$v-$a.elf"
    echo "==> Building $out (golang:$v, GOARCH=$a)"
    docker run --rm \
      -v "$PWD/tools/go-tls-offsets/fixture":/src \
      -w /src \
      -e GOARCH="$a" -e GOOS=linux -e CGO_ENABLED=0 \
      "golang:$v" \
      go build -o "/src/fixture-$v-$a.elf" .
    mv "$PWD/tools/go-tls-offsets/fixture/fixture-$v-$a.elf" "$out"
    ls -lh "$out"
  done
done

echo
echo "Built $((${#VERSIONS[@]} * ${#ARCHES[@]})) fixtures in $OUT/"
