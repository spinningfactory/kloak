#!/usr/bin/env bash
# Build the go-tls-offsets fixture binary against every supported Go version
# × architecture. Outputs ELF binaries to pkg/ebpf/testdata/go-tls-fixtures/
# for the table-driven DWARF tests in pkg/ebpf/go_tls_offsets_test.go.
#
# Versions are auto-discovered from go.dev's release feed: every stable
# major.minor at or above GO_MIN_VERSION (default 1.20) is built. This
# means a new Go release ships → the next run picks it up automatically;
# no edits to this script when the upstream version list changes.
#
# Containers spin once per (version, arch) cell during fixture generation,
# never per test. The tests themselves read the resulting ELF files from
# disk in milliseconds.
#
# Usage:
#   tools/go-tls-offsets/build-fixtures.sh                          # MIN=1.20, both arches
#   GO_MIN_VERSION=1.22 tools/go-tls-offsets/build-fixtures.sh      # narrower window
#   GO_VERSIONS="1.21 1.22" tools/go-tls-offsets/build-fixtures.sh  # explicit list (skips discovery)
#   GO_ARCHES="amd64" tools/go-tls-offsets/build-fixtures.sh        # one arch
#
# Requirements: Docker with buildx, qemu-user-static for cross-arch builds,
# curl + jq for upstream version discovery (only when GO_VERSIONS is unset).

set -euo pipefail

cd "$(dirname "$0")/../.."

OUT="pkg/ebpf/testdata/go-tls-fixtures"
mkdir -p "$OUT"

MIN="${GO_MIN_VERSION:-1.20}"

if [ -n "${GO_VERSIONS:-}" ]; then
  # Explicit list provided — use it verbatim, skip upstream discovery.
  read -r -a VERSIONS <<<"$GO_VERSIONS"
else
  # Pull stable major.minor versions from go.dev, keep those ≥ MIN.
  echo "==> Discovering Go versions ≥ $MIN from go.dev"
  awk_min=$(echo "$MIN" | awk -F. '{ printf "%d.%d", $1, $2 }')
  mapfile -t VERSIONS < <(
    curl -fsS "https://go.dev/dl/?mode=json&include=all" \
      | jq -r '.[] | select(.stable) | .version' \
      | sed 's/^go//' \
      | awk -F. '{ printf "%d.%d\n", $1, $2 }' \
      | sort -u -V \
      | awk -v m="$awk_min" -F. '{ v = $1 "." $2; cur = $1 + $2/100; lim = (split(m, mm, ".") ? mm[1] + mm[2]/100 : 0); if (cur >= lim) print v }'
  )
  echo "    Versions: ${VERSIONS[*]}"
fi

if [ ${#VERSIONS[@]} -eq 0 ]; then
  echo "ERROR: no Go versions to build (MIN=$MIN, GO_VERSIONS=${GO_VERSIONS:-unset})" >&2
  exit 1
fi

read -r -a ARCHES <<<"${GO_ARCHES:-amd64 arm64}"

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
