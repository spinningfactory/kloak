#!/usr/bin/env bash
# Discover BoringSSL struct offsets for kloak TLS key extraction.
#
# Usage:
#   ./discover.sh                          # default tag, both architectures
#   ./discover.sh 0.20260616.0             # specific release tag, both arches
#   ./discover.sh 0.20260616.0 linux/arm64 # specific tag and platform
#
# BoringSSL has no semver ABI guarantee; we key off its published release tags
# (0.YYYYMMDD.0 from github.com/google/boringssl).
#
# Requirements: docker with buildx and QEMU (for cross-arch)
#   docker buildx create --use
#   docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DEFAULT_VERSIONS=(
  "0.20260616.0"
)

PLATFORMS=("linux/arm64" "linux/amd64")

versions=("${@:-${DEFAULT_VERSIONS[@]}}")
if [[ $# -ge 2 ]]; then
  versions=("$1")
  PLATFORMS=("$2")
fi
if [[ $# -eq 1 ]]; then
  versions=("$1")
fi

echo "=== Kloak BoringSSL Offset Discovery ==="
echo "Versions: ${versions[*]}"
echo "Platforms: ${PLATFORMS[*]}"
echo ""

mkdir -p "$SCRIPT_DIR/results"

for version in "${versions[@]}"; do
  for platform in "${PLATFORMS[@]}"; do
    arch="${platform#linux/}"
    outfile="$SCRIPT_DIR/results/boringssl-${version}-${arch}.json"
    echo "--- BoringSSL ${version} / ${arch} ---"

    if docker buildx build \
      --platform "$platform" \
      --build-arg "BORINGSSL_VERSION=${version}" \
      --load \
      -t "kloak-boringssl-offsets:${version}-${arch}" \
      "$SCRIPT_DIR" 2>/dev/null; then

      # stdout is the JSON; stderr carries the pahole struct dumps.
      docker run --rm --platform "$platform" \
        "kloak-boringssl-offsets:${version}-${arch}" > "$outfile" 2>/dev/null

      echo "  Output: $outfile"
      cat "$outfile"
    else
      echo "  FAILED to build for BoringSSL ${version} / ${arch}"
      echo "{\"error\": \"build failed\", \"version\": \"${version}\", \"arch\": \"${arch}\"}" > "$outfile"
    fi
    echo ""
  done
done

echo "=== Results ==="
echo "All results saved to $SCRIPT_DIR/results/"
ls -la "$SCRIPT_DIR/results/"
