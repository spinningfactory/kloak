#!/usr/bin/env bash
# Discover OpenSSL struct offsets for kloak TLS key extraction.
#
# Usage:
#   ./discover.sh                          # All versions, both architectures
#   ./discover.sh 3.5.0                    # Specific version, both architectures
#   ./discover.sh 3.5.0 linux/arm64        # Specific version and platform
#
# Requirements: docker with buildx and QEMU (for cross-arch)
#   docker buildx create --use
#   docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# OpenSSL versions to discover (tag names from github.com/openssl/openssl)
DEFAULT_VERSIONS=(
  "3.5.0"
  "3.4.1"
  "3.3.3"
  "3.2.4"
  "3.1.7"
  "3.0.16"
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

echo "=== Kloak OpenSSL Offset Discovery ==="
echo "Versions: ${versions[*]}"
echo "Platforms: ${PLATFORMS[*]}"
echo ""

mkdir -p "$SCRIPT_DIR/results"

for version in "${versions[@]}"; do
  for platform in "${PLATFORMS[@]}"; do
    arch="${platform#linux/}"
    outfile="$SCRIPT_DIR/results/openssl-${version}-${arch}.json"
    echo "--- OpenSSL ${version} / ${arch} ---"

    # Build and run in one step
    if docker buildx build \
      --platform "$platform" \
      --build-arg "OPENSSL_VERSION=${version}" \
      --load \
      -t "kloak-offsets:${version}-${arch}" \
      "$SCRIPT_DIR" 2>/dev/null; then

      docker run --rm --platform "$platform" \
        "kloak-offsets:${version}-${arch}" > "$outfile" 2>&1

      echo "  Output: $outfile"
      cat "$outfile"
    else
      echo "  FAILED to build for OpenSSL ${version} / ${arch}"
      echo "{\"error\": \"build failed\", \"version\": \"${version}\", \"arch\": \"${arch}\"}" > "$outfile"
    fi
    echo ""
  done
done

echo "=== Results ==="
echo "All results saved to $SCRIPT_DIR/results/"
ls -la "$SCRIPT_DIR/results/"
