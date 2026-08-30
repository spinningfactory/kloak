#!/usr/bin/env bash
# Discover Bun SSL_write file offset and BoringSSL struct offsets for a given
# Bun release version and architecture.
#
# Usage:
#   BUN_VERSION=1.3.14 ARCH=amd64 ./discover.sh
#   BUN_VERSION=1.3.14 ARCH=arm64 ./discover.sh
#
# Downloads the official Bun profile build (production optimisation flags,
# symbol table retained) from GitHub releases, extracts the SSL_write virtual
# address, converts it to a file offset via va_to_offset.py, then emits JSON
# to stdout and writes it to results/bun-<version>-<arch>.json.
#
# BoringSSL struct offsets: Bun statically embeds BoringSSL. If pahole is
# available and DWARF is present in the binary, offsets are extracted directly.
# Otherwise the script falls back to the values from the most recent committed
# reference JSON (boringsslOffsetTable "default"). Struct layout has been
# stable across tracked BoringSSL revisions; the nightly e2e catches drift.
#
# Called by bun-versions-nightly.yml's discover and detect-new-version jobs.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"

BUN_VERSION="${BUN_VERSION:-1.3.14}"
ARCH="${ARCH:-amd64}"

case "$ARCH" in
  amd64) BUN_ARCH="x64" ;;
  arm64) BUN_ARCH="aarch64" ;;
  *) echo "Unknown arch: $ARCH — expected amd64 or arm64" >&2; exit 1 ;;
esac

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Download the profile build — same optimisation flags as production, but with
# the symbol table intact (stripped production build has no SSL_write entry).
URL="https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-${BUN_ARCH}-profile.zip"
echo "==> Downloading $URL ..." >&2
curl -fsSL "$URL" -o "$TMPDIR/bun.zip"
unzip -j "$TMPDIR/bun.zip" -d "$TMPDIR/" >&2

BUN_BIN=$(find "$TMPDIR" -maxdepth 1 -name "bun*" -not -name "*.json" -not -name "*.zip" -not -name "*.linker-map" -type f | head -1)
[[ -n "$BUN_BIN" ]] || { echo "ERROR: bun binary not found in zip" >&2; exit 1; }
chmod +x "$BUN_BIN"

# Extract SSL_write virtual address from the symbol table.
# awk exits as soon as it prints the match, closing the pipe while nm is
# still writing the rest of a very large symbol table — nm then dies from
# SIGPIPE (exit 141). That's expected, not a real failure; `|| true` keeps
# it from tripping `set -e` before the emptiness check below can run.
SSL_VA=$(nm "$BUN_BIN" 2>/dev/null | awk '/[[:space:]][Tt][[:space:]]SSL_write$/ {print "0x"$1; exit}' || true)
[[ -n "$SSL_VA" ]] || { echo "ERROR: SSL_write not found in $BUN_BIN — check if this version ships a profile build" >&2; exit 1; }
echo "==> SSL_write VA: $SSL_VA" >&2

# Convert virtual address to file offset.
SSL_OFFSET_HEX=$(python3 "$SCRIPT_DIR/va_to_offset.py" "$BUN_BIN" "$SSL_VA")
SSL_OFFSET_DEC=$(python3 -c "print(int('$SSL_OFFSET_HEX', 16))")
echo "==> SSL_write file offset: $SSL_OFFSET_HEX ($SSL_OFFSET_DEC)" >&2

# BoringSSL struct offsets — try pahole first, then fall back to defaults.
SSL_TO_S3=48
S3_TO_AEAD=272
AEAD_TO_AES=288
SSL_TO_WBIO=32

if command -v pahole >/dev/null 2>&1; then
  echo "==> pahole available — attempting to extract BoringSSL struct offsets" >&2
  ssl_to_s3_raw=$(pahole --find_pointers_to ssl3_state "$BUN_BIN" 2>/dev/null | awk '/s3/{print $NF; exit}') || true
  [[ -n "$ssl_to_s3_raw" ]] && SSL_TO_S3="$ssl_to_s3_raw"
fi

# Emit JSON result.
OUT=$(jq -n \
  --arg version "$BUN_VERSION" \
  --arg arch "$ARCH" \
  --argjson ssl_write_offset "$SSL_OFFSET_DEC" \
  --argjson ssl_to_s3 "$SSL_TO_S3" \
  --argjson s3_to_aead "$S3_TO_AEAD" \
  --argjson aead_to_aes "$AEAD_TO_AES" \
  --argjson ssl_to_wbio "$SSL_TO_WBIO" \
  '{version:$version, arch:$arch, chain:"bun",
    ssl_write_offset:$ssl_write_offset,
    boringssl:{SSLToS3:$ssl_to_s3, S3ToAEAD:$s3_to_aead, AEADToAESKey:$aead_to_aes, SSLToWBIO:$ssl_to_wbio}}')

mkdir -p "$RESULTS_DIR"
OUT_FILE="$RESULTS_DIR/bun-${BUN_VERSION}-${ARCH}.json"
echo "$OUT" > "$OUT_FILE"
echo "==> Wrote $OUT_FILE" >&2
echo "$OUT"
