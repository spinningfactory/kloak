#!/usr/bin/env bash
# Insert new Bun version rows into pkg/ebpf/bun_offsets.go after discovering
# their offsets into tools/bun-offsets/results/.
#
# Usage:  apply-new-versions.sh <comma-separated-versions>
#   e.g.  apply-new-versions.sh 1.3.14
#         apply-new-versions.sh 1.3.14,1.3.15
#
# Unlike BoringSSL (one "default" row), each Bun version gets its own row
# per architecture because SSL_write's file offset changes with every release.
# This script inserts missing rows and is a no-op for versions already present.
#
# Called by bun-versions-nightly.yml's detect-new-version job.

set -euo pipefail

if [[ $# -lt 1 || -z "${1:-}" ]]; then
  echo "Usage: $0 <comma-separated-versions>" >&2
  echo "  e.g. $0 1.3.14" >&2
  exit 1
fi

cd "$(dirname "$0")/../.."

BUN_GO="pkg/ebpf/bun_offsets.go"
RESULTS_DIR="tools/bun-offsets/results"

IFS=',' read -r -a VERSIONS <<<"$1"

for ver in "${VERSIONS[@]}"; do
  for arch in amd64 arm64; do
    json="$RESULTS_DIR/bun-${ver}-${arch}.json"
    if [[ ! -f "$json" ]]; then
      echo "WARN: no results JSON for $ver/$arch — skipping (run discover.sh first)" >&2
      continue
    fi

    ssl_write_offset=$(jq '.ssl_write_offset' "$json")
    ssl_to_s3=$(jq '.boringssl.SSLToS3' "$json")
    s3_to_aead=$(jq '.boringssl.S3ToAEAD' "$json")
    aead_to_aes=$(jq '.boringssl.AEADToAESKey' "$json")
    ssl_to_wbio=$(jq '.boringssl.SSLToWBIO' "$json")

    for f in ssl_write_offset ssl_to_s3 s3_to_aead aead_to_aes ssl_to_wbio; do
      v="${!f}"
      if [[ -z "$v" || "$v" == "null" ]]; then
        echo "ERROR: $json missing field $f — re-run discover.sh" >&2
        exit 1
      fi
    done

    key="${ver}/${arch}"
    # Skip if row already present (idempotent).
    if grep -qF "\"${key}\":" "$BUN_GO"; then
      echo "==> $key already in bunOffsetTable — skipping" >&2
      continue
    fi

    new_row=$(printf '\t"%s": {SSLWriteOffset: %s, BoringSSL: BoringSSLOffsets{SSLToS3: %s, S3ToAEAD: %s, AEADToAESKey: %s, SSLToWBIO: %s}}, // discovered from bun-v%s profile build' \
      "$key" "$ssl_write_offset" "$ssl_to_s3" "$s3_to_aead" "$aead_to_aes" "$ssl_to_wbio" "$ver")

    # Insert before the closing brace of bunOffsetTable.
    awk -v row="$new_row" '
      /^}$/ && in_table { print row; in_table=0 }
      /^var bunOffsetTable/ { in_table=1 }
      { print }
    ' "$BUN_GO" > "$BUN_GO.tmp"
    mv "$BUN_GO.tmp" "$BUN_GO"

    echo "==> Inserted $key into bunOffsetTable" >&2
  done
done

if command -v gofmt >/dev/null 2>&1; then
  gofmt -w "$BUN_GO"
fi

echo "==> Done"
git diff --name-only -- "$BUN_GO" "$RESULTS_DIR" 2>/dev/null || true
