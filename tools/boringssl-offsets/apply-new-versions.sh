#!/usr/bin/env bash
# Sync the BoringSSL "default" offset row in pkg/ebpf/boringssl_offsets.go with
# the offsets discovered for one or more release tags, after their JSON
# reference files have been generated into results/.
#
# Inputs:
#   $1 — comma-separated list of BoringSSL release tags (e.g. "0.20260616.0")
#
# Unlike OpenSSL (one Go table row per major.minor, selected at runtime by the
# version string the library embeds), BoringSSL embeds no resolvable version,
# so kloak keys every BoringSSL build to a single "default" offset row. The
# nightly matrix is resolved dynamically from github.com/google/boringssl tags,
# so there is no matrix list to edit here.
#
# This script reads the newest tag's results JSON and, if its kloak_config
# differs from the current "default" row, rewrites that row (recording the tag
# in the adjacent comment). When offsets are unchanged it is a no-op — the
# committed results JSON alone records that the tag was verified. Drift between
# tags is also caught by TestBoringSSLOffsets_AgainstReferenceJSON.
#
# Idempotent. Used by boringssl-versions-nightly.yml's auto-PR job.

set -euo pipefail

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "Usage: $0 <comma-separated-tags>" >&2
  echo "  e.g. $0 0.20260616.0" >&2
  exit 1
fi

cd "$(dirname "$0")/../.."

OFFSETS_GO="pkg/ebpf/boringssl_offsets.go"
RESULTS_DIR="tools/boringssl-offsets/results"

IFS=',' read -r -a TAGS <<<"$1"
# Newest tag wins for the "default" row (tags sort lexically by date).
NEWEST=$(printf '%s\n' "${TAGS[@]}" | sort | tail -1)

# Prefer the amd64 JSON (CI's arch); fall back to arm64. The struct layout is
# architecture-independent, so either is authoritative.
json=""
for arch in amd64 arm64; do
  cand="$RESULTS_DIR/boringssl-${NEWEST}-${arch}.json"
  if [ -f "$cand" ]; then json="$cand"; break; fi
done
if [ -z "$json" ]; then
  echo "ERROR: no results JSON for $NEWEST in $RESULTS_DIR — generate it first" >&2
  exit 1
fi

ssl_to_s3=$(jq -r '.kloak_config.SSLToS3' "$json")
s3_to_aead=$(jq -r '.kloak_config.S3ToAEAD' "$json")
aead_to_aeskey=$(jq -r '.kloak_config.AEADToAESKey' "$json")
ssl_to_wbio=$(jq -r '.kloak_config.SSLToWBIO' "$json")

for f in ssl_to_s3 s3_to_aead aead_to_aeskey ssl_to_wbio; do
  v="${!f}"
  if [ -z "$v" ] || [ "$v" = "null" ]; then
    echo "ERROR: $json missing field $f — re-run discovery" >&2
    exit 1
  fi
done

new_row=$(printf '\t"default": {SSLToS3: %s, S3ToAEAD: %s, AEADToAESKey: %s, SSLToWBIO: %s}, // verified against %s' \
  "$ssl_to_s3" "$s3_to_aead" "$aead_to_aeskey" "$ssl_to_wbio" "$NEWEST")

# Replace the existing "default" row in-place. Match the row regardless of its
# trailing comment so re-runs are idempotent.
awk -v newrow="$new_row" '
  /^[[:space:]]*"default":[[:space:]]*\{/ { print newrow; next }
  { print }
' "$OFFSETS_GO" > "$OFFSETS_GO.tmp"
mv "$OFFSETS_GO.tmp" "$OFFSETS_GO"

if command -v gofmt >/dev/null 2>&1; then
  gofmt -w "$OFFSETS_GO"
fi

echo "==> Synced BoringSSL \"default\" offsets from $NEWEST ($json)"
git diff --name-only -- "$OFFSETS_GO" "$RESULTS_DIR" 2>/dev/null || true
