#!/usr/bin/env bash
# Append opensslOffsetTable entries + matrix list updates for newly-supported
# OpenSSL versions, after their JSON reference files have been generated.
#
# Inputs:
#   $1 — comma-separated list of new full versions (e.g. "3.6.0,3.7.0")
#
# Reads tools/openssl-offsets/results/openssl-<v>-amd64.json (must exist)
# and updates:
#   - pkg/ebpf/openssl_offsets.go         (appends to opensslOffsetTable)
#   - .github/workflows/openssl-offsets.yml  (appends to matrix.openssl)
#
# Note: openssl-versions-nightly.yml is NOT updated here — its discover/e2e
# matrix is resolved dynamically at runtime via the resolve-matrix job, so
# adding a row to opensslOffsetTable is enough for it to appear automatically.
#
# Idempotent: versions already in the table or matrix are skipped.
# Used by openssl-versions-nightly.yml's auto-PR job.

set -euo pipefail

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "Usage: $0 <comma-separated-versions>" >&2
  echo "  e.g. $0 3.6.0,3.7.0" >&2
  exit 1
fi

cd "$(dirname "$0")/../.."

IFS=',' read -r -a NEW_VERSIONS <<<"$1"

OFFSETS_GO="pkg/ebpf/openssl_offsets.go"
DISCOVERY_YML=".github/workflows/openssl-offsets.yml"

for v in "${NEW_VERSIONS[@]}"; do
  json="tools/openssl-offsets/results/openssl-$v-amd64.json"
  if [ ! -f "$json" ]; then
    echo "ERROR: $json not found — generate it before running this script" >&2
    exit 1
  fi

  # Derive major.minor table key (e.g. "3.6" from "3.6.0").
  major_minor=$(echo "$v" | awk -F. '{ printf "%d.%d", $1, $2 }')

  # ── opensslOffsetTable insert ──────────────────────────────────────────────
  if grep -qE "^[[:space:]]+\"${major_minor}\":[[:space:]]*\{" "$OFFSETS_GO"; then
    echo "==> $major_minor already in $OFFSETS_GO — skipping table insert"
  else
    ssl_to_wrl=$(jq -r '.kloak_config.SSLToWRL' "$json")
    wrl_to_enc=$(jq -r '.kloak_config.WRLToEncCtx' "$json")
    enc_to_algctx=$(jq -r '.kloak_config.EncCtxToAlgctx' "$json")
    algctx_to_h=$(jq -r '.kloak_config.AlgctxToH' "$json")
    ssl_to_ver=$(jq -r '.kloak_config.SSLToVersion' "$json")
    ssl_to_wbio=$(jq -r '.kloak_config.SSLToWBIO' "$json")

    for field in ssl_to_wrl wrl_to_enc enc_to_algctx algctx_to_h ssl_to_ver ssl_to_wbio; do
      val="${!field}"
      if [ -z "$val" ] || [ "$val" = "null" ]; then
        echo "ERROR: $json is missing field $field — re-run offset discovery" >&2
        exit 1
      fi
    done

    entry=$(printf '\t"%s": {SSLToWRL: %s, WRLToEncCtx: %s, EncCtxToAlgctx: %s, AlgctxToH: %s, SSLToVersion: %s, SSLToWBIO: %s},' \
      "$major_minor" "$ssl_to_wrl" "$wrl_to_enc" "$enc_to_algctx" "$algctx_to_h" "$ssl_to_ver" "$ssl_to_wbio")

    # Insert immediately before the closing `}` of opensslOffsetTable.
    awk -v new="$entry" '
      /^var opensslOffsetTable = map\[string\]TLSOffsets\{/ { in_map=1; print; next }
      in_map && /^\}$/ { print new; print; in_map=0; next }
      { print }
    ' "$OFFSETS_GO" > "$OFFSETS_GO.tmp"
    mv "$OFFSETS_GO.tmp" "$OFFSETS_GO"
    echo "==> Inserted OpenSSL $major_minor entry into $OFFSETS_GO"
  fi

  # ── matrix.openssl append ─────────────────────────────────────────────────
  # The openssl matrix is a YAML block list (one entry per line). We append
  # the new full version immediately after the last existing `- "X.Y.Z"` entry
  # in each openssl: section, using awk to locate the insertion point.
  for yml in "$DISCOVERY_YML"; do
    [ -f "$yml" ] || continue
    if grep -qF "\"$v\"" "$yml"; then
      echo "==> $v already in $yml — skipping"
      continue
    fi
    # Insert `          - "v"` immediately after the last `- "X.Y.Z"` line
    # in each openssl: block. Stream-based so line order is preserved.
    awk -v new="          - \"$v\"" '
      /^[[:space:]]+openssl:/ { in_openssl=1; has_versions=0; print; next }
      in_openssl && /^[[:space:]]+-[[:space:]]+"[0-9]+\.[0-9]+\.[0-9]+"/ {
        has_versions=1; print; next
      }
      in_openssl {
        if (has_versions) { print new; has_versions=0 }
        in_openssl=0
      }
      { print }
      END { if (in_openssl && has_versions) print new }
    ' "$yml" > "$yml.tmp"
    mv "$yml.tmp" "$yml"
    echo "==> Appended OpenSSL $v to matrix in $yml"
  done
done

# gofmt so the table patch lands clean.
if command -v gofmt >/dev/null 2>&1; then
  gofmt -w "$OFFSETS_GO"
fi

echo
echo "Done. Modified files:"
git diff --name-only -- "$OFFSETS_GO" "$DISCOVERY_YML" 2>/dev/null || true
