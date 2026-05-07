#!/usr/bin/env bash
# Append goTLSOffsetTableBase entries + matrix list updates for newly-supported
# Go versions, after their JSON reference files have been generated.
#
# Inputs:
#   $1 — comma-separated list of new major.minor versions (e.g. "1.27,1.28")
#
# Reads tools/go-tls-offsets/results/go-<v>-amd64.json (must already exist)
# and updates:
#   - pkg/ebpf/go_tls_offsets.go            (appends to goTLSOffsetTableBase)
#   - .github/workflows/go-tls-offsets.yml  (appends to matrix.go)
#   - .github/workflows/go-versions-nightly.yml (appends to matrix.go in every job)
#
# Idempotent: skipping versions already in the table or matrix is fine; running
# the script twice is a no-op. Used by go-versions-nightly.yml's auto-PR job.
#
# Note: tools/go-tls-offsets/build-fixtures.sh is auto-discovery driven from
# go.dev's release feed and needs no edit when a new version ships.

set -euo pipefail

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "Usage: $0 <comma-separated-versions>" >&2
  echo "  e.g. $0 1.27,1.28" >&2
  exit 1
fi

cd "$(dirname "$0")/../.."

IFS=',' read -r -a NEW_VERSIONS <<<"$1"

OFFSETS_GO="pkg/ebpf/go_tls_offsets.go"
DISCOVERY_YML=".github/workflows/go-tls-offsets.yml"
NIGHTLY_YML=".github/workflows/go-versions-nightly.yml"

for v in "${NEW_VERSIONS[@]}"; do
  json="tools/go-tls-offsets/results/go-$v-amd64.json"
  if [ ! -f "$json" ]; then
    echo "ERROR: $json not found — generate it before running this script" >&2
    exit 1
  fi

  # Skip if the table already contains this version (idempotent).
  if grep -qE "^[[:space:]]+\"$v\":[[:space:]]*\{" "$OFFSETS_GO"; then
    echo "==> $v already in $OFFSETS_GO — skipping table insert"
  else
    cc=$(jq -r '.conn_to_cipher' "$json")
    ai=$(jq -r '.aead_iface_off' "$json")
    pd=$(jq -r '.raw.pd_base' "$json")
    cv=$(jq -r '.conn_vers_off' "$json")

    if [ -z "$cc" ] || [ -z "$ai" ] || [ -z "$pd" ] || [ -z "$cv" ] \
        || [ "$cc" = "null" ] || [ "$ai" = "null" ] || [ "$pd" = "null" ] || [ "$cv" = "null" ]; then
      echo "ERROR: $json is missing one of conn_to_cipher / aead_iface_off / raw.pd_base / conn_vers_off" >&2
      exit 1
    fi

    entry=$(printf '\t"%s": {ConnToCipher: %s, AEADIfaceOff: %s, PDBase: %s, ConnVersOff: %s},' \
      "$v" "$cc" "$ai" "$pd" "$cv")

    # Insert immediately before the closing `}` of goTLSOffsetTableBase.
    awk -v new="$entry" '
      /^var goTLSOffsetTableBase = map\[string\]goTLSOffsetEntry\{/ { in_map=1; print; next }
      in_map && /^\}$/ { print new; print; in_map=0; next }
      { print }
    ' "$OFFSETS_GO" > "$OFFSETS_GO.tmp"
    mv "$OFFSETS_GO.tmp" "$OFFSETS_GO"
    echo "==> Inserted Go $v entry into $OFFSETS_GO"
  fi

  # Append $v to matrix.go list in each workflow if not already present.
  for yml in "$DISCOVERY_YML" "$NIGHTLY_YML"; do
    [ -f "$yml" ] || continue
    if grep -qE "go: \[[^]]*\"$v\"" "$yml"; then
      echo "==> $v already in $yml matrix — skipping"
      continue
    fi
    # Append `, "$v"` just before the closing `]` on every `go: [...]` line.
    sed -E -i.bak "/^[[:space:]]*go: \[/ s/\]/, \"$v\"]/" "$yml"
    rm -f "$yml.bak"
    echo "==> Appended Go $v to matrix in $yml"
  done
done

# gofmt the result so the patch lands clean. `go fmt` is the safest invocation
# (no compile required); it operates on source text only.
if command -v gofmt >/dev/null 2>&1; then
  gofmt -w "$OFFSETS_GO"
fi

echo
echo "Done. Modified files:"
git diff --name-only -- "$OFFSETS_GO" "$DISCOVERY_YML" "$NIGHTLY_YML" 2>/dev/null || true
