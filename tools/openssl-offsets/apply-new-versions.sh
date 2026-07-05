#!/usr/bin/env bash
# Append opensslOffsetTable entries + matrix list updates for newly-supported
# OpenSSL versions, after their JSON reference files have been generated.
#
# Inputs:
#   $1 — comma-separated list of new full versions (e.g. "3.6.0,3.7.0")
#
# Reads tools/openssl-offsets/results/openssl-<v>-amd64.json (must exist)
# and updates:
#   - pkg/ebpf/openssl_offsets.go         (inserts into opensslOffsetTable, newest-first)
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

IFS=',' read -r -a _RAW_VERSIONS <<<"$1"
# Process oldest-first: each entry is inserted at the top of the table (above the
# current newest), so the final order ends up newest-first (descending), matching
# the table's hand-curated convention. Portable numeric sort (no bash mapfile /
# GNU `sort -V`, so this also works on the BSD tools shipped on macOS).
NEW_VERSIONS=()
while IFS= read -r _v; do
  [ -n "$_v" ] && NEW_VERSIONS+=("$_v")
done < <(printf '%s\n' "${_RAW_VERSIONS[@]}" | sort -t. -k1,1n -k2,2n -k3,3n)

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
    # AlgctxToAESKey powers the AES-round-key H fallback (issue #275). It MUST be
    # carried into new table entries — a missing/zero value silently disables the
    # fallback for the new version, re-exposing the lazy-H rewrite-skip flake.
    algctx_to_aeskey=$(jq -r '.kloak_config.AlgctxToAESKey' "$json")
    ssl_to_ver=$(jq -r '.kloak_config.SSLToVersion' "$json")
    ssl_to_wbio=$(jq -r '.kloak_config.SSLToWBIO' "$json")

    for field in ssl_to_wrl wrl_to_enc enc_to_algctx algctx_to_h algctx_to_aeskey ssl_to_ver ssl_to_wbio; do
      val="${!field}"
      if [ -z "$val" ] || [ "$val" = "null" ]; then
        echo "ERROR: $json is missing field $field — re-run offset discovery" >&2
        exit 1
      fi
    done

    entry=$(printf '\t"%s": {SSLToWRL: %s, WRLToEncCtx: %s, EncCtxToAlgctx: %s, AlgctxToH: %s, SSLToVersion: %s, SSLToWBIO: %s, AlgctxToAESKey: %s},' \
      "$major_minor" "$ssl_to_wrl" "$wrl_to_enc" "$enc_to_algctx" "$algctx_to_h" "$ssl_to_ver" "$ssl_to_wbio" "$algctx_to_aeskey")

    # Insert before the first existing entry so new (newer) versions land at the
    # top of the table, keeping it in descending version order.
    #
    # Comments need care: the leading *general* doc comments (separated from the
    # entries by blank lines) must stay at the top, but a *version-specific*
    # comment block sitting immediately above the first entry (e.g.
    # "// OpenSSL 3.5.x — …") documents that entry and must move down with it,
    # below the newly inserted line. So we buffer comment lines, flush them in
    # place at each blank line (general blocks), and emit whatever remains
    # buffered *after* the new entry (the version-specific block). Falls back to
    # before the closing `}` if the table somehow has no entries yet.
    awk -v new="$entry" '
      /^var opensslOffsetTable = map\[string\]TLSOffsets\{/ { in_map=1; print; next }
      in_map && !done && /^[[:space:]]*\/\// { comment_buf = comment_buf $0 "\n"; next }
      in_map && !done && /^[[:space:]]*$/ { printf "%s%s\n", comment_buf, $0; comment_buf=""; next }
      in_map && !done && /^[[:space:]]*"[0-9]+\.[0-9]+":[[:space:]]*\{/ {
        print new; printf "%s", comment_buf; comment_buf=""; done=1
      }
      in_map && /^\}$/ {
        if (!done) { printf "%s", comment_buf; comment_buf=""; print new; done=1 }
        in_map=0
      }
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
