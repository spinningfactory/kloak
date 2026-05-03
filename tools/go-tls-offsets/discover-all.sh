#!/usr/bin/env bash
# Run tools/go-tls-offsets/main.go against every fixture binary built by
# build-fixtures.sh, capturing the JSON output to
# tools/go-tls-offsets/results/go-<version>-<arch>.json.
#
# These JSONs are committed and serve as the canonical reference for the
# table-driven test in pkg/ebpf/go_tls_offsets_test.go.
#
# Usage:
#   tools/go-tls-offsets/discover-all.sh         # process every fixture present
#   GO_VERSIONS="1.21 1.22" tools/go-tls-offsets/discover-all.sh   # subset
#
# Requires: fixtures already built via build-fixtures.sh.

set -euo pipefail

cd "$(dirname "$0")/../.."

FIXTURES="pkg/ebpf/testdata/go-tls-fixtures"
RESULTS="tools/go-tls-offsets/results"
mkdir -p "$RESULTS"

if [ ! -d "$FIXTURES" ] || [ -z "$(ls -A "$FIXTURES" 2>/dev/null)" ]; then
  echo "ERROR: no fixtures in $FIXTURES — run tools/go-tls-offsets/build-fixtures.sh first" >&2
  exit 1
fi

VERSIONS_FILTER="${GO_VERSIONS:-}"

for elf in "$FIXTURES"/go-*.elf; do
  base=$(basename "$elf" .elf)        # go-1.22-amd64
  short=${base#go-}                   # 1.22-amd64
  version=${short%-*}                 # 1.22
  arch=${short##*-}                   # amd64

  if [ -n "$VERSIONS_FILTER" ]; then
    case " $VERSIONS_FILTER " in
      *" $version "*) ;;
      *) continue ;;
    esac
  fi

  out="$RESULTS/go-$version-$arch.json"
  echo "==> $elf  →  $out"
  go run ./tools/go-tls-offsets "$elf" > "$out"
done

echo
echo "Wrote $(ls -1 "$RESULTS"/go-*.json 2>/dev/null | wc -l | tr -d ' ') JSON files in $RESULTS/"
