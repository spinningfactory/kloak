#!/usr/bin/env bash
# Report discovery results that cannot become a working opensslOffsetTable row:
# a null offset, or an AVX-512 GCM layout that discovery did not recognise
# (HashKey_1 recovery disabled). TestOpenSSLOffsets_AgainstReferenceJSON fails
# on either, so openssl-versions-nightly.yml runs this before it opens a PR and
# on the pre-release canary.
#
# Usage: check-results.sh <openssl-*.json>...
# Prints one line per problem and exits 1 if there is any.

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <openssl-*.json>..." >&2
  exit 2
fi

status=0
for json in "$@"; do
  problems=$(jq -r '
    [.kloak_config | to_entries[] | select(.value == null) | "null offset \(.key)"]
    + (if .vaes_hkey1_status == "unrecognized" then
         ["AVX-512 GCM layout unrecognized (HashKey_1 recovery disabled): \(.vaes_hkey1_reason // "no reason reported")"]
       elif .vaes_hkey1_status == "ok" or .vaes_hkey1_status == "not_applicable" then
         []
       else
         ["unexpected vaes_hkey1_status \(.vaes_hkey1_status)"]
       end)
    | .[]' "$json")
  if [ -n "$problems" ]; then
    name=$(basename "$json")
    printf '%s\n' "$problems" | while IFS= read -r line; do
      printf '%s: %s\n' "$name" "$line"
    done
    status=1
  fi
done
exit "$status"
