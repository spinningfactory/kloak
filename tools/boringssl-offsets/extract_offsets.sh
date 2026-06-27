#!/bin/sh
# Extract kloak-required BoringSSL struct offsets using pahole (DWARF debug info).
# Run inside a BoringSSL cmake build tree built with -g -O0 (see Dockerfile).
#
# BoringSSL's H-extraction chain (no OSSL_RECORD_LAYER indirection — simpler
# than OpenSSL 3.2+'s 4-hop):
#
#   SSL* + ssl_to_s3            -> SSL3_STATE*       (pointer deref)
#       + s3_to_aead_write_ctx  -> SSLAEADContext*   (pointer deref, UniquePtr)
#       + aead_to_ctx           -> EVP_AEAD_CTX      (embedded struct, add)
#       + ctx_to_aead_state     -> aead_state*       (pointer deref, void*)
#       + state_to_h            -> H / Htable        (direct 16-byte read)
#
# Whether each hop is a pointer-deref or an embedded-struct add is determined
# empirically from the pahole dumps emitted to stderr; the kloak BPF walk
# encodes those semantics, this script only reports the numeric offsets.
#
# Emits the same JSON envelope shape as tools/openssl-offsets/extract_offsets.sh
# (version / arch / chain / offsets / sizes / kloak_config) so the in-tree
# table test (pkg/ebpf/boringssl_offsets_test.go) can assert against it.

set -e

BUILD_DIR="${BUILD_DIR:-/tmp/boringssl/build}"
VERSION="${BORINGSSL_VERSION:-unknown}"
ARCH=$(uname -m)

# Helper: get offset of a field from pahole output.
# Usage: get_offset <object_file> <struct_name> <field_name>
get_offset() {
    obj="$1"; struct="$2"; field="$3"
    pahole -C "$struct" "$obj" 2>/dev/null | \
        grep -E "[[:space:]]${field}[;[:space:]\[]" | head -1 | \
        sed -n 's|.*/\*[[:space:]]*\([0-9]*\)[[:space:]].*\*/|\1|p' | tr -d ' '
}

# Helper: get sizeof a struct.
get_sizeof() {
    obj="$1"; struct="$2"
    pahole -C "$struct" "$obj" 2>/dev/null | grep '/\* size:' | \
        sed -n 's|.*size: \([0-9]*\).*|\1|p' | head -1
}

# Try a field across several candidate struct names (BoringSSL is C++ and may
# namespace structs as bssl::Name in DWARF). Echoes "offset|struct" on success.
get_offset_multi() {
    obj="$1"; field="$2"; shift 2
    for s in "$@"; do
        off=$(get_offset "$obj" "$s" "$field")
        if [ -n "$off" ]; then
            echo "${off}|${s}"
            return 0
        fi
    done
    return 0
}

# Object files in a cmake Debug build live under build/ as *.c.o / *.cc.o.
SSL_OBJ=$(find "$BUILD_DIR" -name 'ssl_lib.cc.o' -o -name 'ssl_lib.c.o' 2>/dev/null | head -1)
[ -z "$SSL_OBJ" ] && SSL_OBJ=$(find "$BUILD_DIR" -path '*ssl*' -name '*.o' 2>/dev/null | head -1)
T13_OBJ=$(find "$BUILD_DIR" -name 'tls13_enc.cc.o' -o -name 'tls_record.cc.o' 2>/dev/null | head -1)
CRYPTO_OBJ=$(find "$BUILD_DIR" -name 'gcm.c.o' -o -name 'gcm.cc.o' -o -name 'e_aes.c.o' -o -name 'cipher_extra.c.o' 2>/dev/null | head -1)
[ -z "$CRYPTO_OBJ" ] && CRYPTO_OBJ=$(find "$BUILD_DIR" -path '*crypto*' -name '*.o' 2>/dev/null | head -1)

echo "=== BoringSSL Offset Discovery ===" >&2
echo "Version: $VERSION  Arch: $ARCH" >&2
echo "SSL object:    $SSL_OBJ" >&2
echo "TLS13 object:  $T13_OBJ" >&2
echo "Crypto object: $CRYPTO_OBJ" >&2

# SSL* -> s3
r=$(get_offset_multi "$SSL_OBJ" "s3" "ssl_st" "bssl::SSL" "SSL")
SSL_TO_S3="${r%%|*}"; SSL_STRUCT="${r##*|}"

# SSL* -> wbio (socket fd recovery)
r=$(get_offset_multi "$SSL_OBJ" "wbio" "ssl_st" "bssl::SSL" "SSL")
SSL_TO_WBIO="${r%%|*}"

# SSL3_STATE -> aead_write_ctx
r=$(get_offset_multi "$SSL_OBJ" "aead_write_ctx" "ssl3_state_st" "bssl::SSL3_STATE" "SSL3_STATE")
S3_TO_AEAD="${r%%|*}"; S3_STRUCT="${r##*|}"

# SSLAEADContext -> ctx_ (EVP_AEAD_CTX)
r=$(get_offset_multi "$SSL_OBJ" "ctx_" "bssl::SSLAEADContext" "SSLAEADContext")
[ -z "${r%%|*}" ] && r=$(get_offset_multi "$SSL_OBJ" "ctx" "bssl::SSLAEADContext" "SSLAEADContext")
AEAD_TO_CTX="${r%%|*}"; AEAD_STRUCT="${r##*|}"

# EVP_AEAD_CTX -> state (embedded union holding the cipher-specific aead ctx).
# In modern BoringSSL the cipher state is INLINE (union evp_aead_ctx_st_state),
# not a pointer — so this is an additive offset, not a deref.
r=$(get_offset_multi "$SSL_OBJ" "state" "evp_aead_ctx_st" "EVP_AEAD_CTX")
[ -z "${r%%|*}" ] && r=$(get_offset_multi "$CRYPTO_OBJ" "state" "evp_aead_ctx_st" "EVP_AEAD_CTX")
CTX_TO_STATE="${r%%|*}"; EVP_AEAD_STRUCT="${r##*|}"

# aead_aes_gcm_ctx.key (GCM128_KEY) — offset of the gcm key within the inline
# aes-gcm aead state (0 in current BoringSSL).
r=$(get_offset_multi "$CRYPTO_OBJ" "key" "aead_aes_gcm_ctx")
AEAD_GCM_KEY="${r%%|*}"

# GCM ghash table (Htable) within gcm128_key_st (offset 0). The 16 bytes here
# are the first GHASH-table entry, NOT the raw subkey — kloak's BPF recovers
# raw H from it (see the BoringSSL branch in bpf/tls_uprobe.c).
r=$(get_offset_multi "$CRYPTO_OBJ" "Htable" "gcm128_key_st" "gcm128_context" "GCM128_KEY")
[ -z "${r%%|*}" ] && r=$(get_offset_multi "$CRYPTO_OBJ" "H" "gcm128_key_st" "gcm128_context" "GCM128_KEY")
GCM_H_OFFSET="${r%%|*}"; GCM_STRUCT="${r##*|}"

# gcm128_key_st.aes (AES_KEY) — kloak reads the round-key schedule here and
# recomputes H = AES_encrypt(0) in-kernel (BoringSSL doesn't persist raw H).
r=$(get_offset_multi "$CRYPTO_OBJ" "aes" "gcm128_key_st" "gcm128_context" "GCM128_KEY")
GCM_AES_OFF="${r%%|*}"

# AEADToH collapses the embedded hops SSLAEADContext.ctx_ → EVP_AEAD_CTX.state
# → aead_aes_gcm_ctx.key → gcm128_key.Htable into one additive offset from the
# SSLAEADContext pointer (the GHASH table — for reference/debug only).
AEAD_TO_H=""
if [ -n "$AEAD_TO_CTX" ] && [ -n "$CTX_TO_STATE" ] && [ -n "$AEAD_GCM_KEY" ] && [ -n "$GCM_H_OFFSET" ]; then
    AEAD_TO_H=$((AEAD_TO_CTX + CTX_TO_STATE + AEAD_GCM_KEY + GCM_H_OFFSET))
fi

# AEADToAESKey collapses SSLAEADContext.ctx_ → EVP_AEAD_CTX.state →
# aead_aes_gcm_ctx.key → gcm128_key.aes into one additive offset to AES_KEY.rd_key.
AEAD_TO_AESKEY=""
if [ -n "$AEAD_TO_CTX" ] && [ -n "$CTX_TO_STATE" ] && [ -n "$AEAD_GCM_KEY" ] && [ -n "$GCM_AES_OFF" ]; then
    AEAD_TO_AESKEY=$((AEAD_TO_CTX + CTX_TO_STATE + AEAD_GCM_KEY + GCM_AES_OFF))
fi

# BIO -> num (socket fd)
r=$(get_offset_multi "$SSL_OBJ" "num" "bio_st" "bssl::BIO" "BIO")
[ -z "${r%%|*}" ] && r=$(get_offset_multi "$CRYPTO_OBJ" "num" "bio_st" "BIO")
BIO_NUM="${r%%|*}"

# Dump the relevant struct layouts to stderr so the deref-vs-embed semantics
# of each hop can be confirmed when calibrating the BPF walk.
echo "" >&2
echo "=== struct dumps ===" >&2
for sp in "$SSL_STRUCT:$SSL_OBJ" "$S3_STRUCT:$SSL_OBJ" "$AEAD_STRUCT:$SSL_OBJ" \
          "$EVP_AEAD_STRUCT:$CRYPTO_OBJ" "$GCM_STRUCT:$CRYPTO_OBJ"; do
    s="${sp%%:*}"; o="${sp##*:}"
    [ -n "$s" ] || continue
    echo "--- $s ($o) ---" >&2
    pahole -C "$s" "$o" 2>/dev/null | head -60 >&2 || true
done

SIZEOF_SSL=$(get_sizeof "$SSL_OBJ" "${SSL_STRUCT:-ssl_st}")
SIZEOF_S3=$(get_sizeof "$SSL_OBJ" "${S3_STRUCT:-ssl3_state_st}")

cat <<EOF
{
  "library": "BoringSSL",
  "version": "${VERSION}",
  "arch": "${ARCH}",
  "chain": "boringssl",
  "structs": {
    "ssl": "${SSL_STRUCT:-unknown}",
    "s3": "${S3_STRUCT:-unknown}",
    "aead_ctx": "${AEAD_STRUCT:-unknown}",
    "evp_aead_ctx": "${EVP_AEAD_STRUCT:-unknown}",
    "gcm_key": "${GCM_STRUCT:-unknown}"
  },
  "offsets": {
    "ssl_to_s3": ${SSL_TO_S3:-null},
    "ssl_to_wbio": ${SSL_TO_WBIO:-null},
    "s3_to_aead_write_ctx": ${S3_TO_AEAD:-null},
    "aead_to_ctx": ${AEAD_TO_CTX:-null},
    "ctx_to_state": ${CTX_TO_STATE:-null},
    "aead_gcm_key": ${AEAD_GCM_KEY:-null},
    "gcm_h_offset": ${GCM_H_OFFSET:-null},
    "gcm_aes_offset": ${GCM_AES_OFF:-null},
    "aead_to_h": ${AEAD_TO_H:-null},
    "aead_to_aeskey": ${AEAD_TO_AESKEY:-null},
    "bio_num_offset": ${BIO_NUM:-null}
  },
  "sizes": {
    "SSL": ${SIZEOF_SSL:-null},
    "SSL3_STATE": ${SIZEOF_S3:-null}
  },
  "kloak_config": {
    "SSLToS3": ${SSL_TO_S3:-null},
    "S3ToAEAD": ${S3_TO_AEAD:-null},
    "AEADToAESKey": ${AEAD_TO_AESKEY:-null},
    "SSLToWBIO": ${SSL_TO_WBIO:-null}
  }
}
EOF
