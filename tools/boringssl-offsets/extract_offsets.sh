#!/bin/sh
# Extract kloak-required BoringSSL struct offsets using pahole (DWARF debug info).
# Run inside the BoringSSL build directory after cmake build with -g.
#
# BoringSSL's H extraction chain:
#   SSL* → s3 (SSL3_STATE*) → aead_write_ctx (SSLAEADContext)
#       → ctx (EVP_AEAD_CTX) → aead_state → gcm.ghash_key (GCM128_KEY)
#
# This is simpler than OpenSSL 3.2+'s 4-hop chain because BoringSSL
# doesn't have the OSSL_RECORD_LAYER indirection.

set -e

ARCH=$(uname -m)
BUILD_DIR="/tmp/boringssl/build"

# Helper: get offset of a field from pahole output
get_offset() {
    local obj="$1" struct="$2" field="$3"
    pahole -C "$struct" "$obj" 2>/dev/null | \
        grep -E "[[:space:]]${field}[;[:space:]\[]" | head -1 | \
        sed -n 's|.*/\*[[:space:]]*\([0-9]*\)[[:space:]].*\*/|\1|p' | tr -d ' '
}

# Helper: get sizeof
get_sizeof() {
    local obj="$1" struct="$2"
    pahole -C "$struct" "$obj" 2>/dev/null | grep '\/\* size:' | \
        sed -n 's|.*size: \([0-9]*\).*|\1|p' | head -1
}

# Find object files in the BoringSSL build
SSL_OBJ=$(find "$BUILD_DIR" -name 'ssl_lib.c.o' -o -name 'tls13_enc.c.o' | head -1)
if [ -z "$SSL_OBJ" ]; then
    SSL_OBJ=$(find "$BUILD_DIR/ssl" -name '*.o' | head -1)
fi

CRYPTO_OBJ=$(find "$BUILD_DIR" -name 'gcm.c.o' -o -name 'cipher.c.o' | head -1)
if [ -z "$CRYPTO_OBJ" ]; then
    CRYPTO_OBJ=$(find "$BUILD_DIR/crypto" -name '*.o' | head -1)
fi

echo "=== BoringSSL Offset Discovery ===" >&2
echo "SSL object: $SSL_OBJ" >&2
echo "Crypto object: $CRYPTO_OBJ" >&2
echo "Arch: $ARCH" >&2

# Try to list all structs available for debugging
echo "" >&2
echo "=== Available structs ===" >&2
if [ -n "$SSL_OBJ" ]; then
    echo "SSL object structs:" >&2
    pahole -C bssl::SSL "$SSL_OBJ" 2>/dev/null | head -5 >&2 || true
    pahole -C ssl_st "$SSL_OBJ" 2>/dev/null | head -5 >&2 || true
    pahole -C ssl3_state_st "$SSL_OBJ" 2>/dev/null | head -5 >&2 || true
fi

# BoringSSL uses C++ internally — struct names may be namespaced.
# Try various naming conventions.

# SSL struct → s3 field
SSL_TO_S3=""
for struct in "ssl_st" "bssl::SSL" "SSL"; do
    SSL_TO_S3=$(get_offset "$SSL_OBJ" "$struct" "s3")
    if [ -n "$SSL_TO_S3" ]; then
        echo "Found SSL.s3 at offset $SSL_TO_S3 (struct: $struct)" >&2
        SSL_STRUCT="$struct"
        break
    fi
done

# SSL struct → wbio field (for ssl_read_fd)
SSL_TO_WBIO=""
for struct in "ssl_st" "bssl::SSL" "SSL"; do
    SSL_TO_WBIO=$(get_offset "$SSL_OBJ" "$struct" "wbio")
    if [ -n "$SSL_TO_WBIO" ]; then
        echo "Found SSL.wbio at offset $SSL_TO_WBIO (struct: $struct)" >&2
        break
    fi
done

# SSL3_STATE → aead_write_ctx
S3_TO_AEAD=""
for struct in "ssl3_state_st" "bssl::SSL3_STATE" "SSL3_STATE"; do
    S3_TO_AEAD=$(get_offset "$SSL_OBJ" "$struct" "aead_write_ctx")
    if [ -n "$S3_TO_AEAD" ]; then
        echo "Found SSL3_STATE.aead_write_ctx at offset $S3_TO_AEAD (struct: $struct)" >&2
        S3_STRUCT="$struct"
        break
    fi
done

# SSLAEADContext → ctx (EVP_AEAD_CTX)
AEAD_TO_CTX=""
for struct in "bssl::SSLAEADContext" "SSLAEADContext"; do
    AEAD_TO_CTX=$(get_offset "$SSL_OBJ" "$struct" "ctx")
    if [ -n "$AEAD_TO_CTX" ]; then
        echo "Found SSLAEADContext.ctx at offset $AEAD_TO_CTX (struct: $struct)" >&2
        AEAD_STRUCT="$struct"
        break
    fi
done

# EVP_AEAD_CTX → aead_state (void* to the actual GCM context)
CTX_TO_STATE=""
for struct in "evp_aead_ctx_st" "bssl::EVP_AEAD_CTX" "EVP_AEAD_CTX"; do
    CTX_TO_STATE=$(get_offset "$SSL_OBJ" "$struct" "aead_state" 2>/dev/null || get_offset "$CRYPTO_OBJ" "$struct" "aead_state" 2>/dev/null)
    if [ -n "$CTX_TO_STATE" ]; then
        echo "Found EVP_AEAD_CTX.aead_state at offset $CTX_TO_STATE (struct: $struct)" >&2
        EVP_AEAD_STRUCT="$struct"
        break
    fi
done

# GCM128_KEY (or gcm128_context).H — the GHASH key
GCM_H_OFFSET=""
for struct in "gcm128_key" "GCM128_KEY" "gcm128_context"; do
    GCM_H_OFFSET=$(get_offset "$CRYPTO_OBJ" "$struct" "Htable" 2>/dev/null || get_offset "$CRYPTO_OBJ" "$struct" "H" 2>/dev/null)
    if [ -n "$GCM_H_OFFSET" ]; then
        echo "Found $struct.H at offset $GCM_H_OFFSET" >&2
        GCM_STRUCT="$struct"
        break
    fi
done

# BIO → num (fd) — may differ from OpenSSL's 56
BIO_NUM=""
for struct in "bio_st" "bssl::BIO" "BIO"; do
    BIO_NUM=$(get_offset "$SSL_OBJ" "$struct" "num" 2>/dev/null || get_offset "$CRYPTO_OBJ" "$struct" "num" 2>/dev/null)
    if [ -n "$BIO_NUM" ]; then
        echo "Found BIO.num at offset $BIO_NUM (struct: $struct)" >&2
        break
    fi
done

# Sizes
SIZEOF_SSL=$(get_sizeof "$SSL_OBJ" "${SSL_STRUCT:-ssl_st}")
SIZEOF_S3=$(get_sizeof "$SSL_OBJ" "${S3_STRUCT:-ssl3_state_st}")
SIZEOF_AEAD=$(get_sizeof "$SSL_OBJ" "${AEAD_STRUCT:-SSLAEADContext}")
SIZEOF_EVP_AEAD=$(get_sizeof "${CRYPTO_OBJ:-$SSL_OBJ}" "${EVP_AEAD_STRUCT:-evp_aead_ctx_st}")

# Also dump full struct layouts for manual inspection
echo "" >&2
echo "=== Full struct dumps (for manual verification) ===" >&2
for struct in "$SSL_STRUCT" "$S3_STRUCT" "$AEAD_STRUCT" "$EVP_AEAD_STRUCT"; do
    if [ -n "$struct" ]; then
        echo "--- $struct ---" >&2
        pahole -C "$struct" "$SSL_OBJ" 2>/dev/null | head -40 >&2 || true
    fi
done
if [ -n "$GCM_STRUCT" ] && [ -n "$CRYPTO_OBJ" ]; then
    echo "--- $GCM_STRUCT ---" >&2
    pahole -C "$GCM_STRUCT" "$CRYPTO_OBJ" 2>/dev/null | head -40 >&2 || true
fi

cat <<EOF
{
  "library": "BoringSSL",
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
    "ctx_to_aead_state": ${CTX_TO_STATE:-null},
    "gcm_h_offset": ${GCM_H_OFFSET:-null},
    "bio_num_offset": ${BIO_NUM:-null}
  },
  "sizes": {
    "SSL": ${SIZEOF_SSL:-null},
    "SSL3_STATE": ${SIZEOF_S3:-null},
    "SSLAEADContext": ${SIZEOF_AEAD:-null},
    "EVP_AEAD_CTX": ${SIZEOF_EVP_AEAD:-null}
  }
}
EOF
