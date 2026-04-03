#!/bin/sh
# Extract kloak-required OpenSSL struct offsets using pahole (DWARF debug info).
# Run inside the OpenSSL build directory after `make build_sw` with -g.

set -e

OPENSSL_VERSION=$(grep 'OPENSSL_VERSION_TEXT' include/openssl/opensslv.h 2>/dev/null | sed 's/.*"\(.*\)".*/\1/' || echo "unknown")
ARCH=$(uname -m)

# Helper: get offset of a field from pahole output
# Usage: get_offset <object_file> <struct_name> <field_name>
get_offset() {
    local obj="$1" struct="$2" field="$3"
    pahole -C "$struct" "$obj" 2>/dev/null | \
        grep -E "[[:space:]]${field}[;[]" | head -1 | \
        sed -n 's|.*/\*[[:space:]]*\([0-9]*\)[[:space:]].*\*/|\1|p' | tr -d ' '
}

# Helper: get sizeof
get_sizeof() {
    local obj="$1" struct="$2"
    pahole -C "$struct" "$obj" 2>/dev/null | grep '\/\* size:' | \
        sed -n 's|.*size: \([0-9]*\).*|\1|p' | head -1
}

# Find object files (OpenSSL 3.x prefixes with libssl-lib- or libcrypto-lib-)
SSL_OBJ=$(find . -name '*s3_lib.o' | head -1)
EVP_OBJ=$(find . -name '*evp_enc.o' | head -1)
MODES_OBJ=$(find . -name '*gcm128.o' | head -1)
PROV_OBJ=$(find . -name '*ciphercommon_gcm.o' -o -name '*cipher_aes_gcm.o' -o -name '*gcm_hw.o' | head -1)
# OSSL_RECORD_LAYER is in the record layer source files
REC_OBJ=$(find . -name '*tls_common.o' -o -name '*tlsrecord.o' | head -1)

# SSL_CONNECTION offsets (3.2+) or ssl_st (3.0-3.1)
# Try ssl_connection_st first, fall back to ssl_st
SSL_STRUCT="ssl_connection_st"
SSL_TO_VERSION=$(get_offset "$SSL_OBJ" "$SSL_STRUCT" "version")
if [ -z "$SSL_TO_VERSION" ]; then
    SSL_STRUCT="ssl_st"
    SSL_TO_VERSION=$(get_offset "$SSL_OBJ" "$SSL_STRUCT" "version")
fi
SIZEOF_SSL_CONNECTION=$(get_sizeof "$SSL_OBJ" "$SSL_STRUCT")

# rlayer.wrl (3.2+ only — nested struct)
RLAYER_OFFSET=$(get_offset "$SSL_OBJ" "$SSL_STRUCT" "rlayer")
WRL_IN_RLAYER=$(get_offset "$SSL_OBJ" "record_layer_st" "wrl")
# For 3.0-3.1: enc_write_ctx directly on the SSL struct
SSL_TO_ENC_WRITE_CTX=$(get_offset "$SSL_OBJ" "$SSL_STRUCT" "enc_write_ctx")

SSL_TO_WRL=""
if [ -n "$RLAYER_OFFSET" ] && [ -n "$WRL_IN_RLAYER" ]; then
    SSL_TO_WRL=$((RLAYER_OFFSET + WRL_IN_RLAYER))
fi

# OSSL_RECORD_LAYER.enc_ctx (4-hop chain, 3.2+)
WRL_TO_ENC_CTX=""
if [ -n "$REC_OBJ" ]; then
    WRL_TO_ENC_CTX=$(get_offset "$REC_OBJ" "ossl_record_layer_st" "enc_ctx")
fi

# EVP_CIPHER_CTX.algctx
ENC_CTX_TO_ALGCTX=$(get_offset "$EVP_OBJ" "evp_cipher_ctx_st" "algctx")

# GCM128_CONTEXT.H
GCM128_H_OFFSET=$(get_offset "$MODES_OBJ" "gcm128_context" "H")

# PROV_GCM_CTX.gcm (provider-internal)
ALGCTX_TO_GCM=""
if [ -n "$PROV_OBJ" ]; then
    ALGCTX_TO_GCM=$(get_offset "$PROV_OBJ" "prov_gcm_ctx_st" "gcm")
fi

# Compute algctx_to_h = PROV_GCM_CTX.gcm + GCM128_CONTEXT.H
ALGCTX_TO_H=""
if [ -n "$ALGCTX_TO_GCM" ] && [ -n "$GCM128_H_OFFSET" ]; then
    ALGCTX_TO_H=$((ALGCTX_TO_GCM + GCM128_H_OFFSET))
fi

# Chain type
CHAIN="unknown"
if [ -n "$SSL_TO_WRL" ] && [ -n "$WRL_TO_ENC_CTX" ]; then
    CHAIN="4-hop"
elif [ -n "$SSL_TO_ENC_WRITE_CTX" ]; then
    CHAIN="3-hop"
fi

# Sizes
SIZEOF_SSL_CONNECTION=$(get_sizeof "$SSL_OBJ" "ssl_connection_st")
SIZEOF_EVP_CIPHER_CTX=$(get_sizeof "$EVP_OBJ" "evp_cipher_ctx_st")
SIZEOF_GCM128=$(get_sizeof "$MODES_OBJ" "gcm128_context")
SIZEOF_PROV_GCM=$(get_sizeof "$PROV_OBJ" "prov_gcm_ctx_st" 2>/dev/null)

cat <<EOF
{
  "openssl_version": "${OPENSSL_VERSION}",
  "arch": "${ARCH}",
  "chain": "${CHAIN}",
  "offsets": {
    "ssl_to_wrl": ${SSL_TO_WRL:-null},
    "ssl_to_enc_write_ctx": ${SSL_TO_ENC_WRITE_CTX:-null},
    "wrl_to_enc_ctx": ${WRL_TO_ENC_CTX:-null},
    "enc_ctx_to_algctx": ${ENC_CTX_TO_ALGCTX:-null},
    "algctx_to_gcm": ${ALGCTX_TO_GCM:-null},
    "gcm128_h_offset": ${GCM128_H_OFFSET:-null},
    "algctx_to_h": ${ALGCTX_TO_H:-null},
    "ssl_to_version": ${SSL_TO_VERSION:-null}
  },
  "sizes": {
    "SSL_CONNECTION": ${SIZEOF_SSL_CONNECTION:-null},
    "EVP_CIPHER_CTX": ${SIZEOF_EVP_CIPHER_CTX:-null},
    "GCM128_CONTEXT": ${SIZEOF_GCM128:-null},
    "PROV_GCM_CTX": ${SIZEOF_PROV_GCM:-null}
  },
  "kloak_config": {
    "SSLToWRL": ${SSL_TO_WRL:-null},
    "WRLToEncCtx": ${WRL_TO_ENC_CTX:-null},
    "EncCtxToAlgctx": ${ENC_CTX_TO_ALGCTX:-null},
    "AlgctxToH": ${ALGCTX_TO_H:-null}
  }
}
EOF
