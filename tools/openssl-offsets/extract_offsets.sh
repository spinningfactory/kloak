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

# ssl_to_wbio: SSL/SSL_CONNECTION → wbio BIO* field.
# 3-hop (3.0/3.1): ssl_st.wbio is a direct field (offset 24).
# 4-hop (3.2+):    try ssl_connection_st.wbio directly; if wbio lives
# inside an embedded ssl_st, fall back to ssl_connection_st.ssl + ssl_st.wbio.
SSL_TO_WBIO=$(get_offset "$SSL_OBJ" "$SSL_STRUCT" "wbio")
if [ -z "$SSL_TO_WBIO" ] && [ "$SSL_STRUCT" = "ssl_connection_st" ]; then
    SSL_ST_IN_CONN=$(get_offset "$SSL_OBJ" "ssl_connection_st" "ssl")
    WBIO_IN_SSL_ST=$(get_offset "$SSL_OBJ" "ssl_st" "wbio")
    if [ -n "$SSL_ST_IN_CONN" ] && [ -n "$WBIO_IN_SSL_ST" ]; then
        SSL_TO_WBIO=$((SSL_ST_IN_CONN + WBIO_IN_SSL_ST))
    fi
fi

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

# ---------------------------------------------------------------------------
# GCM self-pointer gate + AVX-512 HashKey_1 (issue #275), consumed by
# ossl_read_gcm_h in pkg/ebpf/bpf/tls_uprobe.c.
# ---------------------------------------------------------------------------

# Like get_offset, but for a member declared as an inline union/struct: pahole
# prints the members of `union { ... } ks;` first, so the offset of the member
# itself is on its closing `} ks;` line.
get_offset_closing() {
    local obj="$1" struct="$2" field="$3"
    pahole -C "$struct" "$obj" 2>/dev/null | \
        grep -E "^[[:space:]]*}[[:space:]]*${field};" | head -1 | \
        sed -n 's|.*/\*[[:space:]]*\([0-9]*\)[[:space:]].*\*/|\1|p' | tr -d ' '
}

# GCM128_CONTEXT.key: every keyed OpenSSL GCM context points it at its own
# PROV_AES_GCM_CTX.ks (CRYPTO_gcm128_init / vaes_gcm_setkey).
GCM128_KEY_OFFSET=$(get_offset "$MODES_OBJ" "gcm128_context" "key")
GCM128_HTABLE_OFFSET=$(get_offset "$MODES_OBJ" "gcm128_context" "Htable")
ALGCTX_TO_GCM_KEY=""
if [ -n "$ALGCTX_TO_GCM" ] && [ -n "$GCM128_KEY_OFFSET" ]; then
    ALGCTX_TO_GCM_KEY=$((ALGCTX_TO_GCM + GCM128_KEY_OFFSET))
fi

# PROV_AES_GCM_CTX.ks — looked up in the AES-GCM objects specifically (the
# shared PROV_OBJ glob above may resolve to ciphercommon_gcm.o). The union
# follows the PROV_GCM_CTX base at its 8-byte alignment; anything else means
# the layout changed, so emit null and fail loudly.
AES_GCM_OBJ=$(find . -name '*cipher_aes_gcm.o' -o -name '*cipher_aes_gcm_hw.o' | head -1)
ALGCTX_TO_KS=""
if [ -n "$AES_GCM_OBJ" ]; then
    ALGCTX_TO_KS=$(get_offset_closing "$AES_GCM_OBJ" "prov_aes_gcm_ctx_st" "ks")
fi
SIZEOF_PROV_GCM_FOR_KS=$(get_sizeof "$PROV_OBJ" "prov_gcm_ctx_st" 2>/dev/null)
if [ -n "$ALGCTX_TO_KS" ] && [ -n "$SIZEOF_PROV_GCM_FOR_KS" ] && \
   [ "$ALGCTX_TO_KS" -ne $(( (SIZEOF_PROV_GCM_FOR_KS + 7) / 8 * 8 )) ]; then
    echo "WARNING: PROV_AES_GCM_CTX.ks at $ALGCTX_TO_KS, expected right after the ${SIZEOF_PROV_GCM_FOR_KS}-byte PROV_GCM_CTX" >&2
    ALGCTX_TO_KS=""
fi

# HashKey_1 — OpenSSL >= 3.1 on x86-64 with AVX-512 + VAES + VPCLMULQDQ runs
# vaes_gcm, which never writes GCM128_CONTEXT.H; ossl_aes_gcm_init_avx512
# stores HashKey_1 = bswap128(H)<<1 mod POLY in Htable instead, and the data
# plane inverts it. That inversion is only correct for the exact layout and
# transform checked below, so the offset is emitted only when every check
# passes; otherwise 0 (recovery disabled) with status "unrecognized", which
# fails TestOpenSSLOffsets_AgainstReferenceJSON until a human reviews it. The
# checks read sources, not built objects, so both arches agree.
AVX512_PL=crypto/modes/asm/aes-gcm-avx512.pl
AESNI_INC=providers/implementations/ciphers/cipher_aes_gcm_hw_aesni.inc
VAES_INC=providers/implementations/ciphers/cipher_aes_gcm_hw_vaes_avx512.inc

# The instruction sequence (comments and whitespace stripped) between
# HashKey = AES_K(0) and the HashKey_1 store that gf128_halve_to_h inverts.
VAES_HKEY1_EXPECTED_ASM='vpshufb SHUF_MASK(%rip),%xmm16,%xmm16
vmovdqa64 %xmm16,%xmm2
vpsllq \$1,%xmm16,%xmm16
vpsrlq \$63,%xmm2,%xmm2
vmovdqa %xmm2,%xmm1
vpslldq \$8,%xmm2,%xmm2
vpsrldq \$8,%xmm1,%xmm1
vporq %xmm2,%xmm16,%xmm16
vpshufd \$0b00100100,%xmm1,%xmm2
vpcmpeqd TWOONE(%rip),%xmm2,%xmm2
vpand POLY(%rip),%xmm2,%xmm2
vpxorq %xmm2,%xmm16,%xmm16
vmovdqu64 %xmm16,@{[HashKeyByIdx(1,$arg2)]}'

# Prints "<HashKey_1 offset in GCM128_CONTEXT> <asm Htable offset>" when the
# tree matches; returns non-zero (printing the reason to stderr) otherwise.
vaes_hkey1_offset() {
    # (a) The x86 dispatch still chooses only between these three GCM paths.
    dispatch=$(sed -n '/^const PROV_GCM_HW \*ossl_prov_aes_hw_gcm/,/^}/p' "$AESNI_INC" | \
        grep -o 'return &[a-z_]*' | sed 's/return &//' | LC_ALL=C sort -u | tr '\n' ' ')
    if [ "$dispatch" != "aes_gcm aesni_gcm vaes_gcm " ]; then
        echo "hkey1: unexpected GCM dispatch: $dispatch" >&2; return 1
    fi
    # (b) vaes_gcm_setkey zeroes the context and leaves H to the asm.
    setkey=$(sed -n '/^static int vaes_gcm_setkey/,/^}/p' "$VAES_INC")
    for want in 'memset(gcmctx, 0, sizeof(*gcmctx));' 'gcmctx->key = ks;' \
                'ossl_aes_gcm_init_avx512(ks, gcmctx);'; do
        if ! printf '%s\n' "$setkey" | grep -qF "$want"; then
            echo "hkey1: vaes_gcm_setkey lacks: $want" >&2; return 1
        fi
    done
    # (c) HashKey = AES_K(0), then exactly the expected transform and store.
    init=$(awk '/^ossl_aes_gcm_init_avx512:/{f=1} f{print} f&&/^\.Labort_init:/{exit}' "$AVX512_PL")
    if ! printf '%s\n' "$init" | grep -qE '"vpxorq[[:space:]]+%xmm16,%xmm16,%xmm16' || \
       ! printf '%s\n' "$init" | grep -qF 'ENCRYPT_SINGLE_BLOCK("$arg1", "%xmm16"'; then
        echo "hkey1: HashKey is no longer AES_K(0) of a zeroed xmm16" >&2; return 1
    fi
    asm=$(printf '%s\n' "$init" | \
        awk '/vpshufb[[:space:]]+SHUF_MASK\(%rip\),%xmm16,%xmm16/{p=1} p{print} p&&/HashKeyByIdx\(1,/{exit}' | \
        sed 's/#.*//' | tr -s ' \t' ' ' | sed 's/^ //;s/ $//' | grep -v '^$')
    if [ "$asm" != "$VAES_HKEY1_EXPECTED_ASM" ]; then
        echo "hkey1: HashKey_1 precompute differs from the inverted transform" >&2; return 1
    fi
    # (d) The constants that transform depends on.
    grep -qE '^POLY:[[:space:]]+\.quad[[:space:]]+0x0000000000000001,[[:space:]]*0xC200000000000000[[:space:]]*$' "$AVX512_PL" && \
    grep -qE '^TWOONE:[[:space:]]+\.quad[[:space:]]+0x0000000000000001,[[:space:]]*0x0000000100000000[[:space:]]*$' "$AVX512_PL" && \
    grep -A1 '^SHUF_MASK:' "$AVX512_PL" | grep -qE '\.quad[[:space:]]+0x08090A0B0C0D0E0F,[[:space:]]*0x0001020304050607' || {
        echo "hkey1: POLY/TWOONE/SHUF_MASK constants changed" >&2; return 1; }
    # (e) Evaluate the asm's own HashKey_1 context offset.
    perl -e '
        my $src = do { local $/; <STDIN> };
        my $code = "";
        for my $n (qw(AES_BLOCK_SIZE HKEYS_CONTEXT_CAPACITY CTX_OFFSET_HTable)) {
            $src =~ /^(my \$$n\s*=[^;]*;)/m or die "missing \$$n\n";
            $code .= "$1\n";
        }
        $src =~ /^(sub HashKeyOffsetByIdx \{.*?^\})/ms or die "missing HashKeyOffsetByIdx\n";
        $code .= "$1\nprint HashKeyOffsetByIdx(1, \"context\"), \" \", \$CTX_OFFSET_HTable, \"\\n\";\n";
        eval $code; die $@ if $@;
    ' < "$AVX512_PL"
}

ALGCTX_TO_VAES_HKEY1=0
VAES_HKEY1_STATUS="not_applicable"   # no AVX-512 GCM path in this version (3.0)
if [ -f "$AVX512_PL" ]; then
    VAES_HKEY1_STATUS="unrecognized"
    if offs=$(vaes_hkey1_offset); then
        hkey1_in_gcm=${offs% *}
        asm_htable=${offs#* }
        if [ -n "$ALGCTX_TO_GCM" ] && [ "$asm_htable" = "$GCM128_HTABLE_OFFSET" ]; then
            ALGCTX_TO_VAES_HKEY1=$((ALGCTX_TO_GCM + hkey1_in_gcm))
            VAES_HKEY1_STATUS="ok"
        else
            echo "hkey1: asm Htable offset $asm_htable != pahole $GCM128_HTABLE_OFFSET" >&2
        fi
    fi
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
  "vaes_hkey1_status": "${VAES_HKEY1_STATUS}",
  "offsets": {
    "ssl_to_wrl": ${SSL_TO_WRL:-null},
    "ssl_to_enc_write_ctx": ${SSL_TO_ENC_WRITE_CTX:-null},
    "wrl_to_enc_ctx": ${WRL_TO_ENC_CTX:-null},
    "enc_ctx_to_algctx": ${ENC_CTX_TO_ALGCTX:-null},
    "algctx_to_gcm": ${ALGCTX_TO_GCM:-null},
    "gcm128_h_offset": ${GCM128_H_OFFSET:-null},
    "algctx_to_h": ${ALGCTX_TO_H:-null},
    "gcm128_key_offset": ${GCM128_KEY_OFFSET:-null},
    "gcm128_htable_offset": ${GCM128_HTABLE_OFFSET:-null},
    "algctx_to_gcm_key": ${ALGCTX_TO_GCM_KEY:-null},
    "algctx_to_ks": ${ALGCTX_TO_KS:-null},
    "algctx_to_vaes_hkey1": ${ALGCTX_TO_VAES_HKEY1},
    "ssl_to_version": ${SSL_TO_VERSION:-null},
    "ssl_to_wbio": ${SSL_TO_WBIO:-null}
  },
  "sizes": {
    "SSL_CONNECTION": ${SIZEOF_SSL_CONNECTION:-null},
    "EVP_CIPHER_CTX": ${SIZEOF_EVP_CIPHER_CTX:-null},
    "GCM128_CONTEXT": ${SIZEOF_GCM128:-null},
    "PROV_GCM_CTX": ${SIZEOF_PROV_GCM:-null}
  },
  "kloak_config": {
$(if [ "$CHAIN" = "3-hop" ]; then
    echo "    \"SSLToWRL\": ${SSL_TO_ENC_WRITE_CTX:-null},"
    echo "    \"WRLToEncCtx\": 0,"
else
    echo "    \"SSLToWRL\": ${SSL_TO_WRL:-null},"
    echo "    \"WRLToEncCtx\": ${WRL_TO_ENC_CTX:-null},"
fi)
    "EncCtxToAlgctx": ${ENC_CTX_TO_ALGCTX:-null},
    "AlgctxToH": ${ALGCTX_TO_H:-null},
    "SSLToVersion": ${SSL_TO_VERSION:-null},
    "SSLToWBIO": ${SSL_TO_WBIO:-null},
    "AlgctxToGCMKey": ${ALGCTX_TO_GCM_KEY:-null},
    "AlgctxToKeySched": ${ALGCTX_TO_KS:-null},
    "AlgctxToVAESHKey1": ${ALGCTX_TO_VAES_HKEY1}
  }
}
EOF
