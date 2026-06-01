// offset_finder.c — Prints kloak-required struct offsets for a given OpenSSL build.
//
// Compiled inside the OpenSSL source tree (see Dockerfile).
// Outputs JSON with offsets for the 4-hop (3.2+) or 3-hop (3.0-3.1) chain.

#include <stdio.h>
#include <stddef.h>

#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

// Internal headers (from OpenSSL source tree, not installed packages)
#include "ssl_local.h"        // SSL_CONNECTION
#include "evp_local.h"        // EVP_CIPHER_CTX internals
#include "crypto/modes.h"     // GCM128_CONTEXT

int main(void) {
    printf("{\n");
    printf("  \"openssl_version\": \"%s\",\n", OPENSSL_VERSION_TEXT);
    printf("  \"openssl_version_num\": \"0x%08lxL\",\n", (unsigned long)OPENSSL_VERSION_NUMBER);
#if defined(__aarch64__)
    printf("  \"arch\": \"aarch64\",\n");
#elif defined(__x86_64__)
    printf("  \"arch\": \"x86_64\",\n");
#else
    printf("  \"arch\": \"unknown\",\n");
#endif

    printf("  \"sizeof_SSL\": %zu,\n", sizeof(SSL));
    printf("  \"sizeof_SSL_CONNECTION\": %zu,\n", sizeof(SSL_CONNECTION));
    printf("  \"sizeof_EVP_CIPHER_CTX\": %zu,\n", sizeof(EVP_CIPHER_CTX));
    printf("  \"sizeof_GCM128_CONTEXT\": %zu,\n", sizeof(GCM128_CONTEXT));

    // SSL_CONNECTION.version
    printf("  \"ssl_to_version\": %zu,\n", offsetof(SSL_CONNECTION, version));

    // SSL/SSL_CONNECTION.wbio — used by BPF data plane to recover the socket fd.
    // 3-hop (3.0/3.1): ssl_st.wbio = 24. 4-hop (3.2+): ssl_connection_st.wbio = 88.
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    printf("  \"ssl_to_wbio\": %zu,\n", offsetof(SSL_CONNECTION, wbio));
#else
    printf("  \"ssl_to_wbio\": %zu,\n", offsetof(SSL, wbio));
#endif

    // EVP_CIPHER_CTX.algctx (provider context pointer)
    printf("  \"enc_ctx_to_algctx\": %zu,\n", offsetof(EVP_CIPHER_CTX, algctx));

    // GCM128_CONTEXT.H (GHASH key)
    printf("  \"gcm128_h_offset\": %zu,\n", offsetof(GCM128_CONTEXT, H));

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
    // OpenSSL 3.2+: 4-hop chain via record layer
    printf("  \"chain\": \"4-hop\",\n");
    printf("  \"ssl_to_wrl\": %zu,\n", offsetof(SSL_CONNECTION, rlayer.wrl));
    // OSSL_RECORD_LAYER is opaque — wrl_to_enc_ctx must be found via gdb/pahole.
    // Print a placeholder that the user must verify.
    printf("  \"wrl_to_enc_ctx\": \"OPAQUE — use: pahole -C OSSL_RECORD_LAYER libssl.a | grep enc_ctx\"\n");
#else
    // OpenSSL 3.0-3.1: 3-hop chain (enc_write_ctx directly on SSL_CONNECTION)
    printf("  \"chain\": \"3-hop\",\n");
    printf("  \"ssl_to_enc_write_ctx\": %zu\n", offsetof(SSL_CONNECTION, enc_write_ctx));
#endif

    printf("}\n");
    return 0;
}
