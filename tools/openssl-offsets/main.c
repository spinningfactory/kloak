// Tool to print OpenSSL struct offsets for kloak TLS key extraction.
// Compile against the target OpenSSL:
//   gcc -o offsets main.c -lssl -lcrypto
// Or in a container:
//   apk add openssl-dev gcc musl-dev && gcc -o offsets main.c -lssl -lcrypto

#include <stdio.h>
#include <stddef.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

// These are internal structs — we need to peek at the headers or source.
// For OpenSSL 3.x, the offsets can be found via:
//   1. pahole on libssl.so (if built with debug info)
//   2. gdb: p/d &((SSL*)0)->enc_write_ctx
//   3. This tool (links against the actual library)

int main(void) {
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("Architecture: %s\n",
#if defined(__aarch64__)
        "aarch64"
#elif defined(__x86_64__)
        "x86_64"
#else
        "unknown"
#endif
    );
    printf("\n");

    // Create a real SSL context + SSL object to measure runtime offsets.
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); return 1; }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { fprintf(stderr, "SSL_new failed\n"); return 1; }

    // Use pointer arithmetic to find field offsets by scanning.
    // This is fragile but works for a given build.
    unsigned char *base = (unsigned char *)ssl;

    // enc_write_ctx: scan for the EVP_CIPHER_CTX pointer.
    // After SSL_do_handshake, enc_write_ctx is set. Before that, it's NULL.
    // We'll just print the known compile-time offset if available,
    // or scan for it.

    printf("=== Compile-time offsets (if available) ===\n");
    printf("sizeof(SSL): %zu\n", sizeof(*ssl));

    // For runtime offset discovery, do a TLS handshake to populate fields.
    // This requires a connection, which we don't have here.
    // Instead, print sizes of related structs.
    printf("sizeof(EVP_CIPHER_CTX): (opaque in OpenSSL 3.x)\n");

    printf("\n");
    printf("=== To get runtime offsets, use gdb ===\n");
    printf("  gdb -batch -ex 'p/d &((SSL*)0)->enc_write_ctx' -ex quit libssl.so\n");
    printf("  gdb -batch -ex 'p/d (int)&((EVP_CIPHER_CTX*)0)->cipher_data' -ex quit libcrypto.so\n");
    printf("\n");
    printf("Or attach to a running process:\n");
    printf("  gdb -p <pid> -batch \\\n");
    printf("    -ex 'p/d (char*)&ssl->enc_write_ctx - (char*)ssl' \\\n");
    printf("    -ex 'p/d (char*)&ctx->cipher_data - (char*)ctx'\n");

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}
