// Minimal BoringSSL raw-TLS client for kloak e2e testing.
//
// Mirrors examples/demo-python-raw-tls/app.py but linked against BoringSSL
// instead of OpenSSL. It resolves a Kubernetes Service name via DNS (which
// populates kloak's dns_ip_map), connects to the resolved IP, and sends a
// raw TLS payload carrying two secrets:
//
//   ALLOWED=<secret>\nBLOCKED=<secret>\n
//
// The allowed secret's kloak Secret has getkloak.io/hosts set to this echo
// Service, so the kernel rewrites the shadow placeholder to the real value on
// the wire; the echo server returns whatever it received, and we print it so
// the e2e test can assert the real ALLOWED value appears and the BLOCKED one
// does not.
//
// SSL_write is the symbol kloak attaches its uprobe to — the whole point of
// this demo is to exercise that attach + the BoringSSL H-extraction chain.

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

#define LISTEN_PORT "8443"

// read_file slurps a file and trims trailing whitespace/newlines. Returns a
// malloc'd string (caller frees) or NULL.
static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) { fclose(f); return NULL; }
    char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, len, f);
    buf[n] = '\0';
    fclose(f);
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' '))
        buf[--n] = '\0';
    return buf;
}

static char *load_secret(const char *env_var, const char *fallback) {
    const char *path = getenv(env_var);
    if (path && *path) {
        char *v = read_file(path);
        if (v) {
            printf("Loaded secret from %s\n", path);
            return v;
        }
    }
    return strdup(fallback);
}

// tcp_connect resolves host via DNS (populating kloak's dns_ip_map) and opens
// a TCP connection to host:port.
static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

// send_and_echo connects to the echo server, sends the ALLOWED/BLOCKED
// payload via SSL_write, and prints the echoed response.
static int send_and_echo(SSL_CTX *ctx, const char *host,
                         const char *secret_allowed, const char *secret_blocked,
                         int req_num) {
    int fd = tcp_connect(host, LISTEN_PORT);
    if (fd < 0) {
        printf("\n--- Request #%d ---\nError: TCP connect to %s:%s failed\n",
               req_num, host, LISTEN_PORT);
        fflush(stdout);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { close(fd); return -1; }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) <= 0) {
        printf("\n--- Request #%d ---\nError: SSL_connect failed\n", req_num);
        ERR_print_errors_fp(stderr);
        fflush(stdout);
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    if (req_num == 1) {
        printf("Negotiated: %s / %s\n", SSL_get_version(ssl), SSL_get_cipher_name(ssl));
        fflush(stdout);
    }

    char payload[1024];
    int plen = snprintf(payload, sizeof(payload), "ALLOWED=%s\nBLOCKED=%s\n",
                        secret_allowed, secret_blocked);
    if (plen >= (int)sizeof(payload))
        plen = (int)sizeof(payload) - 1;

    // SSL_write — kloak's uprobe fires here and the kernel rewrites the
    // shadow placeholders to real values on the encrypted wire.
    int wr = SSL_write(ssl, payload, plen);
    if (wr <= 0) {
        printf("\n--- Request #%d ---\nError: SSL_write failed\n", req_num);
        ERR_print_errors_fp(stderr);
        fflush(stdout);
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    char echo[16384];
    int total = 0, n;
    while ((n = SSL_read(ssl, echo + total, sizeof(echo) - total - 1)) > 0) {
        total += n;
        if (total >= (int)sizeof(echo) - 1) break;
    }
    echo[total] = '\0';

    printf("\n--- Request #%d (target=%s) ---\n", req_num, host);
    printf("Echo: %s\n", echo);
    fflush(stdout);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return 0;
}

int main(void) {
    char *secret_allowed = load_secret("SECRET_ALLOWED_FILE", "allowed-default-key");
    char *secret_blocked = load_secret("SECRET_BLOCKED_FILE", "blocked-default-key");
    const char *target_host = getenv("TARGET_HOST");
    const char *interval_str = getenv("REQUEST_INTERVAL");
    if (!target_host || !*target_host) target_host = "tls-boring";
    int interval = interval_str ? atoi(interval_str) : 5;
    if (interval < 1) interval = 5;

    printf("============================================================\n");
    printf("Kloak Demo (BoringSSL C): Raw TLS Echo\n");
    printf("============================================================\n");
    printf("Target: %s:%s\n", target_host, LISTEN_PORT);
    printf("Secret Allowed: %.30s...\n", secret_allowed);
    printf("Secret Blocked: %.30s...\n", secret_blocked);
    printf("============================================================\n");
    fflush(stdout);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return 1;
    }
    // Self-signed echo cert — skip verification (this is a local demo).
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    // Force AES-128-GCM. kloak rewrites AES-GCM records only; BoringSSL clients
    // otherwise often negotiate ChaCha20-Poly1305, which kloak can't patch.
    // BoringSSL doesn't allow configuring TLS 1.3 cipher suites, so pin to
    // TLS 1.2 and select the AES-128-GCM suite explicitly.
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256");

    // Wait for the echo server sidecar to come up.
    printf("Waiting for echo server sidecar to be ready...\n");
    fflush(stdout);
    for (int attempt = 0; attempt < 30; attempt++) {
        int fd = tcp_connect(target_host, LISTEN_PORT);
        if (fd >= 0) { close(fd); printf("Echo server is ready.\n"); fflush(stdout); break; }
        sleep(1);
    }

    for (int i = 1; ; i++) {
        send_and_echo(ctx, target_host, secret_allowed, secret_blocked, i);
        sleep(interval);
    }

    SSL_CTX_free(ctx);
    free(secret_allowed);
    free(secret_blocked);
    return 0;
}
