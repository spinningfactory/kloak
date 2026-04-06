// Minimal BoringSSL HTTPS client for kloak e2e testing.
// Uses SSL_write directly (the symbol kloak attaches uprobes to).

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
        buf[--len] = '\0';
    return buf;
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res;
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

static int do_request(SSL_CTX *ctx, const char *host,
                      const char *secret_allowed, const char *secret_blocked,
                      int req_num) {
    int fd = tcp_connect(host, "443");
    if (fd < 0) {
        fprintf(stderr, "TCP connect to %s:443 failed\n", host);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { close(fd); return -1; }
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        fflush(stderr);
        SSL_free(ssl);
        close(fd);
        return -1;
    }
    printf("[debug] SSL_connect OK, version=%s cipher=%s\n",
           SSL_get_version(ssl), SSL_get_cipher_name(ssl));
    fflush(stdout);

    char request[2048];
    snprintf(request, sizeof(request),
        "GET /headers HTTP/1.1\r\n"
        "Host: %s\r\n"
        "X-Secret-Allowed: %s\r\n"
        "X-Secret-Blocked: %s\r\n"
        "Authorization: Bearer %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        host,
        secret_allowed ? secret_allowed : "",
        secret_blocked ? secret_blocked : "",
        secret_allowed ? secret_allowed : "");

    // SSL_write — this is where kloak's uprobe fires
    int wr = SSL_write(ssl, request, strlen(request));
    printf("[debug] SSL_write returned %d (len=%zu)\n", wr, strlen(request));
    fflush(stdout);
    if (wr <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        return -1;
    }

    char response[8192];
    int total = 0, n;
    while ((n = SSL_read(ssl, response + total, sizeof(response) - total - 1)) > 0) {
        total += n;
        if (total >= (int)sizeof(response) - 1) break;
    }
    if (n < 0) {
        int ssl_err = SSL_get_error(ssl, n);
        fprintf(stderr, "SSL_read error: %d\n", ssl_err);
        ERR_print_errors_fp(stderr);
        fflush(stderr);
    }
    response[total] = '\0';
    printf("[debug] SSL_read total=%d bytes\n", total);
    fflush(stdout);

    printf("\n--- Request #%d ---\n", req_num);
    char *body = strstr(response, "\r\n\r\n");
    if (body) {
        body += 4;
        char *status_end = strstr(response, "\r\n");
        if (status_end) {
            *status_end = '\0';
            printf("Status: %s\n", response);
            *status_end = '\r';
        }
        printf("Response headers echoed back by httpbin:\n%s\n", body);
    } else {
        printf("Raw response:\n%s\n", response);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    return 0;
}

int main(void) {
    const char *allowed_file = getenv("SECRET_ALLOWED_FILE");
    const char *blocked_file = getenv("SECRET_BLOCKED_FILE");
    const char *target_host = getenv("TARGET_HOST");
    const char *interval_str = getenv("REQUEST_INTERVAL");

    if (!target_host) target_host = "httpbin.org";
    int interval = interval_str ? atoi(interval_str) : 5;
    if (interval < 1) interval = 5;

    char *secret_allowed = allowed_file ? read_file(allowed_file) : NULL;
    char *secret_blocked = blocked_file ? read_file(blocked_file) : NULL;

    printf("============================================================\n");
    printf("Kloak Demo (BoringSSL C): HTTPS client\n");
    printf("============================================================\n");
    printf("Target: %s\n", target_host);
    printf("Secret Allowed: %.30s...\n", secret_allowed ? secret_allowed : "(none)");
    printf("Secret Blocked: %.30s...\n", secret_blocked ? secret_blocked : "(none)");
    printf("Interval: %ds\n\n", interval);
    fflush(stdout);

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        return 1;
    }
    // Load system CA certificates for server verification.
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Warning: failed to load CA certificates\n");
    }

    for (int i = 1; ; i++) {
        do_request(ctx, target_host, secret_allowed, secret_blocked, i);
        fflush(stdout);
        printf("\nWaiting %ds before next request...\n", interval);
        fflush(stdout);
        sleep(interval);
    }

    SSL_CTX_free(ctx);
    free(secret_allowed);
    free(secret_blocked);
    return 0;
}
