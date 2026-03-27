#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <rustls.h>

#define MAX_BUF 8192
#define DEFAULT_URL "https://httpbin.org/headers"
#define DEFAULT_INTERVAL "5"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Failed to open file: %s\n", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    fread(buf, 1, len, f);
    fclose(f);
    buf[len] = '\0';
    /* Trim trailing newline */
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    return buf;
}

/* Parse host and path from URL like https://host/path */
static int parse_url(const char *url, char *host, size_t host_len, char *path, size_t path_len) {
    if (strncmp(url, "https://", 8) != 0) {
        fprintf(stderr, "URL must start with https://\n");
        return -1;
    }
    const char *h = url + 8;
    const char *slash = strchr(h, '/');
    if (slash) {
        size_t hlen = slash - h;
        if (hlen >= host_len) hlen = host_len - 1;
        strncpy(host, h, hlen);
        host[hlen] = '\0';
        strncpy(path, slash, path_len - 1);
        path[path_len - 1] = '\0';
    } else {
        strncpy(host, h, host_len - 1);
        host[host_len - 1] = '\0';
        strncpy(path, "/", path_len - 1);
        path[path_len - 1] = '\0';
    }
    return 0;
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to connect to %s:%s\n", host, port);
    }
    return sockfd;
}

/* I/O callback: write encrypted TLS data to socket */
static int write_tls_cb(void *userdata, const uint8_t *buf, size_t len, size_t *out_n) {
    int fd = *(int *)userdata;
    ssize_t written = write(fd, buf, len);
    if (written < 0) return errno;
    *out_n = (size_t)written;
    return 0;
}

/* I/O callback: read encrypted TLS data from socket */
static int read_tls_cb(void *userdata, uint8_t *buf, size_t len, size_t *out_n) {
    int fd = *(int *)userdata;
    ssize_t n = read(fd, buf, len);
    if (n < 0) return errno;
    if (n == 0) return ECONNRESET;
    *out_n = (size_t)n;
    return 0;
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    const char *allowed_file = getenv("SECRET_ALLOWED_FILE");
    const char *blocked_file = getenv("SECRET_BLOCKED_FILE");
    const char *target_url = getenv("TARGET_URL");
    const char *interval_str = getenv("REQUEST_INTERVAL");

    if (!allowed_file || !blocked_file) {
        fprintf(stderr, "SECRET_ALLOWED_FILE and SECRET_BLOCKED_FILE must be set\n");
        return 1;
    }
    if (!target_url) target_url = DEFAULT_URL;
    if (!interval_str) interval_str = DEFAULT_INTERVAL;
    int interval = atoi(interval_str);
    if (interval <= 0) interval = 5;

    char *secret_allowed = read_file(allowed_file);
    char *secret_blocked = read_file(blocked_file);
    if (!secret_allowed || !secret_blocked) {
        fprintf(stderr, "Failed to read secret files\n");
        return 1;
    }

    char host[256], path[1024];
    if (parse_url(target_url, host, sizeof(host), path, sizeof(path)) != 0) {
        return 1;
    }

    printf("=== Kloak rustls-ffi Demo ===\n");
    printf("Target URL: %s\n", target_url);
    printf("Request interval: %d seconds\n", interval);
    printf("Secret (allowed): %s\n", secret_allowed);
    printf("Secret (blocked): %s\n", secret_blocked);
    printf("Using rustls-ffi for TLS (rustls_connection_write)\n");
    printf("\n");

    printf("Waiting 15 seconds for kloak controller to sync...\n");
    sleep(15);

    /* Build rustls client config with system root certificates */
    rustls_result result;

    /* 1. Build root certificate store from system CA bundle */
    struct rustls_root_cert_store_builder *store_builder = rustls_root_cert_store_builder_new();
    result = rustls_root_cert_store_builder_load_roots_from_file(store_builder,
        "/etc/ssl/certs/ca-certificates.crt", false);
    if (result != RUSTLS_RESULT_OK) {
        fprintf(stderr, "Failed to load root certificates\n");
        return 1;
    }

    const struct rustls_root_cert_store *root_store = NULL;
    result = rustls_root_cert_store_builder_build(store_builder, &root_store);
    if (result != RUSTLS_RESULT_OK) {
        fprintf(stderr, "Failed to build root cert store\n");
        return 1;
    }

    /* 2. Build server certificate verifier using the root store */
    struct rustls_web_pki_server_cert_verifier_builder *verifier_builder =
        rustls_web_pki_server_cert_verifier_builder_new(root_store);
    struct rustls_server_cert_verifier *verifier = NULL;
    result = rustls_web_pki_server_cert_verifier_builder_build(verifier_builder, &verifier);
    if (result != RUSTLS_RESULT_OK) {
        fprintf(stderr, "Failed to build server cert verifier\n");
        return 1;
    }

    /* 3. Build client config with the verifier */
    struct rustls_client_config_builder *builder = rustls_client_config_builder_new();
    rustls_client_config_builder_set_server_verifier(builder, verifier);

    const struct rustls_client_config *config = NULL;
    result = rustls_client_config_builder_build(builder, &config);
    if (result != RUSTLS_RESULT_OK) {
        fprintf(stderr, "Failed to build rustls config\n");
        return 1;
    }

    int iteration = 0;
    while (1) {
        iteration++;
        printf("\n--- Request #%d ---\n", iteration);

        int sockfd = tcp_connect(host, "443");
        if (sockfd < 0) {
            printf("Connection failed, retrying in %d seconds...\n", interval);
            sleep(interval);
            continue;
        }

        struct rustls_connection *conn = NULL;
        result = rustls_client_connection_new(config, host, &conn);
        if (result != RUSTLS_RESULT_OK) {
            fprintf(stderr, "Failed to create rustls connection\n");
            close(sockfd);
            sleep(interval);
            continue;
        }

        rustls_connection_set_userdata(conn, &sockfd);

        /* Handshake loop */
        size_t n = 0;
        while (rustls_connection_is_handshaking(conn)) {
            /* Write any pending TLS data to socket */
            rustls_connection_write_tls(conn, write_tls_cb, &sockfd, &n);

            /* Read TLS data from socket */
            rustls_connection_read_tls(conn, read_tls_cb, &sockfd, &n);

            /* Process the data */
            result = rustls_connection_process_new_packets(conn);
            if (result != RUSTLS_RESULT_OK) {
                fprintf(stderr, "TLS handshake error during process_new_packets\n");
                break;
            }
        }

        if (result != RUSTLS_RESULT_OK) {
            rustls_connection_free(conn);
            close(sockfd);
            sleep(interval);
            continue;
        }

        printf("TLS handshake complete\n");

        /* Build HTTP request */
        char request[MAX_BUF];
        int req_len = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Secret-Allowed: %s\r\n"
            "X-Secret-Blocked: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host, secret_allowed, secret_blocked);

        /* Send plaintext - THIS is the function kloak hooks */
        n = 0;
        result = rustls_connection_write(conn, (const uint8_t *)request, (size_t)req_len, &n);
        if (result != RUSTLS_RESULT_OK) {
            fprintf(stderr, "rustls_connection_write failed\n");
            rustls_connection_free(conn);
            close(sockfd);
            sleep(interval);
            continue;
        }

        /* Flush encrypted data to socket */
        rustls_connection_write_tls(conn, write_tls_cb, &sockfd, &n);

        /* Read response */
        printf("Response:\n");
        char buf[MAX_BUF];
        while (1) {
            n = 0;
            rustls_connection_read_tls(conn, read_tls_cb, &sockfd, &n);
            if (n == 0) break;

            result = rustls_connection_process_new_packets(conn);
            if (result != RUSTLS_RESULT_OK) break;

            n = 0;
            result = rustls_connection_read(conn, (uint8_t *)buf, sizeof(buf) - 1, &n);
            if (n == 0) break;
            if (result != RUSTLS_RESULT_OK) break;
            buf[n] = '\0';
            printf("%s", buf);
        }
        printf("\n");

        /* Clean shutdown */
        rustls_connection_send_close_notify(conn);
        rustls_connection_write_tls(conn, write_tls_cb, &sockfd, &n);

        rustls_connection_free(conn);
        close(sockfd);

        printf("Sleeping %d seconds...\n", interval);
        sleep(interval);
    }

    /* Unreachable, but good practice */
    free(secret_allowed);
    free(secret_blocked);
    rustls_client_config_free(config);
    rustls_server_cert_verifier_free(verifier);
    rustls_root_cert_store_free(root_store);
    return 0;
}
