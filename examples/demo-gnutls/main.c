#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gnutls/gnutls.h>

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

int main(void) {
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

    printf("=== Kloak GnuTLS Demo ===\n");
    printf("Target URL: %s\n", target_url);
    printf("Request interval: %d seconds\n", interval);
    printf("Secret (allowed): %s\n", secret_allowed);
    printf("Secret (blocked): %s\n", secret_blocked);
    printf("Using GnuTLS for TLS (gnutls_record_send)\n");
    printf("\n");

    printf("Waiting 15 seconds for kloak controller to sync...\n");
    sleep(15);

    gnutls_global_init();

    gnutls_certificate_credentials_t cred;
    gnutls_certificate_allocate_credentials(&cred);
    gnutls_certificate_set_x509_system_trust(cred);

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

        gnutls_session_t session;
        gnutls_init(&session, GNUTLS_CLIENT);
        gnutls_set_default_priority(session);
        gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
        gnutls_server_name_set(session, GNUTLS_NAME_DNS, host, strlen(host));
        gnutls_transport_set_int(session, sockfd);

        int ret = gnutls_handshake(session);
        if (ret < 0) {
            fprintf(stderr, "TLS handshake failed: %s\n", gnutls_strerror(ret));
            gnutls_deinit(session);
            close(sockfd);
            sleep(interval);
            continue;
        }

        printf("TLS handshake complete (version: %s)\n",
               gnutls_protocol_get_name(gnutls_protocol_get_version(session)));

        char request[MAX_BUF];
        int req_len = snprintf(request, sizeof(request),
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "X-Secret-Allowed: %s\r\n"
            "X-Secret-Blocked: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host, secret_allowed, secret_blocked);

        ret = gnutls_record_send(session, request, req_len);
        if (ret < 0) {
            fprintf(stderr, "gnutls_record_send failed: %s\n", gnutls_strerror(ret));
            gnutls_bye(session, GNUTLS_SHUT_RDWR);
            gnutls_deinit(session);
            close(sockfd);
            sleep(interval);
            continue;
        }

        printf("Response:\n");
        char buf[MAX_BUF];
        while (1) {
            ret = gnutls_record_recv(session, buf, sizeof(buf) - 1);
            if (ret == 0) break; /* EOF */
            if (ret < 0) {
                if (ret == GNUTLS_E_PREMATURE_TERMINATION) break;
                fprintf(stderr, "gnutls_record_recv: %s\n", gnutls_strerror(ret));
                break;
            }
            buf[ret] = '\0';
            printf("%s", buf);
        }
        printf("\n");

        gnutls_bye(session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session);
        close(sockfd);

        printf("Sleeping %d seconds...\n", interval);
        sleep(interval);
    }

    /* Unreachable, but good practice */
    free(secret_allowed);
    free(secret_blocked);
    gnutls_certificate_free_credentials(cred);
    gnutls_global_deinit();
    return 0;
}
