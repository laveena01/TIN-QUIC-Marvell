#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const unsigned char alpn_proto[] = {8,'o','s','s','l','t','e','s','t'};
static size_t server_payload_size = 0;
static bool   server_enable_0rtt  = false;

static int select_alpn(SSL *ssl,
                       const unsigned char **out, unsigned char *out_len,
                       const unsigned char *in, unsigned int in_len,
                       void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len,
                              alpn_proto, sizeof(alpn_proto),
                              in, in_len) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *create_ctx(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) return NULL;
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0) goto err;
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) goto err;
    if (!SSL_CTX_check_private_key(ctx)) goto err;
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    if (server_enable_0rtt)
        SSL_CTX_set_max_early_data(ctx, 16 * 1024);
    return ctx;
err:
    SSL_CTX_free(ctx);
    return NULL;
}

static int create_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) { perror("socket"); return -1; }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    return fd;
}

static int run_quic_conn(SSL *conn) {
    if (server_enable_0rtt) {
        switch (SSL_get_early_data_status(conn)) {
            case SSL_EARLY_DATA_ACCEPTED:
                fprintf(stderr, "=> 0-RTT accepted\n"); break;
            case SSL_EARLY_DATA_REJECTED:
                fprintf(stderr, "=> 0-RTT rejected\n"); break;
            default: break;
        }
        // Echo any early data
        char *early_buf = malloc(server_payload_size);
        size_t early_len = 0;
        int r = SSL_read_early_data(conn, early_buf, server_payload_size, &early_len);
        if (r == SSL_READ_EARLY_DATA_SUCCESS && early_len > 0) {
            size_t written = 0;
            SSL_write_ex2(conn, early_buf, early_len, SSL_WRITE_FLAG_CONCLUDE, &written);
            free(early_buf);
            SSL_shutdown(conn);
            return 1;
        }
        free(early_buf);
    }
    // Normal post-handshake payload
    char *payload = malloc(server_payload_size);
    memset(payload, 'X', server_payload_size);
    size_t written = 0;
    if (!SSL_write_ex2(conn, payload, server_payload_size,
                       SSL_WRITE_FLAG_CONCLUDE, &written)
        || written != server_payload_size) {
        ERR_print_errors_fp(stderr);
        free(payload);
        return 0;
    }
    free(payload);
    SSL_shutdown(conn);
    return 1;
}

static void *client_thread(void *arg) {
    SSL *conn = (SSL *)arg;
    run_quic_conn(conn);
    SSL_free(conn);
    return NULL;
}

static int run_quic_server(SSL_CTX *ctx, int fd) {
    SSL *listener = SSL_new_listener(ctx, 0);
    if (!listener) { ERR_print_errors_fp(stderr); return 0; }
    SSL_set_fd(listener, fd);
    SSL_listen(listener);
    SSL_set_blocking_mode(listener, 1);
    while (1) {
        SSL *conn = SSL_accept_connection(listener, 0);
        if (!conn) { ERR_print_errors_fp(stderr); break; }
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, conn) == 0)
            pthread_detach(tid);
        else {
            perror("pthread_create");
            SSL_free(conn);
        }
    }
    SSL_free(listener);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
                "usage: %s <port> <cert> <key> <payload_size> [--0rtt]\n",
                argv[0]);
        return 1;
    }
    uint16_t port = (uint16_t)strtoul(argv[1], NULL, 0);
    const char *cert = argv[2];
    const char *key  = argv[3];
    server_payload_size = strtoul(argv[4], NULL, 0);
    if (argc >= 6 && strcmp(argv[5], "--0rtt") == 0)
        server_enable_0rtt = true;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX *ctx = create_ctx(cert, key);
    if (!ctx) return 1;
    int fd = create_socket(port);
    if (fd < 0) { SSL_CTX_free(ctx); return 1; }

    run_quic_server(ctx, fd);

    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
