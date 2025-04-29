
// client.c – QUIC client with separate HS vs RD metrics, configurable payload
// build: gcc -pthread client.c -o client -lssl -lcrypto
// usage: ./client <threads> <mode:0rtt|1rtt> <duration_s> <server_ip> <server_port> <payload_size>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

static int    NUM_THREADS        = 1;
static bool   enable_0rtt        = false;
static char  *SERVER_IP          = "127.0.0.1";
static uint16_t SERVER_PORT      = 4433;
static double DURATION           = 10.0;
static size_t client_payload_size = 0;

static const unsigned char ALPN_PROTO[] = {8,'o','s','s','l','t','e','s','t'};
// 0-RTT session cache
static SSL_SESSION *session_cache = NULL;
static pthread_mutex_t session_mtx = PTHREAD_MUTEX_INITIALIZER;

// Metrics
static atomic_long handshake_count  = 0;
static atomic_long handshake_lat_us = 0;
static atomic_long data_count       = 0;
static atomic_long data_lat_us      = 0;
static atomic_long total_bytes      = 0;

static double now_sec() {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
}
static long now_us() {
    struct timeval tv; gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000L + tv.tv_usec;
}

static SSL_CTX *create_ctx(void) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!ctx) { fprintf(stderr, "SSL_CTX_new() failed\n"); return NULL; }
    SSL_CTX_set_alpn_protos(ctx, ALPN_PROTO, sizeof(ALPN_PROTO));
    return ctx;
}

static void warm_up_ticket(void) {
    SSL_CTX *ctx = create_ctx(); if (!ctx) return;
    SSL *ssl = SSL_new(ctx);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(SERVER_PORT)};
    inet_pton(AF_INET, SERVER_IP, &sa.sin_addr);
    BIO_ADDR *peer = BIO_ADDR_new();
    BIO_ADDR_rawmake(peer, AF_INET, &sa.sin_addr, sizeof(sa.sin_addr), sa.sin_port);
    BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
    BIO_dgram_set_peer(bio, peer);
    BIO_up_ref(bio);
    SSL_set0_rbio(ssl, bio); SSL_set0_wbio(ssl, bio);
    SSL_set_connect_state(ssl); SSL_set_blocking_mode(ssl, 1);
    if (SSL_connect(ssl) == 1) {
        SSL_SESSION *sess = SSL_get1_session(ssl);
        if (sess) {
            pthread_mutex_lock(&session_mtx);
            if (!session_cache) session_cache = sess;
            else SSL_SESSION_free(sess);
            pthread_mutex_unlock(&session_mtx);
        }
    }
    SSL_free(ssl); SSL_CTX_free(ctx); BIO_ADDR_free(peer); close(fd);
}

void *worker_thread(void *arg) {
    (void)arg;
    SSL_CTX *ctx = create_ctx(); if (!ctx) return NULL;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in sa = {.sin_family=AF_INET, .sin_port=htons(SERVER_PORT)};
    inet_pton(AF_INET, SERVER_IP, &sa.sin_addr);
    BIO_ADDR *peer = BIO_ADDR_new();
    BIO_ADDR_rawmake(peer, AF_INET, &sa.sin_addr, sizeof(sa.sin_addr), sa.sin_port);

    char *read_buf = malloc(client_payload_size + 1);
    double end_time = now_sec() + DURATION;
    while (now_sec() < end_time) {
        SSL *ssl = SSL_new(ctx);
        BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
        BIO_dgram_set_peer(bio, peer); BIO_up_ref(bio);
        SSL_set0_rbio(ssl, bio); SSL_set0_wbio(ssl, bio);
        SSL_set_connect_state(ssl); SSL_set_blocking_mode(ssl, 1);
        if (enable_0rtt && session_cache) {
            SSL_set_session(ssl, session_cache);
            size_t wrote = 0;
            SSL_write_early_data(ssl, "ping", 4, &wrote);
        }
        long hs_start = now_us();
        if (SSL_connect(ssl) == 1) {
            long hs_end = now_us();
            atomic_fetch_add(&handshake_count, 1);
            atomic_fetch_add(&handshake_lat_us, (hs_end - hs_start));

            long rd_start = now_us();
            size_t got = 0;
            if (SSL_read_ex(ssl, read_buf, client_payload_size, &got) == 1) {
                read_buf[got] = '\0';
                long rd_end = now_us();
                atomic_fetch_add(&data_count, 1);
                atomic_fetch_add(&data_lat_us, (rd_end - rd_start));
                atomic_fetch_add(&total_bytes, got);
            }
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }
    free(read_buf);
    BIO_ADDR_free(peer); SSL_CTX_free(ctx); close(fd);
    return NULL;
}

void *monitor_thread(void *arg) {
    (void)arg;
    double end_time = now_sec() + DURATION;
    long last_hsc = 0, last_hsl = 0;
    long last_dc = 0,  last_dsl = 0;
    long last_b  = 0;
    while (now_sec() < end_time) {
        sleep(2);
        long hsc = atomic_load(&handshake_count);
        long hsl = atomic_load(&handshake_lat_us);
        long dc  = atomic_load(&data_count);
        long dsl = atomic_load(&data_lat_us);
        long b   = atomic_load(&total_bytes);

        long dhsc = hsc - last_hsc;
        long dhsl = hsl - last_hsl;
        long ddc  = dc  - last_dc;
        long ddsl = dsl - last_dsl;
        long db   = b   - last_b;

        double hs_tps = dhsc / 2.0;
        double hs_ms  = dhsc > 0 ? ((dhsl / 1000.0) / dhsc) : 0;
        double rd_tps = ddc  / 2.0;
        double rd_ms  = ddc  > 0 ? ((ddsl / 1000.0) / ddc) : 0;
        double mib_s  = (db / (1024.0 * 1024.0)) / 2.0;

        printf("[Metrics] HS-TPS: %.2f, HS-Lat: %.2f ms  |  RD-TPS: %.2f, RD-Lat: %.2f ms  |  Thrpt: %.2f MiB/s\n",
               hs_tps, hs_ms, rd_tps, rd_ms, mib_s);

        last_hsc = hsc; last_hsl = hsl;
        last_dc  = dc;  last_dsl = dsl;
        last_b   = b;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr,
                "Usage: %s <num_threads> <mode:0rtt|1rtt> <duration_s> <server_ip> <server_port> <payload_size>\n",
                argv[0]);
        return 1;
    }
    NUM_THREADS       = atoi(argv[1]);
    enable_0rtt       = (strcmp(argv[2], "0rtt") == 0);
    DURATION          = atof(argv[3]);
    SERVER_IP         = argv[4];
    SERVER_PORT       = (uint16_t)atoi(argv[5]);
    client_payload_size = strtoul(argv[6], NULL, 0);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    if (enable_0rtt) warm_up_ticket();

    pthread_t monitor;
    pthread_create(&monitor, NULL, monitor_thread, NULL);

    pthread_t *threads = malloc(sizeof(pthread_t) * NUM_THREADS);
    for (int i = 0; i < NUM_THREADS; ++i)
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    for (int i = 0; i < NUM_THREADS; ++i)
        pthread_join(threads[i], NULL);
    pthread_join(monitor, NULL);

    long total_hs  = atomic_load(&handshake_count);
    long total_hsl = atomic_load(&handshake_lat_us);
    long total_dc  = atomic_load(&data_count);
    long total_dsl = atomic_load(&data_lat_us);
    long total_b   = atomic_load(&total_bytes);

    double avg_hs_ms = total_hs > 0 ? ((total_hsl / 1000.0) / total_hs) : 0;
    double avg_rd_ms = total_dc > 0 ? ((total_dsl / 1000.0) / total_dc) : 0;
    double total_mib = total_b / (1024.0 * 1024.0);

    printf("\nSummary:\n");
    printf("  Handshakes: %ld, Avg HS Latency: %.2f ms\n",
           total_hs, avg_hs_ms);
    printf("  Data Reads: %ld, Avg RD Latency: %.2f ms\n",
           total_dc, avg_rd_ms);
    printf("  Total Data Received: %.2f MiB\n", total_mib);

    return 0;
}
