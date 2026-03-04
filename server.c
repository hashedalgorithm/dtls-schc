#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dtls_schc.h"
#include "dtls_rules_config.h"

#define SERV_PORT 11111
#define MSGLEN    4096

static volatile int  cleanup = 0;
static WOLFSSL_CTX  *ctx     = NULL;

/* ── shared send buffer (file-scope) ────────────────────────────── */
static uint8_t g_send_buf[4096];

/* ------------------------------------------------------------------ */
void sig_handler(int sig)
{
    printf("\nSIGINT %d handled\n", sig);
    cleanup = 1;
}

/* ------------------------------------------------------------------ */
/* Custom wolfSSL send callback (server side, mirror of client)       */
/* ------------------------------------------------------------------ */
static int schc_send_callback(WOLFSSL *ssl, char *buf, int sz, void *ctx_arg)
{
    (void)ssl;
    int sockfd = *(int *)ctx_arg;

    if (sz < DTLS_HEADER_LEN) {
        return (int)send(sockfd, buf, (size_t)sz, 0);
    }

    uint8_t        header[DTLS_HEADER_LEN];
    const uint8_t *payload     = (const uint8_t *)buf + DTLS_HEADER_LEN;
    uint16_t       payload_len = (uint16_t)(sz - DTLS_HEADER_LEN);

    memcpy(header, buf, DTLS_HEADER_LEN);

    schc_result_t result;
    if (dtls_schc_compress(header, &dtls_device_strict, &result) < 0) {
        fprintf(stderr, "[server] SCHC compress failed, sending raw\n");
        return (int)send(sockfd, buf, (size_t)sz, 0);
    }
    dtls_schc_print_result(&result);

    int total = dtls_rebuild_packet(
                    result.compressed, result.compressed_len,
                    payload,           payload_len,
                    g_send_buf,        (uint16_t)sizeof(g_send_buf));

    if (total < 0) {
        fprintf(stderr, "[server] dtls_rebuild_packet failed\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return (int)send(sockfd, g_send_buf, (size_t)total, 0);
}

/* ------------------------------------------------------------------ */
/* Custom wolfSSL recv callback (server side, mirror of client)       */
/* ------------------------------------------------------------------ */
static int schc_recv_callback(WOLFSSL *ssl, char *buf, int sz, void *ctx_arg)
{
    (void)ssl;
    int     sockfd = *(int *)ctx_arg;
    uint8_t raw[4096];

    int n = (int)recv(sockfd, raw, sizeof(raw), 0);
    if (n <= 0) return WOLFSSL_CBIO_ERR_GENERAL;

    if (n < 1) return WOLFSSL_CBIO_ERR_GENERAL;

    uint8_t  comp_hdr_len = raw[0];
    if ((int)(1 + comp_hdr_len) > n) return WOLFSSL_CBIO_ERR_GENERAL;

    const uint8_t *comp_hdr = raw + 1;
    const uint8_t *payload  = raw + 1 + comp_hdr_len;
    uint16_t       pay_len  = (uint16_t)(n - 1 - comp_hdr_len);

    uint8_t restored_header[DTLS_HEADER_LEN];
    int hdr_len = dtls_schc_decompress(comp_hdr, comp_hdr_len,
                                        &dtls_device_strict,
                                        restored_header);
    if (hdr_len != DTLS_HEADER_LEN) {
        fprintf(stderr,
                "[server] SCHC decompress returned %d (expected %d)\n",
                hdr_len, DTLS_HEADER_LEN);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    int total = DTLS_HEADER_LEN + (int)pay_len;
    if (total > sz) return WOLFSSL_CBIO_ERR_GENERAL;

    memcpy(buf,                   restored_header, DTLS_HEADER_LEN);
    memcpy(buf + DTLS_HEADER_LEN, payload,         pay_len);

    return total;
}

/* ------------------------------------------------------------------ */
int main(void)
{
    int                listenfd;
    int                on     = 1;
    socklen_t          optlen = sizeof(on);
    socklen_t          clilen;
    struct sockaddr_in servAddr;
    struct sockaddr_in cliAddr;
    unsigned char      peek_buf[1500];
    int                bytes_peeked;
    char               buff[MSGLEN];
    int                recvlen;
    WOLFSSL           *ssl;

    struct sigaction act = { .sa_handler = sig_handler, .sa_flags = 0 };
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, NULL);

    wolfSSL_Init();

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error\n");
        return 1;
    }
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    if (wolfSSL_CTX_load_verify_locations(ctx, "../certs/ca-cert.pem", 0)
            != SSL_SUCCESS) {
        fprintf(stderr, "Error loading ca-cert.pem\n");
        return 1;
    }
    if (wolfSSL_CTX_use_certificate_file(ctx, "../certs/server-cert.pem",
            SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading server-cert.pem\n");
        return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "../certs/server-key.pem",
            SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading server-key.pem\n");
        return 1;
    }

    printf("DTLS server listening on port %d\n", SERV_PORT);

    while (!cleanup) {

        if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("socket");
            break;
        }

        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, optlen);

        memset(&servAddr, 0, sizeof(servAddr));
        servAddr.sin_family      = AF_INET;
        servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servAddr.sin_port        = htons(SERV_PORT);

        if (bind(listenfd, (struct sockaddr *)&servAddr,
                 sizeof(servAddr)) < 0) {
            perror("bind");
            close(listenfd);
            break;
        }

        printf("Waiting for client...\n");

        clilen       = sizeof(cliAddr);
        bytes_peeked = (int)recvfrom(listenfd,
                                     (char *)peek_buf, sizeof(peek_buf),
                                     MSG_PEEK,
                                     (struct sockaddr *)&cliAddr, &clilen);

        if (bytes_peeked < 0) {
            printf("No clients in queue, continuing...\n");
            close(listenfd);
            continue;
        }

        printf("Client from %s\n", inet_ntoa(cliAddr.sin_addr));

        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "wolfSSL_new error\n");
            close(listenfd);
            break;
        }

        wolfSSL_dtls_set_peer(ssl, &cliAddr, sizeof(cliAddr));

        /* Wire up SCHC IO hooks before the handshake */
        wolfSSL_SetIOSend(ssl,     schc_send_callback);
        wolfSSL_SetIORecv(ssl,     schc_recv_callback);
        wolfSSL_SetIOWriteCtx(ssl, &listenfd);
        wolfSSL_SetIOReadCtx(ssl,  &listenfd);

        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            int  err = wolfSSL_get_error(ssl, 0);
            char ebuf[80];
            fprintf(stderr, "wolfSSL_accept error %d: %s\n",
                    err, wolfSSL_ERR_error_string(err, ebuf));
            wolfSSL_free(ssl);
            close(listenfd);
            continue;
        }

        printf("Handshake complete. Reading message...\n");

        recvlen = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
        if (recvlen > 0) {
            buff[recvlen] = '\0';
            printf("Received: \"%s\"\n", buff);

            /* Echo back */
            wolfSSL_write(ssl, buff, recvlen);
        } else {
            int  err  = wolfSSL_get_error(ssl, 0);
            char ebuf[80];
            fprintf(stderr, "wolfSSL_read error %d: %s\n",
                    err, wolfSSL_ERR_error_string(err, ebuf));
        }

        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(listenfd);

        printf("Session closed, returning to idle\n\n");
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}