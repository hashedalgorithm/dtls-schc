#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <execinfo.h>

#include "dtls_schc.h"
#include "dtls_rules_config.h"

static void crash_handler(int sig)
{
    void *bt[32];
    int   n = backtrace(bt, 32);
    fprintf(stderr, "Signal %d:\n", sig);
    backtrace_symbols_fd(bt, n, 2);
    _exit(1);
}


#define SERV_PORT 11111
#define MSGLEN    4096



/* ── shared send buffer (file-scope, not stack) ─────────────────── */
static uint8_t g_send_buf[4096];

/* ------------------------------------------------------------------ */
/* Custom wolfSSL send callback                                        */
/* Intercepts the raw DTLS record, compresses the 13-byte header with  */
/* SCHC, then sends: [1-byte hdr len][compressed hdr][ciphertext]     */
/* ------------------------------------------------------------------ */
static int schc_send_callback(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{

    if (ctx == NULL) {
        fprintf(stderr, "SEND CALLBACK: ctx is NULL\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    (void)ssl;
    int sockfd = *(int *)ctx;

    /* If the datagram is shorter than a full DTLS header just pass it */
    if (sz < DTLS_HEADER_LEN) {
        return (int)send(sockfd, buf, (size_t)sz, 0);
    }

    /* Split header / payload */
    uint8_t        header[DTLS_HEADER_LEN];
    const uint8_t *payload     = (const uint8_t *)buf + DTLS_HEADER_LEN;
    uint16_t       payload_len = (uint16_t)(sz - DTLS_HEADER_LEN);

    memcpy(header, buf, DTLS_HEADER_LEN);

    /* Compress header */
    schc_result_t result;
    if (dtls_schc_compress(header, &dtls_device_strict, &result) < 0) {
        fprintf(stderr, "[client] SCHC compress failed, sending raw\n");
        return (int)send(sockfd, buf, (size_t)sz, 0);
    }
    dtls_schc_print_result(&result);

    /* Build wire frame: [1-byte len][compressed hdr][payload] */
    int total = dtls_rebuild_packet(
                    result.compressed, result.compressed_len,
                    payload,           payload_len,
                    g_send_buf,        (uint16_t)sizeof(g_send_buf));

    if (total < 0) {
        fprintf(stderr, "[client] dtls_rebuild_packet failed\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    return (int)send(sockfd, g_send_buf, (size_t)total, 0);
}

/* ------------------------------------------------------------------ */
/* Custom wolfSSL recv callback                                        */
/* Reads the wire frame, decompresses the SCHC header, then hands the  */
/* reconstructed DTLS record back to wolfSSL.                         */
/* ------------------------------------------------------------------ */
static int schc_recv_callback(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    if (ctx == NULL) {
        fprintf(stderr, "SEND CALLBACK: ctx is NULL\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    (void)ssl;
    int     sockfd = *(int *)ctx;
    uint8_t raw[4096];

    int n = (int)recv(sockfd, raw, sizeof(raw), 0);
    if (n <= 0) return WOLFSSL_CBIO_ERR_GENERAL;

    /* Parse wire frame ------------------------------------------------
     * Frame: [1-byte comp_hdr_len][compressed header][payload]
     * The 1-byte length prefix tells us where the header ends.
     */
    if (n < 1) return WOLFSSL_CBIO_ERR_GENERAL;

    uint8_t  comp_hdr_len = raw[0];
    if ((int)(1 + comp_hdr_len) > n) return WOLFSSL_CBIO_ERR_GENERAL;

    const uint8_t *comp_hdr  = raw + 1;
    const uint8_t *payload   = raw + 1 + comp_hdr_len;
    uint16_t       pay_len   = (uint16_t)(n - 1 - comp_hdr_len);

    /* Decompress SCHC header */
    uint8_t restored_header[DTLS_HEADER_LEN];
    int hdr_len = dtls_schc_decompress(comp_hdr, comp_hdr_len,
                                        &dtls_device_strict,
                                        restored_header);
    if (hdr_len != DTLS_HEADER_LEN) {
        fprintf(stderr,
                "[client] SCHC decompress returned %d (expected %d)\n",
                hdr_len, DTLS_HEADER_LEN);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* Reconstruct the original DTLS record for wolfSSL */
    int total = DTLS_HEADER_LEN + (int)pay_len;
    if (total > sz) return WOLFSSL_CBIO_ERR_GENERAL;

    memcpy(buf,                      restored_header, DTLS_HEADER_LEN);
    memcpy(buf + DTLS_HEADER_LEN,    payload,         pay_len);

    return total;
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS,  crash_handler);

    int                sockfd;
    struct sockaddr_in servAddr;
    WOLFSSL_CTX       *ctx;
    WOLFSSL           *ssl;
    const char *host = "127.0.0.1";
    const char        *msg  = "Hello from DTLS client!";
    char               buff[MSGLEN];

    wolfSSL_Init();
    wolfSSL_Debugging_ON();
    dtls_schc_init();

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error\n");
        return 1;
    }
    wolfSSL_CTX_SetIOSend(ctx, schc_send_callback);
    wolfSSL_CTX_SetIORecv(ctx, schc_recv_callback);

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    // if (wolfSSL_CTX_load_verify_locations(ctx, "../certs/ca-cert.pem", 0)
    //         != SSL_SUCCESS) {
    //     fprintf(stderr, "Error loading ca-cert.pem\n");
    //     wolfSSL_CTX_free(ctx);
    //     return 1;
    // }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port   = htons(SERV_PORT);


    if (inet_pton(AF_INET, host, &servAddr.sin_addr) < 1) {
        fprintf(stderr, "Invalid address: %s\n", host);
        wolfSSL_CTX_free(ctx);
        return 1;
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        wolfSSL_CTX_free(ctx);
        return 1;
    }

    int *sock_ctx = malloc(sizeof(int));
    if (!sock_ctx) {
        perror("malloc");
        return 1;
    }
    *sock_ctx = sockfd;

    if (connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        perror("connect");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new error\n");
        wolfSSL_CTX_free(ctx);
        close(sockfd);
        return 1;
    }

    /* Set IO context AFTER successful creation */
    wolfSSL_SetIOWriteCtx(ssl, sock_ctx);
    wolfSSL_SetIOReadCtx(ssl,  sock_ctx);

    wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));


    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        int  err = wolfSSL_get_error(ssl, 0);
        char ebuf[80];
        fprintf(stderr, "wolfSSL_connect error %d: %s\n",
                err, wolfSSL_ERR_error_string(err, ebuf));
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        close(sockfd);
        return 1;
    }

    printf("Handshake complete. Sending message...\n");

    if (wolfSSL_write(ssl, msg, (int)strlen(msg)) < 0) {
        int  err = wolfSSL_get_error(ssl, 0);
        char ebuf[80];
        fprintf(stderr, "wolfSSL_write error %d: %s\n",
                err, wolfSSL_ERR_error_string(err, ebuf));
    } else {
        printf("Sent: \"%s\"\n", msg);
    }

    /* Optionally read a reply */
    int n = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
    if (n > 0) {
        buff[n] = '\0';
        printf("Received: \"%s\"\n", buff);
    }

    wolfSSL_shutdown(ssl);
    free(sock_ctx);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);

    printf("Client done.\n");
    return 0;
}