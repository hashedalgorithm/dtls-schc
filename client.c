#include<wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERV_PORT 11111
#define MSGLEN    4096

int main(int argc, char **argv)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    WOLFSSL_CTX       *ctx;
    WOLFSSL           *ssl;
    const char        *host   = (argc > 1) ? argv[1] : "127.0.0.1";
    const char        *msg    = "Hello from DTLS client!";
    char               buff[MSGLEN];
    int                n;

    wolfSSL_Init();

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error\n");
        return 1;
    }

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    /* Load CA cert to verify server */
    if (wolfSSL_CTX_load_verify_locations(ctx, "../certs/ca-cert.pem", 0)
            != SSL_SUCCESS) {
        fprintf(stderr, "Error loading ca-cert.pem\n");
        return 1;
    }

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port   = htons(SERV_PORT);
    if (inet_pton(AF_INET, host, &servAddr.sin_addr) < 1) {
        fprintf(stderr, "Invalid address: %s\n", host);
        return 1;
    }

    /* Create UDP socket */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "wolfSSL_new error\n");
        return 1;
    }

    /* Tell wolfSSL the peer address before connecting */
    wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

    wolfSSL_set_fd(ssl, sockfd);


    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

    /* DTLS handshake */
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        int  err = wolfSSL_get_error(ssl, 0);
        char buf[80];
        fprintf(stderr, "wolfSSL_connect error %d: %s\n", err,
                wolfSSL_ERR_error_string(err, buf));
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        close(sockfd);
        return 1;
    }

    printf("Handshake complete! Sending message...\n");

    /* Send one message */
    if (wolfSSL_write(ssl, msg, (int)strlen(msg)) < 0) {
        int  err = wolfSSL_get_error(ssl, 0);
        char buf[80];
        fprintf(stderr, "wolfSSL_write error %d: %s\n", err,
                wolfSSL_ERR_error_string(err, buf));
    } else {
        printf("Sent: \"%s\"\n", msg);
    }

    /* Clean shutdown */
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    close(sockfd);

    printf("Client done, exiting.\n");
    return 0;
}