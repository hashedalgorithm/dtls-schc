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

#define SERV_PORT 11111
#define MSGLEN    4096

static int cleanup = 0;
WOLFSSL_CTX *ctx;

void sig_handler(const int sig)
{
    printf("\nSIGINT %d handled\n", sig);
    cleanup = 1;
}

int main(void)
{
    int                listenfd;
    int                on  = 1;
    int                res = 1;
    socklen_t          len = sizeof(on);
    socklen_t          clilen;
    struct sockaddr_in servAddr;
    struct sockaddr_in cliAddr;
    unsigned char      b[1500];
    int                bytesReceived;
    char               buff[MSGLEN];
    int                recvlen;
    WOLFSSL           *ssl;

    /* Signal handling */
    struct sigaction act, oact;
    act.sa_handler = sig_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, &oact);

    /* Init wolfSSL */
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

    while (cleanup != 1) {

        /* Create UDP socket */
        if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            printf("Cannot create socket\n");
            cleanup = 1;
            break;
        }

        /* Avoid socket-in-use error */
        res = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0) {
            printf("setsockopt SO_REUSEADDR failed\n");
            cleanup = 1;
            break;
        }

        memset(&servAddr, 0, sizeof(servAddr));
        servAddr.sin_family      = AF_INET;
        servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servAddr.sin_port        = htons(SERV_PORT);

        if (bind(listenfd, (struct sockaddr *)&servAddr,
                sizeof(servAddr)) < 0) {
            printf("bind failed\n");
            cleanup = 1;
            break;
        }

        printf("Waiting for client...\n");

        /* Peek for incoming datagram */
        clilen        = sizeof(cliAddr);
        bytesReceived = (int)recvfrom(listenfd, (char *)b, sizeof(b),
                                      MSG_PEEK,
                                      (struct sockaddr *)&cliAddr, &clilen);

        if (bytesReceived < 0) {
            printf("No clients in queue, returning to idle\n");
            close(listenfd);
            continue;
        }


        printf("Client connected from %s\n", inet_ntoa(cliAddr.sin_addr));

        /* Create WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            printf("wolfSSL_new error\n");
            cleanup = 1;
            break;
        }

        wolfSSL_dtls_set_peer(ssl, &cliAddr, sizeof(cliAddr));
        wolfSSL_set_fd(ssl, listenfd);

        /* DTLS handshake */
        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            int   err = wolfSSL_get_error(ssl, 0);
            char  buf[80];
            printf("wolfSSL_accept error %d: %s\n", err,
                   wolfSSL_ERR_error_string(err, buf));
            wolfSSL_free(ssl);
            close(listenfd);
            continue;
        }

        printf("Handshake complete! Reading message...\n");

        /* Read one message */
        recvlen = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
        if (recvlen > 0) {
            buff[recvlen] = '\0';
            printf("Received: \"%s\"\n", buff);
        } else {
            int err = wolfSSL_get_error(ssl, 0);
            char ebuf[80];
            printf("wolfSSL_read error %d: %s\n", err,
                   wolfSSL_ERR_error_string(err, ebuf));
        }

        /* Cleanup session */
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(listenfd);

        printf("Session closed, returning to idle\n\n");
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}