#include <signal.h>
#include<wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERV_IP "127.0.0.1"
#define SERV_PORT 11111
#define MSGLEN    4096

static int flag_stop = 0;

WOLFSSL_CTX *wolfssl_ctx;
WOLFSSL *wolfssl;

int initialize_wolfssl() {
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    wolfssl_ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method());

    if (wolfssl_ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error\n");
        return 1;
    }

    // Disables Server certificate verification.
    wolfSSL_CTX_set_verify(wolfssl_ctx, SSL_VERIFY_NONE, 0);

    // Creating new wolfssl object from contex
    wolfssl = wolfSSL_new(wolfssl_ctx);

    if (wolfssl == NULL) {
        fprintf(stderr, "wolfSSL_new error\n");
        return 1;
    }

    return 0;
}

void close_connection(int socket_file_descriptor) {
    wolfSSL_shutdown(wolfssl);
    wolfSSL_free(wolfssl);
    wolfSSL_CTX_free(wolfssl_ctx);
    wolfSSL_Cleanup();
    close(socket_file_descriptor);
    printf("Closing connection and exiting.\n");
}

int handle_error(int result, int socket_file_descriptor) {
    int error = wolfSSL_get_error(wolfssl, result);
    char buf[80];
    fprintf(stderr, "wolfSSL_connect error %d: %s\n", error,
            wolfSSL_ERR_error_string(error, buf));
    close_connection(socket_file_descriptor);
    return 1;
}

void signal_handler(const int sig) {
    printf("\nSIGINT %d handled\n", sig);
    flag_stop = 1;
}

int main() {
    int socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in server_address;
    const char *msg = "Hello from DTLS client!";

    /* Signal handling */
    struct sigaction new_signal_action, old_signal_action;
    new_signal_action.sa_handler = signal_handler;
    sigemptyset(&new_signal_action.sa_mask);
    new_signal_action.sa_flags = 0;
    sigaction(SIGINT, &new_signal_action, &old_signal_action);

    int resp = initialize_wolfssl();
    if ( resp > 0) return resp;

    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERV_PORT);

    const int inet_pton_result = inet_pton(AF_INET, SERV_IP, &server_address.sin_addr);
    if (inet_pton_result < 1) {
        fprintf(stderr, "Invalid address: %s\n", SERV_IP);
        return 1;
    }

    if (socket_file_descriptor < 0) {
        perror("socket");
        return 1;
    }

    /* Tell wolfSSL the peer address before connecting */
    wolfSSL_dtls_set_peer(wolfssl, &server_address, sizeof(server_address));
    wolfSSL_set_fd(wolfssl, socket_file_descriptor);
    wolfSSL_CTX_set_verify(wolfssl_ctx, SSL_VERIFY_NONE, 0);


    /* DTLS handshake */
    const int handshake_result = wolfSSL_connect(wolfssl);

    if (handshake_result != SSL_SUCCESS) {
        return handle_error(handshake_result, socket_file_descriptor);
    }

    printf("Handshake complete! Sending message...\n");

    /* Send one message */
    resp = wolfSSL_write(wolfssl, msg, (int) strlen(msg));
    if (resp < 0) {
       return handle_error(resp, socket_file_descriptor);
    }

    printf("Sent: \"%s\"\n", msg);

    close_connection(socket_file_descriptor);
    return 0;
}
