#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "schc_mini.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <execinfo.h>


#define SERV_IP "127.0.0.1"
#define SERV_PORT 11111
#define MSGLEN    4096


static int flag_stop = 0;

WOLFSSL_CTX *wolfssl_ctx;
WOLFSSL *wolfssl;


static int send_dtls_record(WOLFSSL *_, char *buffer, int size, void *context) {
    uint8_t result_buffer[MSGLEN];
    const int socket_file_descriptor = *(int *) context;

    int out_len = schc_compress((uint8_t *) buffer, (size_t) size, result_buffer, sizeof(result_buffer));
    if (out_len < 0) {
        fprintf(stderr, "dtls_mini_compress failed\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    // print_dtls_record(SEND_DTLS_RECORD, buffer, size);
    // print_dtls_record(SEND_DTLS_RECORD, (char *)result_buffer, out_len);

    printf("dtls_mini_compress %d bytes\n", out_len);
    int resp = (int) send(socket_file_descriptor, result_buffer, out_len, 0);
    if (resp < 0) {
        perror("send");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return size;
}

static int receive_dtls_record(WOLFSSL *_, char *buffer, int size, void *context) {
    uint8_t result_buffer[MSGLEN];
    int socket_file_descriptor = *(int *) context;

    const int resp = (int) recv(socket_file_descriptor, result_buffer, sizeof(result_buffer), 0);
    if (resp < 0) {
        perror("recv");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (resp == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;

    const int out_len = schc_decompress(result_buffer, (size_t) resp, (uint8_t *) buffer, (size_t) size);
    if (out_len < 0) {
        fprintf(stderr, "dtls_mini_decompress failed (received %d bytes)\n",
                resp);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    printf("dtls_mini_decompress %d bytes\n", out_len);
    // print_dtls_record(SEND_DTLS_RECORD, buffer, size);
    // print_dtls_record(SEND_DTLS_RECORD, (char *)result_buffer, MSGLEN);

    return out_len;
}


static int initialize_wolfssl() {
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    wolfssl_ctx = wolfSSL_CTX_new(wolfDTLSv1_3_client_method());

    if (wolfssl_ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error\n");
        return 1;
    }

    // Disables Server certificate verification.
    wolfSSL_CTX_set_verify(wolfssl_ctx, SSL_VERIFY_NONE, 0);

    wolfSSL_CTX_SetIOSend(wolfssl_ctx, send_dtls_record);
    wolfSSL_CTX_SetIORecv(wolfssl_ctx, receive_dtls_record);

    // Creating new wolfssl object from contex
    wolfssl = wolfSSL_new(wolfssl_ctx);

    if (wolfssl == NULL) {
        fprintf(stderr, "wolfSSL_new error\n");
        return 1;
    }

    return 0;
}

static void close_connection(int socket_file_descriptor) {
    wolfSSL_shutdown(wolfssl);
    wolfSSL_free(wolfssl);
    wolfSSL_CTX_free(wolfssl_ctx);
    wolfSSL_Cleanup();
    close(socket_file_descriptor);
    printf("Closing connection and exiting.\n");
}

static int handle_error(int result, int socket_file_descriptor) {
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
    if (resp > 0) return resp;

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

    // Connect to the socket before binding it with Wolfssl
    const int connect_result = connect(socket_file_descriptor, (struct sockaddr *) &server_address,
                                       sizeof(server_address));
    if (connect_result < 0) {
        fprintf(stderr, "Connection to the server failed: %s\n", SERV_IP);
        close_connection(socket_file_descriptor);
        return 1;
    }

    /* Tell wolfSSL the peer address before connecting */
    wolfSSL_dtls_set_peer(wolfssl, &server_address, sizeof(server_address));
    wolfSSL_set_fd(wolfssl, socket_file_descriptor);

    wolfSSL_SetIOWriteCtx(wolfssl, &socket_file_descriptor);
    wolfSSL_SetIOReadCtx(wolfssl, &socket_file_descriptor);

    wolfSSL_CTX_set_verify(wolfssl_ctx, SSL_VERIFY_NONE, 0);


    /* DTLS handshake */
    const int handshake_result = wolfSSL_connect(wolfssl);

    if (handshake_result != SSL_SUCCESS) {
        return handle_error(handshake_result, socket_file_descriptor);
    }

    printf("Handshake complete!. Sending message...\n");

    /* Send one message */
    resp = wolfSSL_write(wolfssl, msg, (int) strlen(msg));
    if (resp < 0) {
        return handle_error(resp, socket_file_descriptor);
    }

    printf("Sent: \"%s\"\n", msg);

    close_connection(socket_file_descriptor);
    return 0;
}
