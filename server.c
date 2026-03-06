#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "schc_mini.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define SERV_IP "127.0.0.1"
#define SERV_PORT 11111
#define MSGLEN    4096

WOLFSSL_CTX *wolfssl_ctx;
WOLFSSL *wolfssl;

static int flag_stop = 0;

static int send_dtls_record(WOLFSSL *_, char *buffer, int size, void *context) {
    uint8_t result_buffer[MSGLEN];
    const int socket_file_descriptor = *(int *)context;

    int out_len = schc_compress((uint8_t *)buffer, (size_t)size, result_buffer, sizeof(result_buffer));
    if (out_len < 0) {
        fprintf(stderr, "dtls_mini_compress failed\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    // print_dtls_record(SEND_DTLS_RECORD, buffer, size);
    // print_dtls_record(SEND_DTLS_RECORD, (char *)result_buffer, out_len);

    printf("dtls_mini_compress %d bytes\n", out_len);
    int resp = (int)send(socket_file_descriptor, result_buffer, out_len, 0);
    if (resp < 0) {
        perror("send");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    return size;
}

static int receive_dtls_record(WOLFSSL *_, char *buffer, int size, void *context) {
    uint8_t result_buffer[MSGLEN];
    const int socket_file_descriptor = *(int *)context;

    const int resp = (int)recv(socket_file_descriptor, result_buffer, sizeof(result_buffer), 0);
    if (resp < 0) {
        perror("recv");
        return WOLFSSL_CBIO_ERR_GENERAL;
    }
    if (resp == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;

    const int out_len = schc_decompress(result_buffer, (size_t)resp, (uint8_t *)buffer, (size_t)size);

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


int initialize_wolfssl() {
    wolfSSL_Init();
    wolfSSL_Debugging_ON();

    wolfssl_ctx = wolfSSL_CTX_new(wolfDTLSv1_3_server_method());

    if (wolfssl_ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error\n");
        return 1;
    }

    // Disables Server certificate verification.
    wolfSSL_CTX_set_verify(wolfssl_ctx, SSL_VERIFY_NONE, 0);

    int resp = wolfSSL_CTX_use_certificate_file(wolfssl_ctx, "../certs/server-cert.pem",SSL_FILETYPE_PEM);
    if (resp != SSL_SUCCESS) {
        fprintf(stderr, "Error loading server-cert.pem\n");
        return 1;
    }

    resp = wolfSSL_CTX_use_PrivateKey_file(wolfssl_ctx, "../certs/server-key.pem",SSL_FILETYPE_PEM);
    if (resp != SSL_SUCCESS) {
        fprintf(stderr, "Error loading server-key.pem\n");
        return 1;
    }

    wolfSSL_CTX_SetIOSend(wolfssl_ctx, send_dtls_record);
    wolfSSL_CTX_SetIORecv(wolfssl_ctx, receive_dtls_record);

    return 0;
}

void handle_error(int result) {
    int error = wolfSSL_get_error(wolfssl, result);
    char buffer[100];

    printf("wolfSSL_connect error %d: %s\n", error,
            wolfSSL_ERR_error_string(error, buffer));
}


void signal_handler(const int sig) {
    printf("\nSIGINT %d handled\n", sig);
    flag_stop = 1;
}

int main() {
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;


    /* Signal handling */
    struct sigaction new_signal_action, old_signal_action;
    new_signal_action.sa_handler = signal_handler;
    sigemptyset(&new_signal_action.sa_mask);
    new_signal_action.sa_flags = 0;
    sigaction(SIGINT, &new_signal_action, &old_signal_action);


    const int resp = initialize_wolfssl();
    if ( resp > 0) return resp;

    printf("UDP Server listening on port %d\n", SERV_PORT);

    while (flag_stop != 1) {

        // Creating new wolfssl object from contex
        wolfssl = wolfSSL_new(wolfssl_ctx);

        if (wolfssl == NULL) {
            fprintf(stderr, "wolfSSL_new error\n");
            return 1;
        }

        /* Create UDP socket */
        const int socket_file_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_file_descriptor < 0) {
            printf("Cannot create socket\n");
            flag_stop = 1;
            break;
        }
        /* Avoid socket-in-use error */
        int on = 1;
        const int res = setsockopt(socket_file_descriptor, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));

        if (res < 0) {
            printf("setsockopt SO_REUSEADDR failed\n");
            flag_stop = 1;
            break;
        }

        memset(&server_address, 0, sizeof(server_address));
        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(SERV_PORT);
        const int inet_pton_result = inet_pton(AF_INET, SERV_IP, &server_address.sin_addr);

        if (inet_pton_result < 1) {
            fprintf(stderr, "Invalid address: %s\n", SERV_IP);
            return 1;
        }

        const int bind_result = bind(socket_file_descriptor, (struct sockaddr *) &server_address,
                                     sizeof(server_address));
        if (bind_result < 0) {
            printf("bind failed\n");
            flag_stop = 1;
            break;
        }

        printf("Waiting for client...\n");

        /* Peek for incoming datagram */
        socklen_t client_address_size = sizeof(client_address);
        unsigned char raw_bytes[1500];
        const int bytesReceived = (int) recvfrom(socket_file_descriptor, (char *)raw_bytes, sizeof(raw_bytes), MSG_PEEK,
                                       (struct sockaddr *) &client_address, &client_address_size);

        if (bytesReceived < 0) {
            printf("No clients in queue, returning to idle\n");
            close(socket_file_descriptor);
            continue;
        }
        const int connect_result = connect(socket_file_descriptor, (struct sockaddr *)&client_address, sizeof(client_address));
        if (connect_result < 0) {
            fprintf(stderr, "Connection to the server failed: %s\n", SERV_IP);
            /* Cleanup session */
            wolfSSL_shutdown(wolfssl);
            wolfSSL_free(wolfssl);
            close(socket_file_descriptor);
            return 1;
        }

        printf("Client connected from %s\n", inet_ntoa(client_address.sin_addr));

        wolfSSL_dtls_set_peer(wolfssl, &client_address, sizeof(client_address));
        wolfSSL_set_fd(wolfssl, socket_file_descriptor);

        wolfSSL_SetIOWriteCtx(wolfssl, (void *)&socket_file_descriptor);
        wolfSSL_SetIOReadCtx(wolfssl,  (void *)&socket_file_descriptor);

        const int handshake_result = wolfSSL_accept(wolfssl);

        /* DTLS handshake */
        if (handshake_result != SSL_SUCCESS) {
            handle_error(handshake_result);
            wolfSSL_free(wolfssl);
            close(socket_file_descriptor);
            continue;
        }

        printf("Handshake complete. Reading message...\n");

        /* Read one message */
        char buffer[MSGLEN];
        const int received_length = wolfSSL_read(wolfssl, buffer, sizeof(buffer) - 1);
        if (received_length > 0) {
            buffer[received_length] = '\0';
            printf("Received: \"%s\"\n", buffer);
        } else {
           handle_error(received_length);
        }

        /* Cleanup session */
        wolfSSL_shutdown(wolfssl);
        wolfSSL_free(wolfssl);
        close(socket_file_descriptor);

        printf("Session closed, returning to idle\n\n");
    }

    wolfSSL_CTX_free(wolfssl_ctx);
    wolfSSL_Cleanup();
    return 0;
}
