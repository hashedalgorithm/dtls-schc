#ifndef __SCHC_CONFIG_H__
#define __SCHC_CONFIG_H__

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#define CLICK                           0
#define DYNAMIC_MEMORY                  0
#define STATIC_MEMORY_BUFFER_LENGTH     1024

#define SCHC_CONF_RX_CONNS              1
#define SCHC_CONF_TX_CONNS              1
#define SCHC_CONF_MBUF_POOL_LEN         128

/* disable all built-in layers - we only use bit operations */
#define USE_COAP                        0
#define USE_IP6_UDP                     0

#define MAX_FIELD_LENGTH                32

/* we define our own DTLS fields - set built-in layer fields to minimum */
#define IP6_FIELDS                      1
#define UDP_FIELDS                      1
#define COAP_FIELDS                     1

/* number of fields in our DTLS record header rule */
#define DTLS_FIELDS                     5

#define MAX_HEADER_LENGTH               256
#define MAX_COAP_HEADER_LENGTH          64
#define MAX_PAYLOAD_LENGTH              256
#define MAX_COAP_MSG_SIZE               (MAX_COAP_HEADER_LENGTH + MAX_PAYLOAD_LENGTH)
#define MAX_MTU_LENGTH                  242
#define JSON_TOKENS                     16

#define DEBUG_PRINTF(...)               printf(__VA_ARGS__)

#define MAX_ACK_REQUESTS                3
#define BITMAP_SIZE_BYTES               2
#define MAX_WINDOWS                     8
#define MAX_WINDOW_SIZE                 64

#endif