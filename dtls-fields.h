
#ifndef __DTLS_FIELDS_H__
#define __DTLS_FIELDS_H__

#include <stdint.h>

/*
 * DTLS 1.2 Record Layer Header (RFC 6347)
 * Total: 13 bytes
 *
 * +-------------+--------+-------+--------------------+--------+
 * | ContentType | Version| Epoch | SequenceNumber     | Length |
 * |  (1 byte)   |(2 bytes)|(2 bytes)|   (6 bytes)     |(2 bytes)|
 * +-------------+--------+-------+--------------------+--------+
 */

/* DTLS content type values */
#define DTLS_CT_CHANGE_CIPHER_SPEC  20
#define DTLS_CT_ALERT               21
#define DTLS_CT_HANDSHAKE           22
#define DTLS_CT_APPLICATION_DATA    23

/* DTLS version bytes */
#define DTLS_VERSION_1_2_HI         0xFE
#define DTLS_VERSION_1_2_LO         0xFD

/* DTLS record header size in bytes */
#define DTLS_RECORD_HEADER_SIZE     13

/*
 * DTLS field IDs for our SCHC rules
 * Start at 2048 to avoid any collision with libschc's
 * existing IP6/UDP/CoAP field enums
 */
typedef enum {
    DTLS_CONTENT_TYPE   = 2048,
    DTLS_VERSION        = 2049,
    DTLS_EPOCH          = 2050,
    DTLS_SEQ_NUM        = 2051,
    DTLS_LENGTH         = 2052
} dtls_header_fields;

/* plain C struct matching the 13-byte DTLS record header */
typedef struct {
    uint8_t  content_type;      /* 1 byte  */
    uint8_t  version_hi;        /* 1 byte  - 0xFE for DTLS 1.2 */
    uint8_t  version_lo;        /* 1 byte  - 0xFD for DTLS 1.2 */
    uint8_t  epoch_hi;          /* 1 byte  */
    uint8_t  epoch_lo;          /* 1 byte  */
    uint8_t  seq_num[6];        /* 6 bytes */
    uint8_t  length_hi;         /* 1 byte  */
    uint8_t  length_lo;         /* 1 byte  */
} dtls_record_header_t;

#endif
