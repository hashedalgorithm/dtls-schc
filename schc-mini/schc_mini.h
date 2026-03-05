/* schc_mini.h
 * SCHC-based DTLS 1.2 header compression (RFC 8724)
 * Rule table covers DTLS handshake and application data.
 */
#ifndef SCHC_MINI_H
#define SCHC_MINI_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------
 * DTLS 1.2 record header layout (13 bytes)
 *  [0]      Content Type  (1 byte)
 *  [1-2]    Version       (2 bytes)  0xFEFD = DTLS 1.2
 *  [3-4]    Epoch         (2 bytes)
 *  [5-10]   Sequence Num  (6 bytes)
 *  [11-12]  Length        (2 bytes)
 * ------------------------------------------------------------- */
#define DTLS_HDR_LEN        13
#define DTLS_VERSION_12     0xFEFDu


/* ---------------------------------------------------------------
 * RFC 8724 §7.3 - Matching Operators
 * ------------------------------------------------------------- */
typedef enum {
    MO_EQUAL = 0,   /* field == TV                  */
    MO_IGNORE,      /* any value matches            */
    MO_MSB,         /* MSBs of field == TV          */
    MO_MATCH_MAP    /* field in TV set (not used here) */
} schc_mo_t;

/* ---------------------------------------------------------------
 * RFC 8724 §7.4 - Compression/Decompression Actions
 * ------------------------------------------------------------- */
typedef enum {
    CDA_NOT_SENT = 0,   /* elide field; reconstruct from TV */
    CDA_VALUE_SENT,     /* send field as compression residue */
    CDA_LSB,            /* send N LSBs as residue           */
    CDA_MAPPING_SENT    /* send index into TV mapping       */
} schc_cda_t;

/* ---------------------------------------------------------------
 * Field descriptor (one row in the rule table)
 * RFC 8724 §7.1: FID | FL | FP | DI | TV | MO | CDA
 * ------------------------------------------------------------- */
#define DTLS_FID_TYPE   0
#define DTLS_FID_VER    1
#define DTLS_FID_EPOCH  2
#define DTLS_FID_SEQ    3
#define DTLS_FID_LEN    4
#define DTLS_NFIELDS    5

typedef struct {
    uint8_t     fid;            /* field identifier (DTLS_FID_*)      */
    uint8_t     fl;             /* field length in bytes               */
    uint8_t     hdr_offset;     /* byte offset in DTLS header          */
    schc_mo_t   mo;             /* matching operator                   */
    schc_cda_t  cda;            /* compression/decompression action    */
    /* Target Value: stored as uint64_t, left-aligned, 0 if MO_IGNORE */
    uint64_t    tv;
} schc_field_desc_t;

/* ---------------------------------------------------------------
 * Rule descriptor - one complete rule
 * ------------------------------------------------------------- */
typedef struct {
    uint8_t             rule_id;
    schc_field_desc_t   fields[DTLS_NFIELDS];
} schc_rule_t;

/* ---------------------------------------------------------------
 * Rule IDs
 * ------------------------------------------------------------- */
#define RULE_ID_1   0x01  /* type=22, epoch=0, seq=0  */
#define RULE_ID_2   0x02  /* type=22, epoch=0, seq=1  */
#define RULE_ID_3   0x03  /* type=22, epoch=1, seq=0  */
#define RULE_ID_4   0x04  /* type!=22 catch-all       */

/* ---------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------- */

/* ---------------------------------------------------------------
 * input direction
 * ------------------------------------------------------------- */

#define SEND_DTLS_RECORD "SEND"
#define RECV_DTLS_RECORD "RECV"
int schc_compress(
    const uint8_t *input,  size_t input_len,
    uint8_t       *output, size_t output_max);

int schc_decompress(
    const uint8_t *input,  size_t input_len,
    uint8_t       *output, size_t output_max);

const char *schc_rule_name(uint8_t rule_id);

void print_dtls_record(
    const char *direction,
    const uint8_t *buf,
    int size);

#endif /* SCHC_MINI_H */


