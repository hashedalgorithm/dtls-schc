/* schc_mini.c
 * RFC 8724-aligned SCHC compression for DTLS 1.2 records.
 *
 * SCHC Packet wire format (this profile):
 *   [ RuleID : 1 byte ] [ Compression Residue : variable ]
 *                                                [ Payload ]
 *
 * Compression Residue = value-sent fields concatenated in
 * field-descriptor order (§7.4.4).  All fields here are
 * byte-aligned, so no bit-packing is needed.
 */
#include "schc_mini.h"
#include <string.h>
#include <stdio.h>

/* ---------------------------------------------------------------
 * Helpers: read/write big-endian field values from/to header
 * ------------------------------------------------------------- */
static uint64_t read_field(const uint8_t *hdr,
                           uint8_t offset,
                           uint8_t len)
{
    uint64_t v = 0;
    for (uint8_t i = 0; i < len; i++)
        v = (v << 8) | hdr[offset + i];
    return v;
}

static void write_field(uint8_t *hdr,
                        uint8_t offset,
                        uint8_t len,
                        uint64_t v)
{
    for (int i = len - 1; i >= 0; i--) {
        hdr[offset + i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

/* ---------------------------------------------------------------
 * Static Rule Context  (RFC 8724 §7.1)
 *
 * Rule 1 – DTLS Handshake, epoch 0, seq 0
 *   Type=22 / Ver=0xFEFD / Epoch=0 / Seq=0 / Len=value-sent
 *   Residue: Length (2 bytes)
 *
 * Rule 2 – DTLS Handshake, epoch 0, seq 1
 *   Type=22 / Ver=0xFEFD / Epoch=0 / Seq=1 / Len=value-sent
 *   Residue: Length (2 bytes)
 *
 * Rule 3 – DTLS Handshake, epoch 1, seq 0
 *   Type=22 / Ver=0xFEFD / Epoch=1 / Seq=0 / Len=value-sent
 *   Residue: Length (2 bytes)
 *
 * Rule 4 – Catch-all (type != 22)
 *   Type=ignore/value-sent / Ver=0xFEFD/not-sent /
 *   Epoch=ignore/value-sent / Seq=ignore/value-sent /
 *   Len=ignore/value-sent
 *   Residue: Type(1) + Epoch(2) + Seq(6) + Len(2) = 11 bytes
 * ------------------------------------------------------------- */

/* field layout shorthand:
 *  { fid,            fl, offset, mo,        cda,            tv } */
#define F_TYPE_NS(tv_) \
    { DTLS_FID_TYPE,   1,  0,  MO_EQUAL,  CDA_NOT_SENT,  (tv_) }
#define F_VER_NS \
    { DTLS_FID_VER,    2,  1,  MO_EQUAL,  CDA_NOT_SENT,  DTLS_VERSION_12 }
#define F_EPOCH_NS(tv_) \
    { DTLS_FID_EPOCH,  2,  3,  MO_EQUAL,  CDA_NOT_SENT,  (tv_) }
#define F_SEQ_NS(tv_) \
    { DTLS_FID_SEQ,    6,  5,  MO_EQUAL,  CDA_NOT_SENT,  (tv_) }
#define F_LEN_VS \
    { DTLS_FID_LEN,    2, 11,  MO_IGNORE, CDA_VALUE_SENT, 0 }

#define F_TYPE_VS \
    { DTLS_FID_TYPE,   1,  0,  MO_IGNORE, CDA_VALUE_SENT, 0 }
#define F_EPOCH_VS \
    { DTLS_FID_EPOCH,  2,  3,  MO_IGNORE, CDA_VALUE_SENT, 0 }
#define F_SEQ_VS \
    { DTLS_FID_SEQ,    6,  5,  MO_IGNORE, CDA_VALUE_SENT, 0 }

static const schc_rule_t context[] = {
    /* Rule 1: Handshake, epoch=0, seq=0 */
    {
        RULE_ID_1,
        {
            F_TYPE_NS(22),
            F_VER_NS,
            F_EPOCH_NS(0),
            F_SEQ_NS(0),
            F_LEN_VS,
        }
    },
    /* Rule 2: Handshake, epoch=0, seq=1 */
    {
        RULE_ID_2,
        {
            F_TYPE_NS(22),
            F_VER_NS,
            F_EPOCH_NS(0),
            F_SEQ_NS(1),
            F_LEN_VS,
        }
    },
    /* Rule 3: Handshake, epoch=1, seq=0 */
    {
        RULE_ID_3,
        {
            F_TYPE_NS(22),
            F_VER_NS,
            F_EPOCH_NS(1),
            F_SEQ_NS(0),
            F_LEN_VS,
        }
    },
    /* Rule 4: Catch-all - type != 22, version still elided */
    {
        RULE_ID_4,
        {
            F_TYPE_VS,
            F_VER_NS,       /* version still known: DTLS 1.2, elide */
            F_EPOCH_VS,
            F_SEQ_VS,
            F_LEN_VS,
        }
    },
};

#define CONTEXT_SIZE  (sizeof(context) / sizeof(context[0]))

/* ---------------------------------------------------------------
 * match_rule() - RFC 8724 §7.2 Packet Processing
 * Returns pointer to matched rule, or NULL.
 * All MO_EQUAL fields must match; MO_IGNORE always passes.
 * ------------------------------------------------------------- */
static const schc_rule_t *match_rule(const uint8_t *hdr)
{
    for (size_t r = 0; r < CONTEXT_SIZE; r++) {
        const schc_rule_t *rule = &context[r];
        int matched = 1;

        for (int f = 0; f < DTLS_NFIELDS; f++) {
            const schc_field_desc_t *fd = &rule->fields[f];
            if (fd->mo == MO_EQUAL) {
                uint64_t fval =
                    read_field(hdr, fd->hdr_offset, fd->fl);
                if (fval != fd->tv) {
                    matched = 0;
                    break;
                }
            }
            /* MO_IGNORE: always passes */
        }

        if (matched)
            return rule;
    }
    return NULL;
}

/* ---------------------------------------------------------------
 * dtls_schc_compress()
 *
 * Output: [ RuleID (1 byte) | Compression Residue | Payload ]
 * ------------------------------------------------------------- */
int schc_compress(const uint8_t *input,
                       size_t         input_len,
                       uint8_t       *output,
                       size_t         output_max)
{
    if (!input || !output || input_len < DTLS_HDR_LEN)
        return -1;

    const uint8_t *hdr     = input;
    const uint8_t *payload = input + DTLS_HDR_LEN;
    size_t         plen    = input_len - DTLS_HDR_LEN;

    const schc_rule_t *rule = match_rule(hdr);
    if (!rule)
        return -1;   /* no matching rule; caller must handle */

    /* Calculate residue size: sum of fl for value-sent fields */
    size_t residue_len = 0;
    for (int f = 0; f < DTLS_NFIELDS; f++) {
        if (rule->fields[f].cda == CDA_VALUE_SENT)
            residue_len += rule->fields[f].fl;
    }

    size_t needed = 1 + residue_len + plen;
    if (needed > output_max)
        return -1;

    size_t off = 0;

    /* 1. Write RuleID */
    output[off++] = rule->rule_id;

    /* 2. Write Compression Residue (value-sent fields, in order) */
    for (int f = 0; f < DTLS_NFIELDS; f++) {
        const schc_field_desc_t *fd = &rule->fields[f];
        if (fd->cda == CDA_VALUE_SENT) {
            memcpy(output + off, hdr + fd->hdr_offset, fd->fl);
            off += fd->fl;
        }
    }

    /* 3. Append payload */
    memcpy(output + off, payload, plen);
    off += plen;

    return (int)off;
}

/* ---------------------------------------------------------------
 * find_rule_by_id()
 * ------------------------------------------------------------- */
static const schc_rule_t *find_rule_by_id(uint8_t rule_id)
{
    for (size_t r = 0; r < CONTEXT_SIZE; r++) {
        if (context[r].rule_id == rule_id)
            return &context[r];
    }
    return NULL;
}

/* ---------------------------------------------------------------
 * dtls_schc_decompress()
 *
 * Input: [ RuleID (1 byte) | Compression Residue | Payload ]
 * Output: full DTLS record
 * ------------------------------------------------------------- */
int schc_decompress(const uint8_t *input,
                         size_t         input_len,
                         uint8_t       *output,
                         size_t         output_max)
{
    if (!input || !output || input_len < 1)
        return -1;

    uint8_t            rule_id   = input[0];
    const uint8_t     *ptr       = input + 1;
    size_t             remaining = input_len - 1;

    const schc_rule_t *rule = find_rule_by_id(rule_id);
    if (!rule)
        return -1;

    /* Calculate expected residue size */
    size_t residue_len = 0;
    for (int f = 0; f < DTLS_NFIELDS; f++) {
        if (rule->fields[f].cda == CDA_VALUE_SENT)
            residue_len += rule->fields[f].fl;
    }

    if (remaining < residue_len)
        return -1;

    size_t plen = remaining - residue_len;
    size_t total = DTLS_HDR_LEN + plen;

    if (total > output_max)
        return -1;

    uint8_t hdr[DTLS_HDR_LEN];

    /* Reconstruct header:
     *   not-sent  -> restore from TV
     *   value-sent -> read from residue stream */
    for (int f = 0; f < DTLS_NFIELDS; f++) {
        const schc_field_desc_t *fd = &rule->fields[f];

        if (fd->cda == CDA_NOT_SENT) {
            /* Restore from Target Value (RFC 8724 §7.4.3) */
            write_field(hdr, fd->hdr_offset, fd->fl, fd->tv);
        } else if (fd->cda == CDA_VALUE_SENT) {
            /* Read from compression residue (RFC 8724 §7.4.4) */
            memcpy(hdr + fd->hdr_offset, ptr, fd->fl);
            ptr       += fd->fl;
            remaining -= fd->fl;
        }
    }

    /* Copy reconstructed header + payload to output */
    memcpy(output,               hdr, DTLS_HDR_LEN);
    memcpy(output + DTLS_HDR_LEN, ptr, plen);

    return (int)total;
}

const char *schc_rule_name(uint8_t rule_id)
{
    switch (rule_id) {
        case RULE_ID_1: return "Rule-1";
        case RULE_ID_2: return "Rule-2";
        case RULE_ID_3: return "Rule-3";
        case RULE_ID_4: return "Rule-4";
        default:        return "Unknown";
    }
}

/* ---------------------------------------------------------------
 * print_dtls_record() - debug helper
 * ------------------------------------------------------------- */
void print_dtls_record(const char    *direction,
                       const uint8_t *buf,
                       int            size)
{
    printf("\n--- DTLS Record [%s] (%d bytes) ---\n",
           direction, size);

    for (int i = 0; i < size; i++) {
        printf("%02X ", buf[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (size % 16 != 0)
        printf("\n");

    if (size >= DTLS_HDR_LEN) {
        uint16_t ver = (uint16_t)((buf[1] << 8) | buf[2]);
        uint16_t ep  = (uint16_t)((buf[3] << 8) | buf[4]);
        uint16_t len = (uint16_t)((buf[11] << 8) | buf[12]);

        printf("  Content Type : 0x%02X\n", buf[0]);
        printf("  Version      : %04X (%s)\n", ver,
               ver == DTLS_VERSION_12 ? "DTLS 1.2" : "unknown");
        printf("  Epoch        : %04X\n", ep);
        printf("  Sequence     : "
               "%02X%02X%02X%02X%02X%02X\n",
               buf[5], buf[6], buf[7],
               buf[8], buf[9], buf[10]);
        printf("  Length       : %u bytes\n", len);
    }
    printf("-----------------------------------\n\n");
}