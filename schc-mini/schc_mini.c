#include "schc_mini.h"
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------- */
/* Helper: check strict rule                                     */
/* ------------------------------------------------------------- */
static int match_strict_rule(const uint8_t *h)
{
    uint8_t  type    = h[0];
    uint16_t version = (uint16_t)(h[1] << 8 | h[2]);
    uint16_t epoch   = (uint16_t)(h[3] << 8 | h[4]);

    return (type == 23 && version == 0xFEFD && epoch == 0x0001);
}

/* ------------------------------------------------------------- */
/* Helper: check relaxed rule                                    */
/* ------------------------------------------------------------- */
static int match_relaxed_rule(const uint8_t *h)
{
    uint16_t version = (uint16_t)(h[1] << 8 | h[2]);
    return (version == 0xFEFD);
}

/* ------------------------------------------------------------- */
/* Compress                                                       */
/* ------------------------------------------------------------- */
int dtls_mini_compress(const uint8_t *input,
                       size_t input_len,
                       uint8_t *output,
                       size_t output_max)
{
    if (!input || !output || input_len < DTLS_HEADER_LEN)
        return -1;

    const uint8_t *hdr = input;
    const uint8_t *payload = input + DTLS_HEADER_LEN;
    size_t payload_len = input_len - DTLS_HEADER_LEN;

    uint8_t rule = MINI_RULE_NONE;

    if (match_strict_rule(hdr))
        rule = MINI_RULE_STRICT;
    else if (match_relaxed_rule(hdr))
        rule = MINI_RULE_RELAXED;

    size_t needed = 1 + payload_len;

    if (rule == MINI_RULE_NONE)
        needed += DTLS_HEADER_LEN;
    else if (rule == MINI_RULE_STRICT)
        needed += 6 + 2; /* seq + length */
    else if (rule == MINI_RULE_RELAXED)
        needed += 1 + 2 + 6 + 2; /* type + epoch + seq + length */

    if (needed > output_max)
        return -1;

    size_t off = 0;
    output[off++] = rule;

    switch (rule) {

    case MINI_RULE_STRICT:
        memcpy(output + off, hdr + 5, 6);
        off += 6;
        memcpy(output + off, hdr + 11, 2);
        off += 2;
        break;

    case MINI_RULE_RELAXED:
        output[off++] = hdr[0];
        memcpy(output + off, hdr + 3, 2);
        off += 2;
        memcpy(output + off, hdr + 5, 6);
        off += 6;
        memcpy(output + off, hdr + 11, 2);
        off += 2;
        break;

    case MINI_RULE_NONE:
    default:
        memcpy(output + off, hdr, DTLS_HEADER_LEN);
        off += DTLS_HEADER_LEN;
        break;
    }

    memcpy(output + off, payload, payload_len);
    off += payload_len;

    return (int)off;
}

/* ------------------------------------------------------------- */
/* Decompress                                                     */
/* ------------------------------------------------------------- */
int dtls_mini_decompress(const uint8_t *input,
                         size_t input_len,
                         uint8_t *output,
                         size_t output_max)
{
    if (!input || !output || input_len < 1)
        return -1;

    uint8_t rule = input[0];
    const uint8_t *ptr = input + 1;
    size_t remaining = input_len - 1;

    if (output_max < DTLS_HEADER_LEN)
        return -1;

    uint8_t hdr[DTLS_HEADER_LEN];

    switch (rule) {

    case MINI_RULE_STRICT:
        if (remaining < 8)
            return -1;

        hdr[0] = 23;
        hdr[1] = 0xFE;
        hdr[2] = 0xFD;
        hdr[3] = 0x00;
        hdr[4] = 0x01;

        memcpy(hdr + 5, ptr, 6);
        memcpy(hdr + 11, ptr + 6, 2);

        ptr += 8;
        remaining -= 8;
        break;

    case MINI_RULE_RELAXED:
        if (remaining < 11)
            return -1;

        hdr[0] = ptr[0];
        hdr[1] = 0xFE;
        hdr[2] = 0xFD;

        memcpy(hdr + 3, ptr + 1, 2);
        memcpy(hdr + 5, ptr + 3, 6);
        memcpy(hdr + 11, ptr + 9, 2);

        ptr += 11;
        remaining -= 11;
        break;

    case MINI_RULE_NONE:
    default:
        if (remaining < DTLS_HEADER_LEN)
            return -1;

        memcpy(hdr, ptr, DTLS_HEADER_LEN);
        ptr += DTLS_HEADER_LEN;
        remaining -= DTLS_HEADER_LEN;
        break;
    }

    size_t total = DTLS_HEADER_LEN + remaining;

    if (total > output_max)
        return -1;

    memcpy(output, hdr, DTLS_HEADER_LEN);
    memcpy(output + DTLS_HEADER_LEN, ptr, remaining);

    return (int)total;
}

void print_dtls_record(const char *direction, const char *buffer, int size) {
    printf("\n--- DTLS Record [%s] (%d bytes) ---\n", direction, size);
    for (int i = 0; i < size; i++) {
        printf("%02X ", (unsigned char)buffer[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (size % 16 != 0) printf("\n");

    /* Decode DTLS record header fields (first 13 bytes) */
    if (size >= 13) {
        printf("  Content Type : 0x%02X\n", (unsigned char)buffer[0]);
        printf("  Version      : %02X %02X\n",
               (unsigned char)buffer[1], (unsigned char)buffer[2]);
        printf("  Epoch        : %02X %02X\n",
               (unsigned char)buffer[3], (unsigned char)buffer[4]);
        printf("  Sequence     : %02X %02X %02X %02X %02X %02X\n",
               (unsigned char)buffer[5],  (unsigned char)buffer[6],
               (unsigned char)buffer[7],  (unsigned char)buffer[8],
               (unsigned char)buffer[9],  (unsigned char)buffer[10]);
        printf("  Length       : %d bytes\n",
               ((unsigned char)buffer[11] << 8) | (unsigned char)buffer[12]);
    }
    printf("-----------------------------------\n\n");
}