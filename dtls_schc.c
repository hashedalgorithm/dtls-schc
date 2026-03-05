#include "dtls_schc.h"
#include "libschc/compressor.h"
#include "libschc/bit_operations.h"

#include <string.h>
#include <stdio.h>

void dtls_schc_init(void)
{
    schc_compressor_init();
}

/* ------------------------------------------------------------------ */
int dtls_parse_header(const uint8_t *raw,
                      size_t         raw_len,
                      uint8_t       *header_out)
{
    if (!raw || !header_out || raw_len < DTLS_HEADER_LEN)
        return -1;
    memcpy(header_out, raw, DTLS_HEADER_LEN);
    return 0;
}

/* ------------------------------------------------------------------ */
int dtls_schc_compress(const uint8_t      *dtls_header,
                       struct schc_device *device,
                       schc_result_t      *result)
{
    if (!dtls_header || !device || !result)
        return -1;

    memcpy(result->original_header, dtls_header, DTLS_HEADER_LEN);
    memset(result->compressed, 0, SCHC_BUFFER_SIZE);

    schc_bitarray_t dst =
        SCHC_DEFAULT_BIT_ARRAY(SCHC_BUFFER_SIZE, result->compressed);

    struct schc_compression_rule_t *rule =
        schc_compress(dtls_header, DTLS_HEADER_LEN,
                      &dst, device->device_id, UP);

    if (rule != NULL) {
        result->rule_applied   = 1;
        result->rule_id        = rule->rule_id;
        result->compressed_len = (uint16_t)dst.len;
    } else {
        /* No rule matched — store raw header unchanged */
        result->rule_applied   = 0;
        result->rule_id        = 0;
        result->compressed_len = DTLS_HEADER_LEN;
        memcpy(result->compressed, dtls_header, DTLS_HEADER_LEN);
    }

    result->size_delta = (int)result->compressed_len - DTLS_HEADER_LEN;
    return (int)result->compressed_len;
}

/* ------------------------------------------------------------------ */
int dtls_schc_decompress(const uint8_t      *schc_packet,
                         uint16_t            schc_len,
                         struct schc_device *device,
                         uint8_t            *header_out)
{
    if (!schc_packet || !device || !header_out || schc_len == 0)
        return -1;

    /* schc_decompress needs a non-const pointer; copy to local buffer */
    uint8_t tmp[SCHC_BUFFER_SIZE];
    if (schc_len > SCHC_BUFFER_SIZE)
        return -1;
    memcpy(tmp, schc_packet, schc_len);

    schc_bitarray_t bit_arr =
        SCHC_DEFAULT_BIT_ARRAY(schc_len, tmp);

    uint16_t len = schc_decompress(&bit_arr,
                                   header_out,
                                   device->device_id,
                                   schc_len,
                                   UP);
    return (int)len;
}

/* ------------------------------------------------------------------ */
int dtls_rebuild_packet(const uint8_t *comp_hdr,
                        uint16_t       comp_hdr_len,
                        const uint8_t *payload,
                        uint16_t       payload_len,
                        uint8_t       *out,
                        uint16_t       out_max)
{
    /* Frame: [1-byte length prefix][compressed header][payload] */
    uint16_t total = WIRE_LEN_PREFIX_BYTES + comp_hdr_len + payload_len;

    if (total > out_max)
        return -1;
    if (comp_hdr_len > 255)
        return -1;  /* length prefix is only 1 byte */

    out[0] = (uint8_t)comp_hdr_len;
    memcpy(out + WIRE_LEN_PREFIX_BYTES, comp_hdr, comp_hdr_len);
    memcpy(out + WIRE_LEN_PREFIX_BYTES + comp_hdr_len, payload, payload_len);

    return (int)total;
}

/* ------------------------------------------------------------------ */
void dtls_schc_print_result(const schc_result_t *result)
{
    if (!result) return;

    printf("--- SCHC Result ---\n");
    printf("Rule applied   : %s (id=%u)\n",
           result->rule_applied ? "YES" : "NO",
           result->rule_id);
    printf("Original size  : %d bytes\n", DTLS_HEADER_LEN);
    printf("Compressed size: %u bytes\n", result->compressed_len);
    printf("Size delta     : %+d bytes\n", result->size_delta);

    /* Hex dump of original header */
    printf("Original header: ");
    for (int i = 0; i < DTLS_HEADER_LEN; i++)
        printf("%02X ", result->original_header[i]);
    printf("\n");

    /* Hex dump of compressed output */
    printf("Compressed     : ");
    for (int i = 0; i < result->compressed_len; i++)
        printf("%02X ", result->compressed[i]);
    printf("\n");

    printf("-------------------\n");
}