#ifndef DTLS_SCHC_H
#define DTLS_SCHC_H

#include <stdint.h>
#include <stddef.h>
#include "libschc/schc.h"

/* ── constants ─────────────────────────────────────────────────── */
#define DTLS_HEADER_LEN  13
#define SCHC_BUFFER_SIZE 256

/*
 * Wire framing added by our IO hooks:
 *
 *   [ 1-byte compressed-header-length ]
 *   [ N bytes compressed header       ]
 *   [ M bytes encrypted payload       ]
 *
 * The single length-prefix byte lets the receiver split the frame
 * without any shared state.
 */
#define WIRE_LEN_PREFIX_BYTES 1

/* ── result record ─────────────────────────────────────────────── */
typedef struct {
    uint8_t  original_header[DTLS_HEADER_LEN];
    uint8_t  compressed[SCHC_BUFFER_SIZE];
    uint16_t compressed_len;
    uint8_t  rule_applied;   /* 1 = a rule matched; 0 = raw fallback */
    uint32_t rule_id;
    int      size_delta;     /* compressed_len - DTLS_HEADER_LEN     */
} schc_result_t;

/* ── API ────────────────────────────────────────────────────────── */

/*
 * Copy the first DTLS_HEADER_LEN bytes of `raw` into `header_out`.
 * Returns 0 on success, -1 if raw_len < DTLS_HEADER_LEN.
 */
int dtls_parse_header(const uint8_t *raw,
                      size_t         raw_len,
                      uint8_t       *header_out);

/*
 * Compress a 13-byte DTLS header with the given SCHC device.
 * Fills *result and returns the compressed length (>= 0).
 */
int dtls_schc_compress(const uint8_t      *dtls_header,
                       struct schc_device *device,
                       schc_result_t      *result);

/*
 * Decompress a SCHC bitstream back to a 13-byte DTLS header.
 * Returns the number of bytes written to header_out, or -1 on error.
 */
int dtls_schc_decompress(const uint8_t      *schc_packet,
                         uint16_t            schc_len,
                         struct schc_device *device,
                         uint8_t            *header_out);

/*
 * Build the on-wire frame:
 *   [1-byte comp_hdr_len][compressed_header][payload]
 * Returns total bytes written, or -1 if out_max is too small.
 */
int dtls_rebuild_packet(const uint8_t *compressed_header,
                        uint16_t       compressed_header_len,
                        const uint8_t *payload,
                        uint16_t       payload_len,
                        uint8_t       *out,
                        uint16_t       out_max);

/* Pretty-print a schc_result_t to stdout. */
void dtls_schc_print_result(const schc_result_t *result);

#endif /* DTLS_SCHC_H */