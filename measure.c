/*
 * measure.c
 *
 * Standalone side-channel measurement tool.
 * No wolfSSL dependency — purely exercises the SCHC compress path
 * on synthetic DTLS record headers.
 *
 * Build: see CMakeLists.txt (measure target)
 * Run  : ./measure
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "dtls_schc.h"
#include "rules/dtls_rule_config.h"
#include "libschc/compressor.h"

/* ------------------------------------------------------------------ */
/* Helper: build a synthetic 13-byte DTLS record header               */
/* ------------------------------------------------------------------ */
static void make_dtls_header(uint8_t  *out,
                              uint8_t   type,
                              uint16_t  version,
                              uint16_t  epoch,
                              uint64_t  seq,
                              uint16_t  length)
{
    out[0]  = type;
    out[1]  = (uint8_t)((version >> 8) & 0xFF);
    out[2]  = (uint8_t)( version       & 0xFF);
    out[3]  = (uint8_t)((epoch   >> 8) & 0xFF);
    out[4]  = (uint8_t)( epoch         & 0xFF);
    out[5]  = (uint8_t)((seq    >> 40) & 0xFF);
    out[6]  = (uint8_t)((seq    >> 32) & 0xFF);
    out[7]  = (uint8_t)((seq    >> 24) & 0xFF);
    out[8]  = (uint8_t)((seq    >> 16) & 0xFF);
    out[9]  = (uint8_t)((seq    >>  8) & 0xFF);
    out[10] = (uint8_t)( seq           & 0xFF);
    out[11] = (uint8_t)((length  >> 8) & 0xFF);
    out[12] = (uint8_t)( length        & 0xFF);
}

/* ------------------------------------------------------------------ */
/* Test vectors                                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *label;
    const char *description;
    uint8_t     type;
    uint16_t    epoch;
} test_case_t;

static const test_case_t tests[] = {
    { "A", "app-data + epoch=1  (strict rule matches)", 23, 0x0001 },
    { "B", "app-data + epoch=2  (epoch mismatch)",      23, 0x0002 },
    { "C", "handshake+ epoch=1  (type  mismatch)",      22, 0x0001 },
    { "D", "app-data + epoch=1  (repeat of A)",         23, 0x0001 },
};

#define NUM_TESTS  (int)(sizeof(tests) / sizeof(tests[0]))

/* ------------------------------------------------------------------ */
static void print_table_header(void)
{
    printf("%-4s  %-42s  %-6s  %-7s  %-16s  %s\n",
           "Pkt", "Description",
           "Epoch", "Rule?", "Compressed(B)", "Delta");
    printf("%-4s  %-42s  %-6s  %-7s  %-16s  %s\n",
           "----", "------------------------------------------",
           "------", "-------", "----------------", "-----");
}

/* ------------------------------------------------------------------ */
static void run_tests(struct schc_device *device)
{
    for (int i = 0; i < NUM_TESTS; i++) {
        uint8_t header[DTLS_HEADER_LEN];
        make_dtls_header(header,
                         tests[i].type,
                         0xFEFD,
                         tests[i].epoch,
                         (uint64_t)i,   /* incrementing seq */
                         100);          /* arbitrary length  */

        schc_result_t result;
        dtls_schc_compress(header, device, &result);

        printf("%-4s  %-42s  0x%04X  %-7s  %-16u  %+d\n",
               tests[i].label,
               tests[i].description,
               tests[i].epoch,
               result.rule_applied ? "YES" : "NO",
               result.compressed_len,
               result.size_delta);
    }
}

/* ------------------------------------------------------------------ */
int main(void)
{
    schc_compressor_init();

    /* ── Strict rule: side channel visible ───────────────────────── */
    printf("\n=== STRICT RULE (side channel present) ===\n");
    print_table_header();
    run_tests(&dtls_device_strict);

    /*
     * Expected pattern:
     *   A → rule matches   → small compressed size (NOTSENT fields elided)
     *   B → epoch mismatch → larger / no compression
     *   C → type  mismatch → larger / no compression
     *   D → rule matches   → same small size as A  (reproducible)
     *
     * An observer watching packet sizes can distinguish epoch=1 from
     * epoch≠1, which is the CRIME-style side channel.
     */

    /* ── Relaxed rule: side channel eliminated ───────────────────── */
    printf("\n=== RELAXED RULE (side channel mitigated) ===\n");
    print_table_header();
    run_tests(&dtls_device_relaxed);

    /*
     * Expected pattern:
     *   All rows → same compressed size regardless of field values.
     *   An observer learns nothing from size alone.
     */

    /* ── Round-trip sanity check ─────────────────────────────────── */
    printf("\n=== ROUND-TRIP SANITY CHECK ===\n");

    uint8_t original[DTLS_HEADER_LEN];
    make_dtls_header(original, 23, 0xFEFD, 0x0001, 42, 256);

    schc_result_t compress_result;
    dtls_schc_compress(original, &dtls_device_strict, &compress_result);

    uint8_t recovered[DTLS_HEADER_LEN];
    int     recovered_len = dtls_schc_decompress(
                                compress_result.compressed,
                                compress_result.compressed_len,
                                &dtls_device_strict,
                                recovered);

    if (recovered_len == DTLS_HEADER_LEN &&
        memcmp(original, recovered, DTLS_HEADER_LEN) == 0) {
        printf("PASS: decompressed header matches original.\n");
    } else {
        printf("FAIL: mismatch after round-trip "
               "(got %d bytes).\n", recovered_len);
        printf("  original : ");
        for (int i = 0; i < DTLS_HEADER_LEN; i++)
            printf("%02X ", original[i]);
        printf("\n  recovered: ");
        for (int i = 0; i < recovered_len && i < DTLS_HEADER_LEN; i++)
            printf("%02X ", recovered[i]);
        printf("\n");
    }

    return 0;
}