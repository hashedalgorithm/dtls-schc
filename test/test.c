#include "schc_mini.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Fake payload (simulates encrypted application data)
static uint8_t dummy_payload[20] = {0xAB};

static void build_dtls_header(uint8_t *hdr,
                              uint8_t type,
                              uint16_t version,
                              uint16_t epoch,
                              uint8_t seq[6],
                              uint16_t length) {
    hdr[0] = type;
    hdr[1] = (version >> 8) & 0xFF;
    hdr[2] = version & 0xFF;
    hdr[3] = (epoch >> 8) & 0xFF;
    hdr[4] = epoch & 0xFF;
    memcpy(hdr + 5, seq, 6);
    hdr[11] = (length >> 8) & 0xFF;
    hdr[12] = length & 0xFF;
}

static void run_test(const char *label,
                           const uint8_t type,
                           const uint16_t version,
                           const uint16_t epoch,
                           uint8_t seq[6]) {
    uint8_t input[DTLS_HEADER_LEN + sizeof(dummy_payload)];
    uint8_t output[4096];

    build_dtls_header(input, type, version, epoch, seq,
                      sizeof(dummy_payload));
    memcpy(input + DTLS_HEADER_LEN, dummy_payload,
           sizeof(dummy_payload));

    int compressed = dtls_mini_compress(
        input, sizeof(input), output, sizeof(output));

    uint8_t rule = output[0];
    const char *rule_name =
            rule == MINI_RULE_STRICT ? "STRICT" : rule == MINI_RULE_RELAXED ? "RELAXED" : "NONE";

    printf("%-30s | rule=%-7s | in=%3zu | out=%3d | diff=%+d\n",
           label, rule_name,
           sizeof(input), compressed,
           compressed - (int) sizeof(input));
}

int main() {
    // sequence numbers to simulate progression
    uint8_t seq0[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t seq1[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t seq2[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t seq3[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
    uint8_t seq4[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
    uint8_t seq5[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
    uint8_t seq6[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06};
    uint8_t seq7[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    uint8_t seq_hi[6] = {0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t seq_max[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    printf("\n=== DTLS RECORD HEADER SCHC COMPRESSION EXPERIMENT ===\n\n");

    // -------------------------------------------------------
    // SECTION 1: NORMAL DTLS 1.2 HANDSHAKE FLOW
    // epoch=0 unencrypted, epoch=1 encrypted
    // -------------------------------------------------------
    printf("--- [1] NORMAL HANDSHAKE FLOW (DTLS 1.2 / 0xFEFD) ---\n");

    // Client Hello
    run_test("1.01 ClientHello (handshake, epoch=0, seq=0)",
                   22, 0xFEFD, 0x0000, seq0);

    // HelloVerifyRequest (server -> client, DTLS specific)
    run_test("1.02 HelloVerifyRequest (handshake, epoch=0, seq=0)",
                   22, 0xFEFD, 0x0000, seq0);

    // Client Hello retransmit with cookie
    run_test("1.03 ClientHello+Cookie (handshake, epoch=0, seq=1)",
                   22, 0xFEFD, 0x0000, seq1);

    // Server Hello
    run_test("1.04 ServerHello (handshake, epoch=0, seq=1)",
                   22, 0xFEFD, 0x0000, seq1);

    // Certificate
    run_test("1.05 Certificate (handshake, epoch=0, seq=2)",
                   22, 0xFEFD, 0x0000, seq2);

    // ServerKeyExchange
    run_test("1.06 ServerKeyExchange (handshake, epoch=0, seq=3)",
                   22, 0xFEFD, 0x0000, seq3);

    // ServerHelloDone
    run_test("1.07 ServerHelloDone (handshake, epoch=0, seq=4)",
                   22, 0xFEFD, 0x0000, seq4);

    // ClientKeyExchange
    run_test("1.08 ClientKeyExchange (handshake, epoch=0, seq=2)",
                   22, 0xFEFD, 0x0000, seq2);

    // ChangeCipherSpec (type=20, epoch=0->1 transition)
    run_test("1.09 ChangeCipherSpec client (ccs, epoch=0, seq=3)",
                   20, 0xFEFD, 0x0000, seq3);

    // Finished (epoch=1, now encrypted)
    run_test("1.10 Finished client (handshake, epoch=1, seq=0)",
                   22, 0xFEFD, 0x0001, seq0);

    // ChangeCipherSpec server
    run_test("1.11 ChangeCipherSpec server (ccs, epoch=0, seq=5)",
                   20, 0xFEFD, 0x0000, seq5);

    // Finished server (epoch=1)
    run_test("1.12 Finished server (handshake, epoch=1, seq=0)",
                   22, 0xFEFD, 0x0001, seq0);

    // Application Data (post-handshake, epoch=1)
    run_test("1.13 ApplicationData (appdata, epoch=1, seq=1)",
                   23, 0xFEFD, 0x0001, seq1);

    // -------------------------------------------------------
    // SECTION 2: DTLS 1.2 RETRANSMISSION SCENARIOS
    // DTLS mandates retransmit on timeout
    // -------------------------------------------------------
    printf("\n--- [2] RETRANSMISSION SCENARIOS ---\n");

    run_test("2.01 ClientHello retransmit #1 (epoch=0, seq=0)",
                   22, 0xFEFD, 0x0000, seq0);

    run_test("2.02 ClientHello retransmit #2 (epoch=0, seq=0)",
                   22, 0xFEFD, 0x0000, seq0);

    run_test("2.03 ServerHello retransmit (epoch=0, seq=1)",
                   22, 0xFEFD, 0x0000, seq1);

    run_test("2.04 Finished retransmit (epoch=1, seq=0)",
                   22, 0xFEFD, 0x0001, seq0);

    run_test("2.05 AppData retransmit (epoch=1, seq=1)",
                   23, 0xFEFD, 0x0001, seq1);

    // -------------------------------------------------------
    // SECTION 3: ALERT MESSAGES
    // type=21, all standard alert descriptions
    // -------------------------------------------------------
    printf("\n--- [3] ALERT MESSAGES ---\n");

    // Alerts during handshake (epoch=0, unencrypted)
    run_test("3.01 Alert: close_notify (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.02 Alert: unexpected_message (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.03 Alert: bad_record_mac (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.04 Alert: handshake_failure (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.05 Alert: certificate_unknown (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.06 Alert: illegal_parameter (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.07 Alert: decode_error (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.08 Alert: decrypt_error (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.09 Alert: protocol_version (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("3.10 Alert: insufficient_security (epoch=0)",
                   21, 0xFEFD, 0x0000, seq0);

    // Alerts post-handshake (epoch=1, encrypted)
    run_test("3.11 Alert: close_notify (epoch=1, encrypted)",
                   21, 0xFEFD, 0x0001, seq2);

    run_test("3.12 Alert: bad_record_mac (epoch=1, encrypted)",
                   21, 0xFEFD, 0x0001, seq2);

    run_test("3.13 Alert: decrypt_error (epoch=1, encrypted)",
                   21, 0xFEFD, 0x0001, seq2);

    // -------------------------------------------------------
    // SECTION 4: CHANGE CIPHER SPEC VARIANTS
    // -------------------------------------------------------
    printf("\n--- [4] CHANGE CIPHER SPEC VARIANTS ---\n");

    run_test("4.01 CCS epoch=0 seq=0",
                   20, 0xFEFD, 0x0000, seq0);

    run_test("4.02 CCS epoch=0 seq=3",
                   20, 0xFEFD, 0x0000, seq3);

    run_test("4.03 CCS epoch=1 (renegotiation)",
                   20, 0xFEFD, 0x0001, seq0);

    run_test("4.04 CCS epoch=2 (second renegotiation)",
                   20, 0xFEFD, 0x0002, seq0);

    // -------------------------------------------------------
    // SECTION 5: EPOCH PROGRESSION
    // each renegotiation bumps epoch
    // -------------------------------------------------------
    printf("\n--- [5] EPOCH PROGRESSION (AppData type=23) ---\n");

    run_test("5.01 AppData epoch=0 (pre-handshake, unusual)",
                   23, 0xFEFD, 0x0000, seq0);

    run_test("5.02 AppData epoch=1 (normal post-handshake)",
                   23, 0xFEFD, 0x0001, seq1);

    run_test("5.03 AppData epoch=2 (after renegotiation)",
                   23, 0xFEFD, 0x0002, seq1);

    run_test("5.04 AppData epoch=3",
                   23, 0xFEFD, 0x0003, seq1);

    run_test("5.05 AppData epoch=0xFFFF (max epoch)",
                   23, 0xFEFD, 0xFFFF, seq1);

    // -------------------------------------------------------
    // SECTION 6: SEQUENCE NUMBER EDGE CASES
    // -------------------------------------------------------
    printf("\n--- [6] SEQUENCE NUMBER EDGE CASES ---\n");

    run_test("6.01 seq=0 (first packet)",
                   23, 0xFEFD, 0x0001, seq0);

    run_test("6.02 seq=1",
                   23, 0xFEFD, 0x0001, seq1);

    run_test("6.03 seq=7 (late in session)",
                   23, 0xFEFD, 0x0001, seq7);

    run_test("6.04 seq=0x0000FFFFFFFF (near rollover)",
                   23, 0xFEFD, 0x0001, seq_hi);

    run_test("6.05 seq=0xFFFFFFFFFFFF (max)",
                   23, 0xFEFD, 0x0001, seq_max);

    // -------------------------------------------------------
    // SECTION 7: VERSION VARIANTS
    // -------------------------------------------------------
    printf("\n--- [7] VERSION FIELD VARIANTS ---\n");

    run_test("7.01 DTLS 1.2 (0xFEFD) - normal",
                   23, 0xFEFD, 0x0001, seq1);

    run_test("7.02 DTLS 1.0 (0xFEFF) - legacy",
                   23, 0xFEFF, 0x0001, seq1);

    run_test("7.03 TLS 1.2 (0x0303) - wrong protocol",
                   23, 0x0303, 0x0001, seq1);

    run_test("7.04 TLS 1.0 (0x0301) - wrong protocol",
                   23, 0x0301, 0x0001, seq1);

    run_test("7.05 Unknown version (0x0000)",
                   23, 0x0000, 0x0001, seq1);

    run_test("7.06 Unknown version (0xFFFF)",
                   23, 0xFFFF, 0x0001, seq1);

    // -------------------------------------------------------
    // SECTION 8: CONTENT TYPE VARIANTS
    // -------------------------------------------------------
    printf("\n--- [8] CONTENT TYPE VARIANTS ---\n");

    run_test("8.01 type=20 ChangeCipherSpec",
                   20, 0xFEFD, 0x0000, seq0);

    run_test("8.02 type=21 Alert",
                   21, 0xFEFD, 0x0000, seq0);

    run_test("8.03 type=22 Handshake",
                   22, 0xFEFD, 0x0000, seq0);

    run_test("8.04 type=23 ApplicationData",
                   23, 0xFEFD, 0x0001, seq1);

    run_test("8.05 type=24 Heartbeat (RFC 6520)",
                   24, 0xFEFD, 0x0001, seq1);

    run_test("8.06 type=0x00 invalid",
                   0x00, 0xFEFD, 0x0001, seq1);

    run_test("8.07 type=0xFF invalid",
                   0xFF, 0xFEFD, 0x0001, seq1);

    // -------------------------------------------------------
    // SECTION 9: STRICT RULE BOUNDARY CONDITIONS
    // strict = type==23 && ver==0xFEFD && epoch==0x0001
    // -------------------------------------------------------
    printf("\n--- [9] STRICT RULE BOUNDARY CONDITIONS ---\n");

    run_test("9.01 All strict conditions met",
                   23, 0xFEFD, 0x0001, seq1);

    run_test("9.02 type off by one (22 vs 23)",
                   22, 0xFEFD, 0x0001, seq1);

    run_test("9.03 epoch off by one (0x0000 vs 0x0001)",
                   23, 0xFEFD, 0x0000, seq1);

    run_test("9.04 version off by one (0xFEFC vs 0xFEFD)",
                   23, 0xFEFC, 0x0001, seq1);

    run_test("9.05 type+epoch both wrong",
                   22, 0xFEFD, 0x0000, seq1);

    run_test("9.06 all three fields wrong",
                   22, 0x0303, 0x0000, seq1);

    // -------------------------------------------------------
    // SECTION 10: RENEGOTIATION FLOW
    // -------------------------------------------------------
    printf("\n--- [10] RENEGOTIATION FLOW ---\n");

    run_test("10.01 HelloRequest (server initiates, epoch=1)",
                   22, 0xFEFD, 0x0001, seq2);

    run_test("10.02 ClientHello renegotiation (epoch=1)",
                   22, 0xFEFD, 0x0001, seq3);

    run_test("10.03 ServerHello renegotiation (epoch=1)",
                   22, 0xFEFD, 0x0001, seq3);

    run_test("10.04 CCS renegotiation client (epoch=1)",
                   20, 0xFEFD, 0x0001, seq4);

    run_test("10.05 Finished renegotiation (epoch=2)",
                   22, 0xFEFD, 0x0002, seq0);

    run_test("10.06 AppData after renegotiation (epoch=2)",
                   23, 0xFEFD, 0x0002, seq1);

    // -------------------------------------------------------
    // SECTION 11: SESSION RESUMPTION
    // -------------------------------------------------------
    printf("\n--- [11] SESSION RESUMPTION ---\n");

    run_test("11.01 ClientHello resume (epoch=0)",
                   22, 0xFEFD, 0x0000, seq0);

    run_test("11.02 ServerHello resume (epoch=0)",
                   22, 0xFEFD, 0x0000, seq1);

    run_test("11.03 CCS resume client (epoch=0)",
                   20, 0xFEFD, 0x0000, seq2);

    run_test("11.04 Finished resume client (epoch=1)",
                   22, 0xFEFD, 0x0001, seq0);

    run_test("11.05 CCS resume server (epoch=0)",
                   20, 0xFEFD, 0x0000, seq3);

    run_test("11.06 Finished resume server (epoch=1)",
                   22, 0xFEFD, 0x0001, seq0);

    run_test("11.07 AppData resumed session (epoch=1)",
                   23, 0xFEFD, 0x0001, seq1);

    // -------------------------------------------------------
    // SECTION 12: ERROR / MALFORMED SCENARIOS
    // -------------------------------------------------------
    printf("\n--- [12] ERROR / MALFORMED SCENARIOS ---\n");

    run_test("12.01 Alert during handshake (epoch=0)",
                   21, 0xFEFD, 0x0000, seq1);

    run_test("12.02 Alert wrong epoch (type=21, epoch=1)",
                   21, 0xFEFD, 0x0001, seq1);

    run_test("12.03 AppData before handshake (epoch=0)",
                   23, 0xFEFD, 0x0000, seq0);

    run_test("12.04 Handshake after CCS (epoch=1)",
                   22, 0xFEFD, 0x0001, seq1);

    run_test("12.05 Unknown content type (epoch=0)",
                   0x42, 0xFEFD, 0x0000, seq0);

    run_test("12.06 Wrong version + valid type",
                   23, 0x0303, 0x0001, seq1);

    run_test("12.07 Zero epoch + appdata (unusual)",
                   23, 0xFEFD, 0x0000, seq0);

    run_test("12.08 Max epoch + appdata",
                   23, 0xFEFD, 0xFFFF, seq_max);

    printf("\n=== EXPERIMENT COMPLETE ===\n");

    return 0;
}
