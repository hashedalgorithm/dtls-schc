#ifndef __DTLS_RULES_H__
#define __DTLS_RULES_H__

#include "schc.h"
#include "dtls-fields.h"

/*
 * VULNERABLE RULE SET
 * -------------------
 * Rule 1: Handshake packets  (Content Type=22, Epoch=0)
 * Rule 2: App data packets   (Content Type=23, Epoch=1)
 * Rule 3: Fallback           (no match - send everything)
 *
 * Side channel: Rule ID in output reveals Content Type and Epoch
 * to a passive observer without decrypting anything.
 *
 * DTLS record header layout (13 bytes):
 *   [0]      content_type   8 bits
 *   [1-2]    version        16 bits
 *   [3-4]    epoch          16 bits
 *   [5-10]   sequence_num   48 bits
 *   [11-12]  length         16 bits
 *
 * Field entry format (from schc.h schc_field struct):
 *   { field_id, MO_param, field_length_bits, pos, dir,
 *     target_value, MO_function, CDA }
 */

/* ------------------------------------------------------------------ */
/* Rule 1: DTLS Handshake (content_type=22, epoch=0)                  */
/* ------------------------------------------------------------------ */
static struct schc_field dtls_handshake_fields[DTLS_FIELDS] = {
    /*
     * Content Type = 22 (0x16), 8 bits
     * MO: equal — must match exactly 22
     * CDA: NOTSENT — don't send, reconstruct from rule
     */
    { DTLS_CONTENT_TYPE, 0, 8, 1, BI,
      { 0x16 }, mo_equal, NOTSENT },

    /*
     * Version = 0xFEFD (DTLS 1.2), 16 bits
     * MO: equal — fixed for whole session
     * CDA: NOTSENT
     */
    { DTLS_VERSION, 0, 16, 1, BI,
      { 0xFE, 0xFD }, mo_equal, NOTSENT },

    /*
     * Epoch = 0, 16 bits
     * During handshake epoch is always 0
     * MO: equal
     * CDA: NOTSENT
     */
    { DTLS_EPOCH, 0, 16, 1, BI,
      { 0x00, 0x00 }, mo_equal, NOTSENT },

    /*
     * Sequence Number, 48 bits
     * Top 32 bits are almost always 0 during handshake
     * MO: MSB — match top 32 bits
     * CDA: LSB — send only bottom 16 bits
     * MO_param = 32 means: match the first 32 bits
     */
    { DTLS_SEQ_NUM, 32, 48, 1, BI,
      { 0x00, 0x00, 0x00, 0x00 }, mo_MSB, LSB },

    /*
     * Length, 16 bits
     * Varies per packet
     * MO: ignore — match anything
     * CDA: VALUESENT — send full value
     */
    { DTLS_LENGTH, 0, 16, 1, BI,
      { 0x00, 0x00 }, mo_ignore, VALUESENT },
};

static const struct schc_layer_rule_t dtls_rule_handshake = {
    .up     = DTLS_FIELDS,
    .down   = DTLS_FIELDS,
    .length = DTLS_FIELDS,
    .content = { 0 } /* populated via dtls_handshake_fields below */
};

/* ------------------------------------------------------------------ */
/* Rule 2: DTLS Application Data (content_type=23, epoch=1)           */
/* ------------------------------------------------------------------ */
static struct schc_field dtls_appdata_fields[DTLS_FIELDS] = {
    { DTLS_CONTENT_TYPE, 0, 8, 1, BI,
      { 0x17 }, mo_equal, NOTSENT },

    { DTLS_VERSION, 0, 16, 1, BI,
      { 0xFE, 0xFD }, mo_equal, NOTSENT },

    { DTLS_EPOCH, 0, 16, 1, BI,
      { 0x00, 0x01 }, mo_equal, NOTSENT },

    { DTLS_SEQ_NUM, 32, 48, 1, BI,
      { 0x00, 0x00, 0x00, 0x00 }, mo_MSB, LSB },

    { DTLS_LENGTH, 0, 16, 1, BI,
      { 0x00, 0x00 }, mo_ignore, VALUESENT },
};

/* ------------------------------------------------------------------ */
/* Rule 3: Fallback / Uncompressed                                     */
/* All fields VALUESENT — nothing is omitted                           */
/* ------------------------------------------------------------------ */
static struct schc_field dtls_fallback_fields[DTLS_FIELDS] = {
    { DTLS_CONTENT_TYPE, 0, 8,  1, BI,
      { 0x00 }, mo_ignore, VALUESENT },

    { DTLS_VERSION, 0, 16, 1, BI,
      { 0x00, 0x00 }, mo_ignore, VALUESENT },

    { DTLS_EPOCH, 0, 16, 1, BI,
      { 0x00, 0x00 }, mo_ignore, VALUESENT },

    { DTLS_SEQ_NUM, 0, 48, 1, BI,
      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, mo_ignore, VALUESENT },

    { DTLS_LENGTH, 0, 16, 1, BI,
      { 0x00, 0x00 }, mo_ignore, VALUESENT },
};

/* ------------------------------------------------------------------ */
/* Profile and device                                                  */
/* ------------------------------------------------------------------ */
static const struct schc_profile_t dtls_profile = {
    .RULE_ID_SIZE        = 8,   /* 1 byte rule ID */
    .UNCOMPRESSED_RULE_ID = 3,  /* rule 3 = fallback */
    .DTAG_SIZE           = 0
};

#endif
