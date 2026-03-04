#ifndef DTLS_RULE_CONFIG_H
#define DTLS_RULE_CONFIG_H

#include "../libschc/schc.h"

/* ------------------------------------------------------------------
 * DTLS field IDs
 * schc_header_fields tops out around 1045 (COAP_PAYLOAD).
 * Use 2000+ to avoid collisions.
 * ------------------------------------------------------------------ */
#define DTLS_TYPE_FIELD    2000
#define DTLS_VERSION_FIELD 2001
#define DTLS_EPOCH_FIELD   2002
#define DTLS_SEQ_FIELD     2003
#define DTLS_LENGTH_FIELD  2004

/* ------------------------------------------------------------------
 * Rule 1 – STRICT
 * Type=23, Version=0xFEFD, Epoch=1 → NOTSENT
 * Seq, Length                      → VALUESENT
 * Side channel IS visible here.
 * ------------------------------------------------------------------ */
static const struct schc_dtls_rule_t dtls_strict_rule = {
    .up     = 5,
    .down   = 5,
    .length = 5,
    .content = {
        {
            .field           = DTLS_TYPE_FIELD,
            .MO_param_length = 0,
            .field_length    = 8,
            .field_pos       = 1,
            .dir             = BI,
            .target_value    = { 0x17 },   /* 23 = application_data */
            .MO              = mo_equal,
            .action          = NOTSENT
        },
        {
            .field           = DTLS_VERSION_FIELD,
            .MO_param_length = 0,
            .field_length    = 16,
            .field_pos       = 1,
            .dir             = BI,
            .target_value    = { 0xFE, 0xFD },
            .MO              = mo_equal,
            .action          = NOTSENT
        },
        {
            .field           = DTLS_EPOCH_FIELD,
            .MO_param_length = 0,
            .field_length    = 16,
            .field_pos       = 1,
            .dir             = BI,
            .target_value    = { 0x00, 0x01 },
            .MO              = mo_equal,
            .action          = NOTSENT
        },
        {
            .field           = DTLS_SEQ_FIELD,
            .MO_param_length = 0,
            .field_length    = 48,
            .field_pos       = 1,
            .dir             = BI,
            .target_value    = { 0 },
            .MO              = mo_ignore,
            .action          = VALUESENT
        },
        {
            .field           = DTLS_LENGTH_FIELD,
            .MO_param_length = 0,
            .field_length    = 16,
            .field_pos       = 1,
            .dir             = BI,
            .target_value    = { 0 },
            .MO              = mo_ignore,
            .action          = VALUESENT
        }
    }
};

/* ------------------------------------------------------------------
 * Rule 2 – RELAXED  (mitigation: all fields VALUESENT → flat size)
 * ------------------------------------------------------------------ */
static const struct schc_dtls_rule_t dtls_relaxed_rule = {
    .up     = 5,
    .down   = 5,
    .length = 5,
    .content = {
        { DTLS_TYPE_FIELD,    0,  8, 1, BI, { 0 }, mo_ignore, VALUESENT },
        { DTLS_VERSION_FIELD, 0, 16, 1, BI, { 0 }, mo_ignore, VALUESENT },
        { DTLS_EPOCH_FIELD,   0, 16, 1, BI, { 0 }, mo_ignore, VALUESENT },
        { DTLS_SEQ_FIELD,     0, 48, 1, BI, { 0 }, mo_ignore, VALUESENT },
        { DTLS_LENGTH_FIELD,  0, 16, 1, BI, { 0 }, mo_ignore, VALUESENT }
    }
};

/* ------------------------------------------------------------------
 * Compression rule wrappers
 * ------------------------------------------------------------------ */
static const struct schc_compression_rule_t dtls_compression_rule_strict = {
    .rule_id    = 1,
    .ipv6_rule  = NULL,
    .udp_rule   = NULL,
    .coap_rule  = NULL,
    .dtls_rule  = &dtls_strict_rule
};

static const struct schc_compression_rule_t dtls_compression_rule_relaxed = {
    .rule_id    = 2,
    .ipv6_rule  = NULL,
    .udp_rule   = NULL,
    .coap_rule  = NULL,
    .dtls_rule  = &dtls_relaxed_rule
};

/* Pointer arrays expected by schc_device.compression_context */
static const struct schc_compression_rule_t
    *dtls_rules_strict[]  = { &dtls_compression_rule_strict  };
static const struct schc_compression_rule_t
    *dtls_rules_relaxed[] = { &dtls_compression_rule_relaxed };

/* ------------------------------------------------------------------
 * Device descriptors
 * ------------------------------------------------------------------ */
static struct schc_device dtls_device_strict = {
    .device_id              = 1,
    .uncomp_rule_id         = 0,
    .compression_rule_count = 1,
    .compression_context    = (const struct schc_compression_rule_t **)
                                  dtls_rules_strict
};

static struct schc_device dtls_device_relaxed = {
    .device_id              = 2,
    .uncomp_rule_id         = 0,
    .compression_rule_count = 1,
    .compression_context    = (const struct schc_compression_rule_t **)
                                  dtls_rules_relaxed
};

#endif /* DTLS_RULE_CONFIG_H */