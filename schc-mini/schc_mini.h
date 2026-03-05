#ifndef DTLS_MINI_SCHC_H
#define DTLS_MINI_SCHC_H

#include <stdint.h>
#include <stddef.h>

#define DTLS_HEADER_LEN 13

#define MINI_RULE_NONE    0
#define MINI_RULE_STRICT  1
#define MINI_RULE_RELAXED 2

int dtls_mini_compress(const uint8_t *input,
                       size_t input_len,
                       uint8_t *output,
                       size_t output_max);

int dtls_mini_decompress(const uint8_t *input,
                         size_t input_len,
                         uint8_t *output,
                         size_t output_max);

#endif