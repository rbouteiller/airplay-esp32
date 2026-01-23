#pragma once

#include <stdint.h>
#include <stddef.h>
#include "audio_receiver.h"

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to ALAC decoder
typedef struct alac_decoder_handle* alac_handle_t;

/**
 * Create ALAC decoder with format info
 */
alac_handle_t alac_create(const audio_format_t *format);

/**
 * Free ALAC decoder
 */
void alac_free(alac_handle_t decoder);

/**
 * Decode a single ALAC frame
 * @param decoder ALAC decoder instance
 * @param input Input buffer containing ALAC frame
 * @param input_len Input buffer length
 * @param output Output buffer for PCM samples (interleaved stereo, 16-bit)
 * @param max_samples Maximum samples to decode (per channel)
 * @return Number of samples decoded, or negative on error
 */
int alac_decode(alac_handle_t decoder,
                const uint8_t *input, size_t input_len,
                int16_t *output, size_t max_samples);

#ifdef __cplusplus
}
#endif
