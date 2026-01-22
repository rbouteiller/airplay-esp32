#pragma once

#include <stdint.h>
#include <stddef.h>
#include "audio_receiver.h"

/**
 * Lightweight ALAC (Apple Lossless Audio Codec) decoder
 * Based on the reverse-engineered ALAC decoder from the open source community
 */

typedef struct alac_decoder alac_decoder_t;

/**
 * Create ALAC decoder with format info
 */
alac_decoder_t *alac_decoder_create(const audio_format_t *format);

/**
 * Free ALAC decoder
 */
void alac_decoder_free(alac_decoder_t *decoder);

/**
 * Decode a single ALAC frame
 * @param decoder ALAC decoder instance
 * @param input Input buffer containing ALAC frame
 * @param input_len Length of input data
 * @param output Output buffer for PCM samples (interleaved, 16-bit signed)
 * @param max_samples Maximum number of samples per channel
 * @return Number of samples decoded per channel, or negative on error
 */
int alac_decode_frame(alac_decoder_t *decoder,
                      const uint8_t *input, size_t input_len,
                      int16_t *output, size_t max_samples);
