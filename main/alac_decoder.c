/**
 * ALAC (Apple Lossless Audio Codec) Decoder
 *
 * Based on the reverse-engineered ALAC decoder from David Hammerton
 * and the open-source community. This implementation is simplified
 * for embedded use.
 *
 * ALAC is a lossless audio codec that typically compresses audio
 * to about 50-60% of the original size.
 */

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "esp_log.h"
#include "alac_decoder.h"

static const char *TAG = "alac";

// Bit reader for parsing ALAC bitstream
typedef struct {
    const uint8_t *buffer;
    size_t buffer_len;
    size_t byte_pos;
    int bit_pos;
} bitreader_t;

// ALAC decoder state
struct alac_decoder {
    // Configuration from SDP
    uint32_t frame_length;
    uint8_t sample_size;
    uint8_t rice_history_mult;
    uint8_t rice_initial_history;
    uint8_t rice_limit;
    uint8_t channels;
    uint16_t max_run;
    uint32_t max_frame_bytes;
    uint32_t avg_bit_rate;
    uint32_t sample_rate;

    // Decoding state
    int32_t *predictor_buf;
    int32_t *shift_buf;
    size_t buf_size;
};

static void bitreader_init(bitreader_t *br, const uint8_t *buffer, size_t len)
{
    br->buffer = buffer;
    br->buffer_len = len;
    br->byte_pos = 0;
    br->bit_pos = 0;
}

static uint32_t bitreader_read(bitreader_t *br, int bits)
{
    uint32_t result = 0;

    while (bits > 0) {
        if (br->byte_pos >= br->buffer_len) {
            return 0;
        }

        int bits_left = 8 - br->bit_pos;
        int bits_to_read = (bits < bits_left) ? bits : bits_left;

        uint8_t mask = (1 << bits_to_read) - 1;
        uint8_t shift = bits_left - bits_to_read;
        uint8_t val = (br->buffer[br->byte_pos] >> shift) & mask;

        result = (result << bits_to_read) | val;
        bits -= bits_to_read;

        br->bit_pos += bits_to_read;
        if (br->bit_pos >= 8) {
            br->bit_pos = 0;
            br->byte_pos++;
        }
    }

    return result;
}

static int32_t bitreader_read_signed(bitreader_t *br, int bits)
{
    int32_t val = bitreader_read(br, bits);
    // Sign extend
    if (val & (1 << (bits - 1))) {
        val |= ~((1 << bits) - 1);
    }
    return val;
}

// Rice decoding
static int32_t rice_decode(bitreader_t *br, int m, int k, int bits)
{
    int32_t x = 0;

    // Count leading zeros (unary part)
    while (br->byte_pos < br->buffer_len) {
        if (bitreader_read(br, 1)) {
            break;
        }
        x += m;
    }

    // Binary part
    if (k > 0) {
        x += bitreader_read(br, k);
    }

    return x;
}

// Sign extension helper
static inline int32_t sign_extend(int32_t val, int bits)
{
    int shift = 32 - bits;
    return (val << shift) >> shift;
}

// Predictor for lossless decoding
static void predictor_decompress(alac_decoder_t *dec, int32_t *buffer, int num_samples,
                                  int16_t *coefs, int num_coefs, int quant_shift)
{
    if (num_coefs == 0) {
        return;
    }

    // Simple predictor - this is a simplified version
    // Full ALAC uses adaptive prediction with multiple coefficients
    for (int i = num_coefs; i < num_samples; i++) {
        int32_t prediction = 0;
        for (int j = 0; j < num_coefs; j++) {
            prediction += coefs[j] * buffer[i - j - 1];
        }
        prediction >>= quant_shift;
        buffer[i] += prediction;
    }
}

alac_decoder_t *alac_decoder_create(const audio_format_t *format)
{
    alac_decoder_t *dec = calloc(1, sizeof(alac_decoder_t));
    if (!dec) {
        return NULL;
    }

    // Use format config or defaults
    dec->frame_length = format->max_samples_per_frame ? format->max_samples_per_frame : 4096;
    dec->sample_size = format->sample_size ? format->sample_size : 16;
    dec->rice_history_mult = format->rice_history_mult ? format->rice_history_mult : 40;
    dec->rice_initial_history = format->rice_initial_history ? format->rice_initial_history : 10;
    dec->rice_limit = format->rice_limit ? format->rice_limit : 14;
    dec->channels = format->num_channels ? format->num_channels : 2;
    dec->max_run = format->max_run ? format->max_run : 255;
    dec->max_frame_bytes = format->max_coded_frame_size ? format->max_coded_frame_size : 0;
    dec->avg_bit_rate = format->avg_bit_rate ? format->avg_bit_rate : 0;
    dec->sample_rate = format->sample_rate_config ? format->sample_rate_config : 44100;

    // Allocate working buffers
    dec->buf_size = dec->frame_length * dec->channels;
    dec->predictor_buf = malloc(dec->buf_size * sizeof(int32_t));
    dec->shift_buf = malloc(dec->buf_size * sizeof(int32_t));

    if (!dec->predictor_buf || !dec->shift_buf) {
        alac_decoder_free(dec);
        return NULL;
    }

    ESP_LOGI(TAG, "ALAC decoder created: %lu Hz, %d ch, %d bit, %lu samples/frame",
             dec->sample_rate, dec->channels, dec->sample_size, dec->frame_length);

    return dec;
}

void alac_decoder_free(alac_decoder_t *decoder)
{
    if (decoder) {
        free(decoder->predictor_buf);
        free(decoder->shift_buf);
        free(decoder);
    }
}

int alac_decode_frame(alac_decoder_t *decoder,
                      const uint8_t *input, size_t input_len,
                      int16_t *output, size_t max_samples)
{
    if (!decoder || !input || !output || input_len == 0) {
        return -1;
    }

    bitreader_t br;
    bitreader_init(&br, input, input_len);

    // Read frame header
    uint8_t channels = bitreader_read(&br, 3);
    (void)channels;  // We use decoder config

    // Skip unused header bits for now
    bitreader_read(&br, 4);  // Reserved
    uint8_t has_size = bitreader_read(&br, 1);  // Has sample count
    bitreader_read(&br, 2);  // Uncompressed flag (unused)
    uint8_t is_not_compressed = bitreader_read(&br, 1);

    uint32_t num_samples = decoder->frame_length;
    if (has_size) {
        num_samples = bitreader_read(&br, 32);
    }

    if (num_samples > max_samples || num_samples > decoder->frame_length) {
        ESP_LOGW(TAG, "Frame too large: %lu samples", num_samples);
        return -1;
    }

    if (is_not_compressed) {
        // Uncompressed frame - read raw samples
        int sample_bytes = decoder->sample_size / 8;
        int total_samples = num_samples * decoder->channels;

        for (int i = 0; i < total_samples && i < (int)(max_samples * decoder->channels); i++) {
            int32_t sample;
            if (sample_bytes == 2) {
                sample = bitreader_read_signed(&br, 16);
            } else if (sample_bytes == 3) {
                sample = bitreader_read_signed(&br, 24) >> 8;  // Convert to 16-bit
            } else {
                sample = bitreader_read_signed(&br, 8) << 8;  // Convert to 16-bit
            }
            output[i] = (int16_t)sample;
        }

        return num_samples;
    }

    // Compressed frame
    // Read mixing info
    uint8_t mix_bits = bitreader_read(&br, 8);
    uint8_t mix_res = bitreader_read(&br, 8);
    (void)mix_bits;
    (void)mix_res;

    // Read predictor info for each channel
    int16_t coefs[2][32];  // Predictor coefficients per channel
    int num_coefs_ch[2] = {0, 0};
    int quant_shift_ch[2] = {0, 0};

    for (int ch = 0; ch < decoder->channels; ch++) {
        uint8_t mode = bitreader_read(&br, 4);
        (void)mode;

        quant_shift_ch[ch] = bitreader_read(&br, 4);
        uint8_t rice_modifier = bitreader_read(&br, 3);
        (void)rice_modifier;
        num_coefs_ch[ch] = bitreader_read(&br, 5);

        // Read coefficient values
        for (int i = 0; i < num_coefs_ch[ch]; i++) {
            coefs[ch][i] = (int16_t)bitreader_read(&br, 16);
        }
    }

    // Read rice-encoded residuals - interleaved for stereo (L,R,L,R,...)
    int history = decoder->rice_initial_history;
    int rice_k = (int)log2(history) + ((history & (history - 1)) ? 1 : 0);
    if (rice_k > decoder->rice_limit) rice_k = decoder->rice_limit;

    // Temporary buffers for each channel
    int32_t *left_buf = decoder->predictor_buf;
    int32_t *right_buf = decoder->predictor_buf + decoder->frame_length;

    for (uint32_t i = 0; i < num_samples; i++) {
        for (int ch = 0; ch < decoder->channels; ch++) {
            // Rice decode
            int32_t val = rice_decode(&br, 1 << rice_k, rice_k, decoder->sample_size);

            // Unsign (zigzag decode)
            if (val & 1) {
                val = -((val + 1) >> 1);
            } else {
                val = val >> 1;
            }

            // Store in appropriate channel buffer
            if (ch == 0) {
                left_buf[i] = val;
            } else {
                right_buf[i] = val;
            }

            // Update history for adaptive rice
            int abs_val = val < 0 ? -val : val;
            history += abs_val * decoder->rice_history_mult - ((history * decoder->rice_history_mult) >> 9);
            if (history < 0) history = 0;

            rice_k = (int)log2(history + 1);
            if (rice_k > decoder->rice_limit) rice_k = decoder->rice_limit;
        }
    }

    // Apply LPC predictor for each channel
    for (int ch = 0; ch < decoder->channels; ch++) {
        int32_t *channel_buf = (ch == 0) ? left_buf : right_buf;
        int shift = quant_shift_ch[ch];
        int nc = num_coefs_ch[ch];

        for (uint32_t i = 0; i < num_samples; i++) {
            int32_t prediction = 0;

            // Compute prediction from previous samples
            for (int j = 0; j < nc && j < (int)i; j++) {
                prediction += (int32_t)coefs[ch][j] * channel_buf[i - 1 - j];
            }

            // Add quantized prediction to residual
            prediction >>= shift;
            channel_buf[i] += prediction;

            // Clamp to sample range
            if (channel_buf[i] > 32767) channel_buf[i] = 32767;
            if (channel_buf[i] < -32768) channel_buf[i] = -32768;
        }
    }

    // Interleave channels to output
    if (decoder->channels == 2) {
        for (uint32_t i = 0; i < num_samples && i < max_samples; i++) {
            output[i * 2] = (int16_t)left_buf[i];
            output[i * 2 + 1] = (int16_t)right_buf[i];
        }
    } else {
        for (uint32_t i = 0; i < num_samples && i < max_samples; i++) {
            output[i] = (int16_t)left_buf[i];
        }
    }

    return num_samples;
}
