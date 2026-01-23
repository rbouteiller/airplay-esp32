/*
 * C wrapper for Apple ALAC decoder
 */

#include "alac_wrapper.h"
#include "ALACDecoder.h"
#include "ALACBitUtilities.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  // For htonl, htons

extern "C" {
#include "esp_log.h"
}

static const char *TAG = "alac_apple";

struct alac_decoder_handle {
    ALACDecoder decoder;
    uint32_t channels;
    uint32_t sample_rate;
    uint32_t frame_length;
};

extern "C" alac_handle_t alac_create(const audio_format_t *format)
{
    if (!format) {
        return nullptr;
    }

    alac_decoder_handle *handle = new alac_decoder_handle();
    if (!handle) {
        return nullptr;
    }

    // Build the magic cookie (ALACSpecificConfig)
    // Note: The Apple decoder expects the config in BIG-ENDIAN (network byte order)
    // and swaps bytes internally using Swap32BtoN/Swap16BtoN
    ALACSpecificConfig config;
    memset(&config, 0, sizeof(config));

    // Get values in native format first
    uint32_t frameLength = format->frame_size ? format->frame_size :
                           (format->max_samples_per_frame ? format->max_samples_per_frame : 352);
    uint8_t bitDepth = format->sample_size ? format->sample_size :
                       (format->bits_per_sample ? format->bits_per_sample : 16);
    uint8_t numChannels = format->num_channels ? format->num_channels :
                          (format->channels ? format->channels : 2);
    uint16_t maxRun = format->max_run ? format->max_run : 255;
    uint32_t maxFrameBytes = format->max_coded_frame_size ? format->max_coded_frame_size : 0;
    uint32_t avgBitRate = format->avg_bit_rate ? format->avg_bit_rate : 0;
    uint32_t sampleRate = format->sample_rate_config ? format->sample_rate_config :
                          (format->sample_rate ? format->sample_rate : 44100);

    // Store in handle (native format)
    handle->channels = numChannels;
    handle->sample_rate = sampleRate;
    handle->frame_length = frameLength;

    ESP_LOGI(TAG, "ALAC config: frameLen=%u, bitDepth=%u, pb=%u, mb=%u, kb=%u, ch=%u, maxRun=%u, sr=%u",
             frameLength, bitDepth,
             format->rice_history_mult ? format->rice_history_mult : 40,
             format->rice_initial_history ? format->rice_initial_history : 10,
             format->rice_limit ? format->rice_limit : 14,
             numChannels, maxRun, sampleRate);
    ESP_LOGI(TAG, "Input format: frame_size=%d, max_samples=%u, channels=%d, bits=%d, sr=%d",
             format->frame_size, format->max_samples_per_frame, format->channels,
             format->bits_per_sample, format->sample_rate);

    // Convert to big-endian for the Apple decoder
    // The decoder expects data in big-endian format (like in a file) and swaps to native
    config.frameLength = htonl(frameLength);
    config.compatibleVersion = 0;
    config.bitDepth = bitDepth;
    config.pb = format->rice_history_mult ? format->rice_history_mult : 40;
    config.mb = format->rice_initial_history ? format->rice_initial_history : 10;
    config.kb = format->rice_limit ? format->rice_limit : 14;
    config.numChannels = numChannels;
    config.maxRun = htons(maxRun);
    config.maxFrameBytes = htonl(maxFrameBytes);
    config.avgBitRate = htonl(avgBitRate);
    config.sampleRate = htonl(sampleRate);

    // Initialize the decoder
    int32_t result = handle->decoder.Init(&config, sizeof(config));
    if (result != 0) {
        ESP_LOGE(TAG, "ALACDecoder Init failed: %d", (int)result);
        delete handle;
        return nullptr;
    }

    ESP_LOGI(TAG, "Apple ALAC decoder created: %u Hz, %u ch, %u bit, %u samples/frame",
             sampleRate, numChannels, bitDepth, frameLength);

    return handle;
}

extern "C" void alac_free(alac_handle_t decoder)
{
    if (decoder) {
        delete decoder;
    }
}

extern "C" int alac_decode(alac_handle_t decoder,
                           const uint8_t *input, size_t input_len,
                           int16_t *output, size_t max_samples)
{
    if (!decoder || !input || !output || input_len == 0) {
        return -1;
    }

    uint32_t max_samples_u32 = max_samples > 0 ? (uint32_t)max_samples : decoder->frame_length;
    if (decoder->frame_length > 0 &&
        (max_samples_u32 == 0 || max_samples_u32 > decoder->frame_length)) {
        max_samples_u32 = decoder->frame_length;
    }

    // Create a BitBuffer from the input
    BitBuffer bits;
    BitBufferInit(&bits, const_cast<uint8_t*>(input), input_len);

    // Decode
    uint32_t numSamples = 0;
    int32_t result = decoder->decoder.Decode(&bits,
                                              reinterpret_cast<uint8_t*>(output),
                                              max_samples_u32,
                                              decoder->channels,
                                              &numSamples);
    if (result != 0) {
        static int error_count = 0;
        if (error_count < 5) {
            ESP_LOGW(TAG, "ALAC decode error: %d", (int)result);
            error_count++;
        }
        return -1;
    }

    return (int)numSamples;
}
