#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the audio resampler.
 *
 * @param input_rate   Source sample rate (e.g. 44100)
 * @param output_rate  Target sample rate (e.g. 48000)
 * @param channels     Number of channels (2 for stereo)
 * @param quality      Filter size (taps and filters), e.g. 48
 * @return true on success
 */
bool audio_resample_init(uint32_t input_rate, uint32_t output_rate,
                         int channels, int quality);

/**
 * Resample a block of interleaved int16_t PCM.
 *
 * @param in           Input samples (interleaved stereo int16)
 * @param in_frames    Number of input frames (samples per channel)
 * @param out          Output buffer (int16, must hold max_output_frames)
 * @param out_capacity Maximum output frames the buffer can hold
 * @return Number of output frames written
 */
size_t audio_resample_process(const int16_t *in, size_t in_frames, int16_t *out,
                              size_t out_capacity);

/**
 * @return true if resampling is active (rates differ)
 */
bool audio_resample_is_active(void);

/**
 * Reset resampler state (call on stream flush).
 */
void audio_resample_reset(void);

/**
 * Destroy the resampler and free resources.
 */
void audio_resample_destroy(void);

/**
 * Get the maximum number of output frames for a given input frame count.
 */
size_t audio_resample_max_output(size_t in_frames);

#ifdef __cplusplus
}
#endif
