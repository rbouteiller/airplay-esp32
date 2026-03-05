#pragma once

#include "esp_err.h"

/**
 * Initialize I2S audio output
 */
esp_err_t audio_output_init(void);

/**
 * Start the audio playback task
 */
void audio_output_start(void);

/**
 * Flush I2S DMA buffers (clears stale audio on pause/seek)
 */
void audio_output_flush(void);

/**
 * Notify the output of the source sample rate (from AirPlay ANNOUNCE).
 * The resampler is re-initialized if the rate changes.
 */
void audio_output_set_source_rate(int rate);
