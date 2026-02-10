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
