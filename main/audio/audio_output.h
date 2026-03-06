#pragma once

#include "esp_err.h"

#include "freertos/FreeRTOS.h"

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
 * Stop the AirPlay playback task (for yielding I2S to another source)
 */
void audio_output_stop(void);

/**
 * Write raw PCM data to the I2S output.
 * Can be used by any audio source (BT A2DP, etc.) when the AirPlay
 * playback task is stopped.
 *
 * @param data   PCM data buffer (interleaved stereo, 16-bit)
 * @param bytes  Number of bytes to write
 * @param wait   Maximum ticks to wait for I2S DMA space
 * @return ESP_OK on success
 */
esp_err_t audio_output_write(const void *data, size_t bytes, TickType_t wait);

/**
 * Change the I2S sample rate (e.g. when BT negotiates 48 kHz)
 *
 * @param rate  Sample rate in Hz (e.g. 44100, 48000)
 */
void audio_output_set_sample_rate(uint32_t rate);