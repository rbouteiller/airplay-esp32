#pragma once

#include "esp_err.h"

#include "freertos/FreeRTOS.h"

/**
 * Initialize the audio output backend (I2S / SPDIF / USB UAC).
 */
esp_err_t audio_output_init(void);

/**
 * Start the audio playback task.
 */
void audio_output_start(void);

/**
 * Flush output buffers (clears stale audio on pause/seek).
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

/**
 * Notify the output of the source sample rate (from AirPlay ANNOUNCE).
 * The resampler is re-initialized if the rate changes.
 */
void audio_output_set_source_rate(int rate);

/**
 * Return the I2S DMA pipeline latency in microseconds.
 *
 * This is computed from the DMA descriptor count and frame count
 * (both set at init time) divided by the output sample rate — i.e.
 *   (dma_desc_num × dma_frame_num × 1 000 000) / sample_rate
 *
 * Using this value instead of a hard-coded constant means the latency
 * stays correct if the DMA config or sample rate is ever changed.
 */
uint32_t audio_output_get_hardware_latency_us(void);
