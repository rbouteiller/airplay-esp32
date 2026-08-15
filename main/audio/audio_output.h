#pragma once

#include "esp_err.h"

#include "freertos/FreeRTOS.h"

/**
 * Output channel mode. LEFT/RIGHT route the chosen source channel to both
 * speakers; MONO plays the (L+R)/2 downmix on both speakers; STEREO (default)
 * plays the normal left/right mix.
 */
typedef enum {
  AUDIO_CHANNEL_STEREO = 0,
  AUDIO_CHANNEL_LEFT,
  AUDIO_CHANNEL_RIGHT,
  AUDIO_CHANNEL_MONO,
} audio_channel_mode_t;

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

/**
 * Cycle the output channel mode: STEREO -> LEFT -> RIGHT -> MONO -> STEREO.
 * The new mode is persisted to NVS.
 * @return the new mode after cycling.
 */
audio_channel_mode_t audio_output_cycle_channel_mode(void);

/**
 * Set the output channel mode directly and persist it to NVS.
 */
void audio_output_set_channel_mode(audio_channel_mode_t mode);

/**
 * Get the current output channel mode.
 */
audio_channel_mode_t audio_output_get_channel_mode(void);

/**
 * True when the DAC configuration already fixes the per-output routing, in
 * which case the mode is forced to STEREO and set/cycle are ignored.
 */
bool audio_output_channel_mode_locked(void);

/**
 * True when a DSP flow makes the channel selection instead of the software
 * downmix. The outputs are then crossover ways rather than left and right, so
 * STEREO means the (L+R)/2 mix and only LEFT and RIGHT pick a single channel.
 */
bool audio_output_channel_mode_in_dsp(void);
