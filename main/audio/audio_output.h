#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#include "freertos/FreeRTOS.h"

/**
 * Priority of the playback task in every output backend.
 *
 * It MUST outrank every audio source task (realtime UDP receiver = 8,
 * control receiver = 7, buffered TCP reader = 5) because the source tasks
 * are pinned to the same core.  A source task that outranks playback starves
 * it during a receive burst; the DMA ring (~46 ms) then runs dry and
 * auto_clear emits silence, so wall-clock advances while no audio is
 * consumed and the playout position slips permanently late.  That was the
 * mechanism behind the realtime-stream drift in issue #122 — the buffered
 * path was unaffected only because its reader task sits at priority 5.
 *
 * Playback cannot starve the sources in return: it blocks on the DMA write
 * for all but a few hundred microseconds of each ~8 ms frame period.
 */
#define AUDIO_PLAYBACK_TASK_PRIORITY 9

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
 * Sample the live output pipeline delay: how long from now until the first
 * sample of the NEXT backend write is heard.
 *
 * Unlike audio_output_get_hardware_latency_us(), which models a permanently
 * half-full DMA ring, this reports the measured queue depth (frames handed
 * to the hardware minus frames the hardware reports as clocked out).  The
 * measurement is what makes the timing engine's error signal honest:
 *
 *   - it is unaffected by when the playback task happens to be scheduled,
 *     removing the one-sided "late read" noise the model suffers from;
 *   - after a writer stall it correctly reports a near-empty ring, so the
 *     engine sees the real lateness of the content it is about to submit
 *     instead of a fixed 43 ms guess.
 *
 * @param now_us      out: esp_timer_get_time() sampled with the queue depth.
 * @param pipeline_us out: queue depth in microseconds at the output rate.
 * @return false if the backend cannot report a hardware completion cursor,
 *         in which case the caller should fall back to the modelled latency.
 */
bool audio_output_get_pipeline_us(int64_t *now_us, uint32_t *pipeline_us);

/**
 * Local monotonic time (ns) at which the first sample of the NEXT backend
 * write will be heard.
 *
 * Deliberately built on the stable modelled latency rather than the live
 * cursor from audio_output_get_pipeline_us(): this is a *scheduling* input,
 * consumed once per render to pick which RTP timestamp to emit next.  The
 * live cursor steps at DMA descriptor boundaries, so feeding it in here would
 * make the chosen timestamp jitter by a whole descriptor and repeatedly
 * re-target the read cursor.  Error measurement still uses the live value.
 */
int64_t audio_output_get_next_playout_time_ns(int64_t now_us);

/**
 * Number of output-underrun episodes since boot: the DMA clocked out
 * descriptors the playback task never filled, so that much output time was
 * emitted as silence and lost from the playout position.  Non-zero values
 * mean the playback task is being starved.
 */
uint32_t audio_output_get_underruns(void);

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
