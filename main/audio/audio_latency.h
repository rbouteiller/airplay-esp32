// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * Output latency: how long after leaving the DMA ring a sample is heard.
 *
 * The playback task schedules every block for the instant its first frame is
 * heard:
 *
 *   playout = now + live DMA queue depth + post-ring latency
 *
 * The live queue is measured (audio_output_get_pipeline_us()).  The
 * post-ring latency is what this module adds up, the way Apple's receiver
 * sums the latency of every node in its output graph:
 *   - the I2S TX FIFO: a descriptor counts as sent once the DMA has handed
 *     its last word to the FIFO, which still has to shift it out;
 *   - the resampler's group delay, while it runs;
 *   - the common part of the per-output delays (audio_delay.h);
 *   - the DAC's own group delay, from its driver or the plain-DAC preset;
 *   - the user's trim, for anything downstream that only a measurement can
 *     know: an amplifier with DSP, an AV receiver behind S/PDIF or USB.
 * It replaces the fixed, never measured 5 ms the receiver used to assume.
 *
 * Host-testable: depends only on dac.h.
 */

#include <stdbool.h>
#include <stdint.h>

#include "dac.h"

/** The user trim's range, microseconds either way. */
#define AUDIO_LATENCY_TRIM_MAX_US 50000

typedef struct audio_latency {
  uint32_t fifo_us;      /**< I2S TX FIFO after the DMA's EOF */
  uint32_t resampler_us; /**< sinc resampler group delay, 0 when bypassed */
  uint32_t channel_us;   /**< delay common to both outputs */
  uint32_t dac_us;       /**< DAC group delay */
  dac_delay_source_t dac_source;
  int32_t trim_us; /**< user trim, may be negative */
  /** Sum of the above; negative only with a large negative trim. */
  int32_t post_ring_us;
} audio_latency_t;

/**
 * Add up the post-ring latency.  @p output_rate is the I2S (or S/PDIF, USB)
 * rate the DAC runs at; the other terms come from the backend.  Cheap and
 * lock-free: the playback task calls it once per block.
 */
void audio_latency_compute(uint32_t output_rate, uint32_t fifo_frames,
                           uint32_t resampler_us, uint32_t channel_us,
                           audio_latency_t *out);

/**
 * Set the trim, clamped to +-AUDIO_LATENCY_TRIM_MAX_US.  Positive means the
 * sound is heard that much later than the receiver otherwise assumes, so it
 * plays that much earlier.  Takes effect from the next block: the scheduler
 * sees the playout instant move and the drift servo (or, from its step
 * threshold up, one faded step) brings playout onto it, so the audio never
 * jumps.
 * Not persisted here; see settings_set_output_latency_trim_us().
 * @return the value applied.
 */
int32_t audio_latency_set_trim_us(int32_t trim_us);
int32_t audio_latency_get_trim_us(void);
