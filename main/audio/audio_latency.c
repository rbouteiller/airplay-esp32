// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "audio_latency.h"

#include <stdatomic.h>

/* Written by the web server's task, read by the playback task once a block:
 * one aligned word, so an atomic load is all the coordination it needs. */
static _Atomic int32_t s_trim_us;

int32_t audio_latency_set_trim_us(int32_t trim_us) {
  if (trim_us > AUDIO_LATENCY_TRIM_MAX_US) {
    trim_us = AUDIO_LATENCY_TRIM_MAX_US;
  } else if (trim_us < -AUDIO_LATENCY_TRIM_MAX_US) {
    trim_us = -AUDIO_LATENCY_TRIM_MAX_US;
  }
  atomic_store_explicit(&s_trim_us, trim_us, memory_order_relaxed);
  return trim_us;
}

int32_t audio_latency_get_trim_us(void) {
  return atomic_load_explicit(&s_trim_us, memory_order_relaxed);
}

static uint32_t frames_to_us(uint64_t frames_q4, uint32_t rate) {
  if (rate == 0U) {
    return 0;
  }
  /* Q4 frames to microseconds, rounded: 1e6 / 16 = 62500. */
  return (uint32_t)((frames_q4 * 62500ULL + rate / 2U) / rate);
}

void audio_latency_compute(uint32_t output_rate, uint32_t fifo_frames,
                           uint32_t resampler_us, uint32_t channel_us,
                           audio_latency_t *out) {
  if (!out) {
    return;
  }
  out->fifo_us = frames_to_us((uint64_t)fifo_frames * 16U, output_rate);
  out->resampler_us = resampler_us;
  out->channel_us = channel_us;
  out->dac_us = frames_to_us(
      dac_get_output_delay_q4(output_rate, &out->dac_source), output_rate);
  out->trim_us = audio_latency_get_trim_us();
  const int64_t sum = (int64_t)out->fifo_us + out->resampler_us +
                      out->channel_us + out->dac_us + out->trim_us;
  out->post_ring_us = (int32_t)sum;
}
