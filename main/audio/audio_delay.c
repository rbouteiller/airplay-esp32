// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "audio_delay.h"

#include <stdatomic.h>
#include <string.h>

/* A power of two above AUDIO_DELAY_MAX_US at the highest output rate:
 * 2000 us at 96 kHz is 192 samples. */
#define RING      256u
#define RING_MASK (RING - 1u)
#define MAX_RATE  96000u

_Static_assert((uint64_t)AUDIO_DELAY_MAX_US *MAX_RATE / 1000000u < RING,
               "the ring must hold the longest delay at the highest rate");

/* Settings, written by any task. Every change bumps s_gen, and the writer
 * adopts them at the top of its next block. */
static _Atomic uint32_t s_us[AUDIO_DELAY_CHANNELS];
static _Atomic uint32_t s_rate;
static _Atomic uint32_t s_gen;

/* The writer's own: one task writes to I2S. */
static uint32_t s_seen_gen;
static bool s_was_enabled;
static uint32_t s_samples[AUDIO_DELAY_CHANNELS];
static uint32_t s_pos;
static audio_delay_word_t s_ring[AUDIO_DELAY_CHANNELS][RING];

static void changed(void) {
  atomic_fetch_add_explicit(&s_gen, 1, memory_order_release);
}

void audio_delay_set_us(int ch, uint32_t us) {
  if (ch < 0 || ch >= AUDIO_DELAY_CHANNELS) {
    return;
  }
  if (us > AUDIO_DELAY_MAX_US) {
    us = AUDIO_DELAY_MAX_US;
  }
  atomic_store_explicit(&s_us[ch], us, memory_order_relaxed);
  changed();
}

uint32_t audio_delay_get_us(int ch) {
  if (ch < 0 || ch >= AUDIO_DELAY_CHANNELS) {
    return 0;
  }
  return atomic_load_explicit(&s_us[ch], memory_order_relaxed);
}

bool audio_delay_active(void) {
  for (int ch = 0; ch < AUDIO_DELAY_CHANNELS; ch++) {
    if (audio_delay_get_us(ch) != 0) {
      return true;
    }
  }
  return false;
}

void audio_delay_set_rate(uint32_t rate) {
  atomic_store_explicit(&s_rate, rate, memory_order_relaxed);
  changed();
}

void audio_delay_reset(void) {
  changed();
}

/* Take up the current settings and start from silence. */
static void adopt(void) {
  const uint32_t rate = atomic_load_explicit(&s_rate, memory_order_relaxed);
  for (int ch = 0; ch < AUDIO_DELAY_CHANNELS; ch++) {
    const uint64_t us = audio_delay_get_us(ch);
    uint32_t n = (uint32_t)((us * rate + 500000u) / 1000000u);
    s_samples[ch] = n < RING ? n : RING - 1u;
  }
  memset(s_ring, 0, sizeof(s_ring));
  s_pos = 0;
}

void audio_delay_process(audio_delay_word_t *buf, size_t frames, bool enabled) {
  const uint32_t gen = atomic_load_explicit(&s_gen, memory_order_acquire);
  if (gen != s_seen_gen || enabled != s_was_enabled) {
    s_seen_gen = gen;
    s_was_enabled = enabled;
    adopt();
  }
  if (!enabled || (s_samples[0] == 0 && s_samples[1] == 0)) {
    return;
  }
  for (size_t i = 0; i < frames; i++) {
    for (int ch = 0; ch < AUDIO_DELAY_CHANNELS; ch++) {
      const uint32_t d = s_samples[ch];
      if (d == 0) {
        continue;
      }
      audio_delay_word_t *x = &buf[i * AUDIO_DELAY_CHANNELS + ch];
      s_ring[ch][s_pos] = *x;
      *x = s_ring[ch][(s_pos - d) & RING_MASK];
    }
    s_pos = (s_pos + 1u) & RING_MASK;
  }
}
