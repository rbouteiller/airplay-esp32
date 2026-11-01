// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * Per-output delay, for time-aligning the drivers of a multi-way speaker: the
 * one whose acoustic centre sits ahead (usually the tweeter) is held back so
 * both arrive together through the crossover.
 *
 * Runs on the words as they leave for I2S, after routing, EQ and volume, so
 * each I2S slot must feed one output of its own (see
 * audio_output_delay_supported()). Whole samples only: 21-23 us, about 8 mm,
 * at 44.1/48 kHz, a few degrees at a 2 kHz crossover.
 *
 * The settings are safe from any task; they reach the audio at the next
 * block, where the delayed channel restarts from silence.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"

#define AUDIO_DELAY_CHANNELS 2
/** 68.6 cm at 343 m/s, well past any driver offset. */
#define AUDIO_DELAY_MAX_US 2000

#ifdef CONFIG_I2S_32BIT_OUTPUT
typedef int32_t audio_delay_word_t;
#else
typedef int16_t audio_delay_word_t;
#endif

/** Clamped to 0..AUDIO_DELAY_MAX_US. */
void audio_delay_set_us(int ch, uint32_t us);
uint32_t audio_delay_get_us(int ch);
/** Whether either output has a delay set. */
bool audio_delay_active(void);

/** The output rate, which turns microseconds into samples. */
void audio_delay_set_rate(uint32_t rate);
/** Drop what is held, so a new stream never plays an old one's tail. */
void audio_delay_reset(void);

/**
 * Delay the interleaved stereo words in @p buf in place. With @p enabled
 * false the words pass untouched, as when the layout cannot be delayed per
 * output; the delay restarts from silence when it is enabled again.
 */
void audio_delay_process(audio_delay_word_t *buf, size_t frames, bool enabled);
