// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * Software parametric EQ for DACs without a DSP (CONFIG_SOFTWARE_EQ), and
 * for comparing a TAS58xx's own EQ against (CONFIG_SOFTWARE_EQ_AB).
 *
 * Backs the /bq page on plain I2S DACs and amplifiers the way the TAS58xx
 * driver backs it on those chips: two channels of TAS58XX_BQ_SLOTS sections,
 * designed by the same tas58xx_biquad.c code, plus a level trim and mute per
 * output. Edits apply live; the chains persist on audio_eq_commit(), while
 * trims and mutes persist as soon as they change, as on the TAS58xx.
 *
 * Every source that writes to I2S runs through audio_eq_process(), so the
 * tuning applies to AirPlay, Sendspin, USB and Bluetooth audio alike.
 *
 * Edits never restart the filters: sections that stay in the chain keep
 * their state, and level changes glide over a few milliseconds.
 */

#include "esp_err.h"
#include "tas58xx_biquad.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AUDIO_EQ_CHANNELS    2
#define AUDIO_EQ_SLOTS       TAS58XX_BQ_SLOTS
#define AUDIO_EQ_TRIM_MIN_DB (-40.0f)
#define AUDIO_EQ_TRIM_MAX_DB 0.0f

/** Load the committed tuning. Call once SPIFFS and settings are up. */
esp_err_t audio_eq_init(void);

/**
 * Instead of audio_eq_init(), for an amplifier whose own DSP keeps the
 * tuning and lends its chains here to be compared against
 * (CONFIG_SOFTWARE_EQ_AB): start flat, load nothing, and round the preamp
 * down to a multiple of @p preamp_step_db, so the amplifier's volume, which
 * moves in such steps, can give it back exactly. The amplifier keeps its
 * own trims and mutes, so audio_eq_set_trim_db(), audio_eq_set_mute() and
 * audio_eq_commit(), which save, are not for such a board.
 */
esp_err_t audio_eq_init_blank(float preamp_step_db);

/**
 * Follow a new I2S clock, so the corners stay put across 44.1 and 48 kHz
 * sources. Called by audio_output whenever it retunes, from whichever audio
 * task did so: both of those rates are designed ahead of time, whenever the
 * tuning changes, so switching between them costs only a copy. Any other
 * rate is designed here.
 */
void audio_eq_set_rate(uint32_t sample_rate_hz);
uint32_t audio_eq_get_rate(void);

/**
 * Filter an interleaved stereo buffer in place. Called only from whichever
 * task is currently writing to I2S. With every slot bypassed and the trims
 * at 0 dB the buffer is left untouched.
 */
void audio_eq_process(int16_t *buf, size_t frames);

/**
 * The same filtering, for output wider than 16 bits: @p in is filtered into
 * @p out on the int16 scale (32768.0 is full scale), neither rounded nor
 * clipped, so a gain applied afterwards loses nothing. Returns false, with
 * @p out untouched, wherever audio_eq_process() would leave its buffer as it
 * was: @p in is then the output as it stands.
 */
bool audio_eq_process_float(const int16_t *in, float *out, size_t frames);

/**
 * Start the next audio from rest. A source that stops mid-stream leaves its
 * filter tails in the sections, and the next source to write would play
 * them. Safe from any task: the writer clears its state before its next
 * block.
 */
void audio_eq_reset(void);

bool audio_eq_get_chain(int ch, tas58xx_bq_t out[AUDIO_EQ_SLOTS]);
/** Rejects the whole chain if any section is invalid or unstable. */
esp_err_t audio_eq_set_chain(int ch, const tas58xx_bq_t in[AUDIO_EQ_SLOTS]);

/** Ganged: the left chain drives both outputs. */
void audio_eq_set_ganged(bool ganged);
bool audio_eq_get_ganged(void);

/** Persist the current chains and ganging. */
esp_err_t audio_eq_commit(void);
/** Drop uncommitted chain edits. */
esp_err_t audio_eq_revert(void);

/** Per-output level trim in dB, clamped to the AUDIO_EQ_TRIM range. */
void audio_eq_set_trim_db(int ch, float db);
float audio_eq_get_trim_db(int ch);
void audio_eq_set_mute(int ch, bool mute);
bool audio_eq_get_mute(int ch);

/**
 * Attenuation (dB, <= 0) applied ahead of the filters so the loudest point of
 * the current curves, trims included, cannot clip. Reported by /api/bq.
 */
float audio_eq_get_preamp_db(void);
