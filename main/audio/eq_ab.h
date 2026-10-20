// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * Software EQ A/B switch for a TAS58xx amplifier (CONFIG_SOFTWARE_EQ_AB).
 *
 * Switched on, the amplifier's chains play on the software EQ (audio_eq.c)
 * ahead of I2S instead of in its DSP, whose sections are written flat. The
 * software EQ turns the signal down ahead of its filters by as much as they
 * boost; the amplifier's volume gives that back, so the two sides match in
 * level and only the filtering differs. The chains, their editing and the
 * digital gain carry on as before, and follow edits made while it is on.
 *
 * The choice is saved and comes back at boot.
 */

#include "esp_err.h"
#include <stdbool.h>

/**
 * Bring the software EQ up, on the side saved last. Call before the
 * amplifiers are probed and before the first audio, so it follows every
 * sample rate from the start.
 */
esp_err_t eq_ab_init(void);

/** Only a board with one amplifier: one stereo stream feeds it. */
bool eq_ab_available(void);

esp_err_t eq_ab_set(bool software);
bool eq_ab_get(void);
