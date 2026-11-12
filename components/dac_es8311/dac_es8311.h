// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "dac.h"

/**
 * ES8311 DAC driver ops — register with dac_register() before calling
 * dac_init().
 */
extern const dac_ops_t dac_es8311_ops;
