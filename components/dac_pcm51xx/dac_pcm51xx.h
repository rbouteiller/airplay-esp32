// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "dac.h"

/**
 * TI PCM512x (PCM5121/PCM5122/PCM5141/PCM5142) I2C-controlled stereo DAC.
 *
 * Boards register this with dac_register() and pass the DAC I2C bus handle
 * to dac_init(). The driver runs the chip from BCK (no MCLK required),
 * controls the hardware digital volume and the soft-mute / standby state.
 * An optional DAC enable pin (CONFIG_DAC_ENABLE_GPIO, wired to XSMT on the
 * Sonocotta Plus boards) is driven high only while playing.
 */
extern const dac_ops_t dac_pcm51xx_ops;
