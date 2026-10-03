#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * Playback-controlled amplifier GPIOs.
 *
 * Configure one output for the amplifier shutdown/enable pin (SD) and one
 * for its mute pin. SD is driven to its configured playing level first when
 * playback starts; MUTE is released last. Shutdown reverses that sequence.
 */

/**
 * Configure the selected GPIOs and subscribe to playback events.
 *
 * The module is inert when both GPIO numbers are -1.
 */
esp_err_t amp_gpio_control_init(void);

/**
 * Drive the configured outputs to the playing or idle sequence.
 */
void amp_gpio_control_set_playing(bool playing);
