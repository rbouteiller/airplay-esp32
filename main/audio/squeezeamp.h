#pragma once

#include "esp_err.h"

/**
 * This file provides a single point to control the hardware of the squeezeAMP
 * board.
 */

/**
 * State
 */
typedef enum {
  SQUEEZEAMP_INIT = 0,
  SQUEEZEAMP_STANDBY,
  SQUEEZEAMP_PAUSED,
  SQUEEZEAMP_PLAYING,
  SQUEEZEAMP_ERROR,
} squeezeamp_state_e;

/**
 * Initialize the hardware
 */
esp_err_t squeezeamp_init();
esp_err_t squeezeamp_deinit();

squeezeamp_state_e squeezeamp_get_state();
void squeezeamp_set_state(squeezeamp_state_e state);
