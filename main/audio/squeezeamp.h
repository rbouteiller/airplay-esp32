#pragma once

#include "esp_err.h"

/**
 * SqueezeAMP board support (https://github.com/philippe44/SqueezeAMP)
 */

/**
 * Initialize SqueezeAMP hardware (DAC, GPIO).
 * Registers for RTSP events to control DAC power state.
 */
esp_err_t squeezeamp_init(void);

/**
 * Deinitialize SqueezeAMP hardware.
 */
esp_err_t squeezeamp_deinit(void);
