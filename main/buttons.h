#pragma once

#include "esp_err.h"

/**
 * Hardware button input driver.
 *
 * Monitors GPIO pins for button presses (active-low with internal pull-up).
 * Applies software debouncing and dispatches actions via playback_control.
 * Long-press on volume buttons repeats every 200ms.
 *
 * Configure GPIOs in menuconfig under "Button Configuration".
 * Set a GPIO to -1 to disable that button.
 */

/**
 * Initialize button GPIOs and start the button polling task.
 * Must be called after playback_control_init().
 */
esp_err_t buttons_init(void);
