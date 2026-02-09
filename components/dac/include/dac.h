#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * Abstract DAC API
 *
 * Dispatches to the selected DAC driver (CONFIG_DAC_TAS57XX, etc.)
 * or compiles as no-op stubs when no DAC is selected.
 */

typedef enum {
  DAC_POWER_ON = 0,
  DAC_POWER_STANDBY,
  DAC_POWER_OFF,
} dac_power_mode_t;

/**
 * Initialize the DAC using Kconfig pin settings
 */
esp_err_t dac_init(void);

/**
 * Deinitialize the DAC
 */
esp_err_t dac_deinit(void);

/**
 * Set the DAC output volume (AirPlay dB scale: -30 to 0)
 */
void dac_set_volume(float volume_db);

/**
 * Set the DAC/amplifier power mode
 */
void dac_set_power_mode(dac_power_mode_t mode);

/**
 * Enable or disable the speaker output
 */
void dac_enable_speaker(bool enable);

/**
 * Enable or disable the line output
 */
void dac_enable_line_out(bool enable);
