#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"

/**
 * Power control for the amplifier
 */
typedef enum {
  TAS57XX_AMP_ON = 0,
  TAS57XX_AMP_STANDBY,
  TAS57XX_AMP_OFF,
} tas57xx_power_mode_e;

/**
 * Initialize the TI TAS57xx DAC/Amp chip
 * Aassumes dedicated I2C bus
 */
esp_err_t tas57xx_init(int i2c_port, int sda_io, int scl_io);
esp_err_t tas57xx_deinit(int i2c_port, int sda_io, int scl_io);

/**
 * Enable / disable the main amp out
 */
void tas57xx_enable_speaker(bool enable);

/**
 * Enable / disable the line out
 */
void tas57xx_enable_line_out(bool enable);

/**
 * Set the power mode for the amplifier
 */
void tas57xx_set_power_mode(tas57xx_power_mode_e mode);
