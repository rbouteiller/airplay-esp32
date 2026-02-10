#pragma once

#include "esp_err.h"
#include <stdbool.h>

typedef enum {
  DAC_POWER_ON = 0,
  DAC_POWER_STANDBY,
  DAC_POWER_OFF,
} dac_power_mode_t;

/**
 * DAC driver operations — each DAC driver provides one of these.
 * NULL function pointers are treated as no-ops.
 */
typedef struct {
  esp_err_t (*init)(void);
  esp_err_t (*deinit)(void);
  void (*set_volume)(float volume_db);
  void (*set_power_mode)(dac_power_mode_t mode);
  void (*enable_speaker)(bool enable);
  void (*enable_line_out)(bool enable);
} dac_ops_t;

/**
 * Register a DAC driver. Must be called before dac_init().
 */
void dac_register(const dac_ops_t *ops);

/**
 * Initialize the registered DAC driver
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
