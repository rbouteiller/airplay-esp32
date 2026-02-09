/**
 * DAC dispatch layer
 *
 * Routes abstract DAC API calls to the selected DAC driver based on Kconfig.
 * When no DAC is selected (CONFIG_DAC_NONE), all functions are no-ops.
 */

#include "dac.h"
#include "sdkconfig.h"

#if CONFIG_DAC_TAS57XX

#include "dac_tas57xx.h"

esp_err_t dac_init(void) {
  return tas57xx_init(CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
}

esp_err_t dac_deinit(void) {
  return tas57xx_deinit(CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
}

void dac_set_volume(float volume_db) {
  tas57xx_set_volume(volume_db);
}

void dac_set_power_mode(dac_power_mode_t mode) {
  tas57xx_power_mode_e tas_mode;
  switch (mode) {
  case DAC_POWER_ON:
    tas_mode = TAS57XX_AMP_ON;
    break;
  case DAC_POWER_STANDBY:
    tas_mode = TAS57XX_AMP_STANDBY;
    break;
  case DAC_POWER_OFF:
  default:
    tas_mode = TAS57XX_AMP_OFF;
    break;
  }
  tas57xx_set_power_mode(tas_mode);
}

void dac_enable_speaker(bool enable) {
  tas57xx_enable_speaker(enable);
}

void dac_enable_line_out(bool enable) {
  tas57xx_enable_line_out(enable);
}

#else /* CONFIG_DAC_NONE — no-op stubs */

esp_err_t dac_init(void) {
  return ESP_OK;
}
esp_err_t dac_deinit(void) {
  return ESP_OK;
}
void dac_set_volume(float volume_db) {
  (void)volume_db;
}
void dac_set_power_mode(dac_power_mode_t mode) {
  (void)mode;
}
void dac_enable_speaker(bool enable) {
  (void)enable;
}
void dac_enable_line_out(bool enable) {
  (void)enable;
}

#endif
