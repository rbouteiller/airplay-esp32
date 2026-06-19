/**
 * DAC dispatch layer
 *
 * Routes abstract DAC API calls to the registered DAC driver.
 * When no driver is registered, all functions are no-ops.
 */

#include <stdbool.h>
#include <stddef.h>
#include "dac.h"

static const dac_ops_t *s_ops = NULL;

void dac_register(const dac_ops_t *ops) {
  s_ops = ops;
}

esp_err_t dac_init(void *i2c_bus) {
  return (s_ops && s_ops->init) ? s_ops->init(i2c_bus) : ESP_OK;
}

esp_err_t dac_deinit(void) {
  return (s_ops && s_ops->deinit) ? s_ops->deinit() : ESP_OK;
}

void dac_set_volume(float volume_db) {
  if (s_ops && s_ops->set_volume) {
    s_ops->set_volume(volume_db);
  }
}

void dac_set_power_mode(dac_power_mode_t mode) {
  if (s_ops && s_ops->set_power_mode) {
    s_ops->set_power_mode(mode);
  }
}

void dac_on_i2s_started(void) {
  if (s_ops && s_ops->on_i2s_started) {
    s_ops->on_i2s_started();
  }
}

void dac_enable_speaker(bool enable) {
  if (s_ops && s_ops->enable_speaker) {
    s_ops->enable_speaker(enable);
  }
}

void dac_enable_line_out(bool enable) {
  if (s_ops && s_ops->enable_line_out) {
    s_ops->enable_line_out(enable);
  }
}
