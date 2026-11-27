// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * DAC dispatch layer
 *
 * Routes abstract DAC API calls to the registered DAC driver.
 * When no driver is registered, all functions are no-ops.
 */

#include <stdbool.h>
#include <stddef.h>
#include "dac.h"

#include "sdkconfig.h"

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

void dac_on_i2s_stopping(void) {
  if (s_ops && s_ops->on_i2s_stopping) {
    s_ops->on_i2s_stopping();
  }
}

void dac_on_i2s_started(uint32_t sample_rate_hz) {
  if (s_ops && s_ops->on_i2s_started) {
    s_ops->on_i2s_started(sample_rate_hz);
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

/* ---- Output delay ----
 *
 * The plain I2S DAC preset, for a board whose DAC has no driver (or a driver
 * with no figure).  Every value is a datasheet group delay, in 1/16 input
 * sample periods; the sources are in components/dac/Kconfig. */
static uint32_t preset_delay_q4(uint32_t sample_rate_hz) {
#if defined(CONFIG_DAC_PLAIN_DELAY_PCM510X_NORMAL)
  /* TI SLAS859C §9.3.4.1 Tables 4-6 (normal x8/x4/x2): "Filter group delay
   * 22 tS".  §6 and §8.5 of the same revision say 20 tS. */
  (void)sample_rate_hz;
  return 22U * 16U;
#elif defined(CONFIG_DAC_PLAIN_DELAY_PCM510X_LOW_LATENCY)
  /* TI SLAS859C Tables 7-9 and §8.5: 3.5 tS. */
  (void)sample_rate_hz;
  return 56U;
#elif defined(CONFIG_DAC_PLAIN_DELAY_CS434X)
  /* Cirrus DS613F2 p.6, combined interpolation and on-chip analog filter:
   * 10/Fs single speed, 5/Fs double, 2.5/Fs quad.  The part picks the mode
   * from the MCLK/LRCK ratio, which the ESP32 sets so that it follows the
   * rate: up to 50 kHz single, up to 100 kHz double. */
  if (sample_rate_hz <= 50000U) {
    return 160U;
  }
  return sample_rate_hz <= 100000U ? 80U : 40U;
#elif defined(CONFIG_DAC_PLAIN_DELAY_CUSTOM)
  (void)sample_rate_hz;
  return (uint32_t)CONFIG_DAC_PLAIN_DELAY_CUSTOM_Q4;
#else
  (void)sample_rate_hz;
  return DAC_OUTPUT_DELAY_UNKNOWN;
#endif
}

const char *dac_output_delay_preset_name(void) {
#if defined(CONFIG_DAC_PLAIN_DELAY_PCM510X_NORMAL)
  return "PCM510xA normal filter";
#elif defined(CONFIG_DAC_PLAIN_DELAY_PCM510X_LOW_LATENCY)
  return "PCM510xA low-latency filter";
#elif defined(CONFIG_DAC_PLAIN_DELAY_CS434X)
  return "CS4344/5/8";
#elif defined(CONFIG_DAC_PLAIN_DELAY_CUSTOM)
  return "custom";
#else
  return "unknown";
#endif
}

uint32_t dac_get_output_delay_q4(uint32_t sample_rate_hz,
                                 dac_delay_source_t *source) {
  dac_delay_source_t from = DAC_DELAY_UNKNOWN;
  uint32_t q4 = DAC_OUTPUT_DELAY_UNKNOWN;
  if (s_ops && s_ops->output_delay_q4) {
    q4 = s_ops->output_delay_q4(sample_rate_hz);
    from = DAC_DELAY_FROM_DRIVER;
  }
  if (q4 == DAC_OUTPUT_DELAY_UNKNOWN) {
    q4 = preset_delay_q4(sample_rate_hz);
    from = DAC_DELAY_FROM_PRESET;
  }
  if (q4 == DAC_OUTPUT_DELAY_UNKNOWN) {
    q4 = 0;
    from = DAC_DELAY_UNKNOWN;
  }
  if (source) {
    *source = from;
  }
  return q4;
}

const char *dac_delay_source_name(dac_delay_source_t source) {
  switch (source) {
  case DAC_DELAY_FROM_DRIVER:
    return "driver";
  case DAC_DELAY_FROM_PRESET:
    return "preset";
  default:
    return "unknown";
  }
}
