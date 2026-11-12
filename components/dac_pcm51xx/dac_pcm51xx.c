// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * TI PCM512x I2C-controlled stereo DAC driver.
 *
 * Datasheet: https://www.ti.com/lit/ds/symlink/pcm5122.pdf (§12.1, page 0
 * register map). Register values follow the configuration Sonocotta ships in
 * squeezelite-esp32 for the HiFi-ESP32-Plus / Amped-ESP32-Plus, which run the
 * PCM5122 without an MCLK line: the PLL takes BCK as its reference and the
 * MCLK-missing detector is masked.
 */

#include "dac_pcm51xx.h"
#include "board_utils.h"

#include <math.h>

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

// Page 0 registers
#define PCM51XX_REG_PAGE       0x00
#define PCM51XX_REG_RESET      0x01
#define PCM51XX_REG_POWER      0x02 // bit4 RQST standby, bit0 RQPD powerdown
#define PCM51XX_REG_MUTE       0x03 // bit4 RQML mute left, bit0 RQMR mute right
#define PCM51XX_REG_PLL_REF    0x0D // SREF[6:4]: 000 SCK, 001 BCK
#define PCM51XX_REG_IGNORE_ERR 0x25 // clock error detection masks
#define PCM51XX_REG_DAC_ROUTING 0x2A // data path: 0x11 = L->L, R->R
#define PCM51XX_REG_VOL_L       0x3D // digital volume left, 0x30 = 0 dB
#define PCM51XX_REG_VOL_R       0x3E // digital volume right
#define PCM51XX_REG_CLK_STATUS  0x5E // read-only clock detection flags
#define PCM51XX_REG_POWER_STATE 0x76 // read-only power state

// Page 1 registers
#define PCM51XX_PAGE_ANALOG     0x01
#define PCM51XX_REG_ANALOG_GAIN 0x02 // bit4 LAGN, bit0 RAGN: 0dB or -6dB

#define PCM51XX_RESET_ALL 0x11 // RSTM modules + RSTR registers, auto-clearing
#define PCM51XX_POWER_ACTIVE  0x00
#define PCM51XX_POWER_STANDBY 0x10
#define PCM51XX_MUTE_BOTH     0x11
#define PCM51XX_UNMUTE        0x00
#define PCM51XX_PLL_REF_BCK   0x10
#define PCM51XX_IGNORE_MCLK   0x08 // IDCH: ignore SCK halt detection
#define PCM51XX_ROUTE_STEREO  0x11

// Analog Gain Control (P1-R2): LAGN/RAGN select 0 dB or -6 dB analog gain.
// 0 dB (2V RMS) is the chip's power-on-reset default.
#define PCM51XX_ANALOG_GAIN_LAGN (1 << 4)
#define PCM51XX_ANALOG_GAIN_RAGN (1 << 0)
#if CONFIG_PCM51XX_ANALOG_GAIN_MINUS_6DB
#define PCM51XX_ANALOG_GAIN_VAL \
  (PCM51XX_ANALOG_GAIN_LAGN | PCM51XX_ANALOG_GAIN_RAGN)
#define PCM51XX_ANALOG_GAIN_IS_MINUS_6DB 1
#else
#define PCM51XX_ANALOG_GAIN_VAL          0x00
#define PCM51XX_ANALOG_GAIN_IS_MINUS_6DB 0
#endif

// P0-R61/R62: 0x30 is 0 dB, each step is 0.5 dB, 0xFE is -103 dB, 0xFF mutes.
#define PCM51XX_VOL_0DB_CODE 0x30
#define PCM51XX_VOL_MIN_DB   (-103.0f)

#define I2C_LINE_SPEED       100000
#define I2C_PROBE_TIMEOUT_MS 50

#ifndef CONFIG_DAC_ENABLE_GPIO
#define CONFIG_DAC_ENABLE_GPIO -1
#endif

static const char TAG[] = "PCM51xx DAC";

static i2c_master_bus_handle_t s_bus = NULL;
static i2c_master_dev_handle_t s_dev = NULL;
static SemaphoreHandle_t s_mutex = NULL;
static bool s_initialized = false;
static dac_power_mode_t s_power_state = DAC_POWER_OFF;
static float s_volume_db = -15.0f;

static esp_err_t wr(uint8_t reg, uint8_t val) {
  esp_err_t err = board_i2c_write(s_dev, reg, &val, 1);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "write reg 0x%02X=0x%02X failed: %s", reg, val,
             esp_err_to_name(err));
  }
  return err;
}

static esp_err_t set_enable_pin(bool on) {
#if CONFIG_DAC_ENABLE_GPIO >= 0
  return gpio_set_level(CONFIG_DAC_ENABLE_GPIO, on ? 1 : 0);
#else
  (void)on;
  return ESP_OK;
#endif
}

// Best effort after a bus error: XSMT can still silence the output even when
// the register interface is unavailable. A later PLAYING event retries the
// requested volume before unmuting.
static void mute_after_error_locked(void) {
  set_enable_pin(false);
  wr(PCM51XX_REG_MUTE, PCM51XX_MUTE_BOTH);
  s_power_state = DAC_POWER_OFF;
}

static esp_err_t apply_volume_locked(void) {
  // Same curve as the TAS57xx driver: AirPlay 0..-25 dB maps 2:1 onto
  // MAX..MAX-50 dB, -25..-30 dB rolls off steeply to the register floor, and
  // the bottom of the slider (AirPlay -30 dB, sent as -144 dB when muted)
  // writes the hard mute code so nothing leaks out at "volume 0".
  float max_db = (float)CONFIG_PCM51XX_MAX_VOLUME;
  float a = s_volume_db;
  int code;
  if (a <= -30.0f) {
    code = 0xFF; // digital mute
  } else {
    float db;
    if (a >= -25.0f) {
      db = max_db + a * 2.0f;
    } else {
      float normalized = (a + 30.0f) / 5.0f;
      float rolloff_top = max_db - 50.0f;
      db = PCM51XX_VOL_MIN_DB + normalized * (rolloff_top - PCM51XX_VOL_MIN_DB);
    }
    if (db > 0.0f) {
      db = 0.0f;
    }
    if (db < PCM51XX_VOL_MIN_DB) {
      db = PCM51XX_VOL_MIN_DB;
    }
    code = PCM51XX_VOL_0DB_CODE + (int)lroundf(-db * 2.0f);
    if (code > 0xFE) {
      code = 0xFE;
    }
  }
  ESP_LOGI(TAG, "Volume: AirPlay %.1f dB -> code 0x%02X%s", a, code,
           code == 0xFF ? " (mute)" : "");
  esp_err_t err = wr(PCM51XX_REG_VOL_L, (uint8_t)code);
  return err == ESP_OK ? wr(PCM51XX_REG_VOL_R, (uint8_t)code) : err;
}

static esp_err_t configure_locked(void) {
  // An ESP32 reset does not reset the DAC. Configure it muted, and never
  // accept a partial setup: its reset volume is 0 dB on both channels.
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_PAGE, 0x00), TAG, "Select page failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_MUTE, PCM51XX_MUTE_BOTH), TAG,
                      "Mute failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_POWER, PCM51XX_POWER_STANDBY), TAG,
                      "Standby failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_RESET, PCM51XX_RESET_ALL), TAG,
                      "Reset failed");
  vTaskDelay(pdMS_TO_TICKS(20));
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_PAGE, 0x00), TAG, "Select page failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_MUTE, PCM51XX_MUTE_BOTH), TAG,
                      "Mute failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_POWER, PCM51XX_POWER_STANDBY), TAG,
                      "Standby failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_PLL_REF, PCM51XX_PLL_REF_BCK), TAG,
                      "PLL setup failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_IGNORE_ERR, PCM51XX_IGNORE_MCLK), TAG,
                      "Clock setup failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_DAC_ROUTING, PCM51XX_ROUTE_STEREO), TAG,
                      "Routing failed");

  // Analog gain: 0 dB (2V RMS) or -6 dB (1V RMS), per Kconfig. Lives on
  // page 1; select page 0 again immediately after so every register access
  // below (and every runtime set_volume()/set_power_mode() call, neither of
  // which re-selects a page itself) keeps operating on page 0 as they
  // assume.
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_PAGE, PCM51XX_PAGE_ANALOG), TAG,
                      "Select page failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_ANALOG_GAIN, PCM51XX_ANALOG_GAIN_VAL), TAG,
                      "Analog gain failed");
  ESP_RETURN_ON_ERROR(wr(PCM51XX_REG_PAGE, 0x00), TAG, "Select page failed");

  ESP_RETURN_ON_ERROR(apply_volume_locked(), TAG, "Volume setup failed");
  return wr(PCM51XX_REG_POWER, PCM51XX_POWER_ACTIVE);
}

static esp_err_t pcm51xx_init(void *i2c_bus) {
  if (i2c_bus == NULL) {
    ESP_LOGE(TAG, "No I2C bus handle provided");
    return ESP_ERR_INVALID_ARG;
  }
  if (s_mutex == NULL) {
    s_mutex = xSemaphoreCreateMutex();
    if (s_mutex == NULL) {
      return ESP_ERR_NO_MEM;
    }
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (s_dev != NULL) {
    esp_err_t err =
        s_initialized && s_bus == i2c_bus ? ESP_OK : ESP_ERR_INVALID_STATE;
    xSemaphoreGive(s_mutex);
    return err;
  }
  s_bus = (i2c_master_bus_handle_t)i2c_bus;
  esp_err_t err;

#if CONFIG_DAC_ENABLE_GPIO >= 0
  gpio_config_t io_conf = {
      .pin_bit_mask = (1ULL << CONFIG_DAC_ENABLE_GPIO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  err = gpio_config(&io_conf);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to configure DAC enable GPIO %d",
             CONFIG_DAC_ENABLE_GPIO);
    goto fail;
  }
  err = set_enable_pin(false);
  if (err != ESP_OK) {
    goto fail;
  }
  ESP_LOGI(TAG, "DAC enable GPIO %d initialized (muted)",
           CONFIG_DAC_ENABLE_GPIO);
#endif

  uint8_t addr = CONFIG_PCM51XX_I2C_ADDR;
  err = i2c_master_probe(s_bus, addr, I2C_PROBE_TIMEOUT_MS);
  if (err != ESP_OK) {
    // Fall back to scanning the four strap-selectable addresses.
    const uint8_t candidates[] = {0x4C, 0x4D, 0x4E, 0x4F};
    err = ESP_ERR_NOT_FOUND;
    for (size_t i = 0; i < sizeof(candidates); i++) {
      if (i2c_master_probe(s_bus, candidates[i], I2C_PROBE_TIMEOUT_MS) ==
          ESP_OK) {
        addr = candidates[i];
        err = ESP_OK;
        break;
      }
    }
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "No PCM512x found on I2C (tried 0x%02X and 0x4C-0x4F)",
               CONFIG_PCM51XX_I2C_ADDR);
      goto fail;
    }
  }
  err = board_i2c_add_device(s_bus, addr, I2C_LINE_SPEED, &s_dev);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not add device @0x%02X: %s", addr,
             esp_err_to_name(err));
    goto fail;
  }
  ESP_LOGI(TAG, "PCM512x detected @0x%02X (analog gain %s)", addr,
           PCM51XX_ANALOG_GAIN_IS_MINUS_6DB ? "-6 dB" : "0 dB");

  err = configure_locked();
  if (err != ESP_OK) {
    goto fail;
  }
  s_initialized = true;
  s_power_state = DAC_POWER_STANDBY;

  uint8_t clk = 0, pwr = 0;
  if (board_i2c_read(s_dev, PCM51XX_REG_CLK_STATUS, &clk, 1) == ESP_OK &&
      board_i2c_read(s_dev, PCM51XX_REG_POWER_STATE, &pwr, 1) == ESP_OK) {
    ESP_LOGI(TAG, "clock status 0x%02X, power state 0x%02X", clk, pwr);
  }
  xSemaphoreGive(s_mutex);
  return ESP_OK;

fail:
  s_initialized = false;
  s_power_state = DAC_POWER_OFF;
  if (s_dev != NULL) {
    mute_after_error_locked();
    if (board_i2c_remove_device(s_dev) == ESP_OK) {
      s_dev = NULL;
    }
  }
  if (s_dev == NULL) {
    s_bus = NULL;
  }
  xSemaphoreGive(s_mutex);
  return err;
}

static esp_err_t pcm51xx_deinit(void) {
  if (s_mutex == NULL) {
    return ESP_OK;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  s_initialized = false;
  esp_err_t err = ESP_OK;
  if (s_dev) {
    mute_after_error_locked();
    wr(PCM51XX_REG_POWER, PCM51XX_POWER_STANDBY);
    err = board_i2c_remove_device(s_dev);
    if (err == ESP_OK) {
      s_dev = NULL;
      s_bus = NULL;
    }
  }
  s_power_state = DAC_POWER_OFF;
  xSemaphoreGive(s_mutex);
  return err;
}

static void pcm51xx_set_volume(float volume_airplay_db) {
  if (!isfinite(volume_airplay_db)) {
    volume_airplay_db = -144.0f;
  }
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (s_mutex == NULL) {
    s_volume_db = volume_airplay_db;
    return;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  s_volume_db = volume_airplay_db;
  if (s_initialized && apply_volume_locked() != ESP_OK) {
    mute_after_error_locked();
  }
  xSemaphoreGive(s_mutex);
}

static void pcm51xx_set_power_mode(dac_power_mode_t mode) {
  if (s_mutex == NULL) {
    return;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (!s_initialized) {
    xSemaphoreGive(s_mutex);
    return;
  }
  esp_err_t err;
  switch (mode) {
  case DAC_POWER_ON:
    err = wr(PCM51XX_REG_POWER, PCM51XX_POWER_ACTIVE);
    if (err != ESP_OK) {
      break;
    }
    // Let the PLL lock on BCK before unmuting.
    vTaskDelay(pdMS_TO_TICKS(20));
    err = apply_volume_locked();
    if (err == ESP_OK) {
      err = wr(PCM51XX_REG_MUTE, PCM51XX_UNMUTE);
    }
    if (err == ESP_OK) {
      err = set_enable_pin(true);
    }
    break;
  case DAC_POWER_STANDBY:
    err = set_enable_pin(false);
    if (err == ESP_OK) {
      err = wr(PCM51XX_REG_MUTE, PCM51XX_MUTE_BOTH);
    }
    break;
  case DAC_POWER_OFF:
  default:
    mode = DAC_POWER_OFF;
    err = set_enable_pin(false);
    if (err == ESP_OK) {
      err = wr(PCM51XX_REG_MUTE, PCM51XX_MUTE_BOTH);
    }
    if (err == ESP_OK) {
      err = wr(PCM51XX_REG_POWER, PCM51XX_POWER_STANDBY);
    }
    break;
  }
  if (err == ESP_OK) {
    s_power_state = mode;
  } else {
    mute_after_error_locked();
  }
  xSemaphoreGive(s_mutex);
}

static void pcm51xx_on_i2s_started(uint32_t sample_rate_hz) {
  // The PCM512x auto-detects the sample rate from BCK/LRCK and reconfigures
  // its PLL on its own, so nothing to program here. Bring it out of standby
  // in case the output started while the chip was parked.
  (void)sample_rate_hz;
  if (s_mutex == NULL) {
    return;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (s_initialized && s_power_state != DAC_POWER_OFF &&
      wr(PCM51XX_REG_POWER, PCM51XX_POWER_ACTIVE) != ESP_OK) {
    mute_after_error_locked();
  }
  xSemaphoreGive(s_mutex);
}

const dac_ops_t dac_pcm51xx_ops = {
    .init = pcm51xx_init,
    .deinit = pcm51xx_deinit,
    .set_volume = pcm51xx_set_volume,
    .set_power_mode = pcm51xx_set_power_mode,
    .on_i2s_started = pcm51xx_on_i2s_started,
};
