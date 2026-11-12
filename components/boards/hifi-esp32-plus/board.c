// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file board.c
 * @brief Board implementation for the Sonocotta PCM5122 boards
 *
 * Covers HiFi-ESP32-Plus (rev J1+), Amped-ESP32-Plus and
 * Amped-ESP32-S3-Plus. All three put a PCM5122 where the plain boards have a
 * PCM5100, and keep the W5500 + OLED on a shared SPI bus. The PCM5122 is
 * controlled over I2C (address 0x4D) and needs a handful of registers written
 * at boot before it plays without an MCLK line, so this board brings up the
 * DAC I2C bus and registers the PCM51xx driver. CONFIG_DAC_ENABLE_GPIO is the
 * board's enable line — XSMT on the HiFi, the TPA3118's UNMUTE on the Amped
 * boards — and is toggled from playback events like the other Sonocotta
 * boards do. Every pin comes from Kconfig, so the three differ only in their
 * defaults.
 */

#include "iot_board.h"

#include "dac.h"
#include "dac_pcm51xx.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "playback_events.h"
#include "settings.h"

#ifdef CONFIG_ETH_W5500_ENABLED
#include "driver/spi_master.h"
#endif

static const char TAG[] = "Pcm5122Board";

static bool s_board_initialized = false;
static i2c_master_bus_handle_t s_i2c_dac_bus_handle = NULL;

#ifdef CONFIG_ETH_W5500_ENABLED
static bool s_spi_bus_initialized = false;
#endif

static void on_playback_event(playback_source_t source, playback_event_t event,
                              const playback_event_data_t *data,
                              void *user_data);

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
  case BOARD_I2C_DAC_ID:
    return (board_res_handle_t)s_i2c_dac_bus_handle;
  case BOARD_SPI_ETH_ID:
  case BOARD_SPI_DISP_ID:
#ifdef CONFIG_ETH_W5500_ENABLED
    return s_spi_bus_initialized ? (board_res_handle_t)(intptr_t)BOARD_SPI_HOST
                                 : NULL;
#else
    return NULL;
#endif
  default:
    return NULL;
  }
}

esp_err_t iot_board_init(void) {
  esp_err_t err = ESP_OK;

  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

  // A previous failed cleanup may still own a bus. Release it before retrying.
  err = iot_board_deinit();
  if (err != ESP_OK) {
    return err;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  spi_bus_config_t spi_bus_cfg = {
      .mosi_io_num = BOARD_SPI_MOSI_GPIO,
      .miso_io_num = BOARD_SPI_MISO_GPIO,
      .sclk_io_num = BOARD_SPI_CLK_GPIO,
      .quadwp_io_num = -1,
      .quadhd_io_num = -1,
  };
  err = spi_bus_initialize(BOARD_SPI_HOST, &spi_bus_cfg, SPI_DMA_CH_AUTO);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(err));
    return err;
  }
  s_spi_bus_initialized = true;
  ESP_LOGI(TAG, "SPI bus initialized: mosi=%d, miso=%d, clk=%d",
           BOARD_SPI_MOSI_GPIO, BOARD_SPI_MISO_GPIO, BOARD_SPI_CLK_GPIO);
#endif

  // DAC control bus
  i2c_master_bus_config_t i2c_cfg = {
      .i2c_port = BOARD_I2C_PORT,
      .sda_io_num = BOARD_I2C_SDA_GPIO,
      .scl_io_num = BOARD_I2C_SCL_GPIO,
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .glitch_ignore_cnt = 7,
      .flags.enable_internal_pullup = true,
  };
  err = i2c_new_master_bus(&i2c_cfg, &s_i2c_dac_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC I2C bus: %s", esp_err_to_name(err));
    goto fail;
  }
  ESP_LOGI(TAG, "DAC I2C bus %d initialized: sda=%d, scl=%d", BOARD_I2C_PORT,
           BOARD_I2C_SDA_GPIO, BOARD_I2C_SCL_GPIO);

  dac_register(&dac_pcm51xx_ops);
  // Cache the saved volume before init so both channel writes are part of
  // the checked setup, before the DAC can ever be unmuted.
  float vol_db;
  if (ESP_OK == settings_get_volume(&vol_db)) {
    dac_set_volume(vol_db);
  }
  err = dac_init(s_i2c_dac_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize PCM5122: %s", esp_err_to_name(err));
    goto fail;
  }

  if (playback_events_register(on_playback_event, NULL) != 0) {
    ESP_LOGE(TAG, "Failed to register DAC playback listener");
    err = ESP_ERR_NO_MEM;
    goto fail;
  }

  s_board_initialized = true;
  ESP_LOGI(TAG, "%s initialized", BOARD_NAME);
  return ESP_OK;

fail:
  iot_board_deinit();
  return err;
}

esp_err_t iot_board_deinit(void) {
  // Also release resources acquired by an incomplete init.
  s_board_initialized = false;
  playback_events_unregister(on_playback_event);
  ESP_RETURN_ON_ERROR(dac_deinit(), TAG, "DAC cleanup failed");

  if (s_i2c_dac_bus_handle) {
    ESP_RETURN_ON_ERROR(i2c_del_master_bus(s_i2c_dac_bus_handle), TAG,
                        "I2C cleanup failed");
    s_i2c_dac_bus_handle = NULL;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  if (s_spi_bus_initialized) {
    ESP_RETURN_ON_ERROR(spi_bus_free(BOARD_SPI_HOST), TAG,
                        "SPI cleanup failed");
    s_spi_bus_initialized = false;
  }
#endif

  return ESP_OK;
}

static void on_playback_event(playback_source_t source, playback_event_t event,
                              const playback_event_data_t *data,
                              void *user_data) {
  (void)source;
  (void)data;
  (void)user_data;

  switch (event) {
  case PLAYBACK_EVENT_CONNECTED:
  case PLAYBACK_EVENT_PAUSED:
    dac_set_power_mode(DAC_POWER_STANDBY);
    break;
  case PLAYBACK_EVENT_PLAYING:
    dac_set_power_mode(DAC_POWER_ON);
    break;
  case PLAYBACK_EVENT_DISCONNECTED:
    dac_set_power_mode(DAC_POWER_OFF);
    break;
  case PLAYBACK_EVENT_METADATA:
    break;
  }
}
