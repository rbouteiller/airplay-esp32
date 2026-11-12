// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file board.c
 * @brief Board implementation for HiFi-ESP32 / HiFi-Esparagus
 *
 * PCM5100 is a plain I2S DAC with no I2C control and no mute pin, so the
 * only board-specific job here is bringing up the SPI bus that Ethernet
 * and the display share when both are present (e.g. HiFi-ESP32).
 *
 * The bus is only initialized here when Ethernet is enabled: the shared
 * pins (CONFIG_SPI_CLK_GPIO / MOSI / MISO) live in Kconfig's
 * "SPI and Ethernet Configuration" menu, which is entirely gated on
 * CONFIG_ETH_W5500_ENABLED. On a display-only variant (e.g.
 * HiFi-Esparagus-S3), iot_board_get_handle() returns NULL for
 * BOARD_SPI_DISP_ID and the display component falls back to
 * self-initializing its own bus from CONFIG_DISPLAY_SPI_CLK / MOSI
 * instead.
 */

#include "iot_board.h"

#include "esp_check.h"
#include "esp_log.h"

#ifdef CONFIG_ETH_W5500_ENABLED
#include "driver/spi_master.h"
#endif

static const char TAG[] = "HiFiEsp32";

static bool s_board_initialized = false;

#ifdef CONFIG_ETH_W5500_ENABLED
static bool s_spi_bus_initialized = false;
#endif

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
  case BOARD_SPI_ETH_ID:
  case BOARD_SPI_DISP_ID:
    // Display and Ethernet share the same SPI bus on this board
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
  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  // Initialize SPI bus (shared between W5500 and display)
  spi_bus_config_t spi_bus_cfg = {
      .mosi_io_num = BOARD_SPI_MOSI_GPIO,
      .miso_io_num = BOARD_SPI_MISO_GPIO,
      .sclk_io_num = BOARD_SPI_CLK_GPIO,
      .quadwp_io_num = -1,
      .quadhd_io_num = -1,
  };
  esp_err_t err =
      spi_bus_initialize(BOARD_SPI_HOST, &spi_bus_cfg, SPI_DMA_CH_AUTO);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(err));
    return err;
  }
  s_spi_bus_initialized = true;
  ESP_LOGI(TAG, "SPI bus initialized: mosi=%d, miso=%d, clk=%d",
           BOARD_SPI_MOSI_GPIO, BOARD_SPI_MISO_GPIO, BOARD_SPI_CLK_GPIO);
#endif

  s_board_initialized = true;
  ESP_LOGI(TAG, "HiFi-ESP32 initialized");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  if (!s_board_initialized) {
    return ESP_OK;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  if (s_spi_bus_initialized) {
    spi_bus_free(BOARD_SPI_HOST);
    s_spi_bus_initialized = false;
  }
#endif

  s_board_initialized = false;
  return ESP_OK;
}
