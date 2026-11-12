// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "board_common.h"
#include "sdkconfig.h"

#define BOARD_NAME        "Loud-ESP32"
#define BOARD_DESCRIPTION "ESP32 with MAX98357A I2S amp, SPI Ethernet"

// I2S configuration
#define BOARD_I2S_BCK_GPIO CONFIG_I2S_BCK_IO
#define BOARD_I2S_WS_GPIO  CONFIG_I2S_WS_IO
#define BOARD_I2S_DO_GPIO  CONFIG_I2S_DO_IO
#define BOARD_I2S_GND_GPIO CONFIG_I2S_GND_IO
#define BOARD_I2S_VCC_GPIO CONFIG_I2S_VCC_IO

// SPDIF configuration
#define BOARD_SPDIF_BCK_GPIO CONFIG_SPDIF_BCK_IO
#define BOARD_SPDIF_WS_GPIO  CONFIG_SPDIF_WS_IO
#define BOARD_SPDIF_DO_GPIO  CONFIG_SPDIF_DO_IO

// LED configuration
#define BOARD_LED_STATUS_GPIO CONFIG_LED_STATUS_GPIO
#define BOARD_LED_ERROR_GPIO  CONFIG_LED_ERROR_GPIO
#define BOARD_LED_RGB_GPIO    CONFIG_LED_RGB_GPIO

// MAX98357A SD_MODE enable pin (active-high; toggled dynamically from RTSP
// playback events by board.c, unlike the boot-once DAC_PDN_GPIO)
#define BOARD_DAC_ENABLE_GPIO CONFIG_DAC_ENABLE_GPIO

// Battery monitoring
#define BOARD_BAT_CHANNEL CONFIG_BAT_CHANNEL

#ifdef CONFIG_ETH_W5500_ENABLED
// SPI bus configuration (shared between W5500 and display)
#define BOARD_SPI_HOST      SPI2_HOST
#define BOARD_SPI_CLK_GPIO  CONFIG_SPI_CLK_GPIO
#define BOARD_SPI_MOSI_GPIO CONFIG_SPI_MOSI_GPIO
#define BOARD_SPI_MISO_GPIO CONFIG_SPI_MISO_GPIO

// W5500 Ethernet configuration
#define BOARD_ETH_CS_GPIO  CONFIG_ETH_W5500_CS_GPIO
#define BOARD_ETH_INT_GPIO CONFIG_ETH_W5500_INT_GPIO
#define BOARD_ETH_RST_GPIO CONFIG_ETH_W5500_RST_GPIO
#endif
