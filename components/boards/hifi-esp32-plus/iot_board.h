// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "board_common.h"
#include "sdkconfig.h"

// Shared by the four Sonocotta PCM5122 boards: the line-level HiFi-ESP32-Plus
// and HiFi-ESP32-S3-Plus, and the Amped-ESP32-Plus / -S3-Plus, which put a
// TPA3118 behind the same DAC. Only the pins and the label differ.
#if defined(CONFIG_BOARD_AMPED_ESP32_PLUS)
#define BOARD_NAME "Amped-ESP32-Plus"
#define BOARD_DESCRIPTION \
  "ESP32 with PCM5122 I2C DAC, TPA3118 amp, SPI Ethernet"
#elif defined(CONFIG_BOARD_AMPED_ESP32_S3_PLUS)
#define BOARD_NAME "Amped-ESP32-S3-Plus"
#define BOARD_DESCRIPTION \
  "ESP32-S3 with PCM5122 I2C DAC, TPA3118 amp, SPI Ethernet"
#elif defined(CONFIG_BOARD_HIFI_ESP32_S3_PLUS)
#define BOARD_NAME "HiFi-ESP32-S3-Plus"
#define BOARD_DESCRIPTION \
  "ESP32-S3 with PCM5122 I2C-controlled DAC, SPI Ethernet"
#else
#define BOARD_NAME        "HiFi-ESP32-Plus"
#define BOARD_DESCRIPTION "ESP32 with PCM5122 I2C-controlled DAC, SPI Ethernet"
#endif

// I2S configuration (PCM5122 runs from BCK, no MCLK wired)
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

// DAC control I2C (PCM5122 @0x4D)
#define BOARD_I2C_PORT     0
#define BOARD_I2C_SDA_GPIO CONFIG_DAC_I2C_SDA
#define BOARD_I2C_SCL_GPIO CONFIG_DAC_I2C_SCL

// DAC/AMP EN pin (XSMT on the PCM5122): high only while playing. Driven by
// the PCM51xx driver from playback events.
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
