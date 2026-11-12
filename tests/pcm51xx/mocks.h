// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int esp_err_t;
#define ESP_OK                0
#define ESP_FAIL              -1
#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND     0x105
const char *esp_err_to_name(esp_err_t err);
void mock_log(const char *tag, const char *format, ...);
#define ESP_LOGE mock_log
#define ESP_LOGW mock_log
#define ESP_LOGI mock_log
#define ESP_RETURN_ON_ERROR(expr, tag, ...) \
  do {                                      \
    esp_err_t result = (expr);              \
    if (result != ESP_OK) {                 \
      mock_log(tag, __VA_ARGS__);           \
      return result;                        \
    }                                       \
  } while (0)

typedef void *i2c_master_bus_handle_t;
typedef void *i2c_master_dev_handle_t;
typedef struct {
  int i2c_port, sda_io_num, scl_io_num, clk_source, glitch_ignore_cnt;
  struct {
    bool enable_internal_pullup;
  } flags;
} i2c_master_bus_config_t;
#define I2C_CLK_SRC_DEFAULT 0
esp_err_t i2c_new_master_bus(const i2c_master_bus_config_t *config,
                             i2c_master_bus_handle_t *bus);
esp_err_t i2c_del_master_bus(i2c_master_bus_handle_t bus);
esp_err_t i2c_master_probe(i2c_master_bus_handle_t bus, uint16_t address,
                           int timeout);
esp_err_t board_i2c_add_device(i2c_master_bus_handle_t bus, uint8_t address,
                               uint32_t speed, i2c_master_dev_handle_t *dev);
esp_err_t board_i2c_remove_device(i2c_master_dev_handle_t dev);
esp_err_t board_i2c_write(i2c_master_dev_handle_t dev, uint8_t reg,
                          const uint8_t *data, size_t size);
esp_err_t board_i2c_read(i2c_master_dev_handle_t dev, uint8_t reg,
                         uint8_t *data, size_t size);

typedef struct {
  uint64_t pin_bit_mask;
  int mode, pull_up_en, pull_down_en, intr_type;
} gpio_config_t;
#define GPIO_MODE_OUTPUT      1
#define GPIO_PULLUP_DISABLE   0
#define GPIO_PULLDOWN_DISABLE 0
#define GPIO_INTR_DISABLE     0
esp_err_t gpio_config(const gpio_config_t *config);
esp_err_t gpio_set_level(int gpio, uint32_t level);

typedef struct {
  int mosi_io_num, miso_io_num, sclk_io_num, quadwp_io_num, quadhd_io_num;
} spi_bus_config_t;
#define SPI2_HOST       1
#define SPI_DMA_CH_AUTO 0
esp_err_t spi_bus_initialize(int host, const spi_bus_config_t *config, int dma);
esp_err_t spi_bus_free(int host);

typedef void *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateMutex(void);
int xSemaphoreTake(SemaphoreHandle_t mutex, uint32_t timeout);
int xSemaphoreGive(SemaphoreHandle_t mutex);
void vTaskDelay(uint32_t ticks);
#define portMAX_DELAY     UINT32_MAX
#define pdMS_TO_TICKS(ms) (ms)

esp_err_t settings_get_volume(float *volume);
#define CONFIG_PCM51XX_MAX_VOLUME 0
#define CONFIG_PCM51XX_I2C_ADDR   0x4D
#define CONFIG_DAC_ENABLE_GPIO    13
#define CONFIG_DAC_I2C_SDA        21
#define CONFIG_DAC_I2C_SCL        27
#define CONFIG_SPI_MOSI_GPIO      23
#define CONFIG_SPI_MISO_GPIO      19
#define CONFIG_SPI_CLK_GPIO       18
