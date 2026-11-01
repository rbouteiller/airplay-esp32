// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef int esp_err_t;
#define ESP_OK                0
#define ESP_FAIL              -1
#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_INVALID_SIZE  0x104
#define ESP_ERR_NOT_FOUND     0x105
#define ESP_ERR_NOT_SUPPORTED 0x106

const char *esp_err_to_name(esp_err_t err);
void mock_log(const char *tag, const char *format, ...);
#define ESP_LOGD mock_log
#define ESP_LOGI mock_log
#define ESP_LOGW mock_log
#define ESP_LOGE mock_log

typedef void *i2c_master_bus_handle_t;
typedef void *i2c_master_dev_handle_t;
esp_err_t i2c_master_probe(i2c_master_bus_handle_t bus, uint16_t address,
                           int timeout);
esp_err_t board_i2c_add_device(i2c_master_bus_handle_t bus, uint8_t address,
                               uint32_t speed, i2c_master_dev_handle_t *dev);
esp_err_t board_i2c_remove_device(i2c_master_dev_handle_t dev);
esp_err_t board_i2c_write(i2c_master_dev_handle_t dev, uint8_t reg,
                          const uint8_t *data, size_t size);
esp_err_t board_i2c_read(i2c_master_dev_handle_t dev, uint8_t reg,
                         uint8_t *data, size_t size);

typedef void *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateMutex(void);
int xSemaphoreTake(SemaphoreHandle_t mutex, uint32_t timeout);
int xSemaphoreGive(SemaphoreHandle_t mutex);
void vTaskDelay(uint32_t ticks);
#define portMAX_DELAY     UINT32_MAX
#define pdMS_TO_TICKS(ms) (ms)
#define BIT(n)            (1u << (n))

void *heap_caps_calloc(size_t count, size_t size, int caps);
#define MALLOC_CAP_SPIRAM                         0
#define MALLOC_CAP_8BIT                           0
#define CONFIG_TAS58XX_ANALOG_GAIN_UNKNOWN_SUPPLY (-10)
#define CONFIG_OUTPUT_SAMPLE_RATE_HZ              48000
#define CONFIG_SPKFAULT_GPIO                      1
#define CONFIG_I2S_BCK_IO                         1
#define CONFIG_I2S_WS_IO                          2
