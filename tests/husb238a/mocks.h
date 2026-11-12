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
#define ESP_LOGD mock_log

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
#define portMAX_DELAY 0xFFFFFFFFu
SemaphoreHandle_t xSemaphoreCreateMutex(void);
void vSemaphoreDelete(SemaphoreHandle_t mutex);
int xSemaphoreTake(SemaphoreHandle_t mutex, uint32_t timeout);
int xSemaphoreGive(SemaphoreHandle_t mutex);
void vTaskDelay(uint32_t ticks);
#define pdMS_TO_TICKS(ms) (ms)

#define CONFIG_HUSB238A 1
#ifndef CONFIG_HUSB238A_MAX_VOLTS
#define CONFIG_HUSB238A_MAX_VOLTS 20
#endif
