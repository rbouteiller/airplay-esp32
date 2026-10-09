// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef int esp_err_t;
#define ESP_OK                0
#define ESP_FAIL              -1
#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND     0x105

void mock_log(const char *tag, const char *format, ...);
#define ESP_LOGE mock_log
#define ESP_LOGW mock_log
#define ESP_LOGI mock_log
#define ESP_LOGD mock_log

#define CONFIG_OUTPUT_SAMPLE_RATE_HZ 44100

#define MALLOC_CAP_SPIRAM               1
#define MALLOC_CAP_8BIT                 2
#define heap_caps_calloc(n, size, caps) calloc((n), (size))
#define heap_caps_free(p)               free(p)

typedef void *SemaphoreHandle_t;
#define portMAX_DELAY           0
#define xSemaphoreCreateMutex() ((SemaphoreHandle_t)1)
#define xSemaphoreTake(m, t)    ((void)(m), (void)(t))
#define xSemaphoreGive(m)       ((void)(m))

#define SETTINGS_AMP_OUTPUTS 4
esp_err_t settings_get_amp_gain(float gain[SETTINGS_AMP_OUTPUTS]);
esp_err_t settings_set_amp_gain(const float gain[SETTINGS_AMP_OUTPUTS]);
esp_err_t settings_get_amp_mute(uint8_t mute[SETTINGS_AMP_OUTPUTS]);
esp_err_t settings_set_amp_mute(const uint8_t mute[SETTINGS_AMP_OUTPUTS]);
