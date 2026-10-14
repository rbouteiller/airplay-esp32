// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int esp_err_t;
#define ESP_OK                0
#define ESP_FAIL              -1
#define ESP_ERR_INVALID_STATE 0x103

void mock_log(const char *tag, const char *format, ...);
#define ESP_LOGE mock_log
#define ESP_LOGW mock_log
#define ESP_LOGI mock_log
#define ESP_LOGD mock_log

// Time is whatever the test says it is.
extern uint32_t mock_now_ms;
#define esp_timer_get_time() ((int64_t)mock_now_ms * 1000)

typedef int BaseType_t;
typedef uint32_t TickType_t;
typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);
#define pdPASS              1
#define portTICK_PERIOD_MS  1
#define pdMS_TO_TICKS(ms)   (ms)
#define xTaskGetTickCount() ((TickType_t)mock_now_ms)
#define vTaskDelay(ticks)   ((void)(ticks))
#define vTaskDelete(handle) ((void)(handle))

typedef struct {
  void *stack;
} spiram_task_mem_t;
BaseType_t task_create_spiram(TaskFunction_t fn, const char *name,
                              uint32_t depth, void *param, int prio,
                              TaskHandle_t *handle, spiram_task_mem_t *mem);
void task_free_spiram(spiram_task_mem_t *mem);
