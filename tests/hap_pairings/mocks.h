// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Host stand-ins for the ESP-IDF pieces the pairing store and the
 * /pair-add, /pair-remove, /pair-list handlers use: an in-memory NVS that
 * survives a simulated reboot, a no-op mutex and printf logging. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int esp_err_t;
#define ESP_OK                0
#define ESP_FAIL              (-1)
#define ESP_ERR_NO_MEM        0x101
#define ESP_ERR_INVALID_ARG   0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND     0x105
#define ESP_ERR_NVS_NOT_FOUND 0x1102

static inline const char *esp_err_to_name(esp_err_t err) {
  switch (err) {
  case ESP_OK:
    return "ESP_OK";
  case ESP_ERR_NO_MEM:
    return "ESP_ERR_NO_MEM";
  case ESP_ERR_INVALID_STATE:
    return "ESP_ERR_INVALID_STATE";
  case ESP_ERR_NOT_FOUND:
    return "ESP_ERR_NOT_FOUND";
  default:
    return "ESP_ERR";
  }
}

#define ESP_LOGE(tag, fmt, ...) printf("E %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGW(tag, fmt, ...) printf("W %s: " fmt "\n", tag, ##__VA_ARGS__)
#define ESP_LOGI(tag, fmt, ...) printf("I %s: " fmt "\n", tag, ##__VA_ARGS__)

#define MALLOC_CAP_SPIRAM 0
static inline void *heap_caps_calloc(size_t n, size_t size, int caps) {
  (void)caps;
  return calloc(n, size);
}

// A clock the tests move by hand.
extern int64_t mock_now_us;
static inline int64_t esp_timer_get_time(void) {
  return mock_now_us;
}

typedef int *SemaphoreHandle_t;
#define portMAX_DELAY 0
extern int mock_mutex_token, mock_locked;
static inline SemaphoreHandle_t xSemaphoreCreateMutex(void) {
  return &mock_mutex_token;
}
static inline void vSemaphoreDelete(SemaphoreHandle_t s) {
  (void)s;
}
int xSemaphoreTake(SemaphoreHandle_t s, int ticks);
int xSemaphoreGive(SemaphoreHandle_t s);

typedef int nvs_handle_t;
typedef enum { NVS_READONLY, NVS_READWRITE } nvs_open_mode_t;
esp_err_t nvs_open(const char *ns, nvs_open_mode_t mode, nvs_handle_t *h);
esp_err_t nvs_get_blob(nvs_handle_t h, const char *key, void *out, size_t *len);
esp_err_t nvs_set_blob(nvs_handle_t h, const char *key, const void *v,
                       size_t len);
esp_err_t nvs_erase_key(nvs_handle_t h, const char *key);
static inline esp_err_t nvs_commit(nvs_handle_t h) {
  (void)h;
  return ESP_OK;
}
static inline void nvs_close(nvs_handle_t h) {
  (void)h;
}
