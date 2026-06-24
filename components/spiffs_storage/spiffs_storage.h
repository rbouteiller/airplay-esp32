#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * Mount the SPIFFS "storage" partition at /spiffs.
 * Safe to call multiple times — returns ESP_OK if already mounted.
 */
esp_err_t spiffs_storage_init(void);

/**
 * Unmount the SPIFFS "storage" partition.
 * Safe to call multiple times.
 */
void spiffs_storage_deinit(void);

/**
 * Check whether the SPIFFS "storage" partition is currently mounted.
 */
bool spiffs_storage_is_mounted(void);
