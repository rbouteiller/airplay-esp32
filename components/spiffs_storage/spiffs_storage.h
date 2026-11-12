// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "esp_err.h"

/**
 * Mount the SPIFFS "storage" partition at /spiffs.
 * Safe to call multiple times — returns ESP_OK if already mounted.
 */
esp_err_t spiffs_storage_init(void);
