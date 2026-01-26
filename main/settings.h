#pragma once

#include "esp_err.h"

/**
 * Persistent settings storage (NVS)
 */

/**
 * Initialize settings module (call once at startup)
 */
esp_err_t settings_init(void);

/**
 * Get saved volume in dB
 * @param volume_db Output: volume in dB (0 = max, -30 = mute)
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND if no saved value
 */
esp_err_t settings_get_volume(float *volume_db);

/**
 * Save volume to persistent storage
 * @param volume_db Volume in dB (0 = max, -30 = mute)
 */
esp_err_t settings_set_volume(float volume_db);
