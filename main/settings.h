#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * Persistent settings storage (NVS)
 */

// Default device name (used if none configured)
#define SETTINGS_DEFAULT_DEVICE_NAME "ESP32 AirPlay"

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

/**
 * Get saved WiFi SSID
 * @param ssid Output buffer for SSID
 * @param len Size of SSID buffer
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND if no saved value
 */
esp_err_t settings_get_wifi_ssid(char *ssid, size_t len);

/**
 * Get saved WiFi password
 * @param password Output buffer for password
 * @param len Size of password buffer
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND if no saved value
 */
esp_err_t settings_get_wifi_password(char *password, size_t len);

/**
 * Save WiFi credentials to persistent storage
 * @param ssid WiFi SSID
 * @param password WiFi password
 */
esp_err_t settings_set_wifi_credentials(const char *ssid, const char *password);

/**
 * Check if WiFi credentials are stored
 * @return true if credentials exist, false otherwise
 */
bool settings_has_wifi_credentials(void);

/**
 * Get device name (returns default if none saved)
 * @param name Output buffer for device name
 * @param len Size of name buffer
 * @return ESP_OK (always returns a valid name)
 */
esp_err_t settings_get_device_name(char *name, size_t len);

/**
 * Save device name to persistent storage
 * @param name Device name
 */
esp_err_t settings_set_device_name(const char *name);

// ---- EQ settings ----

/** Number of EQ bands stored in NVS */
#define SETTINGS_EQ_BANDS 15

/**
 * Get saved EQ gains.
 * @param gains_db Output array of SETTINGS_EQ_BANDS floats
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND if no saved EQ
 */
esp_err_t settings_get_eq_gains(float gains_db[SETTINGS_EQ_BANDS]);

/**
 * Save EQ gains to persistent storage.
 * @param gains_db Array of SETTINGS_EQ_BANDS floats (dB)
 */
esp_err_t settings_set_eq_gains(const float gains_db[SETTINGS_EQ_BANDS]);

/**
 * Clear saved EQ (revert to flat on next boot).
 */
esp_err_t settings_clear_eq(void);

/**
 * Check if EQ gains are saved.
 */
bool settings_has_eq(void);
