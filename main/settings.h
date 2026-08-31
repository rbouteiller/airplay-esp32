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
 * Apply volume (updates cached value and DAC, does NOT write to NVS).
 * @param volume_db Volume in dB (0 = max, -30 = mute)
 */
esp_err_t settings_set_volume(float volume_db);

/**
 * Persist the current cached volume to NVS.
 * Call once at session disconnect rather than on every change.
 */
esp_err_t settings_persist_volume(void);

#ifdef CONFIG_BT_A2DP_ENABLE
/**
 * Get saved Bluetooth volume (AVRC 0-127 scale).
 * @param volume Output: 0 (mute) to 127 (max)
 * @return ESP_OK if found, ESP_ERR_NOT_FOUND if no saved value
 */
esp_err_t settings_get_bt_volume(uint8_t *volume);

/**
 * Update cached Bluetooth volume (does NOT write to NVS).
 * Caller is responsible for calling dac_set_volume().
 * @param volume 0 (mute) to 127 (max)
 */
esp_err_t settings_set_bt_volume(uint8_t volume);

/**
 * Persist the current cached BT volume to NVS.
 * Call once at session disconnect rather than on every change.
 */
esp_err_t settings_persist_bt_volume(void);
#endif

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

/**
 * Derive a DNS/DHCP-safe hostname from a device name.
 *
 * Host names are restricted to ASCII letters, digits and hyphens (RFC 1123),
 * so the UTF-8 device name cannot be used verbatim. Alphanumerics are kept,
 * every other byte collapses into a single hyphen, and the result is
 * truncated to fit @p len. Names with no usable ASCII (for example Cyrillic
 * or CJK) fall back to "esp32-airplay-<mac>", which stays unique per device.
 *
 * The device name itself must keep its original UTF-8 form wherever it is
 * shown to the user (mDNS service instance names, AirPlay metadata).
 *
 * @param name    Device name (UTF-8, may be NULL)
 * @param out     Output buffer for the hostname
 * @param out_len Size of @p out, must be at least 2
 */
void settings_device_name_to_hostname(const char *name, char *out,
                                      size_t out_len);

// ---- AirPlay protocol mode ----

/**
 * Whether the receiver presents itself as a classic AirPlay 1 (RAOP) device.
 *
 * This is the mode the running services were built around, fixed at
 * settings_init(). The RTSP and mDNS paths must use it rather than the
 * configured value, or a mid-session change would leave the TXT record and
 * the listening port disagreeing. Defaults to AirPlay 2.
 */
bool settings_airplay_v1(void);

/**
 * The AirPlay mode held in storage, which takes effect on the next boot.
 * Differs from settings_airplay_v1() only after a change that needs a restart.
 */
bool settings_airplay_v1_configured(void);

/**
 * Save the AirPlay protocol mode to persistent storage.
 *
 * Takes effect on restart: the advertised services and the RTSP port are both
 * fixed while the receiver is running.
 *
 * @param v1 true for classic AirPlay 1 (RAOP), false for AirPlay 2
 */
esp_err_t settings_set_airplay_v1(bool v1);

// ---- LED settings ----

/**
 * Get saved LED brightness (0–255). Returns compile-time default if not set.
 */
esp_err_t settings_get_led_brightness(uint8_t *brightness);

/**
 * Save LED brightness (0–255) to persistent storage.
 */
esp_err_t settings_set_led_brightness(uint8_t brightness);

// ---- Output channel mode ----

/**
 * Get saved output channel mode (audio_channel_mode_t value).
 * @param mode Output: channel mode enum value
 * @return ESP_OK if found, error otherwise
 */
esp_err_t settings_get_channel_mode(uint8_t *mode);

/**
 * Save output channel mode to persistent storage.
 * @param mode audio_channel_mode_t value
 */
esp_err_t settings_set_channel_mode(uint8_t mode);

// ---- Sub level offset ----

/**
 * Get saved sub level offset in dB (relative to master volume).
 * @param offset_db Output: offset in dB
 * @return ESP_OK if found, error otherwise
 */
esp_err_t settings_get_sub_offset(float *offset_db);

/**
 * Save sub level offset (dB) to persistent storage.
 */
esp_err_t settings_set_sub_offset(float offset_db);

// ---- Per-output level and mute (dual-DAC boards) ----

/** Amplifiers whose outputs can be levelled against each other. */
#define SETTINGS_AMPS 2
/** Outputs (A, B) per amplifier. */
#define SETTINGS_AMP_CHANNELS 2
/** Total addressable outputs, ordered amp-major: A0, B0, A1, B1. */
#define SETTINGS_AMP_OUTPUTS (SETTINGS_AMPS * SETTINGS_AMP_CHANNELS)

/**
 * Get the saved per-output levels in dB, relative to the master volume.
 */
esp_err_t settings_get_amp_gain(float gain_db[SETTINGS_AMP_OUTPUTS]);

/**
 * Save the per-output levels (dB) to persistent storage.
 */
esp_err_t settings_set_amp_gain(const float gain_db[SETTINGS_AMP_OUTPUTS]);

/**
 * Get the saved per-output mute flags.
 */
esp_err_t settings_get_amp_mute(uint8_t mute[SETTINGS_AMP_OUTPUTS]);

/**
 * Save the per-output mute flags to persistent storage.
 */
esp_err_t settings_set_amp_mute(const uint8_t mute[SETTINGS_AMP_OUTPUTS]);

/**
 * Get the saved per-amplifier input routing (values of tas58xx_mix_t).
 */
esp_err_t settings_get_amp_mix(uint8_t mix[SETTINGS_AMPS]);

/**
 * Save the per-amplifier input routing to persistent storage.
 */
esp_err_t settings_set_amp_mix(const uint8_t mix[SETTINGS_AMPS]);

// ---- Per-channel level trim (TAS57xx) ----

/** The two amplifier output channels, A and B. */
#define SETTINGS_CHANNELS 2

/**
 * Get the saved per-channel level trims in dB (relative to master volume).
 * @return ESP_OK if found, error otherwise
 */
esp_err_t settings_get_channel_trim(float trim_db[SETTINGS_CHANNELS]);

/**
 * Save the per-channel level trims (dB) to persistent storage.
 */
esp_err_t settings_set_channel_trim(const float trim_db[SETTINGS_CHANNELS]);

// ---- Dual DAC (second amplifier) wiring ----

/**
 * Get whether the second amplifier is bridged (PBTL) mono.
 * @param pbtl Output: true = bridged mono, false = stereo pair
 * @return ESP_OK if found, error otherwise
 */
esp_err_t settings_get_second_pbtl(bool *pbtl);

/**
 * Save whether the second amplifier is bridged (PBTL) mono.
 */
esp_err_t settings_set_second_pbtl(bool pbtl);
