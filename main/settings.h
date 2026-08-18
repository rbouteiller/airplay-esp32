#pragma once
#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>

#define SETTINGS_DEFAULT_DEVICE_NAME "ESP32 AirPlay"

esp_err_t settings_init(void);
esp_err_t settings_get_wifi_ssid(char *ssid, size_t len);
esp_err_t settings_get_wifi_password(char *password, size_t len);
esp_err_t settings_set_wifi_credentials(const char *ssid, const char *password);
bool settings_has_wifi_credentials(void);
esp_err_t settings_get_device_name(char *name, size_t len);
esp_err_t settings_set_device_name(const char *name);
esp_err_t settings_get_volume(float *volume_db);
esp_err_t settings_set_volume(float volume_db);
esp_err_t settings_persist_volume(void);
