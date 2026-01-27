#include "settings.h"

#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "settings";

#define NVS_NAMESPACE  "airplay"
#define NVS_KEY_VOLUME "volume_db"

// Cached values
static float g_volume_db = 0.0f;
static bool g_volume_loaded = false;

esp_err_t settings_init(void) {
  // Load volume on init
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err == ESP_OK) {
    int32_t vol_fixed;
    err = nvs_get_i32(nvs, NVS_KEY_VOLUME, &vol_fixed);
    if (err == ESP_OK) {
      g_volume_db = (float)vol_fixed / 100.0f;
      g_volume_loaded = true;
      ESP_LOGI(TAG, "Loaded volume: %.2f dB", g_volume_db);
    }
    nvs_close(nvs);
  }

  return ESP_OK;
}

esp_err_t settings_get_volume(float *volume_db) {
  if (!volume_db) {
    return ESP_ERR_INVALID_ARG;
  }

  if (!g_volume_loaded) {
    return ESP_ERR_NOT_FOUND;
  }

  *volume_db = g_volume_db;
  return ESP_OK;
}

esp_err_t settings_set_volume(float volume_db) {
  // Skip if unchanged
  if (g_volume_loaded && volume_db == g_volume_db) {
    return ESP_OK;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  // Store as fixed-point (x100) for 2 decimal precision
  int32_t vol_fixed = (int32_t)(volume_db * 100.0f);
  err = nvs_set_i32(nvs, NVS_KEY_VOLUME, vol_fixed);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    g_volume_db = volume_db;
    g_volume_loaded = true;
    ESP_LOGI(TAG, "Saved volume: %.2f dB", volume_db);
  } else {
    ESP_LOGE(TAG, "Failed to save volume: %s", esp_err_to_name(err));
  }

  return err;
}
