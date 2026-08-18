#include "settings.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <string.h>

static const char *NS = "airplay";
static float s_volume_db = 0.0f;

esp_err_t settings_init(void) {
  nvs_handle_t h;
  esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
  if (e == ESP_OK) nvs_close(h);
  return e;
}

static esp_err_t get_str(const char *key, char *out, size_t len) {
  if (!out || !len) return ESP_ERR_INVALID_ARG;
  nvs_handle_t h;
  esp_err_t e = nvs_open(NS, NVS_READONLY, &h);
  if (e != ESP_OK) return e;
  size_t need = len;
  e = nvs_get_str(h, key, out, &need);
  nvs_close(h);
  return e;
}

static esp_err_t set_str(const char *key, const char *value) {
  nvs_handle_t h;
  esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
  if (e != ESP_OK) return e;
  e = nvs_set_str(h, key, value ? value : "");
  if (e == ESP_OK) e = nvs_commit(h);
  nvs_close(h);
  return e;
}

esp_err_t settings_get_wifi_ssid(char *ssid, size_t len) { return get_str("wifi_ssid", ssid, len); }
esp_err_t settings_get_wifi_password(char *password, size_t len) { return get_str("wifi_pass", password, len); }
esp_err_t settings_set_wifi_credentials(const char *ssid, const char *password) {
  esp_err_t e = set_str("wifi_ssid", ssid);
  if (e != ESP_OK) return e;
  return set_str("wifi_pass", password);
}
bool settings_has_wifi_credentials(void) {
  char ssid[33] = {0};
  return settings_get_wifi_ssid(ssid, sizeof(ssid)) == ESP_OK && ssid[0] != '\0';
}
esp_err_t settings_get_device_name(char *name, size_t len) {
  if (!name || !len) return ESP_ERR_INVALID_ARG;
  esp_err_t e = get_str("device_name", name, len);
  if (e != ESP_OK || name[0] == '\0') {
    strlcpy(name, SETTINGS_DEFAULT_DEVICE_NAME, len);
    return ESP_OK;
  }
  return ESP_OK;
}
esp_err_t settings_set_device_name(const char *name) { return set_str("device_name", name); }
esp_err_t settings_get_volume(float *volume_db) {
  if (!volume_db) return ESP_ERR_INVALID_ARG;
  nvs_handle_t h;
  esp_err_t e = nvs_open(NS, NVS_READONLY, &h);
  if (e != ESP_OK) { *volume_db = s_volume_db; return e; }
  int32_t mv = 0;
  e = nvs_get_i32(h, "volume_mdb", &mv);
  nvs_close(h);
  if (e == ESP_OK) s_volume_db = (float)mv / 1000.0f;
  *volume_db = s_volume_db;
  return e;
}
esp_err_t settings_set_volume(float volume_db) { s_volume_db = volume_db; return ESP_OK; }
esp_err_t settings_persist_volume(void) {
  nvs_handle_t h;
  esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
  if (e != ESP_OK) return e;
  e = nvs_set_i32(h, "volume_mdb", (int32_t)(s_volume_db * 1000.0f));
  if (e == ESP_OK) e = nvs_commit(h);
  nvs_close(h);
  return e;
}
