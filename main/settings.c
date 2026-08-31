#include "settings.h"

#include "dac.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "settings";

#define NVS_NAMESPACE  "airplay"
#define NVS_KEY_VOLUME "volume_db"
#ifdef CONFIG_BT_A2DP_ENABLE
#define NVS_KEY_BT_VOLUME "bt_vol"
#endif
#define NVS_KEY_WIFI_SSID      "wifi_ssid"
#define NVS_KEY_WIFI_PASSWORD  "wifi_pass"
#define NVS_KEY_DEVICE_NAME    "device_name"
#define NVS_KEY_LED_BRIGHTNESS "led_bright"
#define NVS_KEY_CHANNEL_MODE   "chan_mode"
#define NVS_KEY_SUB_OFFSET     "sub_off"
#define NVS_KEY_AMP_GAIN       "amp_gain"
#define NVS_KEY_AMP_MUTE       "amp_mute"
#define NVS_KEY_AMP_MIX        "amp_mix"
#define NVS_KEY_SECOND_PBTL    "amp2_pbtl"
#define NVS_KEY_AIRPLAY_V1     "ap_v1"
#define NVS_KEY_CH_TRIM        "ch_trim"

#define MAX_WIFI_SSID_LEN     32
#define MAX_WIFI_PASSWORD_LEN 64
#define MAX_DEVICE_NAME_LEN   64

// Cached values  (defaults = 50 %)
static float g_volume_db = -15.0f;
static bool g_volume_loaded = false;

#ifdef CONFIG_BT_A2DP_ENABLE
static uint8_t g_bt_volume = 64; /* default: 50 % */
static bool g_bt_volume_loaded = false;
#endif

static bool g_airplay_v1;
static bool g_airplay_v1_configured;

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

    uint8_t airplay_v1;
    if (nvs_get_u8(nvs, NVS_KEY_AIRPLAY_V1, &airplay_v1) == ESP_OK) {
      g_airplay_v1 = airplay_v1 != 0;
      ESP_LOGI(TAG, "Loaded AirPlay mode: %s",
               g_airplay_v1 ? "v1 (classic RAOP)" : "v2");
    }

    nvs_close(nvs);
  }

  g_airplay_v1_configured = g_airplay_v1;

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

  dac_set_volume(volume_db);

  g_volume_db = volume_db;
  g_volume_loaded = true;
  return ESP_OK;
}

esp_err_t settings_persist_volume(void) {
  if (!g_volume_loaded) {
    return ESP_OK;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  int32_t vol_fixed = (int32_t)(g_volume_db * 100.0f);
  err = nvs_set_i32(nvs, NVS_KEY_VOLUME, vol_fixed);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Persisted volume: %.2f dB", g_volume_db);
  } else {
    ESP_LOGE(TAG, "Failed to persist volume: %s", esp_err_to_name(err));
  }

  return err;
}

#ifdef CONFIG_BT_A2DP_ENABLE
esp_err_t settings_get_bt_volume(uint8_t *volume) {
  if (!volume) {
    return ESP_ERR_INVALID_ARG;
  }
  if (!g_bt_volume_loaded) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
      return err;
    }
    err = nvs_get_u8(nvs, NVS_KEY_BT_VOLUME, &g_bt_volume);
    nvs_close(nvs);
    if (err != ESP_OK) {
      return err;
    }
    g_bt_volume_loaded = true;
  }
  *volume = g_bt_volume;
  return ESP_OK;
}

esp_err_t settings_set_bt_volume(uint8_t volume) {
  if (g_bt_volume_loaded && volume == g_bt_volume) {
    return ESP_OK;
  }

  g_bt_volume = volume;
  g_bt_volume_loaded = true;
  return ESP_OK;
}

esp_err_t settings_persist_bt_volume(void) {
  if (!g_bt_volume_loaded) {
    return ESP_OK;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_u8(nvs, NVS_KEY_BT_VOLUME, g_bt_volume);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Persisted BT volume: %d/127", g_bt_volume);
  } else {
    ESP_LOGE(TAG, "Failed to persist BT volume: %s", esp_err_to_name(err));
  }
  return err;
}
#endif

esp_err_t settings_get_wifi_ssid(char *ssid, size_t len) {
  if (!ssid || len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  size_t required_size = len;
  err = nvs_get_str(nvs, NVS_KEY_WIFI_SSID, ssid, &required_size);
  nvs_close(nvs);

  if (err == ESP_OK && required_size > len) {
    return ESP_ERR_NVS_INVALID_LENGTH;
  }

  return err;
}

esp_err_t settings_get_wifi_password(char *password, size_t len) {
  if (!password || len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  size_t required_size = len;
  err = nvs_get_str(nvs, NVS_KEY_WIFI_PASSWORD, password, &required_size);
  nvs_close(nvs);

  if (err == ESP_OK && required_size > len) {
    return ESP_ERR_NVS_INVALID_LENGTH;
  }

  return err;
}

esp_err_t settings_set_wifi_credentials(const char *ssid,
                                        const char *password) {
  if (!ssid || strlen(ssid) == 0 || strlen(ssid) > MAX_WIFI_SSID_LEN) {
    return ESP_ERR_INVALID_ARG;
  }
  if (!password || strlen(password) > MAX_WIFI_PASSWORD_LEN) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_str(nvs, NVS_KEY_WIFI_SSID, ssid);
  if (err == ESP_OK) {
    err = nvs_set_str(nvs, NVS_KEY_WIFI_PASSWORD, password);
  }
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved WiFi credentials: SSID=%s", ssid);
  } else {
    ESP_LOGE(TAG, "Failed to save WiFi credentials: %s", esp_err_to_name(err));
  }

  return err;
}

bool settings_has_wifi_credentials(void) {
  char ssid[MAX_WIFI_SSID_LEN + 1];
  return settings_get_wifi_ssid(ssid, sizeof(ssid)) == ESP_OK;
}

esp_err_t settings_get_device_name(char *name, size_t len) {
  if (!name || len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err == ESP_OK) {
    size_t required_size = len;
    err = nvs_get_str(nvs, NVS_KEY_DEVICE_NAME, name, &required_size);
    nvs_close(nvs);

    if (err == ESP_OK && required_size <= len) {
      return ESP_OK;
    }
  }

  // Return default if not found or error
  strncpy(name, SETTINGS_DEFAULT_DEVICE_NAME, len - 1);
  name[len - 1] = '\0';
  return ESP_OK;
}

esp_err_t settings_set_device_name(const char *name) {
  if (!name || strlen(name) == 0 || strlen(name) > MAX_DEVICE_NAME_LEN) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_str(nvs, NVS_KEY_DEVICE_NAME, name);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved device name: %s", name);
  } else {
    ESP_LOGE(TAG, "Failed to save device name: %s", esp_err_to_name(err));
  }

  return err;
}

void settings_device_name_to_hostname(const char *name, char *out,
                                      size_t out_len) {
  if (!out || out_len < 2) {
    return;
  }

  size_t j = 0;
  for (size_t i = 0; name && name[i] && j < out_len - 1; i++) {
    char c = name[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
      out[j++] = c;
    } else if (j > 0 && out[j - 1] != '-') {
      out[j++] = '-';
    }
  }
  while (j > 0 && out[j - 1] == '-') {
    j--;
  }

  if (j == 0) {
    // No ASCII survived (e.g. an all-Cyrillic name). Suffix the MAC so two
    // such devices do not both answer to the same hostname.
    uint8_t mac[6] = {0};
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(out, out_len, "esp32-airplay-%02x%02x%02x", mac[3], mac[4],
             mac[5]);
    return;
  }

  out[j] = '\0';
}

/* ================================================================== */
/*  LED Brightness                                                     */
/* ================================================================== */

esp_err_t settings_get_led_brightness(uint8_t *brightness) {
  if (!brightness) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  err = nvs_get_u8(nvs, NVS_KEY_LED_BRIGHTNESS, brightness);
  nvs_close(nvs);
  return err;
}

esp_err_t settings_set_led_brightness(uint8_t brightness) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_u8(nvs, NVS_KEY_LED_BRIGHTNESS, brightness);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved LED brightness: %d", brightness);
  } else {
    ESP_LOGE(TAG, "Failed to save LED brightness: %s", esp_err_to_name(err));
  }
  return err;
}

/* ================================================================== */
/*  Output channel mode                                                */
/* ================================================================== */

esp_err_t settings_get_channel_mode(uint8_t *mode) {
  if (!mode) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  err = nvs_get_u8(nvs, NVS_KEY_CHANNEL_MODE, mode);
  nvs_close(nvs);
  return err;
}

esp_err_t settings_set_channel_mode(uint8_t mode) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_u8(nvs, NVS_KEY_CHANNEL_MODE, mode);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved channel mode: %d", mode);
  } else {
    ESP_LOGE(TAG, "Failed to save channel mode: %s", esp_err_to_name(err));
  }
  return err;
}

/* ================================================================== */
/*  Sub level offset                                                   */
/* ================================================================== */

esp_err_t settings_get_sub_offset(float *offset_db) {
  if (!offset_db) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  int32_t fixed;
  err = nvs_get_i32(nvs, NVS_KEY_SUB_OFFSET, &fixed);
  nvs_close(nvs);
  if (err == ESP_OK) {
    *offset_db = (float)fixed / 100.0f;
  }
  return err;
}

esp_err_t settings_set_sub_offset(float offset_db) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_i32(nvs, NVS_KEY_SUB_OFFSET, (int32_t)(offset_db * 100.0f));
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved sub offset: %.1f dB", offset_db);
  } else {
    ESP_LOGE(TAG, "Failed to save sub offset: %s", esp_err_to_name(err));
  }
  return err;
}

/* ================================================================== */
/*  Level trim                                                         */
/* ================================================================== */

esp_err_t settings_get_amp_gain(float gain_db[SETTINGS_AMP_OUTPUTS]) {
  if (!gain_db) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  size_t len = sizeof(float) * SETTINGS_AMP_OUTPUTS;
  err = nvs_get_blob(nvs, NVS_KEY_AMP_GAIN, gain_db, &len);
  nvs_close(nvs);
  if (err == ESP_OK && len != sizeof(float) * SETTINGS_AMP_OUTPUTS) {
    return ESP_ERR_INVALID_SIZE;
  }
  return err;
}

esp_err_t settings_set_amp_gain(const float gain_db[SETTINGS_AMP_OUTPUTS]) {
  if (!gain_db) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_blob(nvs, NVS_KEY_AMP_GAIN, gain_db,
                     sizeof(float) * SETTINGS_AMP_OUTPUTS);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved amp levels: %+.1f %+.1f %+.1f %+.1f dB", gain_db[0],
             gain_db[1], gain_db[2], gain_db[3]);
  } else {
    ESP_LOGE(TAG, "Failed to save amp levels: %s", esp_err_to_name(err));
  }
  return err;
}

esp_err_t settings_get_channel_trim(float trim_db[SETTINGS_CHANNELS]) {
  if (!trim_db) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  size_t len = sizeof(float) * SETTINGS_CHANNELS;
  err = nvs_get_blob(nvs, NVS_KEY_CH_TRIM, trim_db, &len);
  nvs_close(nvs);
  if (err == ESP_OK && len != sizeof(float) * SETTINGS_CHANNELS) {
    return ESP_ERR_INVALID_SIZE;
  }
  return err;
}

esp_err_t settings_set_channel_trim(const float trim_db[SETTINGS_CHANNELS]) {
  if (!trim_db) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_blob(nvs, NVS_KEY_CH_TRIM, trim_db,
                     sizeof(float) * SETTINGS_CHANNELS);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved channel trim: A %+.1f dB, B %+.1f dB", trim_db[0],
             trim_db[1]);
  } else {
    ESP_LOGE(TAG, "Failed to save channel trim: %s", esp_err_to_name(err));
  }
  return err;
}

esp_err_t settings_get_amp_mute(uint8_t mute[SETTINGS_AMP_OUTPUTS]) {
  if (!mute) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  size_t len = SETTINGS_AMP_OUTPUTS;
  err = nvs_get_blob(nvs, NVS_KEY_AMP_MUTE, mute, &len);
  nvs_close(nvs);
  if (err == ESP_OK && len != SETTINGS_AMP_OUTPUTS) {
    return ESP_ERR_INVALID_SIZE;
  }
  return err;
}

esp_err_t settings_set_amp_mute(const uint8_t mute[SETTINGS_AMP_OUTPUTS]) {
  if (!mute) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_blob(nvs, NVS_KEY_AMP_MUTE, mute, SETTINGS_AMP_OUTPUTS);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save amp mutes: %s", esp_err_to_name(err));
  }
  return err;
}

esp_err_t settings_get_amp_mix(uint8_t mix[SETTINGS_AMPS]) {
  if (!mix) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  size_t len = SETTINGS_AMPS;
  err = nvs_get_blob(nvs, NVS_KEY_AMP_MIX, mix, &len);
  nvs_close(nvs);
  if (err == ESP_OK && len != SETTINGS_AMPS) {
    return ESP_ERR_INVALID_SIZE;
  }
  return err;
}

esp_err_t settings_set_amp_mix(const uint8_t mix[SETTINGS_AMPS]) {
  if (!mix) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_blob(nvs, NVS_KEY_AMP_MIX, mix, SETTINGS_AMPS);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved amp input routing: 1 %u, 2 %u", mix[0], mix[1]);
  } else {
    ESP_LOGE(TAG, "Failed to save amp input routing: %s", esp_err_to_name(err));
  }
  return err;
}

/* ================================================================== */
/*  Dual DAC (second amplifier) wiring                                 */
/* ================================================================== */

esp_err_t settings_get_second_pbtl(bool *pbtl) {
  if (!pbtl) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    return ESP_ERR_NOT_FOUND;
  }

  uint8_t stored;
  err = nvs_get_u8(nvs, NVS_KEY_SECOND_PBTL, &stored);
  nvs_close(nvs);
  if (err == ESP_OK) {
    *pbtl = stored != 0;
  }
  return err;
}

esp_err_t settings_set_second_pbtl(bool pbtl) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_u8(nvs, NVS_KEY_SECOND_PBTL, pbtl ? 1 : 0);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Saved second amplifier: %s", pbtl ? "PBTL mono" : "stereo");
  } else {
    ESP_LOGE(TAG, "Failed to save second amplifier wiring: %s",
             esp_err_to_name(err));
  }
  return err;
}

/* ================================================================== */
/*  AirPlay protocol mode                                             */
/* ================================================================== */

bool settings_airplay_v1(void) {
  return g_airplay_v1;
}

bool settings_airplay_v1_configured(void) {
  return g_airplay_v1_configured;
}

esp_err_t settings_set_airplay_v1(bool v1) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_u8(nvs, NVS_KEY_AIRPLAY_V1, v1 ? 1 : 0);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);

  if (err == ESP_OK) {
    // Deliberately not applied to g_airplay_v1: the running services were
    // built around the old value and only a restart can rebuild them.
    g_airplay_v1_configured = v1;
    ESP_LOGI(TAG, "Saved AirPlay mode: %s", v1 ? "v1 (classic RAOP)" : "v2");
  } else {
    ESP_LOGE(TAG, "Failed to save AirPlay mode: %s", esp_err_to_name(err));
  }
  return err;
}
