#include "settings.h"

#include "dac.h"
#include "esp_log.h"
#include "nvs.h"
#include "soc/soc_caps.h"
#include "sdkconfig.h"
#include <string.h>

static const char *TAG = "settings";

#define NVS_NAMESPACE  "airplay"
#define NVS_KEY_VOLUME "volume_db"
#ifdef CONFIG_BT_A2DP_ENABLE
#define NVS_KEY_BT_VOLUME "bt_vol"
#endif
#define NVS_KEY_WIFI_SSID     "wifi_ssid"
#define NVS_KEY_WIFI_PASSWORD "wifi_pass"
#define NVS_KEY_DEVICE_NAME   "device_name"
#define NVS_KEY_EQ_GAINS      "eq_gains"
#define NVS_KEY_GPIO_CFG      "gpio_cfg"

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

static float g_eq_gains[SETTINGS_EQ_BANDS];
static bool g_eq_loaded = false;
static settings_gpio_config_t g_gpio_config;
static bool g_gpio_loaded = false;

void settings_get_default_gpio_config(settings_gpio_config_t *config) {
  if (!config) {
    return;
  }

  *config = (settings_gpio_config_t){
      .i2s_sck = CONFIG_I2S_SCK_IO,
      .i2s_bck = CONFIG_I2S_BCK_IO,
      .i2s_ws = CONFIG_I2S_WS_IO,
      .i2s_do = CONFIG_I2S_DO_IO,
      .i2s_gnd = CONFIG_I2S_GND_IO,
      .i2s_vcc = CONFIG_I2S_VCC_IO,
      .dac_i2c_sda = CONFIG_DAC_I2C_SDA,
      .dac_i2c_scl = CONFIG_DAC_I2C_SCL,
      .jack = CONFIG_JACK_GPIO,
      .spkfault = CONFIG_SPKFAULT_GPIO,
      .mute = CONFIG_MUTE_GPIO,
      .led_status = CONFIG_LED_STATUS_GPIO,
      .led_error = CONFIG_LED_ERROR_GPIO,
      .led_rgb = CONFIG_LED_RGB_GPIO,
      .btn_play_pause = CONFIG_BTN_PLAY_PAUSE_GPIO,
      .btn_volume_up = CONFIG_BTN_VOLUME_UP_GPIO,
      .btn_volume_down = CONFIG_BTN_VOLUME_DOWN_GPIO,
      .btn_next = CONFIG_BTN_NEXT_GPIO,
      .btn_prev = CONFIG_BTN_PREV_GPIO,
  };
}

bool settings_is_valid_gpio(int gpio) {
  return gpio == -1 || (gpio >= 0 && gpio < SOC_GPIO_PIN_COUNT);
}

static bool settings_gpio_config_valid(const settings_gpio_config_t *config) {
  return config && settings_is_valid_gpio(config->i2s_sck) &&
         settings_is_valid_gpio(config->i2s_bck) &&
         settings_is_valid_gpio(config->i2s_ws) &&
         settings_is_valid_gpio(config->i2s_do) &&
         settings_is_valid_gpio(config->i2s_gnd) &&
         settings_is_valid_gpio(config->i2s_vcc) &&
         settings_is_valid_gpio(config->dac_i2c_sda) &&
         settings_is_valid_gpio(config->dac_i2c_scl) &&
         settings_is_valid_gpio(config->jack) &&
         settings_is_valid_gpio(config->spkfault) &&
         settings_is_valid_gpio(config->mute) &&
         settings_is_valid_gpio(config->led_status) &&
         settings_is_valid_gpio(config->led_error) &&
         settings_is_valid_gpio(config->led_rgb) &&
         settings_is_valid_gpio(config->btn_play_pause) &&
         settings_is_valid_gpio(config->btn_volume_up) &&
         settings_is_valid_gpio(config->btn_volume_down) &&
         settings_is_valid_gpio(config->btn_next) &&
         settings_is_valid_gpio(config->btn_prev);
}

esp_err_t settings_init(void) {
  settings_get_default_gpio_config(&g_gpio_config);
  g_gpio_loaded = true;

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

    /* Load EQ gains blob */
    size_t eq_size = sizeof(g_eq_gains);
    err = nvs_get_blob(nvs, NVS_KEY_EQ_GAINS, g_eq_gains, &eq_size);
    if (err == ESP_OK && eq_size == sizeof(g_eq_gains)) {
      g_eq_loaded = true;
      ESP_LOGI(TAG, "Loaded EQ gains (%d bands)", SETTINGS_EQ_BANDS);
    }

    size_t gpio_size = sizeof(g_gpio_config);
    err = nvs_get_blob(nvs, NVS_KEY_GPIO_CFG, &g_gpio_config, &gpio_size);
    if (err == ESP_OK && gpio_size == sizeof(g_gpio_config) &&
        settings_gpio_config_valid(&g_gpio_config)) {
      ESP_LOGI(TAG, "Loaded GPIO overrides from NVS");
    } else {
      settings_get_default_gpio_config(&g_gpio_config);
      if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "GPIO override blob missing or invalid, using defaults");
      }
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

esp_err_t settings_clear_wifi_credentials(void) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_erase_key(nvs, NVS_KEY_WIFI_SSID);
  if (err == ESP_ERR_NVS_NOT_FOUND) {
    err = ESP_OK;
  }
  if (err == ESP_OK) {
    esp_err_t pass_err = nvs_erase_key(nvs, NVS_KEY_WIFI_PASSWORD);
    if (pass_err != ESP_OK && pass_err != ESP_ERR_NVS_NOT_FOUND) {
      err = pass_err;
    }
  }
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Cleared saved WiFi credentials");
  } else {
    ESP_LOGE(TAG, "Failed to clear WiFi credentials: %s",
             esp_err_to_name(err));
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

esp_err_t settings_get_gpio_config(settings_gpio_config_t *config) {
  if (!config) {
    return ESP_ERR_INVALID_ARG;
  }

  if (!g_gpio_loaded) {
    settings_get_default_gpio_config(&g_gpio_config);
    g_gpio_loaded = true;
  }

  *config = g_gpio_config;
  return ESP_OK;
}

esp_err_t settings_set_gpio_config(const settings_gpio_config_t *config) {
  if (!settings_gpio_config_valid(config)) {
    return ESP_ERR_INVALID_ARG;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_blob(nvs, NVS_KEY_GPIO_CFG, config, sizeof(*config));
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    g_gpio_config = *config;
    g_gpio_loaded = true;
    ESP_LOGI(TAG, "Saved GPIO overrides");
  } else {
    ESP_LOGE(TAG, "Failed to save GPIO overrides: %s", esp_err_to_name(err));
  }

  return err;
}

/* ================================================================== */
/*  EQ Gains                                                           */
/* ================================================================== */

esp_err_t settings_get_eq_gains(float gains_db[SETTINGS_EQ_BANDS]) {
  if (!gains_db) {
    return ESP_ERR_INVALID_ARG;
  }

  if (!g_eq_loaded) {
    return ESP_ERR_NOT_FOUND;
  }

  memcpy(gains_db, g_eq_gains, sizeof(g_eq_gains));
  return ESP_OK;
}

esp_err_t settings_set_eq_gains(const float gains_db[SETTINGS_EQ_BANDS]) {
  if (!gains_db) {
    return ESP_ERR_INVALID_ARG;
  }

  /* Skip write if unchanged (compare element-by-element to avoid
     memcmp on floats, which is flagged by
     bugprone-suspicious-memory-comparison) */
  if (g_eq_loaded) {
    bool unchanged = true;
    for (int i = 0; i < SETTINGS_EQ_BANDS; i++) {
      if (gains_db[i] != g_eq_gains[i]) {
        unchanged = false;
        break;
      }
    }
    if (unchanged) {
      return ESP_OK;
    }
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  err = nvs_set_blob(nvs, NVS_KEY_EQ_GAINS, gains_db,
                     sizeof(float) * SETTINGS_EQ_BANDS);
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }

  nvs_close(nvs);

  if (err == ESP_OK) {
    memcpy(g_eq_gains, gains_db, sizeof(g_eq_gains));
    g_eq_loaded = true;
    ESP_LOGI(TAG, "Saved EQ gains (%d bands)", SETTINGS_EQ_BANDS);
  } else {
    ESP_LOGE(TAG, "Failed to save EQ gains: %s", esp_err_to_name(err));
  }

  return err;
}

esp_err_t settings_clear_eq(void) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    return err;
  }

  err = nvs_erase_key(nvs, NVS_KEY_EQ_GAINS);
  if (err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND) {
    nvs_commit(nvs);
    memset(g_eq_gains, 0, sizeof(g_eq_gains));
    g_eq_loaded = false;
    err = ESP_OK;
  }

  nvs_close(nvs);
  return err;
}

bool settings_has_eq(void) {
  return g_eq_loaded;
}
