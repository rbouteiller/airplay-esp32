#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "nvs_flash.h"

#include "wifi.h"
#include "settings.h"

static const char *TAG = "wifi";

// Event group to signal WiFi connection
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

// Re-enable AP after this many consecutive failures
#define AP_REENABLE_THRESHOLD 5

static int s_retry_num = 0;
static esp_netif_t *s_sta_netif = NULL;
static esp_netif_t *s_ap_netif = NULL;
static bool s_wifi_initialized = false;
static bool s_sta_connected = false;
static bool s_bssid_set = false;
static esp_timer_handle_t s_retry_timer = NULL;

// Saved AP config from init, used to re-enable AP without duplication
static wifi_config_t s_ap_config;

static void wifi_select_best_ap(const char *ssid);

static void retry_timer_callback(void *arg) {
  if (!s_sta_connected) {
    ESP_LOGI(TAG, "Retry timer fired, reconnecting (attempt %d)...",
             s_retry_num + 1);
    esp_wifi_connect();
  }
}

static void schedule_retry(void) {
  // Exponential backoff: 5s, 10s, 20s, 30s (max)
  int delay_s = 5;
  if (s_retry_num > AP_REENABLE_THRESHOLD) {
    int backoff_count = s_retry_num - AP_REENABLE_THRESHOLD;
    delay_s = 5 * (1 << (backoff_count > 3 ? 3 : backoff_count));
    if (delay_s > 30) {
      delay_s = 30;
    }
  }
  ESP_LOGI(TAG, "Scheduling retry in %d seconds", delay_s);
  esp_timer_start_once(s_retry_timer, (uint64_t)delay_s * 1000000);
}

static void enable_ap_mode(void) {
  wifi_mode_t mode;
  if (esp_wifi_get_mode(&mode) == ESP_OK && mode != WIFI_MODE_APSTA) {
    ESP_LOGI(TAG, "Re-enabling AP mode for configuration access");
    if (!s_ap_netif) {
      s_ap_netif = esp_netif_create_default_wifi_ap();
    }
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &s_ap_config);
  }
}

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
    // Scan for best AP before first connection
    wifi_config_t cfg;
    if (esp_wifi_get_config(WIFI_IF_STA, &cfg) == ESP_OK &&
        strlen((char *)cfg.sta.ssid) > 0) {
      wifi_select_best_ap((char *)cfg.sta.ssid);
    }
    esp_wifi_connect();
  } else if (event_base == WIFI_EVENT &&
             event_id == WIFI_EVENT_STA_DISCONNECTED) {
    s_sta_connected = false;
    wifi_event_sta_disconnected_t *disconnected =
        (wifi_event_sta_disconnected_t *)event_data;
    ESP_LOGI(TAG, "Disconnected from AP, reason: %d", disconnected->reason);

    s_retry_num++;

    if (s_retry_num < AP_REENABLE_THRESHOLD) {
      // Fast retries — reconnect immediately
      ESP_LOGI(TAG, "Retrying connection (%d/%d)...", s_retry_num,
               AP_REENABLE_THRESHOLD);
      esp_wifi_connect();
    } else {
      if (s_retry_num == AP_REENABLE_THRESHOLD) {
        xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        ESP_LOGW(TAG,
                 "WiFi connection failed after %d attempts, switching to "
                 "backoff retries",
                 AP_REENABLE_THRESHOLD);
        enable_ap_mode();
      }
      // Delayed retries with backoff
      schedule_retry();
    }
  } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    s_retry_num = 0;
    s_sta_connected = true;
    xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);

    // Disable AP mode when STA connects
    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) == ESP_OK && mode == WIFI_MODE_APSTA) {
      ESP_LOGI(TAG, "STA connected, disabling AP mode");
      esp_wifi_set_mode(WIFI_MODE_STA);
    }
  } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_START) {
    ESP_LOGI(TAG, "AP started");
  }
}

// Scan for the best AP matching our SSID and set its BSSID in the STA config
static void wifi_select_best_ap(const char *ssid) {
  wifi_scan_config_t scan_config = {
      .ssid = (uint8_t *)ssid,
      .bssid = NULL,
      .channel = 0,
      .show_hidden = false,
      .scan_type = WIFI_SCAN_TYPE_ACTIVE,
      .scan_time = {.active = {.min = 100, .max = 300}},
  };

  esp_err_t err = esp_wifi_scan_start(&scan_config, true);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Best-AP scan failed: %s", esp_err_to_name(err));
    return;
  }

  uint16_t ap_count = 0;
  esp_wifi_scan_get_ap_num(&ap_count);
  if (ap_count == 0) {
    ESP_LOGW(TAG, "Best-AP scan: no APs found for SSID %s", ssid);
    esp_wifi_scan_get_ap_records(&ap_count, NULL);
    return;
  }

  wifi_ap_record_t *ap_list = malloc(sizeof(wifi_ap_record_t) * ap_count);
  if (!ap_list) {
    esp_wifi_scan_get_ap_records(&ap_count, NULL);
    return;
  }

  esp_wifi_scan_get_ap_records(&ap_count, ap_list);

  // Find AP with strongest signal
  int best_idx = 0;
  for (int i = 1; i < ap_count; i++) {
    if (ap_list[i].rssi > ap_list[best_idx].rssi) {
      best_idx = i;
    }
  }

  ESP_LOGI(TAG, "Found %d APs for SSID '%s', best: " MACSTR " (rssi=%d, ch=%d)",
           ap_count, ssid, MAC2STR(ap_list[best_idx].bssid),
           ap_list[best_idx].rssi, ap_list[best_idx].primary);

  for (int i = 0; i < ap_count; i++) {
    if (i != best_idx) {
      ESP_LOGI(TAG, "  Other AP: " MACSTR " (rssi=%d, ch=%d)",
               MAC2STR(ap_list[i].bssid), ap_list[i].rssi, ap_list[i].primary);
    }
  }

  // Set BSSID in the STA config to lock to the best AP
  wifi_config_t sta_cfg;
  esp_wifi_get_config(WIFI_IF_STA, &sta_cfg);
  memcpy(sta_cfg.sta.bssid, ap_list[best_idx].bssid, 6);
  sta_cfg.sta.bssid_set = true;
  esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
  s_bssid_set = true;

  free(ap_list);
}

static void wifi_init_base(void) {
  if (s_wifi_initialized) {
    return;
  }

  s_wifi_event_group = xEventGroupCreate();

  esp_err_t ret = esp_netif_init();
  if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
    ESP_ERROR_CHECK(ret);
  }

  // Create event loop if it doesn't exist
  ret = esp_event_loop_create_default();
  if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
    ESP_ERROR_CHECK(ret);
  }

  esp_event_handler_instance_t instance_any_id;
  esp_event_handler_instance_t instance_got_ip;
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
      IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

  // Create one-shot retry timer (no background task needed)
  const esp_timer_create_args_t timer_args = {
      .callback = retry_timer_callback,
      .name = "wifi_retry",
  };
  ESP_ERROR_CHECK(esp_timer_create(&timer_args, &s_retry_timer));

  s_wifi_initialized = true;
}

void wifi_init_apsta(const char *ap_ssid, const char *ap_password) {
  wifi_init_base();

  if (!s_sta_netif) {
    s_sta_netif = esp_netif_create_default_wifi_sta();
  }
  if (!s_ap_netif) {
    s_ap_netif = esp_netif_create_default_wifi_ap();
  }

  // Configure STA
  char ssid[33] = {0};
  char password[65] = {0};
  bool has_credentials = false;

  if (settings_get_wifi_ssid(ssid, sizeof(ssid)) == ESP_OK &&
      settings_get_wifi_password(password, sizeof(password)) == ESP_OK &&
      strlen(ssid) > 0) {
    has_credentials = true;
  }

  wifi_config_t sta_config = {0};
  strncpy((char *)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid) - 1);
  strncpy((char *)sta_config.sta.password, password,
          sizeof(sta_config.sta.password) - 1);
  sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

  // Configure AP and save for later re-enable
  const char *default_ssid = ap_ssid ? ap_ssid : "ESP32-AirPlay-Setup";
  const char *default_password = ap_password ? ap_password : "";

  memset(&s_ap_config, 0, sizeof(s_ap_config));
  strncpy((char *)s_ap_config.ap.ssid, default_ssid,
          sizeof(s_ap_config.ap.ssid) - 1);
  s_ap_config.ap.ssid_len = strlen(default_ssid);
  s_ap_config.ap.channel = 1;
  s_ap_config.ap.max_connection = 4;

  if (strlen(default_password) == 0) {
    s_ap_config.ap.authmode = WIFI_AUTH_OPEN;
  } else {
    strncpy((char *)s_ap_config.ap.password, default_password,
            sizeof(s_ap_config.ap.password) - 1);
    s_ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
  }

  s_retry_num = 0;

  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &s_ap_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_LOGI(TAG, "AP+STA mode started: AP SSID=%s", default_ssid);
  if (has_credentials) {
    ESP_LOGI(TAG, "Connecting to WiFi: %s", ssid);
  }
}

bool wifi_wait_connected(uint32_t timeout_ms) {
  if (!s_wifi_event_group) {
    return false;
  }

  TickType_t timeout_ticks =
      timeout_ms > 0 ? pdMS_TO_TICKS(timeout_ms) : portMAX_DELAY;
  EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                         pdFALSE, pdFALSE, timeout_ticks);

  if (bits & WIFI_CONNECTED_BIT) {
    return true;
  }
  if (bits & WIFI_FAIL_BIT) {
    ESP_LOGE(TAG, "Failed to connect to WiFi");
  }
  return false;
}

void wifi_get_mac_str(char *mac_str, size_t len) {
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(mac_str, len, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
}

bool wifi_is_connected(void) {
  return s_sta_connected;
}

esp_err_t wifi_get_ip_str(char *ip_str, size_t len) {
  if (!s_sta_netif || !ip_str || len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  esp_netif_ip_info_t ip_info;
  esp_err_t err = esp_netif_get_ip_info(s_sta_netif, &ip_info);
  if (err == ESP_OK) {
    snprintf(ip_str, len, IPSTR, IP2STR(&ip_info.ip));
  }
  return err;
}

esp_err_t wifi_scan(wifi_ap_record_t **ap_list, uint16_t *ap_count) {
  if (!ap_list || !ap_count) {
    return ESP_ERR_INVALID_ARG;
  }

  // Stop any pending retry and disconnect cleanly
  esp_timer_stop(s_retry_timer);
  esp_wifi_disconnect();
  vTaskDelay(pdMS_TO_TICKS(100));

  // Clear BSSID lock so next connect can use a fresh scan result
  if (s_bssid_set) {
    wifi_config_t sta_cfg;
    if (esp_wifi_get_config(WIFI_IF_STA, &sta_cfg) == ESP_OK) {
      memset(sta_cfg.sta.bssid, 0, sizeof(sta_cfg.sta.bssid));
      sta_cfg.sta.bssid_set = false;
      esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    }
    s_bssid_set = false;
  }

  wifi_scan_config_t scan_config = {
      .ssid = NULL,
      .bssid = NULL,
      .channel = 0,
      .show_hidden = true,
  };

  esp_err_t err = esp_wifi_scan_start(&scan_config, true);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "WiFi scan failed: %s", esp_err_to_name(err));
    return err;
  }

  uint16_t number = 0;
  err = esp_wifi_scan_get_ap_num(&number);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get AP count: %s", esp_err_to_name(err));
    return err;
  }

  if (number == 0) {
    *ap_list = NULL;
    *ap_count = 0;
    return ESP_OK;
  }

  wifi_ap_record_t *aps = malloc(sizeof(wifi_ap_record_t) * number);
  if (!aps) {
    return ESP_ERR_NO_MEM;
  }

  err = esp_wifi_scan_get_ap_records(&number, aps);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to get AP records: %s", esp_err_to_name(err));
    free(aps);
    return err;
  }

  *ap_list = aps;
  *ap_count = number;
  return ESP_OK;
}

void wifi_stop(void) {
  if (s_wifi_initialized) {
    esp_timer_stop(s_retry_timer);
    esp_wifi_stop();
    esp_wifi_deinit();
    s_wifi_initialized = false;
    s_sta_connected = false;
    s_retry_num = 0;
    if (s_wifi_event_group) {
      xEventGroupClearBits(s_wifi_event_group,
                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    }
  }
}
