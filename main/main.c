#include "audio_output.h"
#include "audio_receiver.h"
#include "hap.h"
#include "mdns_airplay.h"
#include "nvs_flash.h"
#include "ptp_clock.h"
#include "rtsp_server.h"
#include "settings.h"
#include "wifi.h"
#include "web_server.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

static const char *TAG = "main";

static bool s_airplay_started = false;

static void start_airplay_services(void) {
  if (s_airplay_started) {
    ESP_LOGD(TAG, "AirPlay services already started, skipping");
    return;
  }

  // Set flag early to prevent race conditions
  s_airplay_started = true;

  ESP_LOGI(TAG, "Starting AirPlay services...");
  esp_err_t err = ptp_clock_init();
  if (err != ESP_OK) {
    if (err == ESP_ERR_INVALID_STATE) {
      ESP_LOGW(TAG, "PTP clock already initialized, continuing...");
    } else {
      ESP_LOGE(TAG, "Failed to initialize PTP clock: %s", esp_err_to_name(err));
      s_airplay_started = false;
      return;
    }
  }
  ESP_ERROR_CHECK(hap_init());
  ESP_ERROR_CHECK(audio_receiver_init());
  ESP_ERROR_CHECK(audio_output_init());
  audio_output_start();

  mdns_airplay_init();
  ESP_ERROR_CHECK(rtsp_server_start());
  ESP_LOGI(TAG, "AirPlay services started");
}

static void wifi_monitor_task(void *pvParameters) {
  // Initialize to current state to avoid triggering on first check
  bool last_connected = wifi_is_connected();
  
  while (1) {
    bool connected = wifi_is_connected();
    
    if (connected && !last_connected) {
      ESP_LOGI(TAG, "WiFi connected! Starting AirPlay services...");
      start_airplay_services();
    } else if (!connected && last_connected) {
      ESP_LOGW(TAG, "WiFi disconnected");
      // AirPlay services will continue running but won't be discoverable
      // They'll resume when WiFi reconnects
    }
    
    last_connected = connected;
    vTaskDelay(pdMS_TO_TICKS(2000)); // Check every 2 seconds
  }
}

void app_main(void) {
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  ESP_ERROR_CHECK(settings_init());

  // Check if WiFi credentials exist
  bool has_wifi = settings_has_wifi_credentials();
  bool wifi_connected = false;

  if (has_wifi) {
    // Start in APSTA mode - AP for configuration, STA keeps trying to connect
    ESP_LOGI(TAG, "WiFi credentials found, starting AP+STA mode...");
    wifi_init_apsta(NULL, NULL); // AP SSID: ESP32-AirPlay-Setup
    
    // Wait a bit for initial connection attempt
    wifi_connected = wifi_wait_connected(30000); // 30 second timeout
    
    if (wifi_connected) {
      ESP_LOGI(TAG, "WiFi connected successfully");
    } else {
      ESP_LOGW(TAG, "Initial WiFi connection failed, will keep trying in background");
      ESP_LOGI(TAG, "AP mode active. Connect to 'ESP32-AirPlay-Setup' and visit http://192.168.4.1");
    }
  } else {
    // No WiFi credentials, start AP mode only for configuration
    ESP_LOGI(TAG, "No WiFi credentials found, starting AP mode for configuration");
    wifi_init_apsta(NULL, NULL); // APSTA mode for scanning
    ESP_LOGI(TAG, "AP mode started. Connect to 'ESP32-AirPlay-Setup' and visit http://192.168.4.1");
  }

  // Start web server (works on both AP and STA interfaces)
  web_server_start(80);

  // Start WiFi monitor task to detect when WiFi connects
  xTaskCreate(wifi_monitor_task, "wifi_monitor", 4096, NULL, 5, NULL);

  // Start AirPlay services if already connected
  if (wifi_connected) {
    start_airplay_services();
  } else {
    ESP_LOGI(TAG, "AirPlay services will start automatically when WiFi connects");
  }

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}
