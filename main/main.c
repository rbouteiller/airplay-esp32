#include "audio_output.h"
#include "audio_receiver.h"
#include "dns_server.h"
#include "led.h"
#include "hap.h"
#include "mdns_airplay.h"
#include "nvs_flash.h"
#include "ptp_clock.h"
#include "rtsp_server.h"
#include "settings.h"
#include "web_server.h"
#include "wifi.h"

#include "iot_board.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

// AP mode IP address (192.168.4.1 in network byte order)
#define AP_IP_ADDR 0x0104A8C0

static bool s_airplay_started = false;

static void start_airplay_services(void) {
  if (s_airplay_started) {
    return;
  }
  s_airplay_started = true;

  ESP_LOGI(TAG, "Starting AirPlay services...");

  esp_err_t err = ptp_clock_init();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
    ESP_LOGE(TAG, "Failed to init PTP clock: %s", esp_err_to_name(err));
    s_airplay_started = false;
    return;
  }

  ESP_ERROR_CHECK(hap_init());
  ESP_ERROR_CHECK(audio_receiver_init());
  ESP_ERROR_CHECK(audio_output_init());
  audio_output_start();
  mdns_airplay_init();
  ESP_ERROR_CHECK(rtsp_server_start());

  ESP_LOGI(TAG, "AirPlay ready");
}

static void wifi_monitor_task(void *pvParameters) {
  bool was_connected = wifi_is_connected();
  bool dns_running = !was_connected;

  // Start captive portal DNS if not connected
  if (dns_running) {
    dns_server_start(AP_IP_ADDR);
  }

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(2000));

    bool connected = wifi_is_connected();
    if (connected == was_connected) {
      continue;
    }

    if (connected) {
      ESP_LOGI(TAG, "WiFi connected");
      start_airplay_services();
      if (dns_running) {
        dns_server_stop();
        dns_running = false;
      }
    } else {
      ESP_LOGW(TAG, "WiFi disconnected");
      if (!dns_running) {
        dns_server_start(AP_IP_ADDR);
        dns_running = true;
      }
    }

    was_connected = connected;
  }
}

void app_main(void) {
  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  ESP_ERROR_CHECK(settings_init());
  led_init();

  // Initialize board-specific hardware
  ESP_LOGI(TAG, "Board: %s", iot_board_get_info());
  esp_err_t err = iot_board_init();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Board init failed: %s", esp_err_to_name(err));
  }

  // Start WiFi (APSTA mode: AP for config, STA for connection)
  wifi_init_apsta(NULL, NULL);

  // Wait for initial connection if credentials exist
  bool connected = false;
  if (settings_has_wifi_credentials()) {
    connected = wifi_wait_connected(30000);
  }

  if (!connected) {
    ESP_LOGI(TAG, "Connect to 'ESP32-AirPlay-Setup' -> http://192.168.4.1");
  }

  // Start services
  web_server_start(80);
  xTaskCreate(wifi_monitor_task, "wifi_mon", 4096, NULL, 5, NULL);

  if (connected) {
    start_airplay_services();
  }
  while (1) {
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}
