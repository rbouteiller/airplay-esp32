#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "wifi.h"
#include "hap.h"
#include "mdns_airplay.h"
#include "rtsp_server.h"
#include "audio_receiver.h"

static const char *TAG = "airplay2";

void app_main(void)
{
    ESP_LOGI(TAG, "AirPlay 2 Receiver starting...");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize WiFi
    wifi_init_sta();

    // Wait for WiFi connection
    ESP_LOGI(TAG, "Waiting for WiFi connection...");
    wifi_wait_connected();

    // Initialize HAP (generates/loads Ed25519 keypair)
    ESP_LOGI(TAG, "Initializing HAP...");
    ESP_ERROR_CHECK(hap_init());

    // Initialize audio receiver
    ESP_LOGI(TAG, "Initializing audio receiver...");
    ESP_ERROR_CHECK(audio_receiver_init());

    // Start mDNS AirPlay advertisement
    ESP_LOGI(TAG, "Starting mDNS AirPlay service...");
    mdns_airplay_init();

    // Start RTSP server for AirPlay connections
    ESP_LOGI(TAG, "Starting RTSP server on port 7000...");
    ESP_ERROR_CHECK(rtsp_server_start());

    ESP_LOGI(TAG, "AirPlay 2 Receiver ready!");
    ESP_LOGI(TAG, "Device should now appear in AirPlay menu on iOS devices");

    // Keep running
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
