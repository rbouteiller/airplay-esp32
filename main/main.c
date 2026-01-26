#include "audio_output.h"
#include "audio_receiver.h"
#include "hap.h"
#include "mdns_airplay.h"
#include "nvs_flash.h"
#include "ptp_clock.h"
#include "rtsp_server.h"
#include "settings.h"
#include "wifi.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void app_main(void) {
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
      ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);

  ESP_ERROR_CHECK(settings_init());

  wifi_init_sta();
  wifi_wait_connected();
  ESP_ERROR_CHECK(ntp_clock_init());
  ESP_ERROR_CHECK(ptp_clock_init());
  ESP_ERROR_CHECK(hap_init());
  ESP_ERROR_CHECK(audio_receiver_init());
  ESP_ERROR_CHECK(audio_output_init());
  audio_output_start();

  mdns_airplay_init();
  ESP_ERROR_CHECK(rtsp_server_start());

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(10000));
  }
}
