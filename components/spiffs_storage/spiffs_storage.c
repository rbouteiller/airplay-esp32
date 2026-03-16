#include "spiffs_storage.h"

#include "esp_log.h"
#include "esp_spiffs.h"

static const char *TAG = "spiffs";
static bool s_mounted = false;

esp_err_t spiffs_storage_init(void) {
  if (s_mounted) {
    return ESP_OK;
  }

  esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = "storage",
      .max_files = 5,
      .format_if_mount_failed = true,
  };

  esp_err_t err = esp_vfs_spiffs_register(&conf);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to mount SPIFFS: %s", esp_err_to_name(err));
    return err;
  }

  size_t total = 0, used = 0;
  esp_spiffs_info("storage", &total, &used);
  ESP_LOGI(TAG, "SPIFFS mounted: %zu/%zu bytes used", used, total);

  s_mounted = true;
  return ESP_OK;
}
