#include "ota.h"

#include "esp_log.h"
#include "esp_ota_ops.h"
#include <sys/param.h>

static const char *TAG = "ota";

esp_err_t ota_start_from_http(httpd_req_t *req) {
  const esp_partition_t *ota_partition = esp_ota_get_next_update_partition(NULL);
  if (!ota_partition) {
    ESP_LOGE(TAG, "No OTA partition found");
    return ESP_ERR_NOT_FOUND;
  }

  esp_ota_handle_t ota_handle;
  esp_err_t err = esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
    return err;
  }

  char buf[1024];
  int remaining = req->content_len;
  ESP_LOGI(TAG, "Receiving firmware (%d bytes)...", remaining);

  while (remaining > 0) {
    int recv_len = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));

    if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    } else if (recv_len <= 0) {
      ESP_LOGE(TAG, "Receive error: %d", recv_len);
      esp_ota_abort(ota_handle);
      return ESP_FAIL;
    }

    if (esp_ota_write(ota_handle, buf, recv_len) != ESP_OK) {
      ESP_LOGE(TAG, "Flash write failed");
      esp_ota_abort(ota_handle);
      return ESP_FAIL;
    }

    remaining -= recv_len;
  }

  if (esp_ota_end(ota_handle) != ESP_OK) {
    ESP_LOGE(TAG, "Image validation failed");
    return ESP_FAIL;
  }

  if (esp_ota_set_boot_partition(ota_partition) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to set boot partition");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "OTA update successful");
  return ESP_OK;
}
