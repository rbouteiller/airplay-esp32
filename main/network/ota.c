// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "ota.h"

#include "esp_app_format.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "psa/crypto.h"
#include <string.h>
#include <sys/param.h>

static const char *TAG = "ota";

/**
 * Validate an in-memory firmware image before writing to flash.
 * Checks: minimum size, magic byte, segment count, and SHA-256 digest
 * (when the image indicates a hash is appended).
 */
static esp_err_t ota_validate_image(const uint8_t *image, size_t len) {
  if (len < sizeof(esp_image_header_t)) {
    ESP_LOGE(TAG, "Image too small (%zu bytes)", len);
    return ESP_ERR_INVALID_SIZE;
  }

  const esp_image_header_t *header = (const esp_image_header_t *)image;

  if (header->magic != ESP_IMAGE_HEADER_MAGIC) {
    ESP_LOGE(TAG, "Bad image magic: 0x%02x (expected 0x%02x)", header->magic,
             ESP_IMAGE_HEADER_MAGIC);
    return ESP_ERR_INVALID_STATE;
  }

  if (header->segment_count == 0 ||
      header->segment_count > ESP_IMAGE_MAX_SEGMENTS) {
    ESP_LOGE(TAG, "Bad segment count: %u", header->segment_count);
    return ESP_ERR_INVALID_STATE;
  }

  if (header->hash_appended) {
    if (len < 32) {
      ESP_LOGE(TAG, "Image claims hash but is too small");
      return ESP_ERR_INVALID_SIZE;
    }
    // SHA-256 digest covers everything except the last 32 bytes
    size_t data_len = len - 32;
    const uint8_t *expected_hash = image + data_len;

    uint8_t computed_hash[32];
    size_t computed_hash_len = 0;
    psa_crypto_init();
    if (psa_hash_compute(PSA_ALG_SHA_256, image, data_len, computed_hash,
                         sizeof(computed_hash), &computed_hash_len) !=
        PSA_SUCCESS) {
      ESP_LOGE(TAG, "SHA-256 hash computation failed");
      return ESP_ERR_INVALID_STATE;
    }

    if (memcmp(computed_hash, expected_hash, 32) != 0) {
      ESP_LOGE(TAG, "SHA-256 mismatch — firmware is corrupt");
      return ESP_ERR_INVALID_STATE;
    }
    ESP_LOGI(TAG, "SHA-256 verified OK");
  }

  return ESP_OK;
}

/**
 * Receive firmware into a PSRAM buffer, validate, then write to flash.
 * Returns ESP_ERR_NO_MEM if PSRAM allocation fails (caller can fall back).
 */
static esp_err_t ota_buffered(httpd_req_t *req) {
  size_t fw_size = req->content_len;

  uint8_t *fw_buf = heap_caps_malloc(fw_size, MALLOC_CAP_SPIRAM);
  if (!fw_buf) {
    ESP_LOGW(TAG, "Cannot allocate %zu bytes in PSRAM", fw_size);
    return ESP_ERR_NO_MEM;
  }

  // Receive entire firmware into RAM
  ESP_LOGI(TAG, "Receiving firmware into PSRAM (%zu bytes)...", fw_size);
  size_t received = 0;
  while (received < fw_size) {
    int recv_len =
        httpd_req_recv(req, (char *)fw_buf + received, fw_size - received);
    if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    } else if (recv_len <= 0) {
      ESP_LOGE(TAG, "Receive error: %d", recv_len);
      heap_caps_free(fw_buf);
      return ESP_FAIL;
    }
    received += recv_len;
  }

  // Validate before touching flash
  esp_err_t err = ota_validate_image(fw_buf, fw_size);
  if (err != ESP_OK) {
    heap_caps_free(fw_buf);
    return err;
  }

  // Write validated image to flash
  const esp_partition_t *ota_partition =
      esp_ota_get_next_update_partition(NULL);
  if (!ota_partition) {
    ESP_LOGE(TAG, "No OTA partition found");
    heap_caps_free(fw_buf);
    return ESP_ERR_NOT_FOUND;
  }

  esp_ota_handle_t ota_handle;
  err = esp_ota_begin(ota_partition, fw_size, &ota_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
    heap_caps_free(fw_buf);
    return err;
  }

  // Write in 4 KB chunks to avoid watchdog triggers on large images
  size_t offset = 0;
  while (offset < fw_size) {
    size_t chunk = MIN(fw_size - offset, 4096);
    if (esp_ota_write(ota_handle, fw_buf + offset, chunk) != ESP_OK) {
      ESP_LOGE(TAG, "Flash write failed at offset %zu", offset);
      esp_ota_abort(ota_handle);
      heap_caps_free(fw_buf);
      return ESP_FAIL;
    }
    offset += chunk;
  }
  heap_caps_free(fw_buf);

  if (esp_ota_end(ota_handle) != ESP_OK) {
    ESP_LOGE(TAG, "Image validation failed (esp_ota_end)");
    return ESP_FAIL;
  }

  if (esp_ota_set_boot_partition(ota_partition) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to set boot partition");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "OTA update successful (buffered)");
  return ESP_OK;
}

/**
 * Stream firmware directly to flash (original approach, used as fallback).
 */
static esp_err_t ota_streaming(httpd_req_t *req) {
  const esp_partition_t *ota_partition =
      esp_ota_get_next_update_partition(NULL);
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
  size_t remaining = req->content_len;
  ESP_LOGI(TAG, "Receiving firmware via streaming (%zu bytes)...", remaining);

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

  ESP_LOGI(TAG, "OTA update successful (streaming)");
  return ESP_OK;
}

esp_err_t ota_start_from_http(httpd_req_t *req) {
  // Try RAM-buffered OTA first (validates image before writing to flash).
  // Falls back to streaming if PSRAM is not available or too small.
  esp_err_t err = ota_buffered(req);
  if (err == ESP_ERR_NO_MEM) {
    ESP_LOGW(TAG, "Falling back to streaming OTA (no PSRAM available)");
    err = ota_streaming(req);
  }
  return err;
}
