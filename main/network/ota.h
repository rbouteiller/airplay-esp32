#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

/**
 * Perform OTA update from HTTP POST request containing raw firmware binary.
 * Does not restart - caller should send response then call esp_restart().
 *
 * @param req HTTP request with firmware in body
 * @return ESP_OK on success
 */
esp_err_t ota_start_from_http(httpd_req_t *req);
