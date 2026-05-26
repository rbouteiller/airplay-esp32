#include "web_server.h"

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_heap_caps.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "cJSON.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_wifi.h"

#include "dns_server.h"
#include "led.h"
#include "spiffs_storage.h"
#include "settings.h"
#include "wifi.h"
#include "ethernet.h"
#include "ota.h"
#include "log_stream.h"
#include "rtsp_server.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef CONFIG_DAC_TAS58XX
#include "eq_events.h"
#include "dac_tas58xx_eq.h"
#endif

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;

#define SPIFFS_CHUNK_SIZE 1024
#define JSON_BODY_MAX     2048
#define AP_IP_ADDR        0x0104A8C0
#define STORAGE_PARTITION_LABEL "storage"
#define STORAGE_WRITE_CHUNK     4096

static esp_err_t serve_spiffs_file(httpd_req_t *req, const char *path,
                                   const char *content_type) {
  FILE *f = fopen(path, "r");
  if (!f) {
    ESP_LOGE(TAG, "Failed to open %s", path);
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    return ESP_FAIL;
  }
  httpd_resp_set_type(req, content_type);
  char buf[SPIFFS_CHUNK_SIZE];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    if (httpd_resp_send_chunk(req, buf, (ssize_t)n) != ESP_OK) {
      fclose(f);
      httpd_resp_send_chunk(req, NULL, 0);
      return ESP_FAIL;
    }
  }
  fclose(f);
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

static esp_err_t read_request_body(httpd_req_t *req, char *content,
                                   size_t content_size) {
  if (req->content_len <= 0 || req->content_len >= (int)content_size) {
    return ESP_ERR_INVALID_SIZE;
  }

  int total = 0;
  while (total < req->content_len) {
    int ret = httpd_req_recv(req, content + total, req->content_len - total);
    if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    }
    if (ret <= 0) {
      return ESP_FAIL;
    }
    total += ret;
  }

  content[total] = '\0';
  return ESP_OK;
}

static const esp_partition_t *find_storage_partition(void) {
  return esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                                  ESP_PARTITION_SUBTYPE_DATA_SPIFFS,
                                  STORAGE_PARTITION_LABEL);
}

static bool storage_update_should_reboot(httpd_req_t *req) {
  char query[48];
  char value[16];

  if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK) {
    return true;
  }

  if (httpd_query_key_value(query, "reboot", value, sizeof(value)) != ESP_OK) {
    return true;
  }

  return !(strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
           strcasecmp(value, "no") == 0);
}

static void gpio_config_to_json(cJSON *obj,
                                const settings_gpio_config_t *config) {
  if (!obj || !config) {
    return;
  }

  cJSON_AddNumberToObject(obj, "i2s_sck", config->i2s_sck);
  cJSON_AddNumberToObject(obj, "i2s_bck", config->i2s_bck);
  cJSON_AddNumberToObject(obj, "i2s_ws", config->i2s_ws);
  cJSON_AddNumberToObject(obj, "i2s_do", config->i2s_do);
  cJSON_AddNumberToObject(obj, "i2s_gnd", config->i2s_gnd);
  cJSON_AddNumberToObject(obj, "i2s_vcc", config->i2s_vcc);
  cJSON_AddNumberToObject(obj, "dac_i2c_sda", config->dac_i2c_sda);
  cJSON_AddNumberToObject(obj, "dac_i2c_scl", config->dac_i2c_scl);
  cJSON_AddNumberToObject(obj, "jack", config->jack);
  cJSON_AddNumberToObject(obj, "spkfault", config->spkfault);
  cJSON_AddNumberToObject(obj, "mute", config->mute);
  cJSON_AddNumberToObject(obj, "led_status", config->led_status);
  cJSON_AddNumberToObject(obj, "led_error", config->led_error);
  cJSON_AddNumberToObject(obj, "led_rgb", config->led_rgb);
  cJSON_AddNumberToObject(obj, "btn_play_pause", config->btn_play_pause);
  cJSON_AddNumberToObject(obj, "btn_volume_up", config->btn_volume_up);
  cJSON_AddNumberToObject(obj, "btn_volume_down", config->btn_volume_down);
  cJSON_AddNumberToObject(obj, "btn_next", config->btn_next);
  cJSON_AddNumberToObject(obj, "btn_prev", config->btn_prev);
}

static bool parse_gpio_json_value(cJSON *item, int *value, const char **error) {
  if (!item || !value) {
    if (error) {
      *error = "Missing GPIO value";
    }
    return false;
  }

  if (cJSON_IsNumber(item)) {
    int gpio = item->valueint;
    if (!settings_is_valid_gpio(gpio)) {
      if (error) {
        *error = "GPIO out of range";
      }
      return false;
    }
    *value = gpio;
    return true;
  }

  if (!cJSON_IsString(item)) {
    if (error) {
      *error = "GPIO must be a string or number";
    }
    return false;
  }

  const char *raw = cJSON_GetStringValue(item);
  if (!raw) {
    if (error) {
      *error = "GPIO value is empty";
    }
    return false;
  }

  char buf[32];
  size_t raw_len = strlen(raw);
  if (raw_len >= sizeof(buf)) {
    if (error) {
      *error = "GPIO value is too long";
    }
    return false;
  }

  memcpy(buf, raw, raw_len + 1);

  char *start = buf;
  while (*start && isspace((unsigned char)*start)) {
    start++;
  }

  char *end = start + strlen(start);
  while (end > start && isspace((unsigned char)*(end - 1))) {
    end--;
  }
  *end = '\0';

  if (*start == '\0') {
    *value = -1;
    return true;
  }

  if (strncasecmp(start, "GPIO", 4) == 0) {
    start += 4;
  }

  if (*start == '\0') {
    if (error) {
      *error = "GPIO number missing";
    }
    return false;
  }

  char *parse_end = NULL;
  long parsed = strtol(start, &parse_end, 10);
  while (parse_end && *parse_end &&
         isspace((unsigned char)*parse_end)) {
    parse_end++;
  }

  if (!parse_end || *parse_end != '\0') {
    if (error) {
      *error = "GPIO format must be like 1, GPIO1, or -1";
    }
    return false;
  }

  if (!settings_is_valid_gpio((int)parsed)) {
    if (error) {
      *error = "GPIO out of range";
    }
    return false;
  }

  *value = (int)parsed;
  return true;
}

static bool update_gpio_field(cJSON *json, const char *key, int *target,
                              const char **error) {
  cJSON *item = cJSON_GetObjectItemCaseSensitive(json, key);
  if (!item) {
    return true;
  }

  int parsed = -1;
  if (!parse_gpio_json_value(item, &parsed, error)) {
    return false;
  }

  *target = parsed;
  return true;
}

// API handlers
static esp_err_t root_handler(httpd_req_t *req) {
  return serve_spiffs_file(req, "/spiffs/www/index.html", "text/html");
}

static esp_err_t favicon_handler(httpd_req_t *req) {
  httpd_resp_set_status(req, "204 No Content");
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

static esp_err_t logs_page_handler(httpd_req_t *req) {
  return serve_spiffs_file(req, "/spiffs/www/logs.html", "text/html");
}

static esp_err_t speedtest_page_handler(httpd_req_t *req) {
  return serve_spiffs_file(req, "/spiffs/www/speedtest.html", "text/html");
}

// Tiny endpoint used by JS for RTT timing. Returns minimal body.
static esp_err_t speedtest_ping_handler(httpd_req_t *req) {
  httpd_resp_set_type(req, "text/plain");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");
  httpd_resp_send(req, "ok", 2);
  return ESP_OK;
}

// Streams `bytes` octets of filler data so the browser can measure DL speed.
// Capped to avoid pathological requests starving audio.
#define SPEEDTEST_MAX_BYTES (16 * 1024 * 1024)
#define SPEEDTEST_CHUNK     2048

static esp_err_t speedtest_download_handler(httpd_req_t *req) {
  size_t bytes = 1024 * 1024;
  char qbuf[64];
  if (httpd_req_get_url_query_str(req, qbuf, sizeof(qbuf)) == ESP_OK) {
    char val[16];
    if (httpd_query_key_value(qbuf, "bytes", val, sizeof(val)) == ESP_OK) {
      long v = strtol(val, NULL, 10);
      if (v > 0)
        bytes = (size_t)v;
    }
  }
  if (bytes > SPEEDTEST_MAX_BYTES)
    bytes = SPEEDTEST_MAX_BYTES;

  // Reuse a single buffer of filler bytes. Static so we don't repeatedly
  // hammer the heap; content is irrelevant but non-zero to thwart any
  // compression along the way.
  static uint8_t filler[SPEEDTEST_CHUNK];
  static bool filler_init = false;
  if (!filler_init) {
    for (size_t i = 0; i < sizeof(filler); i++)
      filler[i] = (uint8_t)(i * 37);
    filler_init = true;
  }

  httpd_resp_set_type(req, "application/octet-stream");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");

  size_t remaining = bytes;
  while (remaining > 0) {
    size_t n = remaining < SPEEDTEST_CHUNK ? remaining : SPEEDTEST_CHUNK;
    if (httpd_resp_send_chunk(req, (const char *)filler, n) != ESP_OK) {
      return ESP_FAIL;
    }
    remaining -= n;
  }
  httpd_resp_send_chunk(req, NULL, 0);
  return ESP_OK;
}

// Consumes a POST body and reports how many bytes were received.
static esp_err_t speedtest_upload_handler(httpd_req_t *req) {
  size_t total = req->content_len;
  size_t got = 0;
  uint8_t buf[SPEEDTEST_CHUNK];
  while (got < total) {
    size_t want = total - got;
    if (want > sizeof(buf))
      want = sizeof(buf);
    int r = httpd_req_recv(req, (char *)buf, want);
    if (r <= 0) {
      if (r == HTTPD_SOCK_ERR_TIMEOUT)
        continue;
      return ESP_FAIL;
    }
    got += (size_t)r;
  }
  char reply[64];
  int n = snprintf(reply, sizeof(reply), "received=%u", (unsigned)got);
  httpd_resp_set_type(req, "text/plain");
  httpd_resp_send(req, reply, n);
  return ESP_OK;
}

// Captive portal detection handlers
// These endpoints are requested by various OS to detect captive portals
static esp_err_t captive_portal_redirect(httpd_req_t *req) {
  // Redirect to the configuration page
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
  httpd_resp_send(req, NULL, 0);
  return ESP_OK;
}

// Apple devices (iOS/macOS) check these
static esp_err_t captive_apple_handler(httpd_req_t *req) {
  // Apple expects specific response, redirect instead
  return captive_portal_redirect(req);
}

// Android checks this
static esp_err_t captive_android_handler(httpd_req_t *req) {
  // Android expects 204 for no captive portal, anything else triggers portal
  return captive_portal_redirect(req);
}

// Windows checks this
static esp_err_t captive_windows_handler(httpd_req_t *req) {
  return captive_portal_redirect(req);
}

static esp_err_t wifi_scan_handler(httpd_req_t *req) {
  wifi_ap_record_t *ap_list = NULL;
  uint16_t ap_count = 0;

  cJSON *json = cJSON_CreateObject();
  esp_err_t err = wifi_scan(&ap_list, &ap_count);

  if (err == ESP_OK && ap_list) {
    cJSON *networks = cJSON_CreateArray();
    for (uint16_t i = 0; i < ap_count; i++) {
      cJSON *net = cJSON_CreateObject();
      cJSON_AddStringToObject(net, "ssid", (char *)ap_list[i].ssid);
      cJSON_AddNumberToObject(net, "rssi", ap_list[i].rssi);
      cJSON_AddNumberToObject(net, "channel", ap_list[i].primary);
      cJSON_AddItemToArray(networks, net);
    }
    cJSON_AddItemToObject(json, "networks", networks);
    cJSON_AddBoolToObject(json, "success", true);
    free(ap_list);
  } else {
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "error", esp_err_to_name(err));
  }

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  return ESP_OK;
}

static esp_err_t wifi_config_handler(httpd_req_t *req) {
  char content[JSON_BODY_MAX];
  if (read_request_body(req, content, sizeof(content)) != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *ssid_json = cJSON_GetObjectItem(json, "ssid");
  cJSON *password_json = cJSON_GetObjectItem(json, "password");

  cJSON *response = cJSON_CreateObject();
  if (ssid_json && cJSON_IsString(ssid_json)) {
    const char *ssid = cJSON_GetStringValue(ssid_json);
    const char *password = password_json && cJSON_IsString(password_json)
                               ? cJSON_GetStringValue(password_json)
                               : "";

    esp_err_t err = settings_set_wifi_credentials(ssid, password);
    if (err == ESP_OK) {
      cJSON_AddBoolToObject(response, "success", true);
      ESP_LOGI(TAG, "WiFi credentials saved. We are restarting...");
      // Schedule restart
      vTaskDelay(pdMS_TO_TICKS(1000));
      esp_restart();
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    }
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Invalid SSID");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);

  return ESP_OK;
}

static esp_err_t device_name_handler(httpd_req_t *req) {
  char content[JSON_BODY_MAX];
  if (read_request_body(req, content, sizeof(content)) != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *name_json = cJSON_GetObjectItem(json, "name");
  cJSON *response = cJSON_CreateObject();

  if (name_json && cJSON_IsString(name_json)) {
    const char *name = cJSON_GetStringValue(name_json);
    esp_err_t err = settings_set_device_name(name);
    if (err == ESP_OK) {
      cJSON_AddBoolToObject(response, "success", true);
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    }
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Invalid name");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);

  return ESP_OK;
}

static esp_err_t gpio_config_get_handler(httpd_req_t *req) {
  settings_gpio_config_t current;
  settings_gpio_config_t defaults;
  settings_get_gpio_config(&current);
  settings_get_default_gpio_config(&defaults);

  cJSON *json = cJSON_CreateObject();
  cJSON *config = cJSON_CreateObject();
  cJSON *default_config = cJSON_CreateObject();

  gpio_config_to_json(config, &current);
  gpio_config_to_json(default_config, &defaults);
  cJSON_AddItemToObject(json, "config", config);
  cJSON_AddItemToObject(json, "defaults", default_config);
  cJSON_AddBoolToObject(json, "success", true);

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t gpio_config_post_handler(httpd_req_t *req) {
  char content[JSON_BODY_MAX];
  if (read_request_body(req, content, sizeof(content)) != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  settings_gpio_config_t config;
  settings_get_gpio_config(&config);
  settings_gpio_config_t previous_config = config;
  const char *parse_error = NULL;
  bool should_restart = false;

  bool ok = update_gpio_field(json, "i2s_sck", &config.i2s_sck, &parse_error) &&
            update_gpio_field(json, "i2s_bck", &config.i2s_bck, &parse_error) &&
            update_gpio_field(json, "i2s_ws", &config.i2s_ws, &parse_error) &&
            update_gpio_field(json, "i2s_do", &config.i2s_do, &parse_error) &&
            update_gpio_field(json, "i2s_gnd", &config.i2s_gnd, &parse_error) &&
            update_gpio_field(json, "i2s_vcc", &config.i2s_vcc, &parse_error) &&
            update_gpio_field(json, "dac_i2c_sda", &config.dac_i2c_sda,
                              &parse_error) &&
            update_gpio_field(json, "dac_i2c_scl", &config.dac_i2c_scl,
                              &parse_error) &&
            update_gpio_field(json, "jack", &config.jack, &parse_error) &&
            update_gpio_field(json, "spkfault", &config.spkfault,
                              &parse_error) &&
            update_gpio_field(json, "mute", &config.mute, &parse_error) &&
            update_gpio_field(json, "led_status", &config.led_status,
                              &parse_error) &&
            update_gpio_field(json, "led_error", &config.led_error,
                              &parse_error) &&
            update_gpio_field(json, "led_rgb", &config.led_rgb, &parse_error) &&
            update_gpio_field(json, "btn_play_pause",
                              &config.btn_play_pause, &parse_error) &&
            update_gpio_field(json, "btn_volume_up",
                              &config.btn_volume_up, &parse_error) &&
            update_gpio_field(json, "btn_volume_down",
                              &config.btn_volume_down, &parse_error) &&
            update_gpio_field(json, "btn_next", &config.btn_next,
                              &parse_error) &&
            update_gpio_field(json, "btn_prev", &config.btn_prev,
                              &parse_error);

  cJSON *response = cJSON_CreateObject();
  if (!ok) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error",
                            parse_error ? parse_error : "Invalid GPIO config");
  } else {
    esp_err_t err = settings_set_gpio_config(&config);
    if (err == ESP_OK) {
      led_prepare_rgb_gpio_change(previous_config.led_rgb, config.led_rgb);
      cJSON_AddBoolToObject(response, "success", true);
      cJSON_AddStringToObject(response, "message",
                              "GPIO config saved. Restarting...");
      should_restart = true;
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    }
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(response);
  cJSON_Delete(json);

  if (should_restart) {
    vTaskDelay(pdMS_TO_TICKS(700));
    esp_restart();
  }

  return ESP_OK;
}

static esp_err_t ota_update_handler(httpd_req_t *req) {
  if (req->content_len == 0) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No firmware uploaded");
    return ESP_FAIL;
  }

  // Stop AirPlay to free resources during OTA
  ESP_LOGI(TAG, "Stopping AirPlay for OTA update");
  rtsp_server_stop();

  esp_err_t err = ota_start_from_http(req);

  if (err != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        esp_err_to_name(err));
    return ESP_FAIL;
  }

  // Send response before restarting
  httpd_resp_sendstr(req, "Firmware update complete, rebooting now!\n");
  vTaskDelay(pdMS_TO_TICKS(500));
  esp_restart();

  return ESP_OK;
}

static esp_err_t storage_update_handler(httpd_req_t *req) {
  bool reboot_after_update = storage_update_should_reboot(req);

  if (req->content_len == 0) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No storage image uploaded");
    return ESP_FAIL;
  }

  const esp_partition_t *storage_partition = find_storage_partition();
  if (!storage_partition) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Storage partition not found");
    return ESP_FAIL;
  }

  if ((size_t)req->content_len != storage_partition->size) {
    char err_msg[160];
    snprintf(err_msg, sizeof(err_msg),
             "Image size mismatch: expected %u bytes for partition '%s', got %d",
             (unsigned)storage_partition->size, STORAGE_PARTITION_LABEL,
             req->content_len);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, err_msg);
    return ESP_FAIL;
  }

  uint8_t *image = heap_caps_malloc((size_t)req->content_len,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!image) {
    image = heap_caps_malloc((size_t)req->content_len, MALLOC_CAP_8BIT);
  }
  if (!image) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Not enough memory for storage image");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Receiving storage image into RAM (%d bytes)...",
           req->content_len);
  size_t received = 0;
  while (received < (size_t)req->content_len) {
    int recv_len = httpd_req_recv(req, (char *)image + received,
                                  (size_t)req->content_len - received);
    if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    }
    if (recv_len <= 0) {
      free(image);
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                          "Failed to receive storage image");
      return ESP_FAIL;
    }
    received += (size_t)recv_len;
  }

  bool was_mounted = spiffs_storage_is_mounted();
  if (was_mounted) {
    spiffs_storage_deinit();
  }

  esp_err_t err =
      esp_partition_erase_range(storage_partition, 0, storage_partition->size);
  if (err != ESP_OK) {
    if (was_mounted) {
      spiffs_storage_init();
    }
    free(image);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Failed to erase storage partition");
    return ESP_FAIL;
  }

  for (size_t offset = 0; offset < (size_t)req->content_len;
       offset += STORAGE_WRITE_CHUNK) {
    size_t chunk =
        ((size_t)req->content_len - offset) < STORAGE_WRITE_CHUNK
            ? (size_t)req->content_len - offset
            : STORAGE_WRITE_CHUNK;
    err = esp_partition_write(storage_partition, offset, image + offset, chunk);
    if (err != ESP_OK) {
      if (was_mounted) {
        spiffs_storage_init();
      }
      free(image);
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                          "Failed to write storage partition");
      return ESP_FAIL;
    }
  }

  free(image);

  ESP_LOGI(TAG, "Storage image updated successfully");
  if (!reboot_after_update && was_mounted) {
    err = spiffs_storage_init();
    if (err != ESP_OK) {
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                          "Storage image written but remount failed");
      return ESP_FAIL;
    }
  }

  if (reboot_after_update) {
    httpd_resp_sendstr(req, "Storage update complete, rebooting now!\n");
    vTaskDelay(pdMS_TO_TICKS(700));
    esp_restart();
  } else {
    httpd_resp_sendstr(req,
                       "Storage update complete, reboot deferred for combined "
                       "OTA flow.\n");
  }

  return ESP_OK;
}

static esp_err_t system_info_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON *info = cJSON_CreateObject();

  char ip_str[16] = {0};
  char mac_str[18] = {0};
  char device_name[65] = {0};
  bool wifi_connected = wifi_is_connected();
  bool eth_connected = ethernet_is_connected();

  // Show IP and MAC for the active interface
  if (eth_connected) {
    ethernet_get_ip_str(ip_str, sizeof(ip_str));
    ethernet_get_mac_str(mac_str, sizeof(mac_str));
  } else {
    wifi_get_ip_str(ip_str, sizeof(ip_str));
    wifi_get_mac_str(mac_str, sizeof(mac_str));
  }
  settings_get_device_name(device_name, sizeof(device_name));

  cJSON_AddStringToObject(info, "ip", ip_str);
  cJSON_AddStringToObject(info, "mac", mac_str);
  cJSON_AddStringToObject(info, "device_name", device_name);
  cJSON_AddBoolToObject(info, "wifi_connected", wifi_connected);
  cJSON_AddBoolToObject(info, "eth_connected", eth_connected);
  cJSON_AddNumberToObject(info, "free_heap", esp_get_free_heap_size());

  // WiFi link diagnostics (only meaningful when associated as STA)
  if (wifi_connected) {
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
      char ssid_buf[33];
      size_t slen = strnlen((const char *)ap.ssid, sizeof(ap.ssid));
      if (slen > sizeof(ssid_buf) - 1)
        slen = sizeof(ssid_buf) - 1;
      memcpy(ssid_buf, ap.ssid, slen);
      ssid_buf[slen] = '\0';
      char bssid_buf[18];
      snprintf(bssid_buf, sizeof(bssid_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
               ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4],
               ap.bssid[5]);
      const char *phy = "?";
      if (ap.phy_11n)
        phy = "11n";
      else if (ap.phy_11g)
        phy = "11g";
      else if (ap.phy_11b)
        phy = "11b";
      else if (ap.phy_lr)
        phy = "LR";
      cJSON_AddStringToObject(info, "wifi_ssid", ssid_buf);
      cJSON_AddStringToObject(info, "wifi_bssid", bssid_buf);
      cJSON_AddNumberToObject(info, "wifi_rssi", ap.rssi);
      cJSON_AddNumberToObject(info, "wifi_channel", ap.primary);
      cJSON_AddStringToObject(info, "wifi_phy", phy);
    }
  }
  const esp_app_desc_t *app_desc = esp_app_get_description();
  cJSON_AddStringToObject(info, "firmware_version", app_desc->version);
#ifdef CONFIG_DAC_TAS58XX
  cJSON_AddBoolToObject(info, "eq_supported", true);
#else
  cJSON_AddBoolToObject(info, "eq_supported", false);
#endif

  cJSON_AddItemToObject(json, "info", info);
  cJSON_AddBoolToObject(json, "success", true);

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  return ESP_OK;
}

static esp_err_t system_restart_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "success", true);

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  ESP_LOGI(TAG, "Restart requested via web interface");
  vTaskDelay(pdMS_TO_TICKS(500));
  esp_restart();

  return ESP_OK;
}

static esp_err_t wifi_enable_ap_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  esp_err_t err = wifi_enable_ap_mode();
  if (err == ESP_OK) {
    err = dns_server_start(AP_IP_ADDR);
  }

  if (err == ESP_OK) {
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(
        json, "message",
        "AP hotspot enabled. Connect to the setup SSID and open 192.168.4.1.");
  } else {
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "error", esp_err_to_name(err));
  }

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t wifi_reset_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  esp_err_t err = settings_clear_wifi_credentials();

  if (err == ESP_OK) {
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(
        json, "message",
        "WiFi credentials cleared. Restarting into AP provisioning mode.");
  } else {
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "error", esp_err_to_name(err));
  }

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  if (err == ESP_OK) {
    ESP_LOGI(TAG, "WiFi reset requested via web interface");
    vTaskDelay(pdMS_TO_TICKS(700));
    esp_restart();
  }

  return ESP_OK;
}

/* ================================================================== */
/*  SPIFFS File Management API                                         */
/* ================================================================== */

// Allowed path prefixes for file upload (prevent writes outside SPIFFS)
static const char *ALLOWED_PREFIXES[] = {"/spiffs/"};

static bool is_path_allowed(const char *path) {
  for (int i = 0; i < sizeof(ALLOWED_PREFIXES) / sizeof(ALLOWED_PREFIXES[0]);
       i++) {
    if (strncmp(path, ALLOWED_PREFIXES[i], strlen(ALLOWED_PREFIXES[i])) == 0) {
      // Reject path traversal
      if (strstr(path, "..") != NULL) {
        return false;
      }
      return true;
    }
  }
  return false;
}

static esp_err_t fs_upload_handler(httpd_req_t *req) {
  // Get target path from query string
  char query[128] = {0};
  char path[64] = {0};

  if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
      httpd_query_key_value(query, "path", path, sizeof(path)) != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                        "Missing 'path' query parameter");
    return ESP_FAIL;
  }

  if (!is_path_allowed(path)) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Path not allowed");
    return ESP_FAIL;
  }

  if (req->content_len == 0 || req->content_len > (size_t)(64 * 1024)) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Body required (max 64KB)");
    return ESP_FAIL;
  }

  FILE *f = fopen(path, "wb");
  if (!f) {
    ESP_LOGE(TAG, "Failed to create %s", path);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Failed to create file");
    return ESP_FAIL;
  }

  char buf[SPIFFS_CHUNK_SIZE];
  size_t remaining = req->content_len;
  while (remaining > 0) {
    size_t to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
    int received = httpd_req_recv(req, buf, to_read);
    if (received <= 0) {
      fclose(f);
      remove(path);
      httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                          "Receive failed");
      return ESP_FAIL;
    }
    fwrite(buf, 1, (size_t)received, f);
    remaining -= (size_t)received;
  }
  fclose(f);

  ESP_LOGI(TAG, "Uploaded %u bytes to %s", (unsigned)req->content_len, path);

  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "success", true);
  cJSON_AddNumberToObject(json, "size", (double)req->content_len);
  cJSON_AddStringToObject(json, "path", path);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t fs_delete_handler(httpd_req_t *req) {
  char query[128] = {0};
  char path[64] = {0};

  if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
      httpd_query_key_value(query, "path", path, sizeof(path)) != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                        "Missing 'path' query parameter");
    return ESP_FAIL;
  }

  if (!is_path_allowed(path)) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Path not allowed");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_CreateObject();
  if (remove(path) == 0) {
    ESP_LOGI(TAG, "Deleted %s", path);
    cJSON_AddBoolToObject(json, "success", true);
  } else {
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "error", "File not found");
  }
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t fs_list_handler(httpd_req_t *req) {
  char query[128] = {0};
  char dir_path[64] = "/spiffs";

  if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
    httpd_query_key_value(query, "dir", dir_path, sizeof(dir_path));
  }

  if (!is_path_allowed(dir_path) && strcmp(dir_path, "/spiffs") != 0) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Path not allowed");
    return ESP_FAIL;
  }

  DIR *d = opendir(dir_path);
  cJSON *json = cJSON_CreateObject();
  cJSON *files = cJSON_CreateArray();

  if (d) {
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
      cJSON *item = cJSON_CreateObject();
      cJSON_AddStringToObject(item, "name", entry->d_name);

      char full_path[320];
      snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
      struct stat st;
      if (stat(full_path, &st) == 0) {
        cJSON_AddNumberToObject(item, "size", (double)st.st_size);
      }
      cJSON_AddItemToArray(files, item);
    }
    closedir(d);
    cJSON_AddBoolToObject(json, "success", true);
  } else {
    cJSON_AddBoolToObject(json, "success", false);
    cJSON_AddStringToObject(json, "error", "Cannot open directory");
  }

  cJSON_AddItemToObject(json, "files", files);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

/* ================================================================== */
/*  EQ Page + API  (only when TAS58xx DAC is configured)               */
/* ================================================================== */

#ifdef CONFIG_DAC_TAS58XX

static esp_err_t eq_page_handler(httpd_req_t *req) {
  return serve_spiffs_file(req, "/spiffs/www/eq.html", "text/html");
}

static esp_err_t eq_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON *arr = cJSON_CreateArray();

  float gains[SETTINGS_EQ_BANDS];
  if (settings_get_eq_gains(gains) == ESP_OK) {
    for (int i = 0; i < SETTINGS_EQ_BANDS; i++) {
      cJSON_AddItemToArray(arr, cJSON_CreateNumber((double)gains[i]));
    }
  } else {
    /* No saved EQ — return all zeros (flat) */
    for (int i = 0; i < SETTINGS_EQ_BANDS; i++) {
      cJSON_AddItemToArray(arr, cJSON_CreateNumber(0.0));
    }
  }

  cJSON_AddItemToObject(json, "gains", arr);
  cJSON_AddNumberToObject(json, "bands", SETTINGS_EQ_BANDS);
  cJSON_AddBoolToObject(json, "success", true);

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t eq_post_handler(httpd_req_t *req) {
  char content[JSON_BODY_MAX];
  if (read_request_body(req, content, sizeof(content)) != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request body");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *gains_arr = cJSON_GetObjectItem(json, "gains");

  if (gains_arr && cJSON_IsArray(gains_arr) &&
      cJSON_GetArraySize(gains_arr) == SETTINGS_EQ_BANDS) {

    float gains[SETTINGS_EQ_BANDS];
    for (int i = 0; i < SETTINGS_EQ_BANDS; i++) {
      cJSON *item = cJSON_GetArrayItem(gains_arr, i);
      gains[i] = cJSON_IsNumber(item) ? (float)item->valuedouble : 0.0f;
      /* Clamp */
      if (gains[i] > 15.0f) {
        gains[i] = 15.0f;
      }
      if (gains[i] < -15.0f) {
        gains[i] = -15.0f;
      }
    }

    /* Emit event — listeners (settings + DAC) will handle it */
    eq_event_data_t ev_data;
    memcpy(ev_data.all_bands.gains_db, gains, sizeof(gains));
    eq_events_emit(EQ_EVENT_ALL_BANDS_SET, &ev_data);

    cJSON_AddBoolToObject(response, "success", true);
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error",
                            "Expected 'gains' array with 15 values");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);
  return ESP_OK;
}

#endif /* CONFIG_DAC_TAS58XX */

esp_err_t web_server_start(uint16_t port) {
  if (s_server) {
    ESP_LOGW(TAG, "Web server already running");
    return ESP_OK;
  }

  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = port;
#ifdef CONFIG_BT_ENABLED
  config.max_open_sockets = 2;   // BT: tighter socket budget (LWIP 12)
  config.send_wait_timeout = 10; // BT/WiFi coexistence slows TCP drain
#else
  config.max_open_sockets = 3; // Limit to save lwIP socket slots for AirPlay
#endif
  config.lru_purge_enable = true; // Reclaim stale sockets when all are in use
  config.max_uri_handlers = 28;   // Room for captive portal + EQ + GPIO APIs
  config.max_resp_headers = 8;
  config.stack_size = 8192;

  esp_err_t err = httpd_start(&s_server, &config);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start web server: %s", esp_err_to_name(err));
    return err;
  }

  // Register handlers
  httpd_uri_t root_uri = {
      .uri = "/", .method = HTTP_GET, .handler = root_handler};
  httpd_register_uri_handler(s_server, &root_uri);

  httpd_uri_t favicon_uri = {
      .uri = "/favicon.ico", .method = HTTP_GET, .handler = favicon_handler};
  httpd_register_uri_handler(s_server, &favicon_uri);

  httpd_uri_t logs_uri = {
      .uri = "/logs", .method = HTTP_GET, .handler = logs_page_handler};
  httpd_register_uri_handler(s_server, &logs_uri);

  httpd_uri_t speedtest_page_uri = {.uri = "/speedtest",
                                    .method = HTTP_GET,
                                    .handler = speedtest_page_handler};
  httpd_register_uri_handler(s_server, &speedtest_page_uri);

  httpd_uri_t speedtest_ping_uri = {.uri = "/api/speedtest/ping",
                                    .method = HTTP_GET,
                                    .handler = speedtest_ping_handler};
  httpd_register_uri_handler(s_server, &speedtest_ping_uri);

  httpd_uri_t speedtest_dl_uri = {.uri = "/api/speedtest/download",
                                  .method = HTTP_GET,
                                  .handler = speedtest_download_handler};
  httpd_register_uri_handler(s_server, &speedtest_dl_uri);

  httpd_uri_t speedtest_ul_uri = {.uri = "/api/speedtest/upload",
                                  .method = HTTP_POST,
                                  .handler = speedtest_upload_handler};
  httpd_register_uri_handler(s_server, &speedtest_ul_uri);

  httpd_uri_t wifi_scan_uri = {.uri = "/api/wifi/scan",
                               .method = HTTP_GET,
                               .handler = wifi_scan_handler};
  httpd_register_uri_handler(s_server, &wifi_scan_uri);

  httpd_uri_t wifi_config_uri = {.uri = "/api/wifi/config",
                                 .method = HTTP_POST,
                                 .handler = wifi_config_handler};
  httpd_register_uri_handler(s_server, &wifi_config_uri);

  httpd_uri_t wifi_enable_ap_uri = {.uri = "/api/wifi/enable-ap",
                                    .method = HTTP_POST,
                                    .handler = wifi_enable_ap_handler};
  httpd_register_uri_handler(s_server, &wifi_enable_ap_uri);

  httpd_uri_t wifi_reset_uri = {.uri = "/api/wifi/reset",
                                .method = HTTP_POST,
                                .handler = wifi_reset_handler};
  httpd_register_uri_handler(s_server, &wifi_reset_uri);

  httpd_uri_t device_name_uri = {.uri = "/api/device/name",
                                 .method = HTTP_POST,
                                 .handler = device_name_handler};
  httpd_register_uri_handler(s_server, &device_name_uri);

  httpd_uri_t gpio_config_get_uri = {.uri = "/api/gpio/config",
                                     .method = HTTP_GET,
                                     .handler = gpio_config_get_handler};
  httpd_register_uri_handler(s_server, &gpio_config_get_uri);

  httpd_uri_t gpio_config_post_uri = {.uri = "/api/gpio/config",
                                      .method = HTTP_POST,
                                      .handler = gpio_config_post_handler};
  httpd_register_uri_handler(s_server, &gpio_config_post_uri);

  httpd_uri_t ota_uri = {.uri = "/api/ota/update",
                         .method = HTTP_POST,
                         .handler = ota_update_handler};
  httpd_register_uri_handler(s_server, &ota_uri);

  httpd_uri_t storage_update_uri = {.uri = "/api/storage/update",
                                    .method = HTTP_POST,
                                    .handler = storage_update_handler};
  httpd_register_uri_handler(s_server, &storage_update_uri);

  httpd_uri_t system_info_uri = {.uri = "/api/system/info",
                                 .method = HTTP_GET,
                                 .handler = system_info_handler};
  httpd_register_uri_handler(s_server, &system_info_uri);

  httpd_uri_t system_restart_uri = {.uri = "/api/system/restart",
                                    .method = HTTP_POST,
                                    .handler = system_restart_handler};
  httpd_register_uri_handler(s_server, &system_restart_uri);

  // File management API
  httpd_uri_t fs_upload_uri = {.uri = "/api/fs/upload",
                               .method = HTTP_POST,
                               .handler = fs_upload_handler};
  httpd_register_uri_handler(s_server, &fs_upload_uri);

  httpd_uri_t fs_delete_uri = {.uri = "/api/fs/delete",
                               .method = HTTP_POST,
                               .handler = fs_delete_handler};
  httpd_register_uri_handler(s_server, &fs_delete_uri);

  httpd_uri_t fs_list_uri = {
      .uri = "/api/fs/list", .method = HTTP_GET, .handler = fs_list_handler};
  httpd_register_uri_handler(s_server, &fs_list_uri);

  // Captive portal detection endpoints
  // Apple iOS/macOS
  httpd_uri_t apple_captive1 = {.uri = "/hotspot-detect.html",
                                .method = HTTP_GET,
                                .handler = captive_apple_handler};
  httpd_register_uri_handler(s_server, &apple_captive1);

  httpd_uri_t apple_captive2 = {.uri = "/library/test/success.html",
                                .method = HTTP_GET,
                                .handler = captive_apple_handler};
  httpd_register_uri_handler(s_server, &apple_captive2);

  // Android
  httpd_uri_t android_captive = {.uri = "/generate_204",
                                 .method = HTTP_GET,
                                 .handler = captive_android_handler};
  httpd_register_uri_handler(s_server, &android_captive);

  // Windows
  httpd_uri_t windows_captive = {.uri = "/connecttest.txt",
                                 .method = HTTP_GET,
                                 .handler = captive_windows_handler};
  httpd_register_uri_handler(s_server, &windows_captive);

#ifdef CONFIG_DAC_TAS58XX
  httpd_uri_t eq_page_uri = {
      .uri = "/eq", .method = HTTP_GET, .handler = eq_page_handler};
  httpd_register_uri_handler(s_server, &eq_page_uri);

  httpd_uri_t eq_get_uri = {
      .uri = "/api/eq", .method = HTTP_GET, .handler = eq_get_handler};
  httpd_register_uri_handler(s_server, &eq_get_uri);

  httpd_uri_t eq_post_uri = {
      .uri = "/api/eq", .method = HTTP_POST, .handler = eq_post_handler};
  httpd_register_uri_handler(s_server, &eq_post_uri);
#endif

  log_stream_register(s_server);

  ESP_LOGI(TAG, "Web server started on port %d with captive portal support",
           port);
  return ESP_OK;
}

void web_server_stop(void) {
  if (s_server) {
    httpd_stop(s_server);
    s_server = NULL;
    ESP_LOGI(TAG, "Web server stopped");
  }
}
