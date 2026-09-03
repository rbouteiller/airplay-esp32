#include "web_server.h"

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_wifi.h"

#include "playback_control.h"
#include "settings.h"
#include "led.h"
#include "wifi.h"
#include "ethernet.h"
#include "ota.h"
#include "log_stream.h"
#include "rtsp_server.h"
#include "playback_events.h"
#include "audio_output.h"
#include "esp_app_desc.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef CONFIG_SENDSPIN_ENABLE
#include "sendspin.h"
#endif

#ifdef CONFIG_DAC_TAS58XX
#include "dac_tas58xx.h"
#endif

#ifdef CONFIG_DAC_TAS57XX
#include "dac_tas57xx.h"
#endif

/* Sub level-trim (2.1 subwoofer) is a TAS57xx concept: that driver flags one
 * device as the sub and offsets it from the master volume. The TAS58xx driver
 * trims every amplifier independently instead, through /api/bq. */
#if defined(CONFIG_DAC_TAS57XX)
#define DAC_HAS_SUB_OFFSET       1
#define DAC_SUB_OFFSET_MIN_DB    TAS57XX_SUB_OFFSET_MIN_DB
#define DAC_SUB_OFFSET_MAX_DB    TAS57XX_SUB_OFFSET_MAX_DB
#define dac_get_sub_offset_db()  dac_tas57xx_get_sub_offset_db()
#define dac_set_sub_offset_db(x) dac_tas57xx_set_sub_offset_db(x)
/* The trim only moves devices flagged is_sub, which is index > 0, so a
 * single-amplifier board has nothing for it to act on. */
#define dac_has_sub() (dac_tas57xx_get_device_count() > 1)
/* Per-channel level and mute, which only the TAS57xx driver implements. */
#define DAC_HAS_CH_TRIM    1
#define DAC_CH_TRIM_MIN_DB TAS57XX_CH_TRIM_MIN_DB
#define DAC_CH_TRIM_MAX_DB TAS57XX_CH_TRIM_MAX_DB
#endif

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;

#define SPIFFS_CHUNK_SIZE 1024

static esp_err_t serve_spiffs_file(httpd_req_t *req, const char *path,
                                   const char *content_type) {
  // The image only ever stores <path>.gz, so trying the plain name first is
  // what lets a page uploaded over /api/fs replace the one that shipped.
  bool gzipped = false;
  FILE *f = fopen(path, "r");
  if (!f) {
    char gz_path[96];
    snprintf(gz_path, sizeof(gz_path), "%s.gz", path);
    gzipped = true;
    f = fopen(gz_path, "r");
  }
  if (!f) {
    ESP_LOGE(TAG, "Failed to open %s", path);
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    return ESP_FAIL;
  }
  httpd_resp_set_type(req, content_type);
  if (gzipped) {
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
  }
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
#define SPEEDTEST_MAX_BYTES ((size_t)16 * 1024 * 1024)
#define SPEEDTEST_CHUNK     2048

static esp_err_t speedtest_download_handler(httpd_req_t *req) {
  size_t bytes = (size_t)1024 * 1024;
  char qbuf[64];
  if (httpd_req_get_url_query_str(req, qbuf, sizeof(qbuf)) == ESP_OK) {
    char val[16];
    if (httpd_query_key_value(qbuf, "bytes", val, sizeof(val)) == ESP_OK) {
      long v = strtol(val, NULL, 10);
      if (v > 0) {
        bytes = (size_t)v;
      }
    }
  }
  if (bytes > SPEEDTEST_MAX_BYTES) {
    bytes = SPEEDTEST_MAX_BYTES;
  }

  // Reuse a single buffer of filler bytes. Static so we don't repeatedly
  // hammer the heap; content is irrelevant but non-zero to thwart any
  // compression along the way.
  static uint8_t filler[SPEEDTEST_CHUNK];
  static bool filler_init = false;
  if (!filler_init) {
    for (size_t i = 0; i < sizeof(filler); i++) {
      filler[i] = (uint8_t)(i * 37);
    }
    filler_init = true;
  }

  httpd_resp_set_type(req, "application/octet-stream");
  httpd_resp_set_hdr(req, "Cache-Control", "no-store");

  size_t remaining = bytes;
  while (remaining > 0) {
    ssize_t n =
        remaining < SPEEDTEST_CHUNK ? (ssize_t)remaining : SPEEDTEST_CHUNK;
    if (httpd_resp_send_chunk(req, (const char *)filler, n) != ESP_OK) {
      return ESP_FAIL;
    }
    remaining -= (size_t)n;
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
    if (want > sizeof(buf)) {
      want = sizeof(buf);
    }
    int r = httpd_req_recv(req, (char *)buf, want);
    if (r <= 0) {
      if (r == HTTPD_SOCK_ERR_TIMEOUT) {
        continue;
      }
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
  char content[512];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

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
  char content[256];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

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
      wifi_set_hostname(name);
      ethernet_set_hostname(name);
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

/* Copy a JSON string field into a fixed metadata slot. Absent or non-string
 * fields are left zeroed, which listeners treat as "unchanged". */
static void metadata_copy_field(const cJSON *json, const char *key, char *dst) {
  const cJSON *item = cJSON_GetObjectItem(json, key);
  if (cJSON_IsString(item) && item->valuestring != NULL) {
    snprintf(dst, METADATA_STRING_MAX, "%s", item->valuestring);
  }
}

static uint32_t metadata_uint_field(const cJSON *json, const char *key) {
  const cJSON *item = cJSON_GetObjectItem(json, key);
  if (cJSON_IsNumber(item) && item->valuedouble > 0) {
    return (uint32_t)item->valuedouble;
  }
  return 0;
}

/* Push now-playing info from an external source, e.g. a host-side helper
 * feeding metadata for USB audio, which UAC itself cannot carry. */
static esp_err_t metadata_post_handler(httpd_req_t *req) {
  char content[512];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  playback_event_data_t data = {0};
  metadata_copy_field(json, "title", data.metadata.title);
  metadata_copy_field(json, "artist", data.metadata.artist);
  metadata_copy_field(json, "album", data.metadata.album);
  metadata_copy_field(json, "genre", data.metadata.genre);
  data.metadata.duration_secs = metadata_uint_field(json, "duration");
  data.metadata.position_secs = metadata_uint_field(json, "position");
  cJSON_Delete(json);

  // Debug/manual injection: attribute it to whichever input owns the display
  // so it is not filtered out, or to AirPlay when the device is idle.
  const playback_source_t active = playback_events_active_source();
  playback_events_emit(active == PLAYBACK_SOURCE_NONE ? PLAYBACK_SOURCE_AIRPLAY
                                                      : active,
                       PLAYBACK_EVENT_METADATA, &data);

  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, "{\"success\":true}", HTTPD_RESP_USE_STRLEN);
  return ESP_OK;
}

static esp_err_t led_brightness_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "brightness", led_get_brightness());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t led_brightness_post_handler(httpd_req_t *req) {
  char content[64];
  int ret = httpd_req_recv(req, content, sizeof(content) - 1);
  if (ret <= 0) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  content[ret] = '\0';

  cJSON *json = cJSON_Parse(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *val = cJSON_GetObjectItem(json, "brightness");
  if (val && cJSON_IsNumber(val)) {
    int b = (int)val->valuedouble;
    if (b < 0) {
      b = 0;
    }
    if (b > 255) {
      b = 255;
    }
    esp_err_t err = led_set_brightness((uint8_t)b);
    if (err == ESP_OK) {
      cJSON_AddBoolToObject(response, "success", true);
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    }
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error",
                            "Expected {\"brightness\": 0-255}");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);
  return ESP_OK;
}

/* Read a whole request body into a NUL-terminated heap buffer. httpd_req_recv()
 * can return a short read, so keep going until the declared length arrives. */
static char *recv_body(httpd_req_t *req, size_t max_len) {
  int len = req->content_len;
  if (len <= 0 || (size_t)len > max_len) {
    return NULL;
  }
  char *buf = malloc((size_t)len + 1);
  if (!buf) {
    return NULL;
  }
  int got = 0;
  while (got < len) {
    int r = httpd_req_recv(req, buf + got, (size_t)(len - got));
    if (r <= 0) {
      free(buf);
      return NULL;
    }
    got += r;
  }
  buf[len] = '\0';
  return buf;
}

/* True for a JSON number that is a whole value inside [lo, hi]. */
static bool json_int_in_range(const cJSON *v, int lo, int hi) {
  return cJSON_IsNumber(v) && v->valuedouble == (double)v->valueint &&
         v->valueint >= lo && v->valueint <= hi;
}

static esp_err_t channel_mode_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "mode", audio_output_get_channel_mode());
  cJSON_AddBoolToObject(json, "locked", audio_output_channel_mode_locked());
  cJSON_AddBoolToObject(json, "dsp", audio_output_channel_mode_in_dsp());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t channel_mode_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 128);
  if (!content) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  free(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *val = cJSON_GetObjectItem(json, "mode");
  if (json_int_in_range(val, AUDIO_CHANNEL_STEREO, AUDIO_CHANNEL_MONO)) {
    audio_output_set_channel_mode((audio_channel_mode_t)val->valueint);
    cJSON_AddBoolToObject(response, "success", true);
    /* Boards with two amplifiers keep stereo whatever was asked for. */
    cJSON_AddNumberToObject(response, "mode", audio_output_get_channel_mode());
    cJSON_AddBoolToObject(response, "locked",
                          audio_output_channel_mode_locked());
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Expected {\"mode\": 0-3}");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);
  return ESP_OK;
}

/* AirPlay dB scale, matching playback_control's clamp. */
#define VOLUME_UI_MIN_DB -30.0f
#define VOLUME_UI_MAX_DB 0.0f

static esp_err_t volume_get_handler(httpd_req_t *req) {
  float db = -15.0f;
  settings_get_volume(&db);
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "volume_db", db);
  cJSON_AddNumberToObject(json, "min", VOLUME_UI_MIN_DB);
  cJSON_AddNumberToObject(json, "max", VOLUME_UI_MAX_DB);
  cJSON_AddBoolToObject(json, "muted", playback_control_is_muted());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t volume_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 512);
  if (!content) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
    return ESP_FAIL;
  }
  cJSON *json = cJSON_Parse(content);
  free(content);
  cJSON *val = json ? cJSON_GetObjectItem(json, "volume_db") : NULL;
  if (!cJSON_IsNumber(val)) {
    cJSON_Delete(json);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Expected volume_db");
    return ESP_FAIL;
  }
  float db = (float)val->valuedouble;
  bool persist = cJSON_IsTrue(cJSON_GetObjectItem(json, "persist"));
  cJSON_Delete(json);
  if (db < VOLUME_UI_MIN_DB) {
    db = VOLUME_UI_MIN_DB;
  }
  if (db > VOLUME_UI_MAX_DB) {
    db = VOLUME_UI_MAX_DB;
  }
  settings_set_volume(db);
  if (persist) {
    settings_persist_volume();
  }

  cJSON *response = cJSON_CreateObject();
  cJSON_AddBoolToObject(response, "success", true);
  cJSON_AddNumberToObject(response, "volume_db", db);
  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(response);
  return ESP_OK;
}

#ifdef DAC_HAS_SUB_OFFSET
static esp_err_t sub_offset_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "offset", dac_get_sub_offset_db());
  cJSON_AddNumberToObject(json, "min", DAC_SUB_OFFSET_MIN_DB);
  cJSON_AddNumberToObject(json, "max", DAC_SUB_OFFSET_MAX_DB);
  cJSON_AddBoolToObject(json, "available", dac_has_sub());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t sub_offset_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 2048);
  if (!content) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  free(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *val = cJSON_GetObjectItem(json, "offset");
  if (val && cJSON_IsNumber(val)) {
    float off = (float)val->valuedouble;
    if (off < DAC_SUB_OFFSET_MIN_DB) {
      off = DAC_SUB_OFFSET_MIN_DB;
    }
    if (off > DAC_SUB_OFFSET_MAX_DB) {
      off = DAC_SUB_OFFSET_MAX_DB;
    }
    dac_set_sub_offset_db(off);
    if (settings_set_sub_offset(off) == ESP_OK) {
      cJSON_AddBoolToObject(response, "success", true);
    } else {
      cJSON_AddBoolToObject(response, "success", false);
      cJSON_AddStringToObject(response, "error", "Applied but could not save");
    }
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Expected {\"offset\": dB}");
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);
  return ESP_OK;
}
#endif /* DAC_HAS_SUB_OFFSET */

#ifdef DAC_HAS_CH_TRIM
static void ch_trim_add_state(cJSON *json) {
  cJSON *arr = cJSON_AddArrayToObject(json, "channels");
  for (int ch = 0; ch < TAS57XX_CHANNELS; ch++) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "trim", dac_tas57xx_get_channel_trim_db(ch));
    cJSON_AddBoolToObject(o, "mute", dac_tas57xx_get_channel_mute(ch));
    cJSON_AddItemToArray(arr, o);
  }
  cJSON_AddNumberToObject(json, "min", DAC_CH_TRIM_MIN_DB);
  cJSON_AddNumberToObject(json, "max", DAC_CH_TRIM_MAX_DB);
}

static esp_err_t ch_trim_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  ch_trim_add_state(json);
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t ch_trim_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 512);
  if (!content) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  free(content);
  cJSON *arr = json ? cJSON_GetObjectItem(json, "channels") : NULL;
  if (!cJSON_IsArray(arr) || cJSON_GetArraySize(arr) != TAS57XX_CHANNELS) {
    cJSON_Delete(json);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                        "Expected {\"channels\":[{\"trim\":dB,\"mute\":bool},"
                        "{...}]}");
    return ESP_FAIL;
  }

  /* Mute is a listening aid rather than a setting, so only the trims are
   * written back to NVS. */
  bool trim_changed = false;
  for (int ch = 0; ch < TAS57XX_CHANNELS; ch++) {
    cJSON *o = cJSON_GetArrayItem(arr, ch);
    cJSON *trim = cJSON_GetObjectItem(o, "trim");
    cJSON *mute = cJSON_GetObjectItem(o, "mute");
    if (cJSON_IsNumber(trim)) {
      dac_tas57xx_set_channel_trim_db(ch, (float)trim->valuedouble);
      trim_changed = true;
    }
    if (cJSON_IsBool(mute)) {
      dac_tas57xx_set_channel_mute(ch, cJSON_IsTrue(mute));
    }
  }
  cJSON_Delete(json);

  esp_err_t save_err = ESP_OK;
  if (trim_changed) {
    float saved[TAS57XX_CHANNELS];
    for (int ch = 0; ch < TAS57XX_CHANNELS; ch++) {
      saved[ch] = dac_tas57xx_get_channel_trim_db(ch);
    }
    save_err = settings_set_channel_trim(saved);
  }

  cJSON *response = cJSON_CreateObject();
  ch_trim_add_state(response);
  if (save_err == ESP_OK) {
    cJSON_AddBoolToObject(response, "success", true);
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Applied but could not save");
  }
  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(response);
  return ESP_OK;
}
#endif /* DAC_HAS_CH_TRIM */

#ifdef CONFIG_DAC_TAS58XX
/* How the second amplifier on a dual-DAC board is wired: bridged (PBTL) mono
 * or a stereo pair. Any crossover between the two is a matter for the biquad
 * chains, so this is the whole of the dual-DAC configuration. */
static esp_err_t dual_mode_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "devices", dac_tas58xx_get_device_count());
  cJSON_AddBoolToObject(json, "pbtl", dac_tas58xx_get_second_pbtl());
  cJSON_AddBoolToObject(json, "restart_required",
                        dac_tas58xx_get_second_pbtl() !=
                            dac_tas58xx_get_active_second_pbtl());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t dual_mode_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 128);
  if (!content) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  free(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *val = cJSON_GetObjectItem(json, "pbtl");
  if (!val || !cJSON_IsBool(val)) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Expected {\"pbtl\": bool}");
  } else {
    const bool pbtl = cJSON_IsTrue(val);
    dac_tas58xx_set_second_pbtl(pbtl);
    settings_set_second_pbtl(pbtl);
    cJSON_AddBoolToObject(response, "success", true);
    /* PBTL is a control-port setting that can only be changed while the
     * output stage is idle, so the change lands on the next boot. */
    cJSON_AddBoolToObject(response, "restart_required", true);
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

static esp_err_t airplay_mode_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "v1", settings_airplay_v1_configured());
  cJSON_AddNumberToObject(json, "port", airplay_rtsp_port());
  cJSON_AddBoolToObject(json, "restart_required",
                        settings_airplay_v1_configured() !=
                            settings_airplay_v1());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t airplay_mode_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 128);
  if (!content) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  free(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *val = cJSON_GetObjectItem(json, "v1");
  if (!val || !cJSON_IsBool(val)) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Expected {\"v1\": bool}");
  } else {
    const bool v1 = cJSON_IsTrue(val);
    esp_err_t err = settings_set_airplay_v1(v1);
    cJSON_AddBoolToObject(response, "success", err == ESP_OK);
    if (err != ESP_OK) {
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    } else {
      // The mDNS records and the RTSP listener are both built at startup.
      cJSON_AddBoolToObject(response, "restart_required",
                            v1 != settings_airplay_v1());
    }
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);
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

static const char *reset_reason_str(esp_reset_reason_t r) {
  switch (r) {
  case ESP_RST_POWERON:
    return "poweron";
  case ESP_RST_EXT:
    return "external";
  case ESP_RST_SW:
    return "software";
  case ESP_RST_PANIC:
    return "panic";
  case ESP_RST_INT_WDT:
    return "int_wdt";
  case ESP_RST_TASK_WDT:
    return "task_wdt";
  case ESP_RST_WDT:
    return "other_wdt";
  case ESP_RST_DEEPSLEEP:
    return "deepsleep";
  case ESP_RST_BROWNOUT:
    return "brownout";
  case ESP_RST_SDIO:
    return "sdio";
  default:
    return "unknown";
  }
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
      if (slen > sizeof(ssid_buf) - 1) {
        slen = sizeof(ssid_buf) - 1;
      }
      memcpy(ssid_buf, ap.ssid, slen);
      ssid_buf[slen] = '\0';
      char bssid_buf[18];
      snprintf(bssid_buf, sizeof(bssid_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
               ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4],
               ap.bssid[5]);
      const char *phy = "?";
      if (ap.phy_11n) {
        phy = "11n";
      } else if (ap.phy_11g) {
        phy = "11g";
      } else if (ap.phy_11b) {
        phy = "11b";
      } else if (ap.phy_lr) {
        phy = "LR";
      }
      cJSON_AddStringToObject(info, "wifi_ssid", ssid_buf);
      cJSON_AddStringToObject(info, "wifi_bssid", bssid_buf);
      cJSON_AddNumberToObject(info, "wifi_rssi", ap.rssi);
      cJSON_AddNumberToObject(info, "wifi_channel", ap.primary);
      cJSON_AddStringToObject(info, "wifi_phy", phy);
    }
  }
  const esp_app_desc_t *app_desc = esp_app_get_description();
  cJSON_AddStringToObject(info, "firmware_version", app_desc->version);
  cJSON_AddStringToObject(info, "reset_reason",
                          reset_reason_str(esp_reset_reason()));
  cJSON_AddNumberToObject(info, "uptime_s",
                          (double)(esp_timer_get_time() / 1000000));
#ifdef CONFIG_DAC_TAS58XX
  cJSON_AddBoolToObject(info, "eq_supported", true);
#else
  cJSON_AddBoolToObject(info, "eq_supported", false);
#endif
#ifdef DAC_HAS_SUB_OFFSET
  cJSON_AddBoolToObject(info, "sub_supported", dac_has_sub());
#else
  cJSON_AddBoolToObject(info, "sub_supported", false);
#endif
#ifdef CONFIG_DAC_TAS58XX
  cJSON_AddBoolToObject(info, "dual_supported", true);
#else
  cJSON_AddBoolToObject(info, "dual_supported", false);
#endif
#ifdef CONFIG_DAC_TAS57XX
  cJSON_AddBoolToObject(info, "hf1_supported", dac_tas57xx_hf1_available());
  cJSON_AddBoolToObject(info, "hf3_supported", dac_tas57xx_hf3_available());
#else
  cJSON_AddBoolToObject(info, "hf1_supported", false);
  cJSON_AddBoolToObject(info, "hf3_supported", false);
#endif
#ifdef CONFIG_SENDSPIN_ENABLE
  cJSON_AddBoolToObject(info, "sendspin_supported", true);
  cJSON_AddBoolToObject(info, "sendspin_enabled",
                        settings_sendspin_enabled_configured());
  cJSON_AddBoolToObject(info, "sendspin_active", settings_sendspin_enabled());
  /* The two secrets a server needs to adopt this device: the PIN an operator
   * types into a pairing prompt, and the token a server enrols itself with.
   * Anyone who can read either can pair, so they ride on the same
   * authentication as the rest of this API.  Both read empty while Sendspin
   * is switched off, because no identity has been derived. */
  cJSON_AddStringToObject(info, "sendspin_pairing_token",
                          sendspin_pairing_token());
  cJSON_AddStringToObject(info, "sendspin_pairing_pin", sendspin_pairing_pin());
  cJSON_AddNumberToObject(info, "sendspin_paired", sendspin_paired_count());
#else
  cJSON_AddBoolToObject(info, "sendspin_supported", false);
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

#ifdef CONFIG_SENDSPIN_ENABLE
static esp_err_t sendspin_mode_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "enabled",
                        settings_sendspin_enabled_configured());
  cJSON_AddBoolToObject(json, "restart_required",
                        settings_sendspin_enabled_configured() !=
                            settings_sendspin_enabled());
  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

static esp_err_t sendspin_mode_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 128);
  if (!content) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(content);
  free(content);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  cJSON *response = cJSON_CreateObject();
  cJSON *val = cJSON_GetObjectItem(json, "enabled");
  if (!val || !cJSON_IsBool(val)) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Expected {\"enabled\": bool}");
  } else {
    const bool enabled = cJSON_IsTrue(val);
    esp_err_t err = settings_set_sendspin_enabled(enabled);
    cJSON_AddBoolToObject(response, "success", err == ESP_OK);
    if (err != ESP_OK) {
      cJSON_AddStringToObject(response, "error", esp_err_to_name(err));
    } else {
      cJSON_AddBoolToObject(response, "restart_required",
                            enabled != settings_sendspin_enabled());
    }
  }

  char *json_str = cJSON_Print(response);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  cJSON_Delete(response);
  return ESP_OK;
}

static esp_err_t sendspin_unpair_handler(httpd_req_t *req) {
  bool force = false;
  char qbuf[64];
  if (httpd_req_get_url_query_str(req, qbuf, sizeof(qbuf)) == ESP_OK) {
    char val[8];
    if (httpd_query_key_value(qbuf, "force", val, sizeof(val)) == ESP_OK) {
      force = strcmp(val, "1") == 0 || strcmp(val, "true") == 0;
    }
  }

  /* Forgetting only this side leaves the server offering a PSK the board can
   * no longer resolve, and that handshake fails silently at both ends.  While
   * a server is connected it can be unpaired from its own UI, which prunes
   * both records, so send the operator there rather than into the deadlock. */
  if (!force && sendspin_paired_count() > 0 && sendspin_server_connected()) {
    httpd_resp_set_status(req, "409 Conflict");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(
        req,
        "{\"success\":false,\"error\":\"a server is connected; unpair from the "
        "server so both sides forget, or repeat with ?force=1\"}");
    return ESP_OK;
  }

  const esp_err_t err = sendspin_forget_pairings();
  if (err == ESP_ERR_INVALID_STATE) {
    httpd_resp_set_status(req, "409 Conflict");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(
        req, "{\"success\":false,\"error\":\"Sendspin is not running\"}");
    return ESP_OK;
  }
  if (err != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        esp_err_to_name(err));
    return ESP_FAIL;
  }

  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "success", true);
  cJSON_AddNumberToObject(json, "sendspin_paired", sendspin_paired_count());

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  ESP_LOGI(TAG, "Sendspin pairings cleared via web interface");
  return ESP_OK;
}

static esp_err_t sendspin_reset_identity_handler(httpd_req_t *req) {
  const esp_err_t err = sendspin_reset_identity();
  if (err == ESP_ERR_INVALID_STATE) {
    httpd_resp_set_status(req, "409 Conflict");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(
        req, "{\"success\":false,\"error\":\"Sendspin is not running\"}");
    return ESP_OK;
  }
  if (err != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                        esp_err_to_name(err));
    return ESP_FAIL;
  }

  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "success", true);
  cJSON_AddStringToObject(json, "sendspin_pairing_token",
                          sendspin_pairing_token());
  cJSON_AddNumberToObject(json, "sendspin_paired", sendspin_paired_count());

  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);

  ESP_LOGI(TAG, "Sendspin identity reset via web interface");
  return ESP_OK;
}
#endif

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

  /* The body is streamed to the file a chunk at a time and never held whole,
   * so this is only here to keep a runaway request from filling the 1.9MB
   * SPIFFS. It has to clear the largest asset we upload, which is the display
   * background at ~110KB. */
  if (req->content_len == 0 || req->content_len > (size_t)(256 * 1024)) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                        "Body required (max 256KB)");
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

/* Pulling a file back off the device is the only way to take an exact copy of
 * a tuned hybrid flow, whose committed coefficients live nowhere else. */
static esp_err_t fs_download_handler(httpd_req_t *req) {
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

  FILE *f = fopen(path, "rb");
  if (!f) {
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
    return ESP_FAIL;
  }

  httpd_resp_set_type(req, "application/octet-stream");
  char buf[SPIFFS_CHUNK_SIZE];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
    if (httpd_resp_send_chunk(req, buf, (ssize_t)n) != ESP_OK) {
      fclose(f);
      return ESP_FAIL;
    }
  }
  fclose(f);
  httpd_resp_send_chunk(req, NULL, 0);
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
/*  HybridFlow 1 tuning  (only when TAS57xx DAC is configured)         */
/* ================================================================== */

#ifdef CONFIG_DAC_TAS57XX

/* A float widened to double carries its representation error into the JSON
 * (0.707f becomes 0.707000017166), which then shows up in the UI's inputs. */
static double hf1_round(float v, double scale) {
  return round((double)v * scale) / scale;
}

static void hf1_add_float(cJSON *o, const char *name, float v) {
  cJSON_AddNumberToObject(o, name, hf1_round(v, 1e4));
}

static cJSON *hf1_bq_to_json(const tas57xx_bq_t *bq) {
  cJSON *o = cJSON_CreateObject();
  cJSON_AddNumberToObject(o, "type", (double)bq->type);
  cJSON_AddNumberToObject(o, "sub", (double)bq->subtype);
  hf1_add_float(o, "freq", bq->freq_hz);
  hf1_add_float(o, "q", bq->q);
  hf1_add_float(o, "gain", bq->gain_db);
  cJSON *c = cJSON_AddArrayToObject(o, "coeff");
  for (int i = 0; i < TAS57XX_BQ_WORDS; i++) {
    // 8 places keeps the DSP's 1.23 resolution, which 4 would quantise away.
    cJSON_AddItemToArray(c, cJSON_CreateNumber(hf1_round(bq->coeff[i], 1e8)));
  }
  return o;
}

static void hf1_bq_from_json(const cJSON *o, tas57xx_bq_t *bq) {
  if (!cJSON_IsObject(o)) {
    return;
  }
  const cJSON *v = cJSON_GetObjectItem(o, "type");
  if (json_int_in_range(v, 0, TAS57XX_BQ_TYPE_MAX - 1)) {
    bq->type = (tas57xx_bq_type_t)v->valueint;
  }
  v = cJSON_GetObjectItem(o, "sub");
  if (json_int_in_range(v, 0, TAS57XX_BQ_SUB_MAX - 1)) {
    bq->subtype = (tas57xx_bq_subtype_t)v->valueint;
  }
  v = cJSON_GetObjectItem(o, "freq");
  if (cJSON_IsNumber(v)) {
    bq->freq_hz = (float)v->valuedouble;
  }
  v = cJSON_GetObjectItem(o, "q");
  if (cJSON_IsNumber(v)) {
    bq->q = (float)v->valuedouble;
  }
  v = cJSON_GetObjectItem(o, "gain");
  if (cJSON_IsNumber(v)) {
    bq->gain_db = (float)v->valuedouble;
  }
  v = cJSON_GetObjectItem(o, "coeff");
  if (cJSON_IsArray(v) && cJSON_GetArraySize(v) == TAS57XX_BQ_WORDS) {
    for (int i = 0; i < TAS57XX_BQ_WORDS; i++) {
      const cJSON *n = cJSON_GetArrayItem(v, i);
      if (cJSON_IsNumber(n)) {
        bq->coeff[i] = (float)n->valuedouble;
      }
    }
  }
}

static void hf1_num_from_json(const cJSON *parent, const char *key,
                              float *dst) {
  const cJSON *v = cJSON_GetObjectItem(parent, key);
  if (cJSON_IsNumber(v)) {
    *dst = (float)v->valuedouble;
  }
}

static cJSON *hf1_config_to_json(const tas57xx_hf1_config_t *cfg) {
  cJSON *root = cJSON_CreateObject();
  cJSON_AddBoolToObject(root, "available", dac_tas57xx_hf1_available());
  cJSON_AddNumberToObject(root, "sample_rate", (double)cfg->sample_rate_hz);

  cJSON *eq = cJSON_AddArrayToObject(root, "eq");
  for (int i = 0; i < TAS57XX_HF1_EQ_BANDS; i++) {
    cJSON_AddItemToArray(eq, hf1_bq_to_json(&cfg->eq[i]));
  }

  cJSON *pbe = cJSON_AddObjectToObject(root, "pbe");
  hf1_add_float(pbe, "hpf", cfg->pbe.hpf_hz);
  cJSON_AddNumberToObject(pbe, "harmonic", cfg->pbe.harmonic);
  cJSON_AddNumberToObject(pbe, "effect", cfg->pbe.effect);
  cJSON_AddBoolToObject(pbe, "enabled", cfg->pbe_enabled);

  cJSON *dbe = cJSON_AddObjectToObject(root, "dbe");
  cJSON *hi = cJSON_AddArrayToObject(dbe, "high");
  cJSON *lo = cJSON_AddArrayToObject(dbe, "low");
  for (int i = 0; i < TAS57XX_HF1_DBE_EQ_BANDS; i++) {
    cJSON_AddItemToArray(hi, hf1_bq_to_json(&cfg->dbe_high[i]));
    cJSON_AddItemToArray(lo, hf1_bq_to_json(&cfg->dbe_low[i]));
  }
  hf1_add_float(dbe, "lower_db", cfg->dbe_lower_db);
  hf1_add_float(dbe, "upper_db", cfg->dbe_upper_db);
  hf1_add_float(dbe, "sense_lo", cfg->sense_lower_hz);
  hf1_add_float(dbe, "sense_hi", cfg->sense_upper_hz);
  hf1_add_float(dbe, "window_ms", cfg->sense_window_ms);

  cJSON *drc = cJSON_AddObjectToObject(root, "drc");
  cJSON *cross = cJSON_AddArrayToObject(drc, "cross");
  for (int i = 0; i < TAS57XX_HF1_DRC_CROSS_SECTIONS; i++) {
    cJSON_AddItemToArray(cross, hf1_bq_to_json(&cfg->drc_cross[i]));
  }
  cJSON *mix = cJSON_AddArrayToObject(drc, "mix");
  for (int i = 0; i < TAS57XX_HF1_DRC_BANDS; i++) {
    cJSON_AddItemToArray(mix,
                         cJSON_CreateNumber(hf1_round(cfg->drc_mix[i], 1e4)));
  }
  cJSON *timing = cJSON_AddArrayToObject(drc, "timing");
  for (int i = 0; i < TAS57XX_HF1_DRC_BANDS; i++) {
    cJSON *t = cJSON_CreateObject();
    hf1_add_float(t, "energy", cfg->drc_timing[i].energy_ms);
    hf1_add_float(t, "attack", cfg->drc_timing[i].attack_ms);
    hf1_add_float(t, "decay", cfg->drc_timing[i].decay_ms);
    cJSON_AddItemToArray(timing, t);
  }
  cJSON *regions = cJSON_AddArrayToObject(drc, "regions");
  for (int i = 0; i < TAS57XX_HF1_DRC_REGIONS; i++) {
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "mode", cfg->drc_region[i].mode);
    hf1_add_float(r, "ratio", cfg->drc_region[i].ratio);
    cJSON_AddItemToArray(regions, r);
  }
  hf1_add_float(drc, "thresh1", cfg->drc_thresh1_db);
  hf1_add_float(drc, "thresh2", cfg->drc_thresh2_db);

  hf1_add_float(root, "smooth_clip", cfg->smooth_clip_db);
  hf1_add_float(root, "fine_volume", cfg->fine_volume_db);
  return root;
}

/* Overlays whatever the body supplies onto the current tuning, so a client can
 * send one section without having to echo the rest back correctly. */
static void hf1_config_from_json(const cJSON *root, tas57xx_hf1_config_t *cfg) {
  const cJSON *v = cJSON_GetObjectItem(root, "sample_rate");
  if (json_int_in_range(v, 8000, 192000)) {
    cfg->sample_rate_hz = (uint32_t)v->valueint;
  }

  const cJSON *eq = cJSON_GetObjectItem(root, "eq");
  if (cJSON_IsArray(eq)) {
    int n = cJSON_GetArraySize(eq);
    for (int i = 0; i < n && i < TAS57XX_HF1_EQ_BANDS; i++) {
      hf1_bq_from_json(cJSON_GetArrayItem(eq, i), &cfg->eq[i]);
    }
  }

  const cJSON *pbe = cJSON_GetObjectItem(root, "pbe");
  if (cJSON_IsObject(pbe)) {
    hf1_num_from_json(pbe, "hpf", &cfg->pbe.hpf_hz);
    v = cJSON_GetObjectItem(pbe, "harmonic");
    if (json_int_in_range(v, 0, TAS57XX_HF1_PBE_HARMONIC_MAX)) {
      cfg->pbe.harmonic = v->valueint;
    }
    v = cJSON_GetObjectItem(pbe, "effect");
    if (json_int_in_range(v, TAS57XX_HF1_PBE_EFFECT_MIN,
                          TAS57XX_HF1_PBE_EFFECT_MAX)) {
      cfg->pbe.effect = v->valueint;
    }
    v = cJSON_GetObjectItem(pbe, "enabled");
    if (cJSON_IsBool(v)) {
      cfg->pbe_enabled = cJSON_IsTrue(v);
    }
  }

  const cJSON *dbe = cJSON_GetObjectItem(root, "dbe");
  if (cJSON_IsObject(dbe)) {
    const cJSON *hi = cJSON_GetObjectItem(dbe, "high");
    const cJSON *lo = cJSON_GetObjectItem(dbe, "low");
    for (int i = 0; i < TAS57XX_HF1_DBE_EQ_BANDS; i++) {
      if (cJSON_IsArray(hi)) {
        hf1_bq_from_json(cJSON_GetArrayItem(hi, i), &cfg->dbe_high[i]);
      }
      if (cJSON_IsArray(lo)) {
        hf1_bq_from_json(cJSON_GetArrayItem(lo, i), &cfg->dbe_low[i]);
      }
    }
    hf1_num_from_json(dbe, "lower_db", &cfg->dbe_lower_db);
    hf1_num_from_json(dbe, "upper_db", &cfg->dbe_upper_db);
    hf1_num_from_json(dbe, "sense_lo", &cfg->sense_lower_hz);
    hf1_num_from_json(dbe, "sense_hi", &cfg->sense_upper_hz);
    hf1_num_from_json(dbe, "window_ms", &cfg->sense_window_ms);
  }

  const cJSON *drc = cJSON_GetObjectItem(root, "drc");
  if (cJSON_IsObject(drc)) {
    const cJSON *cross = cJSON_GetObjectItem(drc, "cross");
    if (cJSON_IsArray(cross) &&
        cJSON_GetArraySize(cross) == TAS57XX_HF1_DRC_CROSS_SECTIONS) {
      for (int i = 0; i < TAS57XX_HF1_DRC_CROSS_SECTIONS; i++) {
        hf1_bq_from_json(cJSON_GetArrayItem(cross, i), &cfg->drc_cross[i]);
      }
    }
    const cJSON *mix = cJSON_GetObjectItem(drc, "mix");
    if (cJSON_IsArray(mix) &&
        cJSON_GetArraySize(mix) == TAS57XX_HF1_DRC_BANDS) {
      for (int i = 0; i < TAS57XX_HF1_DRC_BANDS; i++) {
        const cJSON *v = cJSON_GetArrayItem(mix, i);
        if (cJSON_IsNumber(v)) {
          cfg->drc_mix[i] = (float)v->valuedouble;
        }
      }
    }
    const cJSON *timing = cJSON_GetObjectItem(drc, "timing");
    for (int i = 0; cJSON_IsArray(timing) && i < TAS57XX_HF1_DRC_BANDS; i++) {
      const cJSON *t = cJSON_GetArrayItem(timing, i);
      if (cJSON_IsObject(t)) {
        hf1_num_from_json(t, "energy", &cfg->drc_timing[i].energy_ms);
        hf1_num_from_json(t, "attack", &cfg->drc_timing[i].attack_ms);
        hf1_num_from_json(t, "decay", &cfg->drc_timing[i].decay_ms);
      }
    }
    const cJSON *regions = cJSON_GetObjectItem(drc, "regions");
    for (int i = 0; cJSON_IsArray(regions) && i < TAS57XX_HF1_DRC_REGIONS;
         i++) {
      const cJSON *r = cJSON_GetArrayItem(regions, i);
      if (cJSON_IsObject(r)) {
        v = cJSON_GetObjectItem(r, "mode");
        if (json_int_in_range(v, 0, TAS57XX_HF1_DRC_EXPAND)) {
          cfg->drc_region[i].mode = v->valueint;
        }
        hf1_num_from_json(r, "ratio", &cfg->drc_region[i].ratio);
      }
    }
    hf1_num_from_json(drc, "thresh1", &cfg->drc_thresh1_db);
    hf1_num_from_json(drc, "thresh2", &cfg->drc_thresh2_db);
  }

  hf1_num_from_json(root, "smooth_clip", &cfg->smooth_clip_db);
  hf1_num_from_json(root, "fine_volume", &cfg->fine_volume_db);
}

static esp_err_t hf1_send_result(httpd_req_t *req, esp_err_t err) {
  cJSON *resp = cJSON_CreateObject();
  cJSON_AddBoolToObject(resp, "success", err == ESP_OK);
  if (err != ESP_OK) {
    cJSON_AddStringToObject(resp, "error", esp_err_to_name(err));
  }
  char *s = cJSON_PrintUnformatted(resp);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, s, HTTPD_RESP_USE_STRLEN);
  free(s);
  cJSON_Delete(resp);
  return ESP_OK;
}

/* One page for every flow: it asks which one is loaded and shows that, and
 * offers to swap between the bases that are present. A board only ever runs
 * one at a time, so there is no reason to ship the machinery twice. */
static esp_err_t hf_page_handler(httpd_req_t *req) {
  return serve_spiffs_file(req, "/spiffs/www/hf.html", "text/html");
}

static esp_err_t hf1_get_handler(httpd_req_t *req) {
  tas57xx_hf1_config_t cfg;
  if (dac_tas57xx_hf1_get(&cfg) != ESP_OK) {
    return hf1_send_result(req, ESP_ERR_INVALID_STATE);
  }
  cJSON *root = hf1_config_to_json(&cfg);
  char *s = cJSON_PrintUnformatted(root);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, s, HTTPD_RESP_USE_STRLEN);
  free(s);
  cJSON_Delete(root);
  return ESP_OK;
}

static esp_err_t hf1_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 12288);
  if (!content) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Body required (max 8KB)");
    return ESP_FAIL;
  }
  cJSON *root = cJSON_Parse(content);
  free(content);
  if (!root) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  tas57xx_hf1_config_t cfg;
  esp_err_t err = dac_tas57xx_hf1_get(&cfg);
  if (err == ESP_OK) {
    hf1_config_from_json(root, &cfg);
    err = dac_tas57xx_hf1_set(&cfg);
  }
  cJSON_Delete(root);
  return hf1_send_result(req, err);
}

static esp_err_t hf1_commit_handler(httpd_req_t *req) {
  return hf1_send_result(req, dac_tas57xx_hf1_commit());
}

static esp_err_t hf1_revert_handler(httpd_req_t *req) {
  return hf1_send_result(req, dac_tas57xx_hf1_revert());
}

/* HF3 reuses the hf1_* JSON helpers above: a biquad is a biquad, and the two
 * flows differ only in how many of them there are and what they feed. */

static cJSON *hf3_way_to_json(const tas57xx_hf3_config_t *cfg, int w) {
  cJSON *o = cJSON_CreateObject();
  cJSON_AddItemToObject(o, "crossover", hf1_bq_to_json(&cfg->crossover[w]));
  cJSON *eq = cJSON_AddArrayToObject(o, "eq");
  for (int i = 0; i < TAS57XX_HF3_EQ_BANDS; i++) {
    cJSON_AddItemToArray(eq, hf1_bq_to_json(&cfg->eq[w][i]));
  }
  return o;
}

static cJSON *hf3_config_to_json(const tas57xx_hf3_config_t *cfg) {
  cJSON *root = cJSON_CreateObject();
  cJSON_AddBoolToObject(root, "available", dac_tas57xx_hf3_available());
  cJSON_AddNumberToObject(root, "sample_rate", (double)cfg->sample_rate_hz);

  cJSON *ways = cJSON_AddArrayToObject(root, "ways");
  for (int w = 0; w < TAS57XX_HF3_WAYS; w++) {
    cJSON_AddItemToArray(ways, hf3_way_to_json(cfg, w));
  }
  cJSON_AddNumberToObject(root, "high_delay", cfg->high_delay_samples);

  cJSON *pbe = cJSON_AddObjectToObject(root, "pbe");
  hf1_add_float(pbe, "hpf", cfg->pbe.hpf_hz);
  cJSON_AddNumberToObject(pbe, "harmonic", cfg->pbe.harmonic);
  cJSON_AddNumberToObject(pbe, "effect", cfg->pbe.effect);
  cJSON_AddBoolToObject(pbe, "enabled", cfg->pbe_enabled);

  cJSON *dbe = cJSON_AddObjectToObject(root, "dbe");
  cJSON *hi = cJSON_AddArrayToObject(dbe, "high");
  for (int i = 0; i < TAS57XX_HF3_DBE_HL_BANDS; i++) {
    cJSON_AddItemToArray(hi, hf1_bq_to_json(&cfg->dbe_high[i]));
  }
  cJSON *lo = cJSON_AddArrayToObject(dbe, "low");
  for (int i = 0; i < TAS57XX_HF3_DBE_LL_BANDS; i++) {
    cJSON_AddItemToArray(lo, hf1_bq_to_json(&cfg->dbe_low[i]));
  }
  hf1_add_float(dbe, "lower_db", cfg->dbe_lower_db);
  hf1_add_float(dbe, "upper_db", cfg->dbe_upper_db);
  hf1_add_float(dbe, "sense_lo", cfg->sense_lower_hz);
  hf1_add_float(dbe, "sense_hi", cfg->sense_upper_hz);
  hf1_add_float(dbe, "window_ms", cfg->sense_window_ms);

  cJSON *drc = cJSON_AddObjectToObject(root, "drc");
  cJSON_AddItemToObject(drc, "split_low", hf1_bq_to_json(&cfg->drc_split_low));
  cJSON_AddItemToObject(drc, "split_high",
                        hf1_bq_to_json(&cfg->drc_split_high));
  hf1_add_float(drc, "mix_low", cfg->drc_mix_low);
  hf1_add_float(drc, "mix_mid", cfg->drc_mix_mid);
  cJSON *timing = cJSON_AddArrayToObject(drc, "timing");
  for (int i = 0; i < TAS57XX_HF3_DRC_BANDS; i++) {
    cJSON *t = cJSON_CreateObject();
    hf1_add_float(t, "energy", cfg->drc_timing[i].energy_ms);
    hf1_add_float(t, "attack", cfg->drc_timing[i].attack_ms);
    hf1_add_float(t, "decay", cfg->drc_timing[i].decay_ms);
    cJSON_AddItemToArray(timing, t);
  }
  cJSON *regions = cJSON_AddArrayToObject(drc, "regions");
  for (int i = 0; i < TAS57XX_HF3_DRC_REGIONS; i++) {
    cJSON *r = cJSON_CreateObject();
    cJSON_AddNumberToObject(r, "mode", cfg->drc_region[i].mode);
    hf1_add_float(r, "ratio", cfg->drc_region[i].ratio);
    cJSON_AddItemToArray(regions, r);
  }
  hf1_add_float(drc, "thresh1", cfg->drc_thresh1_db);
  hf1_add_float(drc, "thresh2", cfg->drc_thresh2_db);

  hf1_add_float(root, "smooth_clip", cfg->smooth_clip_db);
  return root;
}

/* Overlays whatever the body supplies onto the current tuning. The input mixer
 * is deliberately absent: it selects which channel this speaker plays, and is
 * owned by the channel-mode setting rather than by a tuning. */
static void hf3_config_from_json(const cJSON *root, tas57xx_hf3_config_t *cfg) {
  const cJSON *v = cJSON_GetObjectItem(root, "sample_rate");
  if (json_int_in_range(v, 8000, 192000)) {
    cfg->sample_rate_hz = (uint32_t)v->valueint;
  }
  v = cJSON_GetObjectItem(root, "high_delay");
  if (json_int_in_range(v, 0, TAS57XX_HF3_DELAY_MAX)) {
    cfg->high_delay_samples = v->valueint;
  }

  const cJSON *ways = cJSON_GetObjectItem(root, "ways");
  for (int w = 0; cJSON_IsArray(ways) && w < TAS57XX_HF3_WAYS; w++) {
    const cJSON *way = cJSON_GetArrayItem(ways, w);
    if (!cJSON_IsObject(way)) {
      continue;
    }
    hf1_bq_from_json(cJSON_GetObjectItem(way, "crossover"), &cfg->crossover[w]);
    const cJSON *eq = cJSON_GetObjectItem(way, "eq");
    for (int i = 0; cJSON_IsArray(eq) && i < TAS57XX_HF3_EQ_BANDS; i++) {
      hf1_bq_from_json(cJSON_GetArrayItem(eq, i), &cfg->eq[w][i]);
    }
  }

  const cJSON *pbe = cJSON_GetObjectItem(root, "pbe");
  if (cJSON_IsObject(pbe)) {
    hf1_num_from_json(pbe, "hpf", &cfg->pbe.hpf_hz);
    v = cJSON_GetObjectItem(pbe, "harmonic");
    if (json_int_in_range(v, 0, TAS57XX_HF3_PBE_HARMONIC_MAX)) {
      cfg->pbe.harmonic = v->valueint;
    }
    v = cJSON_GetObjectItem(pbe, "effect");
    if (json_int_in_range(v, TAS57XX_HF3_PBE_EFFECT_MIN,
                          TAS57XX_HF3_PBE_EFFECT_MAX)) {
      cfg->pbe.effect = v->valueint;
    }
    v = cJSON_GetObjectItem(pbe, "enabled");
    if (cJSON_IsBool(v)) {
      cfg->pbe_enabled = cJSON_IsTrue(v);
    }
  }

  const cJSON *dbe = cJSON_GetObjectItem(root, "dbe");
  if (cJSON_IsObject(dbe)) {
    const cJSON *hi = cJSON_GetObjectItem(dbe, "high");
    for (int i = 0; cJSON_IsArray(hi) && i < TAS57XX_HF3_DBE_HL_BANDS; i++) {
      hf1_bq_from_json(cJSON_GetArrayItem(hi, i), &cfg->dbe_high[i]);
    }
    const cJSON *lo = cJSON_GetObjectItem(dbe, "low");
    for (int i = 0; cJSON_IsArray(lo) && i < TAS57XX_HF3_DBE_LL_BANDS; i++) {
      hf1_bq_from_json(cJSON_GetArrayItem(lo, i), &cfg->dbe_low[i]);
    }
    hf1_num_from_json(dbe, "lower_db", &cfg->dbe_lower_db);
    hf1_num_from_json(dbe, "upper_db", &cfg->dbe_upper_db);
    hf1_num_from_json(dbe, "sense_lo", &cfg->sense_lower_hz);
    hf1_num_from_json(dbe, "sense_hi", &cfg->sense_upper_hz);
    hf1_num_from_json(dbe, "window_ms", &cfg->sense_window_ms);
  }

  const cJSON *drc = cJSON_GetObjectItem(root, "drc");
  if (cJSON_IsObject(drc)) {
    hf1_bq_from_json(cJSON_GetObjectItem(drc, "split_low"),
                     &cfg->drc_split_low);
    hf1_bq_from_json(cJSON_GetObjectItem(drc, "split_high"),
                     &cfg->drc_split_high);
    hf1_num_from_json(drc, "mix_low", &cfg->drc_mix_low);
    hf1_num_from_json(drc, "mix_mid", &cfg->drc_mix_mid);
    const cJSON *timing = cJSON_GetObjectItem(drc, "timing");
    for (int i = 0; cJSON_IsArray(timing) && i < TAS57XX_HF3_DRC_BANDS; i++) {
      const cJSON *t = cJSON_GetArrayItem(timing, i);
      if (cJSON_IsObject(t)) {
        hf1_num_from_json(t, "energy", &cfg->drc_timing[i].energy_ms);
        hf1_num_from_json(t, "attack", &cfg->drc_timing[i].attack_ms);
        hf1_num_from_json(t, "decay", &cfg->drc_timing[i].decay_ms);
      }
    }
    const cJSON *regions = cJSON_GetObjectItem(drc, "regions");
    for (int i = 0; cJSON_IsArray(regions) && i < TAS57XX_HF3_DRC_REGIONS;
         i++) {
      const cJSON *r = cJSON_GetArrayItem(regions, i);
      if (cJSON_IsObject(r)) {
        v = cJSON_GetObjectItem(r, "mode");
        if (json_int_in_range(v, 0, TAS57XX_HF3_DRC_EXPAND)) {
          cfg->drc_region[i].mode = v->valueint;
        }
        hf1_num_from_json(r, "ratio", &cfg->drc_region[i].ratio);
      }
    }
    hf1_num_from_json(drc, "thresh1", &cfg->drc_thresh1_db);
    hf1_num_from_json(drc, "thresh2", &cfg->drc_thresh2_db);
  }

  hf1_num_from_json(root, "smooth_clip", &cfg->smooth_clip_db);
}

static esp_err_t hf3_get_handler(httpd_req_t *req) {
  tas57xx_hf3_config_t cfg;
  if (dac_tas57xx_hf3_get(&cfg) != ESP_OK) {
    return hf1_send_result(req, ESP_ERR_INVALID_STATE);
  }
  cJSON *root = hf3_config_to_json(&cfg);
  char *s = cJSON_PrintUnformatted(root);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, s, HTTPD_RESP_USE_STRLEN);
  free(s);
  cJSON_Delete(root);
  return ESP_OK;
}

static esp_err_t hf3_post_handler(httpd_req_t *req) {
  char *content = recv_body(req, 12288);
  if (!content) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Body required (max 12KB)");
    return ESP_FAIL;
  }
  cJSON *root = cJSON_Parse(content);
  free(content);
  if (!root) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  tas57xx_hf3_config_t cfg;
  esp_err_t err = dac_tas57xx_hf3_get(&cfg);
  if (err == ESP_OK) {
    hf3_config_from_json(root, &cfg);
    err = dac_tas57xx_hf3_set(&cfg);
  }
  cJSON_Delete(root);
  return hf1_send_result(req, err);
}

static esp_err_t hf3_commit_handler(httpd_req_t *req) {
  return hf1_send_result(req, dac_tas57xx_hf3_commit());
}

static esp_err_t hf3_revert_handler(httpd_req_t *req) {
  return hf1_send_result(req, dac_tas57xx_hf3_revert());
}

/* ---- Flow selection --------------------------------------------------- */

static esp_err_t hf_flow_get_handler(httpd_req_t *req) {
  cJSON *root = cJSON_CreateObject();
  cJSON_AddNumberToObject(root, "active", dac_tas57xx_active_flow());
  cJSON_AddNumberToObject(root, "sample_rate", dac_tas57xx_flow_sample_rate());
  cJSON *avail = cJSON_AddArrayToObject(root, "available");
  for (int flow = 1; flow <= 3; flow += 2) {
    if (dac_tas57xx_flow_base_available(flow)) {
      cJSON_AddItemToArray(avail, cJSON_CreateNumber(flow));
    }
  }
  cJSON_AddBoolToObject(root, "success", true);
  char *s = cJSON_PrintUnformatted(root);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, s, HTTPD_RESP_USE_STRLEN);
  free(s);
  cJSON_Delete(root);
  return ESP_OK;
}

static esp_err_t hf_flow_post_handler(httpd_req_t *req) {
  char *body = recv_body(req, 128);
  if (body == NULL) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
    return ESP_FAIL;
  }
  cJSON *root = cJSON_Parse(body);
  free(body);
  cJSON *flow = root ? cJSON_GetObjectItem(root, "flow") : NULL;
  int want = cJSON_IsNumber(flow) ? flow->valueint : -1;
  cJSON_Delete(root);
  if (want != 0 && want != 1 && want != 3) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Expected flow 0, 1 or 3");
    return ESP_FAIL;
  }

  /* Bi-amp hands the two amplifier outputs to a woofer and a tweeter, so the
   * first sound after a switch may be going somewhere it should not. Turn the
   * volume down and leave it down until whoever asked has checked. */
  if (want != dac_tas57xx_active_flow()) {
    settings_set_volume(VOLUME_UI_MIN_DB);
  }
  return hf1_send_result(req, dac_tas57xx_select_flow(want));
}

#endif /* CONFIG_DAC_TAS57XX */

/* ================================================================== */
/*  Biquad chains  (only when TAS58xx DAC is configured)               */
/* ================================================================== */

#ifdef CONFIG_DAC_TAS58XX

/* ---------- Parametric biquad chains ---------- */

/* Enough for 15 filters worth of JSON with room for whitespace. */
#define BQ_POST_MAX 6144

static esp_err_t bq_page_handler(httpd_req_t *req) {
  return serve_spiffs_file(req, "/spiffs/www/bq.html", "text/html");
}

/* Which amplifier a chain belongs to, so the page can label the columns
 * without duplicating the dual-DAC wiring logic. */
static const char *bq_amp_role(int dev) {
  if (dev == 0) {
    return "stereo";
  }
  return dac_tas58xx_get_active_second_pbtl() ? "mono" : "stereo";
}

static cJSON *bq_to_json(const tas58xx_bq_t *bq) {
  cJSON *o = cJSON_CreateObject();
  cJSON_AddNumberToObject(o, "type", bq->type);
  cJSON_AddNumberToObject(o, "sub", bq->sub);
  cJSON_AddNumberToObject(o, "freq", bq->freq_hz);
  cJSON_AddNumberToObject(o, "q", bq->q);
  cJSON_AddNumberToObject(o, "bw", bq->bandwidth_hz);
  cJSON_AddNumberToObject(o, "gain", bq->gain_db);
  cJSON_AddNumberToObject(o, "ripple", bq->ripple_db);
  cJSON_AddBoolToObject(o, "invert", bq->invert != 0);
  if (bq->type == TAS58XX_BQ_CUSTOM) {
    cJSON *c = cJSON_AddArrayToObject(o, "coeff");
    for (int i = 0; i < 5; i++) {
      cJSON_AddItemToArray(c, cJSON_CreateNumber(bq->coeff[i]));
    }
  }
  return o;
}

/* Missing members keep their default, so the page can send a sparse filter.
 * The values themselves are checked by the driver, which owns the limits. */
static bool bq_from_json(const cJSON *o, tas58xx_bq_t *out) {
  if (!cJSON_IsObject(o)) {
    return false;
  }
  tas58xx_bq_init_bypass(out);

  const cJSON *v = cJSON_GetObjectItem(o, "type");
  if (!json_int_in_range(v, 0, TAS58XX_BQ_TYPE_COUNT - 1)) {
    return false;
  }
  out->type = (uint8_t)v->valueint;

  v = cJSON_GetObjectItem(o, "sub");
  if (v) {
    if (!json_int_in_range(v, 0, TAS58XX_BQ_SUB_COUNT - 1)) {
      return false;
    }
    out->sub = (uint8_t)v->valueint;
  }

  v = cJSON_GetObjectItem(o, "invert");
  if (v) {
    if (!cJSON_IsBool(v)) {
      return false;
    }
    out->invert = cJSON_IsTrue(v) ? 1 : 0;
  }

  static const struct {
    const char *key;
    size_t offset;
  } floats[] = {
      {"freq", offsetof(tas58xx_bq_t, freq_hz)},
      {"q", offsetof(tas58xx_bq_t, q)},
      {"bw", offsetof(tas58xx_bq_t, bandwidth_hz)},
      {"gain", offsetof(tas58xx_bq_t, gain_db)},
      {"ripple", offsetof(tas58xx_bq_t, ripple_db)},
  };
  for (size_t i = 0; i < sizeof(floats) / sizeof(floats[0]); i++) {
    v = cJSON_GetObjectItem(o, floats[i].key);
    if (!v) {
      continue;
    }
    if (!cJSON_IsNumber(v)) {
      return false;
    }
    *(float *)((char *)out + floats[i].offset) = (float)v->valuedouble;
  }

  const cJSON *c = cJSON_GetObjectItem(o, "coeff");
  if (c) {
    if (!cJSON_IsArray(c) || cJSON_GetArraySize(c) != 5) {
      return false;
    }
    for (int i = 0; i < 5; i++) {
      const cJSON *n = cJSON_GetArrayItem(c, i);
      if (!cJSON_IsNumber(n)) {
        return false;
      }
      out->coeff[i] = (float)n->valuedouble;
    }
  }
  return true;
}

static esp_err_t bq_get_handler(httpd_req_t *req) {
  const int devices = dac_tas58xx_get_device_count();

  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "success", true);
  cJSON_AddNumberToObject(json, "devices", devices);
  cJSON_AddNumberToObject(json, "channels", TAS58XX_BQ_CHANNELS);
  cJSON_AddNumberToObject(json, "slots", TAS58XX_BQ_SLOTS);
  cJSON_AddNumberToObject(json, "rate", dac_tas58xx_bq_sample_rate());
  cJSON_AddNumberToObject(json, "gain_min", TAS58XX_GAIN_MIN_DB);
  cJSON_AddNumberToObject(json, "gain_max", TAS58XX_GAIN_MAX_DB);

  cJSON *amps = cJSON_AddArrayToObject(json, "amps");
  for (int d = 0; d < devices; d++) {
    cJSON *amp = cJSON_CreateObject();
    cJSON_AddNumberToObject(amp, "index", d);
    cJSON_AddStringToObject(amp, "role", bq_amp_role(d));
    cJSON_AddBoolToObject(amp, "ganged", dac_tas58xx_bq_get_ganged(d));
    cJSON_AddNumberToObject(amp, "mix", dac_tas58xx_get_mix(d));
    cJSON_AddBoolToObject(amp, "pbtl", dac_tas58xx_is_pbtl(d));

    cJSON *gains = cJSON_AddArrayToObject(amp, "gains");
    cJSON *mutes = cJSON_AddArrayToObject(amp, "mutes");
    for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
      cJSON_AddItemToArray(gains,
                           cJSON_CreateNumber(dac_tas58xx_get_gain_db(d, c)));
      cJSON_AddItemToArray(mutes,
                           cJSON_CreateBool(dac_tas58xx_get_ch_mute(d, c)));
    }

    cJSON *chans = cJSON_AddArrayToObject(amp, "channels");
    for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
      tas58xx_bq_t chain[TAS58XX_BQ_SLOTS];
      cJSON *slots = cJSON_CreateArray();
      if (dac_tas58xx_bq_get(d, c, chain)) {
        for (int i = 0; i < TAS58XX_BQ_SLOTS; i++) {
          cJSON_AddItemToArray(slots, bq_to_json(&chain[i]));
        }
      }
      cJSON_AddItemToArray(chans, slots);
    }
    cJSON_AddItemToArray(amps, amp);
  }

  /* Unformatted: the full set already runs to several kilobytes. */
  char *json_str = cJSON_PrintUnformatted(json);
  cJSON_Delete(json);
  if (!json_str) {
    httpd_resp_send_500(req);
    return ESP_FAIL;
  }
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  return ESP_OK;
}

static esp_err_t bq_post_handler(httpd_req_t *req) {
  char *body = recv_body(req, BQ_POST_MAX);
  if (!body) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Body too large or empty");
    return ESP_FAIL;
  }

  cJSON *json = cJSON_Parse(body);
  free(body);
  if (!json) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
    return ESP_FAIL;
  }

  const cJSON *v = cJSON_GetObjectItem(json, "dev");
  if (!json_int_in_range(v, 0, dac_tas58xx_get_device_count() - 1)) {
    cJSON_Delete(json);
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad 'dev'");
    return ESP_FAIL;
  }
  const int dev = v->valueint;

  /* Ganging is applied first: a ganged write only carries the left chain and
   * the driver mirrors it when programming. */
  const cJSON *g = cJSON_GetObjectItem(json, "ganged");
  if (cJSON_IsBool(g)) {
    dac_tas58xx_bq_set_ganged(dev, cJSON_IsTrue(g));
  }

  /* Level and mute are per output rather than per chain, so they ride along
   * with the chain edits instead of needing an endpoint of their own. */
  const cJSON *gain = cJSON_GetObjectItem(json, "gain");
  const cJSON *mute = cJSON_GetObjectItem(json, "mute");
  if (gain || mute) {
    const cJSON *oc = cJSON_GetObjectItem(json, "out");
    if (!json_int_in_range(oc, 0, TAS58XX_BQ_CHANNELS - 1)) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad 'out'");
      return ESP_FAIL;
    }
    if (gain && !cJSON_IsNumber(gain)) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad 'gain'");
      return ESP_FAIL;
    }
    if (mute && !cJSON_IsBool(mute)) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad 'mute'");
      return ESP_FAIL;
    }
    if (gain) {
      dac_tas58xx_set_gain_db(dev, oc->valueint, (float)gain->valuedouble);
      float saved[SETTINGS_AMP_OUTPUTS];
      for (int i = 0; i < SETTINGS_AMP_OUTPUTS; i++) {
        saved[i] = dac_tas58xx_get_gain_db(i / SETTINGS_AMP_CHANNELS,
                                           i % SETTINGS_AMP_CHANNELS);
      }
      settings_set_amp_gain(saved);
    }
    if (mute) {
      dac_tas58xx_set_ch_mute(dev, oc->valueint, cJSON_IsTrue(mute));
      uint8_t saved[SETTINGS_AMP_OUTPUTS];
      for (int i = 0; i < SETTINGS_AMP_OUTPUTS; i++) {
        saved[i] = dac_tas58xx_get_ch_mute(i / SETTINGS_AMP_CHANNELS,
                                           i % SETTINGS_AMP_CHANNELS);
      }
      settings_set_amp_mute(saved);
    }
  }

  const cJSON *mix = cJSON_GetObjectItem(json, "mix");
  if (mix) {
    if (!json_int_in_range(mix, 0, TAS58XX_MIX_COUNT - 1)) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad 'mix'");
      return ESP_FAIL;
    }
    dac_tas58xx_set_mix(dev, (tas58xx_mix_t)mix->valueint);
    uint8_t saved[SETTINGS_AMPS];
    for (int i = 0; i < SETTINGS_AMPS; i++) {
      saved[i] = (uint8_t)dac_tas58xx_get_mix(i);
    }
    settings_set_amp_mix(saved);
  }

  const cJSON *filters = cJSON_GetObjectItem(json, "filters");
  if (filters) {
    v = cJSON_GetObjectItem(json, "ch");
    if (!json_int_in_range(v, 0, TAS58XX_BQ_CHANNELS - 1)) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad 'ch'");
      return ESP_FAIL;
    }
    const int ch = v->valueint;

    if (!cJSON_IsArray(filters) ||
        cJSON_GetArraySize(filters) != TAS58XX_BQ_SLOTS) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                          "'filters' must hold 15 entries");
      return ESP_FAIL;
    }

    tas58xx_bq_t chain[TAS58XX_BQ_SLOTS];
    for (int i = 0; i < TAS58XX_BQ_SLOTS; i++) {
      if (!bq_from_json(cJSON_GetArrayItem(filters, i), &chain[i])) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad filter entry");
        return ESP_FAIL;
      }
    }

    if (dac_tas58xx_bq_set(dev, ch, chain) != ESP_OK) {
      cJSON_Delete(json);
      httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Filter rejected");
      return ESP_FAIL;
    }
  }

  cJSON_Delete(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr(req, "{\"success\":true}");
  return ESP_OK;
}

/* Chain edits stay in RAM until committed, matching the hybrid-flow pages:
 * a tuning can be auditioned and walked away from by rebooting. */
static esp_err_t bq_commit_handler(httpd_req_t *req) {
  if (dac_tas58xx_bq_commit() != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Write failed");
    return ESP_FAIL;
  }
  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr(req, "{\"success\":true}");
  return ESP_OK;
}

static esp_err_t bq_revert_handler(httpd_req_t *req) {
  if (dac_tas58xx_bq_revert() != ESP_OK) {
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Revert failed");
    return ESP_FAIL;
  }
  httpd_resp_set_type(req, "application/json");
  httpd_resp_sendstr(req, "{\"success\":true}");
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
  // Slots are allocated up front and httpd_register_uri_handler failures are
  // unchecked, so an undercount silently drops whatever registers last, which
  // is log_stream's /ws/logs. Keep these in step with the handlers below.
  config.max_uri_handlers = 38; // 32 here + /ws/logs, plus 5 spare
#ifdef CONFIG_SENDSPIN_ENABLE
  config.max_uri_handlers += 5; // /sendspin + mode get/post + unpair + reset
  // The Sendspin server holds its WebSocket open for as long as the speaker
  // exists, so it permanently occupies a slot that the web UI would otherwise
  // reuse.  Without this, opening the config page evicts the audio session.
  config.max_open_sockets += 2;
#endif
#ifdef DAC_HAS_SUB_OFFSET
  config.max_uri_handlers += 2; // sub level get/post
#endif
#ifdef DAC_HAS_CH_TRIM
  config.max_uri_handlers += 2; // per-channel level get/post
#endif
#ifdef CONFIG_DAC_TAS58XX
  // dual DAC wiring plus the biquad page/API
  config.max_uri_handlers += 7;
#endif
#ifdef CONFIG_DAC_TAS57XX
  config.max_uri_handlers += 11; // tuning page + HF1/HF3 get/post/commit/revert
#endif
  config.max_resp_headers = 8;
#ifdef CONFIG_SENDSPIN_OPUS
  /* libopus keeps its CELT scratch on the stack: measured peak is 11.7 KB at
   * 48 kHz stereo, on top of what serving a request already needs. */
  config.stack_size = 16384;
#else
  config.stack_size = 8192;
#endif

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

  httpd_uri_t device_name_uri = {.uri = "/api/device/name",
                                 .method = HTTP_POST,
                                 .handler = device_name_handler};
  httpd_register_uri_handler(s_server, &device_name_uri);

  httpd_uri_t led_brightness_get_uri = {.uri = "/api/led/brightness",
                                        .method = HTTP_GET,
                                        .handler = led_brightness_get_handler};
  httpd_register_uri_handler(s_server, &led_brightness_get_uri);

  httpd_uri_t led_brightness_post_uri = {.uri = "/api/led/brightness",
                                         .method = HTTP_POST,
                                         .handler =
                                             led_brightness_post_handler};
  httpd_register_uri_handler(s_server, &led_brightness_post_uri);

  httpd_uri_t channel_mode_get_uri = {.uri = "/api/audio/channel",
                                      .method = HTTP_GET,
                                      .handler = channel_mode_get_handler};
  httpd_register_uri_handler(s_server, &channel_mode_get_uri);

  httpd_uri_t channel_mode_post_uri = {.uri = "/api/audio/channel",
                                       .method = HTTP_POST,
                                       .handler = channel_mode_post_handler};
  httpd_register_uri_handler(s_server, &channel_mode_post_uri);

  httpd_uri_t volume_get_uri = {.uri = "/api/audio/volume",
                                .method = HTTP_GET,
                                .handler = volume_get_handler};
  httpd_register_uri_handler(s_server, &volume_get_uri);

  httpd_uri_t volume_post_uri = {.uri = "/api/audio/volume",
                                 .method = HTTP_POST,
                                 .handler = volume_post_handler};
  httpd_register_uri_handler(s_server, &volume_post_uri);

#ifdef DAC_HAS_SUB_OFFSET
  httpd_uri_t sub_offset_get_uri = {.uri = "/api/audio/sub",
                                    .method = HTTP_GET,
                                    .handler = sub_offset_get_handler};
  httpd_register_uri_handler(s_server, &sub_offset_get_uri);

  httpd_uri_t sub_offset_post_uri = {.uri = "/api/audio/sub",
                                     .method = HTTP_POST,
                                     .handler = sub_offset_post_handler};
  httpd_register_uri_handler(s_server, &sub_offset_post_uri);
#endif

#ifdef DAC_HAS_CH_TRIM
  httpd_uri_t ch_trim_get_uri = {.uri = "/api/audio/channels",
                                 .method = HTTP_GET,
                                 .handler = ch_trim_get_handler};
  httpd_register_uri_handler(s_server, &ch_trim_get_uri);

  httpd_uri_t ch_trim_post_uri = {.uri = "/api/audio/channels",
                                  .method = HTTP_POST,
                                  .handler = ch_trim_post_handler};
  httpd_register_uri_handler(s_server, &ch_trim_post_uri);
#endif

#ifdef CONFIG_DAC_TAS58XX
  httpd_uri_t dual_mode_get_uri = {.uri = "/api/audio/dual",
                                   .method = HTTP_GET,
                                   .handler = dual_mode_get_handler};
  httpd_register_uri_handler(s_server, &dual_mode_get_uri);

  httpd_uri_t dual_mode_post_uri = {.uri = "/api/audio/dual",
                                    .method = HTTP_POST,
                                    .handler = dual_mode_post_handler};
  httpd_register_uri_handler(s_server, &dual_mode_post_uri);
#endif

  httpd_uri_t airplay_mode_get_uri = {.uri = "/api/airplay/mode",
                                      .method = HTTP_GET,
                                      .handler = airplay_mode_get_handler};
  httpd_register_uri_handler(s_server, &airplay_mode_get_uri);

  httpd_uri_t airplay_mode_post_uri = {.uri = "/api/airplay/mode",
                                       .method = HTTP_POST,
                                       .handler = airplay_mode_post_handler};
  httpd_register_uri_handler(s_server, &airplay_mode_post_uri);

  httpd_uri_t ota_uri = {.uri = "/api/ota/update",
                         .method = HTTP_POST,
                         .handler = ota_update_handler};
  httpd_register_uri_handler(s_server, &ota_uri);

  httpd_uri_t metadata_uri = {.uri = "/api/metadata",
                              .method = HTTP_POST,
                              .handler = metadata_post_handler};
  httpd_register_uri_handler(s_server, &metadata_uri);

  httpd_uri_t system_info_uri = {.uri = "/api/system/info",
                                 .method = HTTP_GET,
                                 .handler = system_info_handler};
  httpd_register_uri_handler(s_server, &system_info_uri);

  httpd_uri_t system_restart_uri = {.uri = "/api/system/restart",
                                    .method = HTTP_POST,
                                    .handler = system_restart_handler};
  httpd_register_uri_handler(s_server, &system_restart_uri);

#ifdef CONFIG_SENDSPIN_ENABLE
  httpd_uri_t sendspin_mode_get_uri = {.uri = "/api/sendspin/mode",
                                       .method = HTTP_GET,
                                       .handler = sendspin_mode_get_handler};
  httpd_register_uri_handler(s_server, &sendspin_mode_get_uri);

  httpd_uri_t sendspin_mode_post_uri = {.uri = "/api/sendspin/mode",
                                        .method = HTTP_POST,
                                        .handler = sendspin_mode_post_handler};
  httpd_register_uri_handler(s_server, &sendspin_mode_post_uri);

  httpd_uri_t sendspin_unpair_uri = {.uri = "/api/sendspin/unpair",
                                     .method = HTTP_POST,
                                     .handler = sendspin_unpair_handler};
  httpd_register_uri_handler(s_server, &sendspin_unpair_uri);

  httpd_uri_t sendspin_reset_identity_uri = {
      .uri = "/api/sendspin/reset-identity",
      .method = HTTP_POST,
      .handler = sendspin_reset_identity_handler};
  httpd_register_uri_handler(s_server, &sendspin_reset_identity_uri);
#endif

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

  httpd_uri_t fs_download_uri = {.uri = "/api/fs/download",
                                 .method = HTTP_GET,
                                 .handler = fs_download_handler};
  httpd_register_uri_handler(s_server, &fs_download_uri);

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
  windows_captive.uri = "/redirect";
  httpd_register_uri_handler(s_server, &windows_captive);

#ifdef CONFIG_DAC_TAS58XX
  httpd_uri_t bq_page_uri = {
      .uri = "/bq", .method = HTTP_GET, .handler = bq_page_handler};
  httpd_register_uri_handler(s_server, &bq_page_uri);

  httpd_uri_t bq_get_uri = {
      .uri = "/api/bq", .method = HTTP_GET, .handler = bq_get_handler};
  httpd_register_uri_handler(s_server, &bq_get_uri);

  httpd_uri_t bq_post_uri = {
      .uri = "/api/bq", .method = HTTP_POST, .handler = bq_post_handler};
  httpd_register_uri_handler(s_server, &bq_post_uri);

  httpd_uri_t bq_commit_uri = {.uri = "/api/bq/commit",
                               .method = HTTP_POST,
                               .handler = bq_commit_handler};
  httpd_register_uri_handler(s_server, &bq_commit_uri);

  httpd_uri_t bq_revert_uri = {.uri = "/api/bq/revert",
                               .method = HTTP_POST,
                               .handler = bq_revert_handler};
  httpd_register_uri_handler(s_server, &bq_revert_uri);
#endif

#ifdef CONFIG_DAC_TAS57XX
  httpd_uri_t hf_page_uri = {
      .uri = "/hf", .method = HTTP_GET, .handler = hf_page_handler};
  httpd_register_uri_handler(s_server, &hf_page_uri);

  httpd_uri_t hf1_get_uri = {
      .uri = "/api/hf1", .method = HTTP_GET, .handler = hf1_get_handler};
  httpd_register_uri_handler(s_server, &hf1_get_uri);

  httpd_uri_t hf1_post_uri = {
      .uri = "/api/hf1", .method = HTTP_POST, .handler = hf1_post_handler};
  httpd_register_uri_handler(s_server, &hf1_post_uri);

  httpd_uri_t hf1_commit_uri = {.uri = "/api/hf1/commit",
                                .method = HTTP_POST,
                                .handler = hf1_commit_handler};
  httpd_register_uri_handler(s_server, &hf1_commit_uri);

  httpd_uri_t hf1_revert_uri = {.uri = "/api/hf1/revert",
                                .method = HTTP_POST,
                                .handler = hf1_revert_handler};
  httpd_register_uri_handler(s_server, &hf1_revert_uri);

  httpd_uri_t hf3_get_uri = {
      .uri = "/api/hf3", .method = HTTP_GET, .handler = hf3_get_handler};
  httpd_register_uri_handler(s_server, &hf3_get_uri);

  httpd_uri_t hf3_post_uri = {
      .uri = "/api/hf3", .method = HTTP_POST, .handler = hf3_post_handler};
  httpd_register_uri_handler(s_server, &hf3_post_uri);

  httpd_uri_t hf3_commit_uri = {.uri = "/api/hf3/commit",
                                .method = HTTP_POST,
                                .handler = hf3_commit_handler};
  httpd_register_uri_handler(s_server, &hf3_commit_uri);

  httpd_uri_t hf3_revert_uri = {.uri = "/api/hf3/revert",
                                .method = HTTP_POST,
                                .handler = hf3_revert_handler};
  httpd_register_uri_handler(s_server, &hf3_revert_uri);

  httpd_uri_t hf_flow_get_uri = {.uri = "/api/hf/flow",
                                 .method = HTTP_GET,
                                 .handler = hf_flow_get_handler};
  httpd_register_uri_handler(s_server, &hf_flow_get_uri);

  httpd_uri_t hf_flow_post_uri = {.uri = "/api/hf/flow",
                                  .method = HTTP_POST,
                                  .handler = hf_flow_post_handler};
  httpd_register_uri_handler(s_server, &hf_flow_post_uri);
#endif

  log_stream_register(s_server);
#ifdef CONFIG_SENDSPIN_ENABLE
  // Returns ESP_ERR_INVALID_STATE when sendspin_init() was skipped, which is
  // the disabled case rather than a failure.
  sendspin_register(s_server);
#endif

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
