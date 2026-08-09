#include "web_server.h"

#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_system.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_wifi.h"

#include "settings.h"
#include "led.h"
#include "wifi.h"
#include "ethernet.h"
#include "ota.h"
#include "log_stream.h"
#include "rtsp_server.h"
#include "audio_output.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef CONFIG_DAC_TAS58XX
#include "eq_events.h"
#include "dac_tas58xx.h"
#include "dac_tas58xx_eq.h"
#endif

#ifdef CONFIG_DAC_TAS57XX
#include "dac_tas57xx.h"
#endif

/* Sub level-trim (2.1 subwoofer) is exposed by both the TAS57xx and TAS58xx
 * drivers with the same API shape. Map to whichever is configured so the
 * /api/audio/sub endpoints work regardless of DAC. */
#if defined(CONFIG_DAC_TAS57XX)
#define DAC_HAS_SUB_OFFSET       1
#define DAC_SUB_OFFSET_MIN_DB    TAS57XX_SUB_OFFSET_MIN_DB
#define DAC_SUB_OFFSET_MAX_DB    TAS57XX_SUB_OFFSET_MAX_DB
#define dac_get_sub_offset_db()  dac_tas57xx_get_sub_offset_db()
#define dac_set_sub_offset_db(x) dac_tas57xx_set_sub_offset_db(x)
/* The trim only moves devices flagged is_sub, which is index > 0, so a
 * single-amplifier board has nothing for it to act on. */
#define dac_has_sub() (dac_tas57xx_get_device_count() > 1)
#elif defined(CONFIG_DAC_TAS58XX)
#define DAC_HAS_SUB_OFFSET       1
#define DAC_SUB_OFFSET_MIN_DB    TAS58XX_SUB_OFFSET_MIN_DB
#define DAC_SUB_OFFSET_MAX_DB    TAS58XX_SUB_OFFSET_MAX_DB
#define dac_get_sub_offset_db()  dac_tas58xx_get_sub_offset_db()
#define dac_set_sub_offset_db(x) dac_tas58xx_set_sub_offset_db(x)
/* Only dual-DAC boards have a sub, and only while the second amplifier is
 * configured as a bridged mono subwoofer rather than a bi-amp channel. A role
 * chosen but not yet restarted into does not count. */
#define dac_has_sub()                    \
  (dac_tas58xx_get_device_count() > 1 && \
   dac_tas58xx_get_active_dual_mode() == TAS58XX_DUAL_SUB)
#endif

static const char *TAG = "web_server";
static httpd_handle_t s_server = NULL;

#define SPIFFS_CHUNK_SIZE 1024

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

#ifdef DAC_HAS_SUB_OFFSET
#ifdef CONFIG_DAC_TAS58XX
/* The NVS blob layout and the driver's band count are declared independently,
 * so a change to either would silently truncate or overrun the other. */
_Static_assert(SETTINGS_WAY_BANDS == TAS58XX_WAY_BANDS,
               "settings/driver per-way band count mismatch");
_Static_assert(SETTINGS_EQ_BANDS == TAS58XX_EQ_BANDS,
               "settings/driver EQ band count mismatch");

/* Both crossovers expose their EQ as 12-float curves plus the band centres
 * they currently sit on, which move whenever the crossover moves. */
static void way_add_array(cJSON *parent, const char *name,
                          const float vals[TAS58XX_WAY_BANDS], bool whole_hz) {
  cJSON *arr = cJSON_CreateArray();
  for (int i = 0; i < TAS58XX_WAY_BANDS; i++) {
    cJSON_AddItemToArray(
        arr, cJSON_CreateNumber(whole_hz ? (double)(int)(vals[i] + 0.5f)
                                         : (double)vals[i]));
  }
  cJSON_AddItemToObject(parent, name, arr);
}

static bool way_read_array(const cJSON *obj, const char *name,
                           float out[TAS58XX_WAY_BANDS]) {
  const cJSON *arr = cJSON_GetObjectItem(obj, name);
  if (!arr || !cJSON_IsArray(arr) ||
      cJSON_GetArraySize(arr) != TAS58XX_WAY_BANDS) {
    return false;
  }
  for (int i = 0; i < TAS58XX_WAY_BANDS; i++) {
    const cJSON *item = cJSON_GetArrayItem(arr, i);
    if (!cJSON_IsNumber(item)) {
      return false;
    }
    out[i] = (float)item->valuedouble;
  }
  return true;
}

static void sub_eq_add_freqs(cJSON *parent) {
  float f[TAS58XX_WAY_BANDS];
  dac_tas58xx_sub_band_freqs(TAS58XX_WAY_LOW, f);
  way_add_array(parent, "freqs_low", f, true);
  dac_tas58xx_sub_band_freqs(TAS58XX_WAY_HIGH, f);
  way_add_array(parent, "freqs_high", f, true);
}

/* The driver only relayouts and flattens the bands when the corner actually
 * moves, so hand the resulting state back rather than let the client guess. */
static void sub_eq_add_state(cJSON *parent) {
  cJSON_AddBoolToObject(parent, "eq_active", dac_tas58xx_sub_eq_active());
  sub_eq_add_freqs(parent);

  cJSON *gains = cJSON_CreateObject();
  float curve[TAS58XX_WAY_BANDS];
  dac_tas58xx_sub_eq_get_gains(TAS58XX_WAY_LOW, curve);
  way_add_array(gains, "sub", curve, false);
  dac_tas58xx_sub_eq_get_gains(TAS58XX_WAY_HIGH, curve);
  way_add_array(gains, "sat", curve, false);
  cJSON_AddItemToObject(parent, "gains", gains);
}

static esp_err_t sub_eq_persist(void) {
  float saved[2][SETTINGS_WAY_BANDS];
  dac_tas58xx_sub_eq_get_gains(TAS58XX_WAY_LOW, saved[0]);
  dac_tas58xx_sub_eq_get_gains(TAS58XX_WAY_HIGH, saved[1]);
  return settings_set_sub_eq(saved);
}
#endif /* CONFIG_DAC_TAS58XX */

static esp_err_t sub_offset_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "offset", dac_get_sub_offset_db());
  cJSON_AddNumberToObject(json, "min", DAC_SUB_OFFSET_MIN_DB);
  cJSON_AddNumberToObject(json, "max", DAC_SUB_OFFSET_MAX_DB);
  cJSON_AddBoolToObject(json, "available", dac_has_sub());
#ifdef CONFIG_DAC_TAS58XX
  cJSON_AddNumberToObject(json, "crossover",
                          dac_tas58xx_get_sub_crossover_hz());
  cJSON_AddNumberToObject(json, "xo_min", TAS58XX_XOVER_MIN_HZ);
  cJSON_AddNumberToObject(json, "xo_max", TAS58XX_XOVER_MAX_HZ);
  cJSON_AddNumberToObject(json, "bands", TAS58XX_WAY_BANDS);
  cJSON_AddNumberToObject(json, "min_db", TAS58XX_EQ_MIN_GAIN_DB);
  cJSON_AddNumberToObject(json, "max_db", TAS58XX_EQ_MAX_GAIN_DB);
  sub_eq_add_state(json);
#endif
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
  bool handled = false;
  esp_err_t save_err = ESP_OK;

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
    settings_set_sub_offset(off);
    handled = true;
  }

#ifdef CONFIG_DAC_TAS58XX
  cJSON *xo = cJSON_GetObjectItem(json, "crossover");
  if (xo && cJSON_IsNumber(xo)) {
    float hz = (float)xo->valuedouble;
    dac_tas58xx_set_sub_crossover_hz(hz);
    settings_set_sub_crossover(dac_tas58xx_get_sub_crossover_hz());
    /* Moving the corner relayouts the bands and flattens the curves. */
    save_err = sub_eq_persist();
    handled = true;
  }

  cJSON *gains = cJSON_GetObjectItem(json, "gains");
  if (gains && cJSON_IsObject(gains)) {
    float curve[TAS58XX_WAY_BANDS];
    bool any = false;
    if (way_read_array(gains, "sub", curve)) {
      dac_tas58xx_sub_eq_set_gains(TAS58XX_WAY_LOW, curve);
      any = true;
    }
    if (way_read_array(gains, "sat", curve)) {
      dac_tas58xx_sub_eq_set_gains(TAS58XX_WAY_HIGH, curve);
      any = true;
    }
    if (any) {
      esp_err_t e = sub_eq_persist();
      if (save_err == ESP_OK) {
        save_err = e;
      }
      handled = true;
    }
  }
#endif

  if (handled && save_err != ESP_OK) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Applied but could not save");
  } else if (handled) {
    cJSON_AddBoolToObject(response, "success", true);
#ifdef CONFIG_DAC_TAS58XX
    sub_eq_add_state(response);
#endif
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error",
                            "Expected {\"offset\": dB} or {\"crossover\": Hz}");
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

#ifdef CONFIG_DAC_TAS58XX
/* Second-amplifier role on dual-DAC boards: bridged mono sub or bi-amp. */
static esp_err_t dual_mode_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddNumberToObject(json, "devices", dac_tas58xx_get_device_count());
  cJSON_AddNumberToObject(json, "mode", dac_tas58xx_get_dual_mode());
  cJSON_AddBoolToObject(json, "restart_required",
                        dac_tas58xx_get_dual_mode() !=
                            dac_tas58xx_get_active_dual_mode());
  cJSON_AddBoolToObject(json, "biamp", TAS58XX_BIAMP_SUPPORTED);
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
  cJSON *val = cJSON_GetObjectItem(json, "mode");
  if (!json_int_in_range(val, TAS58XX_DUAL_SUB, TAS58XX_DUAL_BIAMP)) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Expected {\"mode\": 0-1}");
  } else if (val->valueint == TAS58XX_DUAL_BIAMP && !TAS58XX_BIAMP_SUPPORTED) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Bi-amp is not available");
  } else {
    dac_tas58xx_set_dual_mode((tas58xx_dual_mode_t)val->valueint);
    settings_set_dual_mode((uint8_t)val->valueint);
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

/* Bi-amp: woofer/tweeter crossover plus a 12-band EQ per way per speaker. */
static void biamp_add_gain_array(cJSON *parent, const char *name, int dev,
                                 tas58xx_way_t way) {
  float gains[TAS58XX_WAY_BANDS];
  dac_tas58xx_biamp_get_gains(dev, way, gains);
  way_add_array(parent, name, gains, false);
}

static void biamp_add_freqs(cJSON *parent) {
  float f[TAS58XX_WAY_BANDS];
  dac_tas58xx_biamp_band_freqs(TAS58XX_WAY_LOW, f);
  way_add_array(parent, "freqs_low", f, true);
  dac_tas58xx_biamp_band_freqs(TAS58XX_WAY_HIGH, f);
  way_add_array(parent, "freqs_high", f, true);
}

/* The driver only relayouts and flattens the bands when the corner actually
 * moves, so hand the resulting state back rather than let the client guess. */
static void biamp_add_state(cJSON *parent) {
  biamp_add_freqs(parent);

  cJSON *gains = cJSON_CreateObject();
  biamp_add_gain_array(gains, "l_low", 0, TAS58XX_WAY_LOW);
  biamp_add_gain_array(gains, "l_high", 0, TAS58XX_WAY_HIGH);
  biamp_add_gain_array(gains, "r_low", 1, TAS58XX_WAY_LOW);
  biamp_add_gain_array(gains, "r_high", 1, TAS58XX_WAY_HIGH);
  cJSON_AddItemToObject(parent, "gains", gains);
}

static esp_err_t biamp_get_handler(httpd_req_t *req) {
  cJSON *json = cJSON_CreateObject();
  cJSON_AddBoolToObject(json, "active", dac_tas58xx_biamp_active());
  cJSON_AddNumberToObject(json, "crossover",
                          dac_tas58xx_get_biamp_crossover_hz());
  cJSON_AddNumberToObject(json, "xo_min", TAS58XX_BIAMP_XOVER_MIN_HZ);
  cJSON_AddNumberToObject(json, "xo_max", TAS58XX_BIAMP_XOVER_MAX_HZ);
  cJSON_AddBoolToObject(json, "swap", dac_tas58xx_get_biamp_swap());
  cJSON_AddNumberToObject(json, "bands", TAS58XX_WAY_BANDS);
  cJSON_AddNumberToObject(json, "min_db", TAS58XX_EQ_MIN_GAIN_DB);
  cJSON_AddNumberToObject(json, "max_db", TAS58XX_EQ_MAX_GAIN_DB);
  biamp_add_state(json);

  cJSON_AddBoolToObject(json, "success", true);
  char *json_str = cJSON_Print(json);
  httpd_resp_set_type(req, "application/json");
  httpd_resp_send(req, json_str, HTTPD_RESP_USE_STRLEN);
  free(json_str);
  cJSON_Delete(json);
  return ESP_OK;
}

/* Copy one "gains" member into the driver. Returns true if it was present. */
static bool biamp_apply_gain_member(const cJSON *gains, const char *name,
                                    int dev, tas58xx_way_t way) {
  float vals[TAS58XX_WAY_BANDS];
  if (!way_read_array(gains, name, vals)) {
    return false;
  }
  dac_tas58xx_biamp_set_gains(dev, way, vals);
  return true;
}

static esp_err_t biamp_persist_gains(void) {
  float saved[2][2][SETTINGS_WAY_BANDS];
  for (int spk = 0; spk < 2; spk++) {
    dac_tas58xx_biamp_get_gains(spk, TAS58XX_WAY_LOW, saved[spk][0]);
    dac_tas58xx_biamp_get_gains(spk, TAS58XX_WAY_HIGH, saved[spk][1]);
  }
  return settings_set_biamp_eq(saved);
}

static esp_err_t biamp_post_handler(httpd_req_t *req) {
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

  bool handled = false;
  esp_err_t save_err = ESP_OK;
  cJSON *response = cJSON_CreateObject();

  cJSON *xo = cJSON_GetObjectItem(json, "crossover");
  if (xo && cJSON_IsNumber(xo)) {
    dac_tas58xx_set_biamp_crossover_hz((float)xo->valuedouble);
    settings_set_biamp_crossover(dac_tas58xx_get_biamp_crossover_hz());
    /* Moving the corner relayouts the bands and flattens the curves. */
    save_err = biamp_persist_gains();
    handled = true;
  }

  cJSON *swap = cJSON_GetObjectItem(json, "swap");
  if (swap && cJSON_IsBool(swap)) {
    dac_tas58xx_set_biamp_swap(cJSON_IsTrue(swap));
    settings_set_biamp_swap(dac_tas58xx_get_biamp_swap());
    handled = true;
  }

  cJSON *gains = cJSON_GetObjectItem(json, "gains");
  if (gains && cJSON_IsObject(gains)) {
    bool any = biamp_apply_gain_member(gains, "l_low", 0, TAS58XX_WAY_LOW);
    any |= biamp_apply_gain_member(gains, "l_high", 0, TAS58XX_WAY_HIGH);
    any |= biamp_apply_gain_member(gains, "r_low", 1, TAS58XX_WAY_LOW);
    any |= biamp_apply_gain_member(gains, "r_high", 1, TAS58XX_WAY_HIGH);
    if (any) {
      esp_err_t e = biamp_persist_gains();
      if (save_err == ESP_OK) {
        save_err = e;
      }
      handled = true;
    }
  }

  if (handled && save_err != ESP_OK) {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(response, "error", "Applied but could not save");
  } else if (handled) {
    cJSON_AddBoolToObject(response, "success", true);
    /* Band centres track the crossover, so hand the new layout back. */
    biamp_add_state(response);
  } else {
    cJSON_AddBoolToObject(response, "success", false);
    cJSON_AddStringToObject(
        response, "error", "Expected \"crossover\", \"swap\" and/or \"gains\"");
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
  config.max_uri_handlers =
      30; // Room for captive portal + EQ + speedtest + brightness + channel
#ifdef DAC_HAS_SUB_OFFSET
  config.max_uri_handlers += 2; // sub level get/post
#endif
#ifdef CONFIG_DAC_TAS58XX
  config.max_uri_handlers += 2; // dual DAC role get/post
  config.max_uri_handlers += 2; // bi-amp get/post
#endif
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

#ifdef CONFIG_DAC_TAS58XX
  httpd_uri_t dual_mode_get_uri = {.uri = "/api/audio/dual",
                                   .method = HTTP_GET,
                                   .handler = dual_mode_get_handler};
  httpd_register_uri_handler(s_server, &dual_mode_get_uri);

  httpd_uri_t dual_mode_post_uri = {.uri = "/api/audio/dual",
                                    .method = HTTP_POST,
                                    .handler = dual_mode_post_handler};
  httpd_register_uri_handler(s_server, &dual_mode_post_uri);

  httpd_uri_t biamp_get_uri = {.uri = "/api/audio/biamp",
                               .method = HTTP_GET,
                               .handler = biamp_get_handler};
  httpd_register_uri_handler(s_server, &biamp_get_uri);

  httpd_uri_t biamp_post_uri = {.uri = "/api/audio/biamp",
                                .method = HTTP_POST,
                                .handler = biamp_post_handler};
  httpd_register_uri_handler(s_server, &biamp_post_uri);
#endif

  httpd_uri_t ota_uri = {.uri = "/api/ota/update",
                         .method = HTTP_POST,
                         .handler = ota_update_handler};
  httpd_register_uri_handler(s_server, &ota_uri);

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
  windows_captive.uri = "/redirect";
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
