/**
 * DACP client — sends control commands to AirPlay source device.
 *
 * The client's DACP service is discovered via mDNS using the DACP-ID
 * from the RTSP handshake. Commands are fire-and-forget HTTP GETs.
 *
 * Thread safety: dacp_set_session/clear may be called from the RTSP
 * server task while dacp_send_* are called from the button task.
 * A mutex protects the session state.
 */

#include "dacp_client.h"

#include "esp_http_client.h"
#include "esp_log.h"
#include "mdns.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

static const char *TAG = "dacp";

#define DACP_ID_MAX     32
#define ACTIVE_REMOTE_MAX 32
#define MDNS_TIMEOUT_MS 3000

static SemaphoreHandle_t s_mutex;
static bool s_initialized;
static char s_dacp_id[DACP_ID_MAX];
static char s_active_remote[ACTIVE_REMOTE_MAX];
static uint32_t s_client_ip;
static uint16_t s_dacp_port;   // Discovered via mDNS
static bool s_session_valid;

static void discover_dacp_port(void) {
  if (s_dacp_id[0] == '\0') {
    return;
  }

  s_dacp_port = 0;

  // Query mDNS for _dacp._tcp services
  mdns_result_t *results = NULL;
  esp_err_t err =
      mdns_query_ptr("_dacp", "_tcp", MDNS_TIMEOUT_MS, 8, &results);
  if (err != ESP_OK || !results) {
    ESP_LOGW(TAG, "mDNS DACP query failed or no results (err=%s)",
             esp_err_to_name(err));
    return;
  }

  // Find the result matching our DACP-ID.
  // iOS advertises as "iTunes_Ctrl_<DACPID>" or just "<DACPID>".
  for (mdns_result_t *r = results; r; r = r->next) {
    ESP_LOGI(TAG, "mDNS DACP service: instance='%s' port=%u",
             r->instance_name ? r->instance_name : "(null)", r->port);
    if (!r->instance_name || r->port == 0) {
      continue;
    }
    // Match: exact, or instance contains the DACP-ID as a substring
    if (strcasecmp(r->instance_name, s_dacp_id) == 0 ||
        strcasestr(r->instance_name, s_dacp_id) != NULL) {
      s_dacp_port = r->port;
      ESP_LOGI(TAG, "Matched DACP service: '%s' port %u",
               r->instance_name, s_dacp_port);
      break;
    }
  }

  mdns_query_results_free(results);

  if (s_dacp_port == 0) {
    ESP_LOGW(TAG, "DACP service not found for ID '%s'", s_dacp_id);
  }
}

static void send_dacp_request(const char *path) {
  if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
    ESP_LOGW(TAG, "DACP mutex timeout for '%s'", path);
    return;
  }

  if (!s_session_valid || s_active_remote[0] == '\0') {
    xSemaphoreGive(s_mutex);
    ESP_LOGD(TAG, "DACP: no active session, skipping '%s'", path);
    return;
  }

  // Lazy discover port on first command
  if (s_dacp_port == 0) {
    discover_dacp_port();
    if (s_dacp_port == 0) {
      xSemaphoreGive(s_mutex);
      return;
    }
  }

  // Build URL: http://<ip>:<port>/ctrl-int/1/<path>
  char url[128];
  uint8_t *ip = (uint8_t *)&s_client_ip;
  snprintf(url, sizeof(url), "http://%u.%u.%u.%u:%u/ctrl-int/1/%s",
           ip[0], ip[1], ip[2], ip[3], s_dacp_port, path);

  char active_remote_copy[ACTIVE_REMOTE_MAX];
  strlcpy(active_remote_copy, s_active_remote, sizeof(active_remote_copy));

  xSemaphoreGive(s_mutex);

  // Fire-and-forget HTTP GET
  esp_http_client_config_t config = {
      .url = url,
      .timeout_ms = 2000,
      .disable_auto_redirect = true,
  };

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    ESP_LOGW(TAG, "Failed to init HTTP client");
    return;
  }

  esp_http_client_set_header(client, "Active-Remote", active_remote_copy);
  esp_http_client_set_method(client, HTTP_METHOD_GET);

  esp_err_t err = esp_http_client_perform(client);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "DACP request failed: %s (%s)", path,
             esp_err_to_name(err));
  } else {
    int status = esp_http_client_get_status_code(client);
    ESP_LOGI(TAG, "DACP: %s -> %d", path, status);
    if (status == 403 || status == 401) {
      ESP_LOGW(TAG, "DACP auth rejected — Active-Remote may be wrong");
    }
  }

  esp_http_client_cleanup(client);
}

// ============================================================================
// Public API
// ============================================================================

void dacp_init(void) {
  if (s_initialized) {
    return;
  }
  s_mutex = xSemaphoreCreateMutex();
  s_initialized = true;
  ESP_LOGI(TAG, "DACP client initialized");
}

void dacp_set_session(const char *dacp_id, const char *active_remote,
                      uint32_t client_ip) {
  xSemaphoreTake(s_mutex, portMAX_DELAY);

  strlcpy(s_dacp_id, dacp_id ? dacp_id : "", sizeof(s_dacp_id));
  strlcpy(s_active_remote, active_remote ? active_remote : "",
          sizeof(s_active_remote));
  s_client_ip = client_ip;
  s_dacp_port = 0; // Will be discovered on first use
  s_session_valid = (s_dacp_id[0] != '\0' && s_active_remote[0] != '\0');

  xSemaphoreGive(s_mutex);

  if (s_session_valid) {
    ESP_LOGI(TAG, "DACP session: id=%s remote=%s", s_dacp_id,
             s_active_remote);
  }
}

void dacp_clear_session(void) {
  if (!s_initialized) {
    return;
  }

  xSemaphoreTake(s_mutex, portMAX_DELAY);
  s_dacp_id[0] = '\0';
  s_active_remote[0] = '\0';
  s_dacp_port = 0;
  s_session_valid = false;
  xSemaphoreGive(s_mutex);

  ESP_LOGI(TAG, "DACP session cleared");
}

void dacp_send_playpause(void) { send_dacp_request("playpause"); }

void dacp_send_next(void) { send_dacp_request("nextitem"); }

void dacp_send_prev(void) { send_dacp_request("previtem"); }

void dacp_send_volume(float volume_percent) {
  if (volume_percent < 0.0f)
    volume_percent = 0.0f;
  if (volume_percent > 100.0f)
    volume_percent = 100.0f;

  char path[64];
  snprintf(path, sizeof(path), "setproperty?dmcp.volume=%.0f",
           volume_percent);
  send_dacp_request(path);
}
