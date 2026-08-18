/**
 * WebSocket-based log streaming over HTTP.
 *
 * Intercepts ESP-IDF log output via esp_log_set_vprintf(), stores lines
 * in a ring buffer, and broadcasts them to any connected WebSocket
 * client on /ws/logs.  UART output is preserved.
 */

#include "log_stream.h"
#include "spiram_task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Ring buffer size — must be power of two for masking. */
#define LOG_RING_SIZE 8192
#define LOG_RING_MASK (LOG_RING_SIZE - 1)

#define BROADCAST_TASK_STACK  4096
#define BROADCAST_INTERVAL_MS 100
#define MAX_SEND_CHUNK        1024

static char *s_ring;
static volatile size_t s_head; /* next write position  */
static volatile size_t s_tail; /* next read position   */
static SemaphoreHandle_t s_mutex;

static httpd_handle_t s_server;

static vprintf_like_t s_orig_vprintf;

/* ------------------------------------------------------------------ */
/*  Ring buffer helpers (protected by s_mutex)                         */
/* ------------------------------------------------------------------ */

static inline size_t ring_used(void) {
  return (s_head - s_tail) & LOG_RING_MASK;
}

static void ring_write(const char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    /* If head is about to overwrite tail, discard oldest byte. */
    if (((s_head + 1) & LOG_RING_MASK) == (s_tail & LOG_RING_MASK)) {
      s_tail = (s_tail + 1) & LOG_RING_MASK;
    }
    s_ring[s_head & LOG_RING_MASK] = data[i];
    s_head = (s_head + 1) & LOG_RING_MASK;
  }
}

static size_t ring_read(char *buf, size_t max) {
  size_t avail = ring_used();
  if (avail > max) {
    avail = max;
  }
  for (size_t i = 0; i < avail; i++) {
    buf[i] = s_ring[s_tail & LOG_RING_MASK];
    s_tail = (s_tail + 1) & LOG_RING_MASK;
  }
  return avail;
}

/* ------------------------------------------------------------------ */
/*  Log hook — called from any task/ISR-safe context by esp_log       */
/* ------------------------------------------------------------------ */

static int log_vprintf_hook(const char *fmt, va_list args) {
  /* Always print to UART first. */
  int ret = s_orig_vprintf(fmt, args);

  /* Format into a stack buffer and push to ring. */
  char buf[256];
  va_list copy;
  va_copy(copy, args);
  int len = vsnprintf(buf, sizeof(buf), fmt, copy);
  va_end(copy);

  if (len > 0) {
    if ((size_t)len >= sizeof(buf)) {
      len = sizeof(buf) - 1;
    }
    if (xSemaphoreTake(s_mutex, 0) == pdTRUE) {
      ring_write(buf, (size_t)len);
      xSemaphoreGive(s_mutex);
    }
    /* If the mutex is held we silently drop — better than blocking a log call.
     */
  }
  return ret;
}

/* ------------------------------------------------------------------ */
/*  WebSocket handler                                                  */
/* ------------------------------------------------------------------ */

static esp_err_t ws_log_handler(httpd_req_t *req) {
  /* The server completes the WebSocket handshake internally; depending on the
   * IDF build the handshake GET may or may not reach here.  Return OK for it
   * and do nothing — clients are tracked by the broadcast task, not here. */
  if (req->method == HTTP_GET) {
    return ESP_OK;
  }

  /* A log viewer only receives, but browsers still send frames here (notably
   * CLOSE on tab close/reconnect).  Probe the length, then CONSUME the
   * payload: reading only the header (max_len 0) leaves the 4-byte mask key
   * and payload in the socket, so the next frame is parsed mid-stream and
   * misreported as "not properly masked", failing the handler.  Fully
   * draining each frame keeps the framing aligned; ignore recv errors instead
   * of returning them (which httpd logs as "uri handler execution failed"). */
  httpd_ws_frame_t frame = {0};
  if (httpd_ws_recv_frame(req, &frame, 0) != ESP_OK) {
    return ESP_OK;
  }
  if (frame.len > 0) {
    uint8_t buf[128];
    if (frame.len <= sizeof(buf)) {
      frame.payload = buf;
      httpd_ws_recv_frame(req, &frame, sizeof(buf));
    }
  }
  return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Broadcast task                                                     */
/* ------------------------------------------------------------------ */

static void broadcast_task(void *arg) {
  (void)arg;
  char buf[MAX_SEND_CHUNK];

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(BROADCAST_INTERVAL_MS));

    /* Discover active WebSocket sessions fresh each tick.  No connect-time
     * registration (see ws_log_handler) and no stale-fd list: a client
     * that disconnected simply stops appearing here, so log frames can
     * never be sent to a reused fd now serving an unrelated request. */
    int fds[CONFIG_LWIP_MAX_SOCKETS];
    size_t fd_count = CONFIG_LWIP_MAX_SOCKETS;
    if (httpd_get_client_list(s_server, &fd_count, fds) != ESP_OK) {
      continue;
    }

    int ws_fds[CONFIG_LWIP_MAX_SOCKETS];
    size_t ws_count = 0;
    for (size_t i = 0; i < fd_count; i++) {
      if (httpd_ws_get_fd_info(s_server, fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
        ws_fds[ws_count++] = fds[i];
      }
    }
    if (ws_count == 0) {
      continue; /* leave data in the ring as backlog for the next viewer */
    }

    size_t len = 0;
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
      len = ring_read(buf, sizeof(buf));
      xSemaphoreGive(s_mutex);
    }
    if (len == 0) {
      continue;
    }

    httpd_ws_frame_t frame = {
        .type = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)buf,
        .len = len,
    };

    for (size_t i = 0; i < ws_count; i++) {
      esp_err_t err = httpd_ws_send_frame_async(s_server, ws_fds[i], &frame);
      if (err != ESP_OK) {
        /* Session is closing; httpd cleans it up and it will no longer
         * be listed on the next tick. */
        ESP_LOGD("log_stream", "WS send to fd=%d failed: %s", ws_fds[i],
                 esp_err_to_name(err));
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

esp_err_t log_stream_init(void) {
  s_mutex = xSemaphoreCreateMutex();
  if (!s_mutex) {
    return ESP_ERR_NO_MEM;
  }

#ifdef CONFIG_SPIRAM
  s_ring = heap_caps_malloc(LOG_RING_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
  if (!s_ring) {
    s_ring = malloc(LOG_RING_SIZE);
  }
  if (!s_ring) {
    return ESP_ERR_NO_MEM;
  }

  s_head = s_tail = 0;

  /* Hook into esp_log — keep the original so UART output continues. */
  s_orig_vprintf = esp_log_set_vprintf(log_vprintf_hook);

  return ESP_OK;
}

esp_err_t log_stream_register(httpd_handle_t server) {
  s_server = server;

  httpd_uri_t ws_uri = {
      .uri = "/ws/logs",
      .method = HTTP_GET,
      .handler = ws_log_handler,
      .is_websocket = true,
  };
  esp_err_t err = httpd_register_uri_handler(server, &ws_uri);
  if (err != ESP_OK) {
    ESP_LOGE("log_stream", "Failed to register /ws/logs: %s",
             esp_err_to_name(err));
    return err;
  }

  task_create_pinned_spiram(broadcast_task, "log_ws", BROADCAST_TASK_STACK,
                            NULL, 3, NULL, 0, NULL);
  ESP_LOGI("log_stream", "Log streaming on /ws/logs");
  return ESP_OK;
}
