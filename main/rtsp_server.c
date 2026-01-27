#include "rtsp_server.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "rtsp_conn.h"
#include "rtsp_crypto.h"
#include "rtsp_handlers.h"
#include "rtsp_message.h"

static const char *TAG = "rtsp_server";

#define RTSP_PORT           7000
#define RTSP_BUFFER_INITIAL 4096
#define RTSP_BUFFER_LARGE   (256 * 1024)

static int server_socket = -1;
static TaskHandle_t server_task_handle = NULL;
static bool server_running = false;

// Current connection (one client at a time)
static rtsp_conn_t *current_conn = NULL;

// Public API for volume control
void airplay_set_volume(float volume_db) {
  if (current_conn) {
    rtsp_conn_set_volume(current_conn, volume_db);
  }
}

int32_t airplay_get_volume_q15(void) {
  if (current_conn) {
    return rtsp_conn_get_volume_q15(current_conn);
  }
  return 32768; // Default full volume
}

// Helper to grow buffer using PSRAM if possible
static uint8_t *grow_buffer(uint8_t *old_buf, size_t old_size, size_t new_size,
                            size_t data_len) {
  (void)old_size;
  uint8_t *new_buf =
      heap_caps_malloc(new_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!new_buf) {
    new_buf = malloc(new_size);
  }
  if (!new_buf) {
    return NULL;
  }
  if (old_buf && data_len > 0) {
    memcpy(new_buf, old_buf, data_len);
  }
  if (old_buf) {
    free(old_buf);
  }
  return new_buf;
}

// Process buffered RTSP requests
static void process_rtsp_buffer(int client_socket, rtsp_conn_t *conn,
                                uint8_t *buffer, size_t *buf_len) {
  while (*buf_len > 0) {
    const uint8_t *header_end = rtsp_find_header_end(buffer, *buf_len);
    if (!header_end) {
      break;
    }

    size_t header_len = (size_t)(header_end - buffer) + 4;
    char *header_str = malloc(header_len + 1);
    if (!header_str) {
      ESP_LOGE(TAG, "Failed to allocate header buffer");
      *buf_len = 0;
      break;
    }
    memcpy(header_str, buffer, header_len);
    header_str[header_len] = '\0';

    int content_len = rtsp_parse_content_length(header_str);
    if (content_len < 0) {
      content_len = 0;
    }

    size_t total_len = header_len + (size_t)content_len;
    if (total_len > RTSP_BUFFER_LARGE) {
      ESP_LOGE(TAG, "RTSP message too large: %zu bytes", total_len);
      free(header_str);
      *buf_len = 0;
      break;
    }

    if (*buf_len < total_len) {
      free(header_str);
      break;
    }

    // Dispatch request to handler
    rtsp_dispatch(client_socket, conn, buffer, total_len);

    free(header_str);

    if (*buf_len > total_len) {
      memmove(buffer, buffer + total_len, *buf_len - total_len);
    }
    *buf_len -= total_len;
  }
}

static void handle_client(int client_socket) {
  // Create connection state
  rtsp_conn_t *conn = rtsp_conn_create();
  if (!conn) {
    ESP_LOGE(TAG, "Failed to create connection state");
    close(client_socket);
    return;
  }
  current_conn = conn;

  // Allocate initial buffer
  size_t buf_capacity = RTSP_BUFFER_INITIAL;
  uint8_t *buffer = malloc(buf_capacity);
  if (!buffer) {
    ESP_LOGE(TAG, "Failed to allocate request buffer");
    rtsp_conn_free(conn);
    current_conn = NULL;
    close(client_socket);
    return;
  }

  size_t buf_len = 0;

  while (server_running) {
    // Handle encrypted mode
    if (conn->encrypted_mode) {
      while (server_running && conn->encrypted_mode) {
        // Grow buffer if needed
        if (buf_len >= buf_capacity - 1024) {
          size_t new_capacity = (buf_capacity < RTSP_BUFFER_LARGE)
                                    ? RTSP_BUFFER_LARGE
                                    : buf_capacity * 2;
          if (new_capacity > RTSP_BUFFER_LARGE) {
            ESP_LOGE(TAG, "RTSP buffer overflow (%zu bytes)", buf_len);
            goto cleanup;
          }
          uint8_t *new_buf =
              grow_buffer(buffer, buf_capacity, new_capacity, buf_len);
          if (!new_buf) {
            ESP_LOGE(TAG, "Failed to grow RTSP buffer");
            goto cleanup;
          }
          buffer = new_buf;
          buf_capacity = new_capacity;
        }

        int block_len = rtsp_crypto_read_block(
            client_socket, conn, buffer + buf_len, buf_capacity - buf_len);
        if (block_len <= 0) {
          goto cleanup;
        }

        buf_len += (size_t)block_len;
        process_rtsp_buffer(client_socket, conn, buffer, &buf_len);
      }
      goto cleanup;
    }

    // Plain-text mode (before encryption)
    if (buf_len >= buf_capacity - 1024) {
      size_t new_capacity = (buf_capacity < RTSP_BUFFER_LARGE)
                                ? RTSP_BUFFER_LARGE
                                : buf_capacity * 2;
      if (new_capacity > RTSP_BUFFER_LARGE) {
        ESP_LOGE(TAG, "RTSP buffer overflow (%zu bytes)", buf_len);
        break;
      }
      uint8_t *new_buf =
          grow_buffer(buffer, buf_capacity, new_capacity, buf_len);
      if (!new_buf) {
        ESP_LOGE(TAG, "Failed to grow RTSP buffer");
        break;
      }
      buffer = new_buf;
      buf_capacity = new_capacity;
    }

    int recv_len =
        recv(client_socket, buffer + buf_len, buf_capacity - buf_len, 0);
    if (recv_len <= 0) {
      if (recv_len < 0) {
        ESP_LOGE(TAG, "recv error: %d", errno);
      }
      break;
    }
    buf_len += (size_t)recv_len;
    process_rtsp_buffer(client_socket, conn, buffer, &buf_len);
  }

cleanup:
  ESP_LOGI(TAG, "Client connection closed, cleaning up");
  free(buffer);
  close(client_socket);

  // Stop event port task
  rtsp_stop_event_port_task();

  // Close event socket if open
  if (conn->event_socket >= 0) {
    close(conn->event_socket);
    conn->event_socket = -1;
  }

  // Full cleanup (stops audio, clears PTP, etc.)
  rtsp_conn_cleanup(conn);

  // Free connection state
  rtsp_conn_free(conn);
  current_conn = NULL;
}

static void server_task(void *pvParameters) {
  (void)pvParameters;

  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server_socket < 0) {
    ESP_LOGE(TAG, "Failed to create socket: %d", errno);
    vTaskDelete(NULL);
    return;
  }

  int opt = 1;
  setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(RTSP_PORT);

  if (bind(server_socket, (struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind socket: %d", errno);
    close(server_socket);
    server_socket = -1;
    vTaskDelete(NULL);
    return;
  }

  if (listen(server_socket, 5) < 0) {
    ESP_LOGE(TAG, "Failed to listen: %d", errno);
    close(server_socket);
    server_socket = -1;
    vTaskDelete(NULL);
    return;
  }

  ESP_LOGI(TAG, "RTSP server listening on port %d", RTSP_PORT);
  server_running = true;

  while (server_running) {
    int client_socket = accept(server_socket, (struct sockaddr *)&client_addr,
                               &client_addr_len);
    if (client_socket < 0) {
      if (server_running) {
        ESP_LOGE(TAG, "Failed to accept: %d", errno);
      }
      continue;
    }

    ESP_LOGI(TAG, "Client connected");
    handle_client(client_socket);
  }

  if (server_socket >= 0) {
    close(server_socket);
    server_socket = -1;
  }

  vTaskDelete(NULL);
}

esp_err_t rtsp_server_start(void) {
  if (server_task_handle != NULL) {
    ESP_LOGW(TAG, "Server already running");
    return ESP_ERR_INVALID_STATE;
  }

  BaseType_t ret = xTaskCreate(server_task, "rtsp_server", 8192, NULL, 5,
                               &server_task_handle);
  if (ret != pdPASS) {
    ESP_LOGE(TAG, "Failed to create server task");
    return ESP_FAIL;
  }

  return ESP_OK;
}

void rtsp_server_stop(void) {
  server_running = false;

  if (server_socket >= 0) {
    shutdown(server_socket, SHUT_RDWR);
    close(server_socket);
    server_socket = -1;
  }

  if (server_task_handle != NULL) {
    vTaskDelay(pdMS_TO_TICKS(100));
    server_task_handle = NULL;
  }
}
