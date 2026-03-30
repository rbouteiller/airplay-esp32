#include "rtsp_server.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "audio_receiver.h"
#include "audio_output.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "rtsp_conn.h"
#include "rtsp_crypto.h"
#include "rtsp_handlers.h"
#include "rtsp_message.h"

#include "ntp_clock.h"
#include "ptp_clock.h"
#include "rtsp_events.h"
#include "dacp_client.h"

static const char *TAG = "rtsp_server";

#define RTSP_PORT           7000
#define RTSP_BUFFER_INITIAL 4096
#define RTSP_BUFFER_LARGE   ((size_t)256 * 1024)

#define CLIENT_STACK_SIZE 8192
#define SERVER_STACK_SIZE 4096

static int server_socket = -1;
static TaskHandle_t server_task_handle = NULL;
static bool server_running = false;

// Static task memory for client tasks (one per slot)
static StaticTask_t s_client_tcb[2];
static StackType_t s_client_stack[2][CLIENT_STACK_SIZE / sizeof(StackType_t)];

// Static task memory for server task
static StaticTask_t s_server_tcb;
static StackType_t s_server_stack[SERVER_STACK_SIZE / sizeof(StackType_t)];

// Client slot for tracking connections
typedef struct {
  rtsp_conn_t *conn;
  TaskHandle_t task;
  int socket;
  volatile bool should_stop;
  volatile bool is_old; // Marked as old client being killed
} client_slot_t;

static client_slot_t clients[2] = {0}; // Current and old
static int current_slot = 0;

// Flag set by the play/pause button to tell the grace period loop
// to send a DACP resume command and keep waiting for reconnect.
static volatile bool s_resume_requested = false;

// Public API for volume control
void airplay_set_volume(float volume_db) {
  client_slot_t *c = &clients[current_slot];
  if (c->conn && !c->is_old) {
    rtsp_conn_set_volume(c->conn, volume_db);
  }
}

int32_t airplay_get_volume_q15(void) {
  client_slot_t *c = &clients[current_slot];
  if (c->conn && !c->is_old) {
    return rtsp_conn_get_volume_q15(c->conn);
  }
  return 16384; // 50% volume for new clients
}

void rtsp_server_request_resume(void) {
  s_resume_requested = true;
}

// Helper to grow buffer
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
  free(old_buf);
  return new_buf;
}

// Process buffered RTSP requests
static void process_rtsp_buffer(client_slot_t *slot, uint8_t *buffer,
                                size_t *buf_len) {
  while (*buf_len > 0 && !slot->should_stop) {
    const uint8_t *header_end = rtsp_find_header_end(buffer, *buf_len);
    if (!header_end) {
      break;
    }

    size_t header_len = (size_t)(header_end - buffer) + 4;
    char *header_str = malloc(header_len + 1);
    if (!header_str) {
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
    if (total_len > RTSP_BUFFER_LARGE || *buf_len < total_len) {
      free(header_str);
      if (total_len > RTSP_BUFFER_LARGE) {
        *buf_len = 0;
      }
      break;
    }

    // Null-terminate so strcasestr in parse_raw_header won't read past
    // the message boundary (buffer capacity > total_len).
    uint8_t saved = buffer[total_len];
    buffer[total_len] = '\0';
    rtsp_dispatch(slot->socket, slot->conn, buffer, total_len);
    buffer[total_len] = saved;
    free(header_str);

    if (*buf_len > total_len) {
      memmove(buffer, buffer + total_len, *buf_len - total_len);
    }
    *buf_len -= total_len;
  }
}

// Client task
static void client_task(void *pvParameters) {
  int slot_idx = (int)(intptr_t)pvParameters;
  client_slot_t *slot = &clients[slot_idx];

  // Create connection state
  rtsp_conn_t *conn = rtsp_conn_create();
  if (!conn) {
    ESP_LOGE(TAG, "Failed to create connection state");
    close(slot->socket);
    slot->socket = -1;
    slot->task = NULL;
    vTaskDelete(NULL);
    return;
  }
  slot->conn = conn;

  // Get client IP address for timing requests
  struct sockaddr_in peer_addr;
  socklen_t peer_len = sizeof(peer_addr);
  if (getpeername(slot->socket, (struct sockaddr *)&peer_addr, &peer_len) ==
      0) {
    conn->client_ip = peer_addr.sin_addr.s_addr;
    ESP_LOGI(TAG, "Client IP: %u.%u.%u.%u",
             (unsigned int)(conn->client_ip & 0xFF),
             (unsigned int)((conn->client_ip >> 8) & 0xFF),
             (unsigned int)((conn->client_ip >> 16) & 0xFF),
             (unsigned int)((conn->client_ip >> 24) & 0xFF));
  }

  // Allocate buffer
  size_t buf_capacity = RTSP_BUFFER_INITIAL;
  uint8_t *buffer = malloc(buf_capacity);
  if (!buffer) {
    ESP_LOGE(TAG, "Failed to allocate buffer");
    rtsp_conn_free(conn);
    slot->conn = NULL;
    close(slot->socket);
    slot->socket = -1;
    slot->task = NULL;
    vTaskDelete(NULL);
    return;
  }

  size_t buf_len = 0;

  // Socket timeout for stop signal responsiveness
  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  setsockopt(slot->socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  while (server_running && !slot->should_stop) {
    if (conn->encrypted_mode) {
      // Encrypted mode
      while (server_running && conn->encrypted_mode && !slot->should_stop) {
        if (buf_len >= buf_capacity - 1024) {
          size_t new_cap = buf_capacity < RTSP_BUFFER_LARGE ? RTSP_BUFFER_LARGE
                                                            : buf_capacity * 2;
          if (new_cap > RTSP_BUFFER_LARGE) {
            goto cleanup;
          }
          uint8_t *new_buf =
              grow_buffer(buffer, buf_capacity, new_cap, buf_len);
          if (!new_buf) {
            goto cleanup;
          }
          buffer = new_buf;
          buf_capacity = new_cap;
        }

        int block_len = rtsp_crypto_read_block(
            slot->socket, conn, buffer + buf_len, buf_capacity - buf_len);
        if (block_len <= 0) {
          if (slot->should_stop || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            goto cleanup;
          }
          continue;
        }

        buf_len += (size_t)block_len;
        process_rtsp_buffer(slot, buffer, &buf_len);
      }
      goto cleanup;
    }

    // Plain-text mode
    if (buf_len >= buf_capacity - 1024) {
      size_t new_cap = buf_capacity < RTSP_BUFFER_LARGE ? RTSP_BUFFER_LARGE
                                                        : buf_capacity * 2;
      if (new_cap > RTSP_BUFFER_LARGE) {
        break;
      }
      uint8_t *new_buf = grow_buffer(buffer, buf_capacity, new_cap, buf_len);
      if (!new_buf) {
        break;
      }
      buffer = new_buf;
      buf_capacity = new_cap;
    }

    ssize_t recv_len =
        recv(slot->socket, buffer + buf_len, buf_capacity - buf_len, 0);
    if (recv_len <= 0) {
      if (recv_len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        continue;
      }
      break;
    }
    buf_len += (size_t)recv_len;
    process_rtsp_buffer(slot, buffer, &buf_len);
  }

cleanup:
  ESP_LOGI(TAG, "Client slot %d disconnected", slot_idx);
  free(buffer);
  close(slot->socket);
  slot->socket = -1;

  // Immediate: stop audio and NTP
  audio_receiver_stop();
  audio_output_flush();
  ntp_clock_stop();

#ifdef CONFIG_AIRPLAY_FORCE_V1
  // AirPlay v1 grace period: iOS sends TEARDOWN + TCP close for both pause
  // and genuine disconnect. Wait briefly and probe DACP mDNS to tell them
  // apart. Emit PAUSED immediately so listeners (e.g. BT switching) don't
  // act on the disconnect prematurely.
  if (!slot->should_stop) {
    s_resume_requested = false;
    rtsp_events_emit(RTSP_EVENT_PAUSED, NULL);

    // Phase 1: let mDNS settle (3 s), but exit early on resume or reconnect
    for (int i = 0; i < 6 && !slot->should_stop; i++) {
      vTaskDelay(pdMS_TO_TICKS(500));
      if (s_resume_requested) {
        ESP_LOGI(TAG, "Resume requested during Phase 1 — skipping to Phase 2");
        break;
      }
    }

    // Phase 2: wait for reconnect as long as DACP service is advertised.
    // Re-probe every ~5 s. The phone unadvertises the service when the
    // user switches away, so disappearance = genuine disconnect.
    if (!slot->should_stop) {
      bool stay = dacp_probe_service() || s_resume_requested;
      if (s_resume_requested) {
        s_resume_requested = false;
        ESP_LOGI(TAG, "Resume requested via button — waiting for reconnect");
        stay = true;
      }
      if (stay) {
        ESP_LOGI(TAG, "DACP still advertised — waiting for reconnect");
      }
      while (stay && !slot->should_stop) {
        // Wait 5 s between probes (10 × 500 ms), checking flags each tick
        for (int i = 0; i < 10 && !slot->should_stop; i++) {
          vTaskDelay(pdMS_TO_TICKS(500));
          if (s_resume_requested) {
            s_resume_requested = false;
            ESP_LOGI(TAG,
                     "Resume requested via button — extending grace period");
          }
        }
        if (slot->should_stop) {
          break;
        }
        // Re-probe: still advertised?
        stay = dacp_probe_service();
        if (stay) {
          ESP_LOGD(TAG, "DACP still advertised — continuing wait");
        } else {
          ESP_LOGI(TAG, "DACP service gone — genuine disconnect");
        }
      }
    }

    if (slot->is_old) {
      // New client connected during grace period — treat as reconnect
      ESP_LOGI(TAG, "Client reconnected during grace period");
    } else {
      ESP_LOGI(TAG, "Grace period expired — full disconnect");
      dacp_clear_session();
      rtsp_events_emit(RTSP_EVENT_DISCONNECTED, NULL);
    }
  } else {
    // Forcefully stopped (server shutdown or replaced by new client)
    dacp_clear_session();
    rtsp_events_emit(RTSP_EVENT_DISCONNECTED, NULL);
  }
#else
  dacp_clear_session();
  rtsp_events_emit(RTSP_EVENT_DISCONNECTED, NULL);
#endif

  // When being replaced by a new client (is_old), skip global state changes —
  // the new session's SETUP already manages PTP and the event port task.
  if (!slot->is_old) {
    ptp_clock_init(); // Restart PTP (stopped during v1 SETUP to free sockets)
    rtsp_stop_event_port_task();
  } else if (rtsp_event_port_listen_socket() >= 0 &&
             rtsp_event_port_listen_socket() == conn->event_socket) {
    // Old task still using our socket — stop it before closing
    rtsp_stop_event_port_task();
  }

  if (conn->event_socket >= 0) {
    close(conn->event_socket);
    conn->event_socket = -1;
  }

  rtsp_conn_cleanup(conn);
  rtsp_conn_free(conn);

  slot->conn = NULL;
  slot->socket = -1;
  slot->task = NULL;
  slot->should_stop = false;
  slot->is_old = false;

  vTaskDelete(NULL);
}

// Signal old client to stop (non-blocking)
static void signal_old_client_stop(int old_slot) {
  client_slot_t *old = &clients[old_slot];
  if (old->task == NULL) {
    return;
  }

  ESP_LOGI(TAG, "Signaling old client to stop");
  old->is_old = true;
  old->should_stop = true;

  // Shutdown socket to unblock recv
  if (old->socket >= 0) {
    shutdown(old->socket, SHUT_RDWR);
  }
  // Task will clean itself up
}

static void server_task(void *pvParameters) {
  (void)pvParameters;

  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  // Initialize slots
  for (int i = 0; i < 2; i++) {
    clients[i].socket = -1;
    clients[i].conn = NULL;
    clients[i].task = NULL;
    clients[i].should_stop = false;
    clients[i].is_old = false;
  }

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
    ESP_LOGE(TAG, "Failed to bind: %d", errno);
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
    int new_socket = accept(server_socket, (struct sockaddr *)&client_addr,
                            &client_addr_len);
    if (new_socket < 0) {
      if (server_running) {
        ESP_LOGE(TAG, "Failed to accept: %d", errno);
      }
      continue;
    }

    ESP_LOGI(TAG, "New client connected");

    // Find slot for new client (alternate between 0 and 1)
    int new_slot = 1 - current_slot;

    // If new slot still has a running task, wait for it to fully exit.
    // With static TCBs we MUST NOT reuse until the old task is deleted.
    if (clients[new_slot].task != NULL) {
      clients[new_slot].should_stop = true;
      if (clients[new_slot].socket >= 0) {
        shutdown(clients[new_slot].socket, SHUT_RDWR);
      }
      int timeout = 30; // 3 seconds max
      while (clients[new_slot].task != NULL && timeout > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
        timeout--;
      }
      if (clients[new_slot].task != NULL) {
        ESP_LOGE(TAG, "Slot %d task did not exit in time", new_slot);
        close(new_socket);
        continue;
      }
    }
    // Signal old client to stop (in background)
    signal_old_client_stop(current_slot);

    // Setup new slot
    clients[new_slot].socket = new_socket;
    clients[new_slot].should_stop = false;
    clients[new_slot].is_old = false;

    // Start new client task immediately (static allocation)
    clients[new_slot].task = xTaskCreateStatic(
        client_task, "rtsp_client", CLIENT_STACK_SIZE / sizeof(StackType_t),
        (void *)(intptr_t)new_slot, 5, s_client_stack[new_slot],
        &s_client_tcb[new_slot]);
    if (clients[new_slot].task == NULL) {
      ESP_LOGE(TAG, "Failed to create client task");
      close(new_socket);
      clients[new_slot].socket = -1;
    } else {
      current_slot = new_slot;
    }
  }

  // Stop all clients
  for (int i = 0; i < 2; i++) {
    if (clients[i].task != NULL) {
      clients[i].should_stop = true;
      if (clients[i].socket >= 0) {
        shutdown(clients[i].socket, SHUT_RDWR);
      }
    }
  }

  vTaskDelay(pdMS_TO_TICKS(500));

  if (server_socket >= 0) {
    close(server_socket);
    server_socket = -1;
  }

  vTaskDelete(NULL);
}

esp_err_t rtsp_server_start(void) {
  if (server_task_handle != NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  server_task_handle = xTaskCreateStatic(
      server_task, "rtsp_server", SERVER_STACK_SIZE / sizeof(StackType_t), NULL,
      5, s_server_stack, &s_server_tcb);
  if (server_task_handle == NULL) {
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
