#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "ptp_clock.h"

static const char *TAG = "ptp_clock";

// PTP multicast addresses and ports
#define PTP_MULTICAST_ADDR "224.0.1.129"
#define PTP_EVENT_PORT 319
#define PTP_GENERAL_PORT 320

// PTP message types
#define PTP_MSG_SYNC 0x0
#define PTP_MSG_DELAY_REQ 0x1
#define PTP_MSG_FOLLOW_UP 0x8
#define PTP_MSG_DELAY_RESP 0x9
#define PTP_MSG_ANNOUNCE 0xB

// PTP header size and timestamp offset
#define PTP_HEADER_SIZE 34
#define PTP_TIMESTAMP_OFFSET 34
#define PTP_TIMESTAMP_SIZE 10

// Synchronization parameters
#define LOCK_THRESHOLD_NS 40000000LL // 40ms - consider locked if offset stable
#define MIN_SAMPLES_FOR_LOCK 3
#define LOCK_STABLE_TIME_MS 500 // 500ms of stable readings to declare lock
#define LOCK_TIMEOUT_MS 3000
#define OFFSET_FILTER_ALPHA 4 // IIR filter (lower = faster convergence)

// PTP state
static struct {
  bool running;
  TaskHandle_t task_handle;
  int event_socket;
  int general_socket;

  // Synchronization state
  bool locked;
  uint32_t lock_start_ms;
  uint32_t lock_candidate_start_ms;
  uint32_t last_sync_ms;
  int64_t offset_ns; // PTP_time = local_time + offset
  int64_t filtered_offset_ns;
  uint32_t sample_count;

  // Two-step sync tracking
  uint16_t last_sync_seq;
  int64_t last_sync_local_ns; // Local time when SYNC received
  bool awaiting_followup;

  // Statistics
  uint32_t sync_count;
  uint32_t followup_count;
} ptp = {0};

// Parse 48-bit seconds + 32-bit nanoseconds from PTP timestamp
static uint64_t parse_ptp_timestamp_ns(const uint8_t *data) {
  // Seconds: 6 bytes big-endian
  uint64_t seconds = 0;
  for (int i = 0; i < 6; i++) {
    seconds = (seconds << 8) | data[i];
  }

  // Nanoseconds: 4 bytes big-endian
  uint32_t nanos = ((uint32_t)data[6] << 24) | ((uint32_t)data[7] << 16) |
                   ((uint32_t)data[8] << 8) | (uint32_t)data[9];

  return seconds * 1000000000ULL + nanos;
}

// Get local time in nanoseconds (from esp_timer)
static inline int64_t get_local_time_ns(void) {
  return (int64_t)esp_timer_get_time() * 1000LL;
}

// Update offset with new sample using IIR filter with outlier rejection
static void update_offset(int64_t new_offset_ns) {
  uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;

  ptp.sample_count++;
  ptp.last_sync_ms = now_ms;

  if (ptp.sample_count == 1) {
    // First sample - initialize directly
    ptp.offset_ns = new_offset_ns;
    ptp.filtered_offset_ns = new_offset_ns;
  } else {
    // Reject outliers: if new sample differs by more than 10 seconds, ignore it
    int64_t diff = new_offset_ns - ptp.filtered_offset_ns;
    if (diff < 0)
      diff = -diff;

    if (diff > 10000000000LL) { // 10 seconds
      // Outlier - ignore this sample
      return;
    }

    // IIR low-pass filter
    ptp.offset_ns = new_offset_ns;
    ptp.filtered_offset_ns +=
        (new_offset_ns - ptp.filtered_offset_ns) / OFFSET_FILTER_ALPHA;
  }

  // Check lock status
  if (ptp.sample_count >= MIN_SAMPLES_FOR_LOCK) {
    int64_t diff = ptp.offset_ns - ptp.filtered_offset_ns;
    if (diff < 0)
      diff = -diff;

    if (diff < LOCK_THRESHOLD_NS) {
      if (!ptp.locked) {
        if (ptp.lock_candidate_start_ms == 0) {
          ptp.lock_candidate_start_ms = now_ms;
        }

        if ((now_ms - ptp.lock_candidate_start_ms) >= LOCK_STABLE_TIME_MS) {
          ptp.locked = true;
          ptp.lock_start_ms = now_ms;
          ptp.lock_candidate_start_ms = 0;
          ESP_LOGI(TAG, "PTP locked, offset: %lld.%03lld s (samples: %u)",
                   ptp.filtered_offset_ns / 1000000000LL,
                   (ptp.filtered_offset_ns % 1000000000LL) / 1000000LL,
                   ptp.sample_count);
        }
      }
    } else {
      ptp.lock_candidate_start_ms = 0;
      // Don't lose lock easily - only if really far off
      if (ptp.locked && diff > LOCK_THRESHOLD_NS * 2) {
        ESP_LOGW(TAG, "PTP lock lost, diff: %lld ms", diff / 1000000LL);
        ptp.locked = false;
        ptp.lock_start_ms = 0;
      }
    }
  }
}

// Process SYNC message (records receive time)
static void process_sync(const uint8_t *data, size_t len, uint16_t seq) {
  ptp.sync_count++;
  ptp.last_sync_seq = seq;
  ptp.last_sync_local_ns = get_local_time_ns();
  ptp.awaiting_followup = true;

  // Check if this is a one-step sync (timestamp in SYNC itself)
  // One-step: flags bit 9 (twoStepFlag) is 0
  uint16_t flags = ((uint16_t)data[6] << 8) | data[7];
  bool two_step = (flags & 0x0200) != 0;

  if (!two_step && len >= PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE) {
    // One-step sync - timestamp is in the SYNC message
    uint64_t ptp_time_ns = parse_ptp_timestamp_ns(data + PTP_TIMESTAMP_OFFSET);
    int64_t offset = (int64_t)ptp_time_ns - ptp.last_sync_local_ns;
    update_offset(offset);
    ptp.awaiting_followup = false;
  }
}

// Process FOLLOW_UP message (contains precise timestamp for preceding SYNC)
static void process_followup(const uint8_t *data, size_t len, uint16_t seq) {
  if (!ptp.awaiting_followup) {
    return;
  }

  // FOLLOW_UP should match the sequence of the last SYNC
  if (seq != ptp.last_sync_seq) {
    return;
  }

  ptp.followup_count++;
  ptp.awaiting_followup = false;

  if (len >= PTP_HEADER_SIZE + PTP_TIMESTAMP_SIZE) {
    uint64_t ptp_time_ns = parse_ptp_timestamp_ns(data + PTP_TIMESTAMP_OFFSET);

    // offset = PTP_time - local_time_at_sync_receipt
    int64_t offset = (int64_t)ptp_time_ns - ptp.last_sync_local_ns;
    update_offset(offset);
  }
}

// Process received PTP message
static void process_ptp_message(const uint8_t *data, size_t len,
                                bool is_event_port) {
  if (len < PTP_HEADER_SIZE) {
    return;
  }

  uint8_t msg_type = data[0] & 0x0F;
  uint16_t seq = ((uint16_t)data[30] << 8) | data[31];

  switch (msg_type) {
  case PTP_MSG_SYNC:
    if (is_event_port) {
      process_sync(data, len, seq);
    }
    break;

  case PTP_MSG_FOLLOW_UP:
    if (!is_event_port) {
      process_followup(data, len, seq);
    }
    break;

  case PTP_MSG_ANNOUNCE:
    // Could track master identity here if needed
    break;

  default:
    break;
  }
}

// Create and bind multicast socket
static int create_ptp_socket(uint16_t port) {
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "Failed to create socket: %d", errno);
    return -1;
  }

  // Allow address reuse
  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  // Bind to port
  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind to port %d: %d", port, errno);
    close(sock);
    return -1;
  }

  // Join multicast group
  struct ip_mreq mreq = {0};
  mreq.imr_multiaddr.s_addr = inet_addr(PTP_MULTICAST_ADDR);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);

  if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) <
      0) {
    ESP_LOGE(TAG, "Failed to join multicast group: %d", errno);
    close(sock);
    return -1;
  }

  // Set receive timeout
  struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  return sock;
}

// PTP task - listens for messages on both ports
static void ptp_task(void *pvParameters) {
  uint8_t buffer[256];

  while (ptp.running) {
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    if (ptp.event_socket >= 0) {
      FD_SET(ptp.event_socket, &read_fds);
      if (ptp.event_socket > max_fd)
        max_fd = ptp.event_socket;
    }
    if (ptp.general_socket >= 0) {
      FD_SET(ptp.general_socket, &read_fds);
      if (ptp.general_socket > max_fd)
        max_fd = ptp.general_socket;
    }

    if (max_fd < 0) {
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

    if (ret < 0) {
      if (errno != EINTR) {
        ESP_LOGE(TAG, "select error: %d", errno);
      }
      continue;
    }

    if (ret == 0) {
      // Timeout - check if we lost lock due to no messages
      continue;
    }

    // Check event port (SYNC messages)
    if (ptp.event_socket >= 0 && FD_ISSET(ptp.event_socket, &read_fds)) {
      int len = recv(ptp.event_socket, buffer, sizeof(buffer), 0);
      if (len > 0) {
        process_ptp_message(buffer, len, true);
      }
    }

    // Check general port (FOLLOW_UP messages)
    if (ptp.general_socket >= 0 && FD_ISSET(ptp.general_socket, &read_fds)) {
      int len = recv(ptp.general_socket, buffer, sizeof(buffer), 0);
      if (len > 0) {
        process_ptp_message(buffer, len, false);
      }
    }
  }

  // Cleanup
  if (ptp.event_socket >= 0) {
    close(ptp.event_socket);
    ptp.event_socket = -1;
  }
  if (ptp.general_socket >= 0) {
    close(ptp.general_socket);
    ptp.general_socket = -1;
  }

  ptp.task_handle = NULL;
  vTaskDelete(NULL);
}

esp_err_t ptp_clock_init(void) {
  if (ptp.running) {
    return ESP_ERR_INVALID_STATE;
  }

  memset(&ptp, 0, sizeof(ptp));
  ptp.event_socket = -1;
  ptp.general_socket = -1;

  // Create sockets
  ptp.event_socket = create_ptp_socket(PTP_EVENT_PORT);
  if (ptp.event_socket < 0) {
    return ESP_FAIL;
  }

  ptp.general_socket = create_ptp_socket(PTP_GENERAL_PORT);
  if (ptp.general_socket < 0) {
    close(ptp.event_socket);
    ptp.event_socket = -1;
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "PTP sockets created, listening on %s ports %d/%d",
           PTP_MULTICAST_ADDR, PTP_EVENT_PORT, PTP_GENERAL_PORT);

  // Start task
  ptp.running = true;
  BaseType_t ret =
      xTaskCreate(ptp_task, "ptp_clock", 4096, NULL, 6, &ptp.task_handle);
  if (ret != pdPASS) {
    ESP_LOGE(TAG, "Failed to create PTP task");
    close(ptp.event_socket);
    close(ptp.general_socket);
    ptp.event_socket = -1;
    ptp.general_socket = -1;
    ptp.running = false;
    return ESP_FAIL;
  }

  return ESP_OK;
}

void ptp_clock_stop(void) {
  if (!ptp.running) {
    return;
  }

  ptp.running = false;

  // Close sockets to unblock select
  if (ptp.event_socket >= 0) {
    close(ptp.event_socket);
    ptp.event_socket = -1;
  }
  if (ptp.general_socket >= 0) {
    close(ptp.general_socket);
    ptp.general_socket = -1;
  }

  // Wait for task to exit
  if (ptp.task_handle) {
    vTaskDelay(pdMS_TO_TICKS(200));
  }
}

void ptp_clock_clear(void) {
  // Reset synchronization state without stopping the clock
  // This allows re-sync on new AirPlay session
  ESP_LOGI(TAG, "Clearing PTP clock synchronization state");

  ptp.locked = false;
  ptp.lock_start_ms = 0;
  ptp.lock_candidate_start_ms = 0;
  ptp.last_sync_ms = 0;
  ptp.offset_ns = 0;
  ptp.filtered_offset_ns = 0;
  ptp.sample_count = 0;

  // Reset two-step tracking
  ptp.last_sync_seq = 0;
  ptp.last_sync_local_ns = 0;
  ptp.awaiting_followup = false;

  // Reset statistics
  ptp.sync_count = 0;
  ptp.followup_count = 0;
}

bool ptp_clock_is_locked(void) {
  if (ptp.locked && ptp.last_sync_ms > 0) {
    uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    if ((now_ms - ptp.last_sync_ms) > LOCK_TIMEOUT_MS) {
      ESP_LOGW(TAG, "PTP lock lost (timeout %u ms)",
               (unsigned)(now_ms - ptp.last_sync_ms));
      ptp.locked = false;
      ptp.lock_start_ms = 0;
      ptp.lock_candidate_start_ms = 0;
    }
  }

  return ptp.locked;
}

uint64_t ptp_clock_get_time_ns(void) {
  int64_t local_ns = get_local_time_ns();
  return (uint64_t)(local_ns + ptp.filtered_offset_ns);
}

int64_t ptp_clock_get_offset_ns(void) { return ptp.filtered_offset_ns; }

void ptp_clock_get_stats(ptp_stats_t *stats) {
  stats->sync_count = ptp.sync_count;
  stats->followup_count = ptp.followup_count;
  stats->last_offset_ns = ptp.offset_ns;
  stats->filtered_offset_ns = ptp.filtered_offset_ns;

  if (ptp.locked && ptp.lock_start_ms > 0) {
    uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    stats->lock_time_ms = now_ms - ptp.lock_start_ms;
  } else {
    stats->lock_time_ms = 0;
  }
}
