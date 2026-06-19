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
#include "spiram_task.h"

static const char *TAG = "ptp_clock";

// PTP multicast addresses and ports
#define PTP_MULTICAST_ADDR "224.0.1.129"
#define PTP_EVENT_PORT     319
#define PTP_GENERAL_PORT   320

// PTP message types
#define PTP_MSG_SYNC       0x0
#define PTP_MSG_DELAY_REQ  0x1
#define PTP_MSG_FOLLOW_UP  0x8
#define PTP_MSG_DELAY_RESP 0x9
#define PTP_MSG_ANNOUNCE   0xB

// PTP header size and timestamp offset
#define PTP_HEADER_SIZE      34
#define PTP_TIMESTAMP_OFFSET 34
#define PTP_TIMESTAMP_SIZE   10

// Synchronization parameters
//
// WiFi-side timestamping jitter on ESP32 is ~20–30 ms in practice, so a tight
// 40 ms lock threshold can take 10+ seconds to satisfy.  Loosen the lock
// criteria to converge in <1 s while still rejecting genuine outliers via
// the median filter:
//   • LOCK_THRESHOLD_NS:    50 ms  — accept normal WiFi jitter
//   • OUTLIER_THRESHOLD_NS: 75 ms  — keep the threshold strictly larger than
//                                   LOCK_THRESHOLD_NS so a borderline sample
//                                   isn't both kept and counted against lock
//   • MIN_SAMPLES_FOR_LOCK: 4      — ~500 ms at 8 Hz SYNC rate
//   • LOCK_STABLE_TIME_MS:  250    — confirm stability without long wait
#define LOCK_THRESHOLD_NS    50000000LL // 50ms - tolerant of WiFi jitter
#define MIN_SAMPLES_FOR_LOCK 4
#define LOCK_STABLE_TIME_MS  250 // 250ms of stable readings to declare lock
#define LOCK_TIMEOUT_MS      5000
#define OUTLIER_THRESHOLD_NS 50000000LL // 50ms - reject samples beyond this
// Asymmetric filter parameters (modeled after nqptp):
// Network delays only ADD positive bias to the measured offset, so
//   offset_measured = true_offset - one_way_delay
// The LARGEST measured offsets correspond to the SHORTEST delays and are
// therefore the most accurate.  We accept positive jitter (= shorter delay)
// quickly and dampen negative jitter (= longer delay) heavily.  This causes
// the filter to converge to the minimum-delay offset, matching the behaviour
// of nqptp used by shairport-sync and ensuring tight multi-room sync.
#define SMOOTH_POS_STARTUP_DIV 1   // accept positive jitter fully at start
#define SMOOTH_POS_STEADY_DIV  16  // later, apply 1/16 of positive jitter
#define SMOOTH_NEG_DIV         256 // always apply only 1/256 of negative jitter
#define SMOOTH_NEG_CLAMP_NS    (-2500000LL) // clamp negative jitter at -2.5ms
#define STARTUP_DURATION_MS 1000 // first second: aggressive positive tracking

// Threshold above which we reset the PTP smoothing filter on resume.
// E.g. at 50 ppm crystal accuracy, 30 s of pause accumulates ~1.5 ms of drift —
// large enough to be audible in multi-room but well within the 50 ms outlier
// window.  Below this threshold the drift is negligible (<0.25 ms at 5 s).
#define PTP_LONG_PAUSE_THRESHOLD_MS 30000

// PTP state
static struct {
  bool running;
  TaskHandle_t task_handle;
  spiram_task_mem_t task_mem;
  int event_socket;
  int general_socket;

  // Synchronization state
  bool locked;
  uint32_t lock_start_ms;
  uint32_t lock_candidate_start_ms;
  uint32_t last_sync_ms;
  int64_t filtered_offset_ns; // PTP_time = local_time + offset
  uint32_t sample_count;

  // Asymmetric smoothing state (replaces median ring buffer)
  int64_t previous_offset;
  uint32_t previous_offset_time_ms; // 0 = no previous sample yet
  uint32_t mastership_start_ms;     // when continuous tracking began

  // Two-step sync tracking
  uint16_t last_sync_seq;
  int64_t last_sync_local_ns;
  bool awaiting_followup;

  // Statistics
  uint32_t sync_count;
  uint32_t followup_count;
  uint32_t announce_count;
  uint32_t rejected_master_count; // SYNC/FOLLOW_UP from a non-matching master
  uint32_t outlier_count;         // samples rejected by 50ms threshold

  // Master clock filter (0 = accept any master)
  uint64_t expected_clock_id;
} ptp = {0};

// Parse 8-byte clockIdentity (big-endian) from PTP sourcePortIdentity
// (header bytes 20-27).
static uint64_t parse_ptp_clock_id(const uint8_t *data) {
  uint64_t id = 0;
  for (int i = 0; i < 8; i++) {
    id = (id << 8) | data[20 + i];
  }
  return id;
}

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

// Update offset with new sample using asymmetric smoothing (nqptp-style).
//
// The key insight from nqptp: since we are a passive PTP listener (no
// DELAY_REQ/DELAY_RESP), every measured offset contains a one-way network
// delay bias:  offset_measured = true_offset - delay.
// LARGER offsets come from SHORTER delays and are MORE accurate.
//
// By accepting positive jitter (larger offset = shorter delay) quickly and
// dampening negative jitter (smaller offset = longer delay) slowly, the
// filter converges to the offset corresponding to the minimum network
// delay — the best available approximation of the true clock offset.
static void update_offset(int64_t new_offset_ns) {
  uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
  ptp.last_sync_ms = now_ms;
  ptp.sample_count++;

  int64_t smoothed_offset;

  if (ptp.previous_offset_time_ms == 0) {
    // First sample (or after reset): accept unconditionally
    smoothed_offset = new_offset_ns;
    ptp.mastership_start_ms = now_ms;
  } else {
    // Reject obvious outliers (more than 50ms from current estimate)
    int64_t diff = new_offset_ns - ptp.filtered_offset_ns;
    if (diff < 0) {
      diff = -diff;
    }
    if (diff > OUTLIER_THRESHOLD_NS) {
      ptp.outlier_count++;
      return;
    }

    int64_t jitter = new_offset_ns - ptp.previous_offset;
    uint32_t mastership_time_ms = now_ms - ptp.mastership_start_ms;

    if (jitter >= 0) {
      // Positive jitter: offset increased → shorter network delay → more
      // accurate.  Accept quickly, especially during startup.
      if (mastership_time_ms < STARTUP_DURATION_MS) {
        smoothed_offset = ptp.previous_offset + jitter / SMOOTH_POS_STARTUP_DIV;
      } else {
        smoothed_offset = ptp.previous_offset + jitter / SMOOTH_POS_STEADY_DIV;
      }
    } else {
      // Negative jitter: offset decreased → longer network delay → less
      // reliable.  Clamp and apply only a tiny fraction.
      int64_t clamped_jitter = jitter;
      if (clamped_jitter < SMOOTH_NEG_CLAMP_NS) {
        clamped_jitter = SMOOTH_NEG_CLAMP_NS;
      }
      smoothed_offset = ptp.previous_offset + clamped_jitter / SMOOTH_NEG_DIV;
    }
  }

  ptp.previous_offset = smoothed_offset;
  ptp.previous_offset_time_ms = now_ms;
  ptp.filtered_offset_ns = smoothed_offset;

  // Check lock status: once we have enough samples and the offset is stable,
  // declare lock.  Use the deviation between the raw sample and the smoothed
  // value as a stability indicator.
  if (ptp.sample_count >= MIN_SAMPLES_FOR_LOCK) {
    int64_t dev = new_offset_ns - smoothed_offset;
    if (dev < 0) {
      dev = -dev;
    }

    if (dev < LOCK_THRESHOLD_NS) {
      if (!ptp.locked) {
        if (ptp.lock_candidate_start_ms == 0) {
          ptp.lock_candidate_start_ms = now_ms;
        }
        if ((now_ms - ptp.lock_candidate_start_ms) >= LOCK_STABLE_TIME_MS) {
          ptp.locked = true;
          ptp.lock_start_ms = now_ms;
          ptp.lock_candidate_start_ms = 0;
          ESP_LOGI(TAG,
                   "LOCKED: offset=%+lldns dev=%lldns samples=%lu "
                   "sync=%lu followup=%lu",
                   (long long)ptp.filtered_offset_ns, (long long)dev,
                   (unsigned long)ptp.sample_count,
                   (unsigned long)ptp.sync_count,
                   (unsigned long)ptp.followup_count);
        }
      }
    } else {
      ptp.lock_candidate_start_ms = 0;
      if (ptp.locked && dev > LOCK_THRESHOLD_NS * 4) {
        ptp.locked = false;
        ptp.lock_start_ms = 0;
        ESP_LOGW(TAG, "LOST LOCK: dev=%lldns (threshold=%lldns)",
                 (long long)dev, (long long)(LOCK_THRESHOLD_NS * 4));
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
    // Apply correctionField for one-step sync as well
    if (len >= 16) {
      int64_t correction_field =
          ((int64_t)data[8] << 56) | ((int64_t)data[9] << 48) |
          ((int64_t)data[10] << 40) | ((int64_t)data[11] << 32) |
          ((int64_t)data[12] << 24) | ((int64_t)data[13] << 16) |
          ((int64_t)data[14] << 8) | (int64_t)data[15];
      correction_field /= 65536; // convert from 2^-16 ns to ns
      ptp_time_ns = (uint64_t)((int64_t)ptp_time_ns + correction_field);
    }
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

    // Apply correctionField (IEEE 1588 §11.4.4.2.1):
    // The correctionField accumulates residence time and path delay
    // corrections from PTP-aware network elements.  It is a signed
    // 64-bit value in units of 2^-16 nanoseconds.
    if (len >= 16) {
      int64_t correction_field =
          ((int64_t)data[8] << 56) | ((int64_t)data[9] << 48) |
          ((int64_t)data[10] << 40) | ((int64_t)data[11] << 32) |
          ((int64_t)data[12] << 24) | ((int64_t)data[13] << 16) |
          ((int64_t)data[14] << 8) | (int64_t)data[15];
      correction_field /= 65536; // convert from 2^-16 ns to ns
      ptp_time_ns = (uint64_t)((int64_t)ptp_time_ns + correction_field);
    }

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

  // If a master filter is set, reject messages from other clocks.
  // This applies only to messages that contribute to offset estimation
  // (SYNC / FOLLOW_UP); ANNOUNCE and others are ignored anyway.
  if (ptp.expected_clock_id != 0 &&
      (msg_type == PTP_MSG_SYNC || msg_type == PTP_MSG_FOLLOW_UP)) {
    uint64_t src_clock_id = parse_ptp_clock_id(data);
    if (src_clock_id != ptp.expected_clock_id) {
      ptp.rejected_master_count++;
      return;
    }
  }

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
    ptp.announce_count++;
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
      if (ptp.event_socket > max_fd) {
        max_fd = ptp.event_socket;
      }
    }
    if (ptp.general_socket >= 0) {
      FD_SET(ptp.general_socket, &read_fds);
      if (ptp.general_socket > max_fd) {
        max_fd = ptp.general_socket;
      }
    }

    if (max_fd < 0) {
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    int ret = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

    if (ret < 0) {
      if (!ptp.running) {
        break; // Sockets closed during shutdown
      }
      if (errno != EINTR) {
        ESP_LOGE(TAG, "select error: %d", errno);
      }
      continue;
    }

    if (ret == 0) {
      // Timeout - check if we lost lock due to no messages
    } else {
      // Check event port (SYNC messages)
      if (ptp.event_socket >= 0 && FD_ISSET(ptp.event_socket, &read_fds)) {
        ssize_t len = recv(ptp.event_socket, buffer, sizeof(buffer), 0);
        if (len > 0) {
          process_ptp_message(buffer, (size_t)len, true);
        }
      }

      // Check general port (FOLLOW_UP messages)
      if (ptp.general_socket >= 0 && FD_ISSET(ptp.general_socket, &read_fds)) {
        ssize_t len = recv(ptp.general_socket, buffer, sizeof(buffer), 0);
        if (len > 0) {
          process_ptp_message(buffer, (size_t)len, false);
        }
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

  // Start task
  ptp.running = true;
  BaseType_t ret = task_create_spiram(ptp_task, "ptp_clock", 4096, NULL, 6,
                                      &ptp.task_handle, &ptp.task_mem);
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

  // Wait for task to exit (task sets task_handle = NULL before vTaskDelete)
  for (int i = 0; i < 20 && ptp.task_handle != NULL; i++) {
    vTaskDelay(pdMS_TO_TICKS(50));
  }
  if (ptp.task_handle != NULL) {
    ESP_LOGW(TAG, "PTP task did not exit in time");
  }
  task_free_spiram(&ptp.task_mem);
}

void ptp_clock_clear(void) {
  ptp.locked = false;
  ptp.lock_start_ms = 0;
  ptp.lock_candidate_start_ms = 0;
  ptp.last_sync_ms = 0;
  ptp.filtered_offset_ns = 0;
  ptp.sample_count = 0;
  ptp.previous_offset = 0;
  ptp.previous_offset_time_ms = 0;
  ptp.mastership_start_ms = 0;

  ptp.last_sync_seq = 0;
  ptp.last_sync_local_ns = 0;
  ptp.awaiting_followup = false;

  ptp.sync_count = 0;
  ptp.followup_count = 0;

  // Drop the master filter so the next session can lock to whatever master
  // its anchor packet names (which may differ from the previous session).
  ptp.expected_clock_id = 0;
}

void ptp_clock_notify_resume(uint32_t pause_duration_ms) {
  if (pause_duration_ms < PTP_LONG_PAUSE_THRESHOLD_MS) {
    return; // drift too small to matter
  }
  // Reset the "previous sample" pointer so the very next PTP FOLLOW_UP is
  // accepted unconditionally (the first-sample path in update_offset()).
  // This mirrors what nqptp does on its "B" (begin) signal:
  //   "when the clock goes from inactive to active, NQPTP resets clock
  //    smoothing to the new offset" -- nqptp-shm-structures.h
  //
  // We keep filtered_offset_ns so that audio_timing can continue to use the
  // last-known offset until the first new sample arrives (~125 ms away).
  // We also reset mastership_start_ms so the STARTUP_DURATION_MS aggressive-
  // positive window kicks in again for a faster upward catch-up.
  ptp.previous_offset_time_ms = 0;
  ptp.mastership_start_ms = 0;
  ESP_LOGI(TAG,
           "notify_resume: pause=%lu ms, resetting PTP smoothing "
           "(est. drift %.1f ms @ 50ppm)",
           (unsigned long)pause_duration_ms,
           (float)pause_duration_ms * 50.0f / 1000000.0f);
}

bool ptp_clock_is_locked(void) {
  if (ptp.locked && ptp.last_sync_ms > 0) {
    uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    if ((now_ms - ptp.last_sync_ms) > LOCK_TIMEOUT_MS) {
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

int64_t ptp_clock_get_offset_ns(void) {
  return ptp.filtered_offset_ns;
}

void ptp_clock_set_master_clock_id(uint64_t clock_id) {
  if (clock_id == ptp.expected_clock_id) {
    return;
  }

  ESP_LOGI(TAG, "PTP master clock_id %s: %016llx", clock_id ? "set" : "cleared",
           (unsigned long long)clock_id);
  ptp.expected_clock_id = clock_id;

  // Drop accumulated samples / lock state — they may have come from a
  // different (wrong) master.
  ptp.locked = false;
  ptp.lock_start_ms = 0;
  ptp.lock_candidate_start_ms = 0;
  ptp.filtered_offset_ns = 0;
  ptp.sample_count = 0;
  ptp.previous_offset = 0;
  ptp.previous_offset_time_ms = 0;
  ptp.awaiting_followup = false;
}

uint64_t ptp_clock_get_master_clock_id(void) {
  return ptp.expected_clock_id;
}

void ptp_clock_get_stats(ptp_stats_t *stats) {
  stats->sync_count = ptp.sync_count;
  stats->followup_count = ptp.followup_count;
  stats->last_offset_ns = ptp.previous_offset;
  stats->filtered_offset_ns = ptp.filtered_offset_ns;

  if (ptp.locked && ptp.lock_start_ms > 0) {
    uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    stats->lock_time_ms = now_ms - ptp.lock_start_ms;
  } else {
    stats->lock_time_ms = 0;
  }
}
