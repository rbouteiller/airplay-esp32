// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

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

// A sample newer than this means the master is still sending, so the next
// session can carry on with the lock rather than spend ~0.75 s re-acquiring it.
#define SESSION_KEEP_MS 2000
// A run of samples far below the estimate is either congestion holding SYNCs
// up or the master's clock moving back: an iPhone's stops while it sleeps, so
// its offset falls by the time it slept, 0.5 s to minutes on the board.
// Congestion there held every SYNC 52-206 ms late for 2 s and more, several
// times an hour of playback, and each follow threw the playout error out by
// up to tens of ms for 10-20 s.  So a fall larger than congestion causes is
// followed after ~2 s of SYNCs, and a smaller one only once it has lasted
// ~20 s, far longer than congestion did.
#define OUTLIER_RUN_RESET       16
#define OUTLIER_RUN_RESET_SMALL 160
#define SMALL_STEP_NS           500000000LL // 500 ms
// sample_clock_id when samples from more than one master have been mixed.
#define PTP_CLOCK_ID_MIXED UINT64_MAX

// PTP state, grouped by alignment to avoid padding on 32-bit targets.
static struct {
  int64_t filtered_offset_ns; // PTP_time = local_time + offset

  // Asymmetric smoothing state (replaces median ring buffer)
  int64_t previous_offset;
  // Most recent RAW (unsmoothed) offset sample.  The smoothing filter is
  // deliberately asymmetric (see SMOOTH_* below), so filtered_offset_ns can
  // sit a long way from the truth without any existing log revealing it —
  // every timing figure the firmware prints is derived from the filtered
  // value, so an error in it is invisible to those figures.  Keeping the raw
  // sample lets callers compare the two and detect filter divergence.
  int64_t raw_offset_ns;
  int64_t last_sync_local_ns;

  // Master clock filter (0 = accept any master)
  uint64_t expected_clock_id;
  // Master behind the samples since the last reset (0 = none yet,
  // PTP_CLOCK_ID_MIXED = more than one).
  uint64_t sample_clock_id;
  int64_t outlier_run_best_ns; // highest offset in the current run
  TaskHandle_t task_handle;
  int event_socket;
  int general_socket;
  uint32_t lock_start_ms;
  uint32_t lock_candidate_start_ms;
  uint32_t last_sync_ms;
  uint32_t sample_count;
  uint32_t previous_offset_time_ms; // 0 = no previous sample yet
  uint32_t mastership_start_ms;     // when continuous tracking began
  uint32_t last_sync_received_ms;

  // Statistics
  uint32_t sync_count;
  uint32_t followup_count;
  uint32_t announce_count;
  uint32_t rejected_master_count; // SYNC/FOLLOW_UP from a non-matching master
  uint32_t outlier_count;         // samples rejected by 50ms threshold
  uint32_t consecutive_outliers;
  spiram_task_mem_t task_mem;

  // Two-step sync tracking
  uint16_t last_sync_seq;
  bool running;

  // Synchronization state
  bool locked;
  bool awaiting_followup;
  // The session that named expected_clock_id has ended. The filter stays on,
  // so no other master's samples reach the kept lock, but the next session's
  // master is checked against the samples again.
  bool session_ended;
  uint8_t last_sync_source_port_identity[10];
} ptp = {0};

// PTP packets and RTSP session changes run on different tasks (and cores).
// Accepting a sample and deciding whether its lock can be kept must be one
// coherent transition. Only clock state and bounded packet parsing belong
// under this mux; logs, sockets and task lifecycle operations stay outside.
static portMUX_TYPE ptp_state_mux = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
  bool stepped;
  bool locked;
  int64_t fall_ns;
  int64_t offset_ns;
  int64_t deviation_ns;
  uint32_t samples;
  uint32_t syncs;
  uint32_t followups;
} ptp_update_log_t;

static void log_offset_update(const ptp_update_log_t *log) {
  if (log->stepped) {
    ESP_LOGI(TAG, "offset fell by %lld ms and stayed there, following it",
             (long long)(log->fall_ns / 1000000));
  }
  if (log->locked) {
    ESP_LOGI(TAG,
             "LOCKED: offset=%+lldns dev=%lldns samples=%lu "
             "sync=%lu followup=%lu",
             (long long)log->offset_ns, (long long)log->deviation_ns,
             (unsigned long)log->samples, (unsigned long)log->syncs,
             (unsigned long)log->followups);
  }
}

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
// Caller holds ptp_state_mux; deferred log data is emitted after release.
static void update_offset(int64_t new_offset_ns, uint64_t src_clock_id,
                          uint32_t sync_received_ms, ptp_update_log_t *log) {
  uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
  // A delayed FOLLOW_UP still describes the earlier SYNC. Its arrival must
  // not extend the sample's freshness or revive an expired clock lock.
  ptp.last_sync_ms = sync_received_ms;
  if (ptp.sample_count == 0) {
    ptp.sample_clock_id = src_clock_id;
  } else if (src_clock_id != ptp.sample_clock_id) {
    ptp.sample_clock_id = PTP_CLOCK_ID_MIXED;
  }
  ptp.sample_count++;
  // Record the raw sample before any smoothing or outlier rejection, so the
  // divergence between measured and filtered offset stays observable.
  ptp.raw_offset_ns = new_offset_ns;

  int64_t smoothed_offset;

  if (ptp.previous_offset_time_ms == 0) {
    // First sample (or after reset): accept unconditionally. A resume can
    // re-seed the filter while retaining its lock, but the accepted sample
    // must still break any outlier run from before the reset.
    ptp.consecutive_outliers = 0;
    ptp.outlier_run_best_ns = 0;
    smoothed_offset = new_offset_ns;
    ptp.mastership_start_ms = now_ms;
  } else {
    int64_t diff = new_offset_ns - ptp.filtered_offset_ns;
    if (diff > OUTLIER_THRESHOLD_NS) {
      // Far above the estimate: this SYNC got through faster than the ones it
      // was built on.  Queuing only ever delays a SYNC, so those were held up
      // (or the master's clock stepped forward) -- take this one as it is.
      // Rejecting it instead left a filter seeded by one delayed sample
      // refusing every good one after it.
      ptp.consecutive_outliers = 0;
      smoothed_offset = new_offset_ns;
    } else if (diff < -OUTLIER_THRESHOLD_NS) {
      ptp.outlier_count++;
      if (ptp.consecutive_outliers == 0 ||
          new_offset_ns > ptp.outlier_run_best_ns) {
        ptp.outlier_run_best_ns = new_offset_ns;
      }
      const int64_t fall = ptp.filtered_offset_ns - ptp.outlier_run_best_ns;
      const uint32_t run_needed =
          fall < SMALL_STEP_NS ? OUTLIER_RUN_RESET_SMALL : OUTLIER_RUN_RESET;
      if (++ptp.consecutive_outliers < run_needed) {
        return; // a burst of delayed SYNCs, most likely
      }
      // Too many in a row for delay: the master's clock went back (an
      // iPhone's stops while it sleeps).  Step to the least delayed sample of
      // the run and keep the lock -- a playing stream follows one step, but
      // an unlocked clock reads as an offset of 0 until it re-locks.
      log->stepped = true;
      log->fall_ns = fall;
      smoothed_offset = ptp.outlier_run_best_ns;
      ptp.consecutive_outliers = 0;
      ptp.mastership_start_ms = now_ms; // track upwards quickly again
    } else {
      ptp.consecutive_outliers = 0;

      int64_t jitter = new_offset_ns - ptp.previous_offset;
      uint32_t mastership_time_ms = now_ms - ptp.mastership_start_ms;

      if (jitter >= 0) {
        // Positive jitter: offset increased → shorter network delay → more
        // accurate.  Accept quickly, especially during startup.
        if (mastership_time_ms < STARTUP_DURATION_MS) {
          smoothed_offset =
              ptp.previous_offset + jitter / SMOOTH_POS_STARTUP_DIV;
        } else {
          smoothed_offset =
              ptp.previous_offset + jitter / SMOOTH_POS_STEADY_DIV;
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
          log->locked = true;
          log->offset_ns = ptp.filtered_offset_ns;
          log->deviation_ns = dev;
          log->samples = ptp.sample_count;
          log->syncs = ptp.sync_count;
          log->followups = ptp.followup_count;
        }
      }
    } else {
      // A held lock is never dropped on one sample.  Every path above keeps
      // the sample within OUTLIER_THRESHOLD_NS of the estimate except a
      // followed run, whose last sample can sit hundreds of ms below the one
      // it steps to, and a playing stream reads an unlocked clock as an
      // offset of 0.  Silence (ptp_clock_is_locked()) or a reset drops it.
      ptp.lock_candidate_start_ms = 0;
    }
  }
}

// Process SYNC message (records receive time)
static void process_sync(const uint8_t *data, size_t len, uint16_t seq,
                         ptp_update_log_t *log) {
  ptp.sync_count++;
  ptp.last_sync_seq = seq;
  memcpy(ptp.last_sync_source_port_identity, data + 20,
         sizeof(ptp.last_sync_source_port_identity));
  ptp.last_sync_local_ns = get_local_time_ns();
  ptp.last_sync_received_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
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
    update_offset(offset, parse_ptp_clock_id(data), ptp.last_sync_received_ms,
                  log);
    ptp.awaiting_followup = false;
  }
}

// Process FOLLOW_UP message (contains precise timestamp for preceding SYNC)
static void process_followup(const uint8_t *data, size_t len, uint16_t seq,
                             ptp_update_log_t *log) {
  if (!ptp.awaiting_followup) {
    return;
  }

  // Sequence numbers are only unique within one source port. Before an
  // anchor selects a master, multiple clocks can send the same sequence;
  // pairing one clock's SYNC with another's FOLLOW_UP fabricates an offset
  // and incorrectly attributes it entirely to the FOLLOW_UP clock.
  if (seq != ptp.last_sync_seq ||
      memcmp(data + 20, ptp.last_sync_source_port_identity,
             sizeof(ptp.last_sync_source_port_identity)) != 0) {
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
    update_offset(offset, parse_ptp_clock_id(data), ptp.last_sync_received_ms,
                  log);
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
  ptp_update_log_t log = {0};

  portENTER_CRITICAL(&ptp_state_mux);
  // If a master filter is set, reject messages from other clocks.
  // This applies only to messages that contribute to offset estimation
  // (SYNC / FOLLOW_UP); ANNOUNCE and others are ignored anyway.
  if (ptp.expected_clock_id != 0 &&
      (msg_type == PTP_MSG_SYNC || msg_type == PTP_MSG_FOLLOW_UP)) {
    uint64_t src_clock_id = parse_ptp_clock_id(data);
    if (src_clock_id != ptp.expected_clock_id) {
      ptp.rejected_master_count++;
      portEXIT_CRITICAL(&ptp_state_mux);
      return;
    }
  }

  switch (msg_type) {
  case PTP_MSG_SYNC:
    if (is_event_port) {
      process_sync(data, len, seq, &log);
    }
    break;

  case PTP_MSG_FOLLOW_UP:
    if (!is_event_port) {
      process_followup(data, len, seq, &log);
    }
    break;

  case PTP_MSG_ANNOUNCE:
    ptp.announce_count++;
    // Could track master identity here if needed
    break;

  default:
    break;
  }
  portEXIT_CRITICAL(&ptp_state_mux);
  log_offset_update(&log);
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

  portENTER_CRITICAL(&ptp_state_mux);
  memset(&ptp, 0, sizeof(ptp));
  portEXIT_CRITICAL(&ptp_state_mux);
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

// Caller holds ptp_state_mux.
static void clear_clock_state(void) {
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
  ptp.last_sync_received_ms = 0;
  ptp.awaiting_followup = false;

  ptp.sync_count = 0;
  ptp.followup_count = 0;

  // Drop the master filter so the next session can lock to whatever master
  // its anchor packet names (which may differ from the previous session).
  ptp.expected_clock_id = 0;
  ptp.session_ended = false;
  ptp.sample_clock_id = 0;
  ptp.consecutive_outliers = 0;
}

void ptp_clock_clear(void) {
  portENTER_CRITICAL(&ptp_state_mux);
  clear_clock_state();
  portEXIT_CRITICAL(&ptp_state_mux);
}

// Caller holds ptp_state_mux.
// True when the samples still describe the master: it sent one recently and
// that one was accepted.  An iPhone's PTP clock stops while it sleeps, so after
// a pause the first samples can land seconds away from the filtered offset --
// a lock carried across that would place the next anchor that far out.
static bool samples_current(void) {
  uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
  return ptp.sample_count > 0 && ptp.consecutive_outliers == 0 &&
         ptp.last_sync_ms != 0 && (now_ms - ptp.last_sync_ms) < SESSION_KEEP_MS;
}

void ptp_clock_end_session(void) {
  portENTER_CRITICAL(&ptp_state_mux);
  if (!samples_current()) {
    clear_clock_state();
    portEXIT_CRITICAL(&ptp_state_mux);
    return;
  }
  // The master is still sending, so the samples are current. Keep its filter:
  // with it dropped, any other master on the network (an Apple TV, a HomePod)
  // would feed the offset until the next session names one, and mark the
  // samples mixed, which drops the lock this path keeps. The next session may
  // still name a different master; naming this one again keeps the lock (see
  // ptp_clock_set_master_clock_id()).
  ptp.session_ended = true;
  portEXIT_CRITICAL(&ptp_state_mux);
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
  portENTER_CRITICAL(&ptp_state_mux);
  ptp.previous_offset_time_ms = 0;
  ptp.mastership_start_ms = 0;
  portEXIT_CRITICAL(&ptp_state_mux);
  ESP_LOGI(TAG,
           "notify_resume: pause=%lu ms, resetting PTP smoothing "
           "(est. drift %.1f ms @ 50ppm)",
           (unsigned long)pause_duration_ms,
           (float)pause_duration_ms * 50.0f / 1000000.0f);
}

bool ptp_clock_is_locked(void) {
  portENTER_CRITICAL(&ptp_state_mux);
  if (ptp.locked && ptp.last_sync_ms > 0) {
    uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    if ((now_ms - ptp.last_sync_ms) > LOCK_TIMEOUT_MS) {
      ptp.locked = false;
      ptp.lock_start_ms = 0;
      ptp.lock_candidate_start_ms = 0;
    }
  }

  bool locked = ptp.locked;
  portEXIT_CRITICAL(&ptp_state_mux);
  return locked;
}

uint64_t ptp_clock_get_time_ns(void) {
  int64_t local_ns = get_local_time_ns();
  return (uint64_t)(local_ns + ptp_clock_get_offset_ns());
}

int64_t ptp_clock_get_offset_ns(void) {
  portENTER_CRITICAL(&ptp_state_mux);
  int64_t offset = ptp.filtered_offset_ns;
  portEXIT_CRITICAL(&ptp_state_mux);
  return offset;
}

void ptp_clock_set_master_clock_id(uint64_t clock_id) {
  portENTER_CRITICAL(&ptp_state_mux);
  if (clock_id == ptp.expected_clock_id && !ptp.session_ended) {
    portEXIT_CRITICAL(&ptp_state_mux);
    return;
  }
  ptp.session_ended = false;

  // A session naming the master every current sample came from -- the next
  // track from the same phone -- keeps the lock. Re-acquiring it takes
  // ~0.75 s, and a start waiting on it joins the track that far in.
  bool keep =
      clock_id != 0 && ptp.sample_clock_id == clock_id && samples_current();
  ptp.expected_clock_id = clock_id;
  if (!keep) {
    // Drop accumulated samples / lock state: they may describe another master.
    ptp.locked = false;
    ptp.lock_start_ms = 0;
    ptp.lock_candidate_start_ms = 0;
    ptp.filtered_offset_ns = 0;
    ptp.sample_count = 0;
    ptp.previous_offset = 0;
    ptp.previous_offset_time_ms = 0;
    ptp.awaiting_followup = false;
    ptp.sample_clock_id = 0;
    ptp.consecutive_outliers = 0;
  }
  portEXIT_CRITICAL(&ptp_state_mux);

  ESP_LOGI(TAG, "PTP master clock_id %s: %016llx%s",
           clock_id ? "set" : "cleared", (unsigned long long)clock_id,
           keep ? " (already measuring it, lock kept)" : "");
}

uint64_t ptp_clock_get_master_clock_id(void) {
  portENTER_CRITICAL(&ptp_state_mux);
  uint64_t clock_id = ptp.expected_clock_id;
  portEXIT_CRITICAL(&ptp_state_mux);
  return clock_id;
}

void ptp_clock_get_stats(ptp_stats_t *stats) {
  portENTER_CRITICAL(&ptp_state_mux);
  stats->sync_count = ptp.sync_count;
  stats->followup_count = ptp.followup_count;
  // last_offset_ns previously reported previous_offset, which is itself a
  // smoothed value — so it could never reveal filter divergence.  Report the
  // genuinely raw sample instead.
  stats->last_offset_ns = ptp.raw_offset_ns;
  stats->filtered_offset_ns = ptp.filtered_offset_ns;
  stats->outlier_count = ptp.outlier_count;

  if (ptp.locked && ptp.lock_start_ms > 0) {
    uint32_t now_ms = xTaskGetTickCount() * portTICK_PERIOD_MS;
    stats->lock_time_ms = now_ms - ptp.lock_start_ms;
  } else {
    stats->lock_time_ms = 0;
  }
  portEXIT_CRITICAL(&ptp_state_mux);
}
