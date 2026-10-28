// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "audio_receiver_internal.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "audio_crypto.h"
#include "network/socket_utils.h"

#define RTP_HEADER_SIZE 12
// Must fit the ~11 KB largest free block that survives the Bluetooth teardown,
// so keep it under that even though the heap has ~40 KB free at this point.
#define AUDIO_RECV_STACK_SIZE   8192
#define AUDIO_CTRL_STACK_SIZE   4096
#define RESEND_ERROR_BACKOFF_US 300000 // Backoff after sendto failure
// Requests per pass over the missing packets, one per run of them.
#define RESEND_MAX_REQUESTS 16
#define RESEND_REPORT_US    1000000

#if CONFIG_FREERTOS_UNICORE || CONFIG_AUDIO_OUTPUT_USB_HOST
/* USB-host builds: the playback task (44.1->48 resampler + iso-OUT pacing)
 * runs at high priority on core 1 and costs ~50% of it for a 48 kHz sink.
 * Co-residing there, this receive task's burst-drain latency grows enough
 * to overflow the lwIP UDP mailbox — measured 25-40% RTP arrival loss on
 * 48 kHz devices (realtime/UDP mode unusable), zero loss at 44.1 kHz.
 * Pinned to core 0 the loss goes to zero: WiFi/lwIP there are bursty
 * peers, not a continuous high-priority preemptor. Non-USB builds keep
 * the upstream layout. */
#define AUDIO_TASK_CORE 0
#else
#define AUDIO_TASK_CORE 1
#endif

// Packet buffers are allocated once from SPIRAM. Tasks are created dynamically:
// restartable static TCBs can be corrupted if a new task reuses the TCB before
// the idle task has removed the old self-deleted task from FreeRTOS lists.
static uint8_t *s_recv_packet_buf;
static uint8_t *s_ctrl_packet_buf;

static const char *TAG = "audio_rt";

typedef struct __attribute__((packed)) {
  uint8_t flags;
  uint8_t type;
  uint16_t seq;
  uint32_t timestamp;
  uint32_t ssrc;
} rtp_header_t;

static const uint8_t *parse_rtp(const uint8_t *packet, size_t len,
                                uint16_t *seq, uint32_t *timestamp,
                                size_t *payload_len) {
  if (len < RTP_HEADER_SIZE) {
    return NULL;
  }

  const rtp_header_t *hdr = (const rtp_header_t *)packet;
  uint8_t version = (hdr->flags >> 6) & 0x03;
  if (version != 2) {
    ESP_LOGW(TAG, "Invalid RTP version: %d", version);
    return NULL;
  }

  *seq = ntohs(hdr->seq);
  *timestamp = ntohl(hdr->timestamp);

  size_t header_len = RTP_HEADER_SIZE;
  if (hdr->flags & 0x10) {
    if (len < RTP_HEADER_SIZE + 4) {
      return NULL;
    }
    uint16_t ext_len = ntohs(*(uint16_t *)(packet + RTP_HEADER_SIZE + 2));
    header_len += 4 + (size_t)ext_len * 4;
  }

  uint8_t csrc_count = hdr->flags & 0x0F;
  header_len += (size_t)csrc_count * 4;

  if (len <= header_len) {
    return NULL;
  }

  *payload_len = len - header_len;
  return packet + header_len;
}

/* Send an AirTunes retransmission request for missing sequence numbers.
   AirPlay 1 docs describe this as an RTP header without SSRC; in practice
   (and in Shairport) the RTP timestamp word is split into first_seq/count:
   0x80 0xD5 <rtp_seq=1:u16> <first_seq:u16> <count:u16>. */
static bool send_resend_request(audio_receiver_state_t *state,
                                uint16_t first_seq, uint16_t count) {
  if (!state->retransmit_enabled || state->control_socket <= 0 || count == 0) {
    return false;
  }

  /* Backoff: skip if we recently had a sendto error */
  int64_t now = esp_timer_get_time();
  if (state->last_resend_error_time_us > 0 &&
      (now - state->last_resend_error_time_us) < RESEND_ERROR_BACKOFF_US) {
    return false;
  }

  uint8_t nack[8];
  nack[0] = 0x80;
  nack[1] = 0xD5;
  nack[2] = 0;
  nack[3] = 1; // Shairport sends a fixed RTP sequence number for resend asks.
  nack[4] = (uint8_t)(first_seq >> 8);
  nack[5] = (uint8_t)(first_seq & 0xFF);
  nack[6] = (uint8_t)(count >> 8);
  nack[7] = (uint8_t)(count & 0xFF);

  ssize_t ret = sendto(state->control_socket, nack, sizeof(nack), 0,
                       (struct sockaddr *)&state->client_control_addr,
                       sizeof(state->client_control_addr));
  if (ret < 0) {
    state->last_resend_error_time_us = now;
    ESP_LOGD(TAG, "NACK sendto failed: %d", errno);
    return false;
  } else {
    state->last_resend_error_time_us = 0;
    ESP_LOGD(TAG, "NACK sent: seq=%u count=%u", first_seq, count);
    return true;
  }
}

// Carries out a reset another task asked for, before the tracker is used.
static void resend_sync(audio_receiver_state_t *state) {
  const uint32_t generation =
      __atomic_load_n(&state->resend_generation, __ATOMIC_ACQUIRE);
  if (generation != state->resend_generation_seen) {
    state->resend_generation_seen = generation;
    rtp_resend_reset(&state->resend, AUDIO_TIMELINE_RT_FRAME_SAMPLES);
  }
}

/* Once a second while packets go astray, what became of them.  queue_max is
 * the most still waiting on the socket after a read: the socket drops what
 * does not fit, so a queue near its limit means this task fell behind, and
 * a short one that the packets never reached the board. */
static void resend_report(audio_receiver_state_t *state, int64_t now) {
  if (now - state->resend_report_us < RESEND_REPORT_US) {
    return;
  }
  state->resend_report_us = now;

  rtp_resend_counts_t *c = &state->resend.counts;
  const uint32_t events = c->skipped + c->resent + c->late + c->expired +
                          c->unwanted + state->resend_rejected;
  if (events != 0U) {
    ESP_LOGI(TAG,
             "loss: rx=%" PRIu32 " skipped=%" PRIu32 " resent=%" PRIu32
             " late=%" PRIu32 " expired=%" PRIu32 " unwanted=%" PRIu32
             " asked=%" PRIu32 " in %" PRIu32 " open=%" PRIu32
             " queue_max=%" PRIu32 " B rejected=%" PRIu32,
             c->received, c->skipped, c->resent, c->late, c->expired,
             c->unwanted, c->asked, c->requests,
             rtp_resend_outstanding(&state->resend), state->resend_queue_max,
             state->resend_rejected);
  }
  memset(c, 0, sizeof(*c));
  state->resend_queue_max = 0;
  state->resend_rejected = 0;
}

/* Asks for every missing packet that could still play and has not been asked
 * for in the last RTP_RESEND_RETRY_MS.  Runs after every packet and on every
 * receive timeout, so a hole is asked for as soon as it opens, and again for
 * as long as its audio is still to come. */
static void resend_service(audio_receiver_state_t *state) {
  const int64_t now = esp_timer_get_time();
  const bool can_ask =
      state->retransmit_enabled && state->control_socket > 0 &&
      (state->last_resend_error_time_us == 0 ||
       now - state->last_resend_error_time_us >= RESEND_ERROR_BACKOFF_US);

  uint32_t cursor_rtp = 0;
  const bool playing =
      audio_engine_v2_play_cursor(&state->engine_v2, &cursor_rtp);
  rtp_resend_range_t ranges[RESEND_MAX_REQUESTS];
  const size_t n =
      rtp_resend_collect(&state->resend, (uint32_t)(now / 1000), playing,
                         cursor_rtp, ranges, can_ask ? RESEND_MAX_REQUESTS : 0);
  for (size_t i = 0; i < n; i++) {
    if (!send_resend_request(state, ranges[i].first, ranges[i].count)) {
      break;
    }
  }

  resend_report(state, now);
}

/* What became of the packets, every PKT_REPORT_US while any fail to decrypt
 * or the engine is not playing them.  Only this task touches the counts. */
#define PKT_REPORT_US 5000000LL
static struct {
  int64_t since_us;
  uint32_t received, decrypt_failed, rejected, accepted;
} s_pkt;

static void packet_report(audio_receiver_state_t *state,
                          const audio_stream_t *stream, int64_t now) {
  if (now - s_pkt.since_us < PKT_REPORT_US) {
    return;
  }
  uint32_t cursor_rtp = 0;
  const bool playing =
      audio_engine_v2_play_cursor(&state->engine_v2, &cursor_rtp);
  if (s_pkt.received != 0U && (s_pkt.decrypt_failed != 0U || !playing)) {
    ESP_LOGW(TAG,
             "packets: rx=%" PRIu32 " decrypt_failed=%" PRIu32
             " rejected=%" PRIu32 " accepted=%" PRIu32
             " playing=%d encrypt=%d key_len=%u gates=%d/%d",
             s_pkt.received, s_pkt.decrypt_failed, s_pkt.rejected,
             s_pkt.accepted, playing ? 1 : 0, (int)stream->encrypt.type,
             (unsigned)stream->encrypt.key_len,
             state->discard_before_rtp_valid ? 1 : 0,
             state->discard_above_rtp_valid ? 1 : 0);
  }
  memset(&s_pkt, 0, sizeof(s_pkt));
  s_pkt.since_us = now;
}

static bool realtime_receive_packet(audio_stream_t *stream, uint8_t *packet,
                                    struct sockaddr_in *src_addr,
                                    socklen_t *addr_len) {
  audio_receiver_state_t *state = audio_stream_state(stream);
  packet_report(state, stream, esp_timer_get_time());

  ssize_t len = recvfrom(state->data_socket, packet, MAX_RTP_PACKET_SIZE, 0,
                         (struct sockaddr *)src_addr, addr_len);
  if (len < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      resend_sync(state);
      resend_service(state);
      return true;
    }
    if (stream->running) {
      ESP_LOGE(TAG, "recvfrom error: %d", errno);
    }
    return false;
  }

  if (len == 0) {
    return true;
  }

  state->stats.packets_received++;
  s_pkt.received++;
  int queued = 0;
  if (ioctl(state->data_socket, FIONREAD, &queued) == 0 &&
      (uint32_t)queued > state->resend_queue_max) {
    state->resend_queue_max = (uint32_t)queued;
  }

  const uint8_t *rtp_data = packet;
  size_t rtp_len = (size_t)len;

  /* Retransmit packets (payload type 0x56, usually marker 0xD6) have a
     4-byte outer header before the inner RTP packet. Strip it and parse the
     inner RTP normally. */
  bool is_retransmit = (rtp_len >= 16 && (rtp_data[1] & 0x7F) == 0x56);
  if (is_retransmit) {
    rtp_data += 4;
    rtp_len -= 4;
  }

  uint16_t seq = 0;
  uint32_t timestamp = 0;
  size_t payload_len = 0;
  const uint8_t *payload =
      parse_rtp(rtp_data, rtp_len, &seq, &timestamp, &payload_len);

  if (!payload || payload_len == 0) {
    state->stats.packets_dropped++;
    return true;
  }

  resend_sync(state);
  const rtp_resend_verdict_t verdict =
      rtp_resend_on_packet(&state->resend, seq, timestamp, is_retransmit);
  resend_service(state);
  if (verdict == RTP_RESEND_UNWANTED) {
    ESP_LOGD(TAG, "Dropping unwanted %s seq=%u",
             is_retransmit ? "retransmit" : "packet", seq);
    return true;
  }
  if (verdict == RTP_RESEND_NEWEST) {
    state->stats.last_seq = seq;
    state->stats.last_timestamp = timestamp;
  }

  state->blocks_read++;
  state->blocks_read_in_sequence++;

  const uint8_t *audio_data = payload;
  size_t audio_len = payload_len;

  if (stream->encrypt.type != AUDIO_ENCRYPT_NONE && state->decrypt_buffer) {
    int decrypted_len = audio_crypto_decrypt_rtp(
        &stream->encrypt, payload, payload_len, state->decrypt_buffer,
        MAX_RTP_PACKET_SIZE, rtp_data, rtp_len);
    if (decrypted_len < 0) {
      state->stats.decrypt_errors++;
      state->stats.packets_dropped++;
      s_pkt.decrypt_failed++;
      return true;
    }
    audio_data = state->decrypt_buffer;
    audio_len = (size_t)decrypted_len;
  }

  if (!audio_stream_process_frame(state, timestamp, audio_data, audio_len)) {
    state->stats.packets_dropped++;
    state->resend_rejected++;
    s_pkt.rejected++;
  } else {
    s_pkt.accepted++;
  }

  return true;
}

static void receiver_task(void *pvParameters) {
  audio_stream_t *stream = (audio_stream_t *)pvParameters;
  audio_receiver_state_t *state = audio_stream_state(stream);

  if (!s_recv_packet_buf) {
    s_recv_packet_buf =
        heap_caps_malloc(MAX_RTP_PACKET_SIZE, MALLOC_CAP_SPIRAM);
  }
  if (!s_recv_packet_buf) {
    s_recv_packet_buf = malloc(MAX_RTP_PACKET_SIZE);
  }
  uint8_t *packet = s_recv_packet_buf;
  if (!packet) {
    ESP_LOGE(TAG, "Failed to allocate receiver packet buffer");
    state->task_handle = NULL;
    vTaskDelete(NULL);
    return;
  }

  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  while (stream->running) {
    if (!realtime_receive_packet(stream, packet, &src_addr, &addr_len)) {
      break;
    }
  }

  ESP_LOGI(TAG, "receiver task stack headroom: %u bytes",
           (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
  state->task_handle = NULL;
  vTaskDelete(NULL);
}

static uint64_t nctoh64(const uint8_t *data) {
  return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
         ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
         ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) |
         ((uint64_t)data[6] << 8) | (uint64_t)data[7];
}

static uint32_t nctoh32(const uint8_t *data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static void control_receiver_task(void *pvParameters) {
  audio_stream_t *stream = (audio_stream_t *)pvParameters;
  audio_receiver_state_t *state = audio_stream_state(stream);

  if (!s_ctrl_packet_buf) {
    s_ctrl_packet_buf =
        heap_caps_malloc(MAX_RTP_PACKET_SIZE, MALLOC_CAP_SPIRAM);
  }
  if (!s_ctrl_packet_buf) {
    s_ctrl_packet_buf = malloc(MAX_RTP_PACKET_SIZE);
  }
  uint8_t *packet = s_ctrl_packet_buf;
  if (!packet) {
    ESP_LOGE(TAG, "Failed to allocate control packet buffer");
    state->control_task_handle = NULL;
    vTaskDelete(NULL);
    return;
  }
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  while (stream->running) {
    ssize_t len = recvfrom(state->control_socket, packet, MAX_RTP_PACKET_SIZE,
                           0, (struct sockaddr *)&src_addr, &addr_len);

    if (len < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      if (stream->running) {
        ESP_LOGE(TAG, "control recvfrom error: %d", errno);
      }
      break;
    }

    if (len < 2) {
      continue;
    }

    uint8_t packet_type = packet[1] & 0x7F;

    switch (packet_type) {
    case 0x54: // AirPlay 1 sync packet (NTP timing)
      // Layout (per shairport-sync / Apple protocol documentation):
      //   [4-7]  rtp_timestamp_less_latency  — the RTP frame PLAYING at the
      //          NTP time in [8-15].  This is the correct anchor RTP.
      //   [8-11] NTP seconds
      //   [12-15] NTP fraction
      //   [16-19] sync_rtp_timestamp — the RTP frame currently being SENT
      //           (ahead by the stream latency).  Do NOT use as anchor.
      if (len >= 20) {
        uint32_t rtp_timestamp =
            nctoh32(packet + 4); // rtp_timestamp_less_latency
        uint64_t ntp_secs = nctoh32(packet + 8);
        uint64_t ntp_frac = nctoh32(packet + 12);
        uint64_t network_time_ns =
            (ntp_secs * 1000000000ULL) + ((ntp_frac * 1000000000ULL) >> 32);
        audio_receiver_set_anchor_time(0, network_time_ns, rtp_timestamp);
      }
      break;

    case 0x57: // AirPlay 2 anchor timing packet (PTP timing)
      // Format: [4] RTP frame, [8] PTP time ns, [16] RTP frame 2, [20] clock ID
      // The RTP timestamp at [4] is the frame that should play at the
      // PTP time — use it directly (matching the NTP anchor path).
      // compute_early_us handles hardware latency compensation.
      if (len >= 28) {
        uint32_t frame_1 = nctoh32(packet + 4);
        uint64_t network_time_ns = nctoh64(packet + 8);
        uint64_t clock_id = nctoh64(packet + 20);

        audio_receiver_set_anchor_time(clock_id, network_time_ns, frame_1);
      }
      break;

    case 0x56: { // Retransmit response — forward inner RTP to data socket
      if (len < 8 || state->data_socket <= 0) {
        break;
      }
      /* Re-wrap as a 0x56 retransmit and send to our own data socket so the
         receiver task processes it in the same thread as normal packets.
         This avoids concurrent access to the decoder and decrypt buffer. */
      packet[1] = 0x56;
      struct sockaddr_in self = {0};
      self.sin_family = AF_INET;
      self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      self.sin_port = htons(state->data_port);
      sendto(state->data_socket, packet, (size_t)len, 0,
             (struct sockaddr *)&self, sizeof(self));
      break;
    }

    default:
      if (len >= 4) {
        ESP_LOGD(TAG,
                 "Control packet type 0x%02X, len=%d, data=%02x %02x %02x %02x",
                 packet_type, len, packet[0], packet[1], packet[2], packet[3]);
      }
      break;
    }
  }

  state->control_task_handle = NULL;
  vTaskDelete(NULL);
}

static bool realtime_wait_for_tasks_stopped(audio_receiver_state_t *state,
                                            int timeout_ticks) {
  while ((state->task_handle || state->control_task_handle) &&
         timeout_ticks-- > 0) {
    vTaskDelay(pdMS_TO_TICKS(50));
  }
  return state->task_handle == NULL && state->control_task_handle == NULL;
}

static esp_err_t realtime_start(audio_stream_t *stream, uint16_t port) {
  audio_receiver_state_t *state = audio_stream_state(stream);
  if (stream->running) {
    ESP_LOGI(TAG, "Audio receiver already running on port %u",
             state->data_port);
    return ESP_OK;
  }
  if (state->task_handle || state->control_task_handle) {
    ESP_LOGW(TAG, "Audio receiver task still stopping, waiting");
    if (!realtime_wait_for_tasks_stopped(state, 20)) {
      ESP_LOGW(TAG, "Audio receiver task still active");
      return ESP_ERR_INVALID_STATE;
    }
  }

  uint16_t bound_port = port;
  state->data_socket = socket_utils_bind_udp(port, 1, 131072, &bound_port);
  if (state->data_socket < 0) {
    return ESP_FAIL;
  }
  // Keep the receive loop awake so resend_service() can repeat NACKs even
  // when no fresh RTP packets arrive.
  struct timeval tv = {.tv_sec = 0, .tv_usec = 100000};
  setsockopt(state->data_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  state->data_port = bound_port;

  if (state->control_port > 0) {
    uint16_t ctrl_bound = state->control_port;
    state->control_socket =
        socket_utils_bind_udp(state->control_port, 1, 0, &ctrl_bound);
    if (state->control_socket < 0) {
      close(state->data_socket);
      state->data_socket = 0;
      return ESP_FAIL;
    }
    state->control_port = ctrl_bound;
  }

  stream->running = true;

  ESP_LOGI(TAG, "Free heap: %lu DRAM (largest block %lu), %lu SPIRAM",
           (unsigned long)heap_caps_get_free_size(AUDIO_DRAM_CAPS),
           (unsigned long)heap_caps_get_largest_free_block(AUDIO_DRAM_CAPS),
           (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

  state->task_handle = NULL;
  BaseType_t task_ret = xTaskCreatePinnedToCore(
      receiver_task, "audio_recv", AUDIO_RECV_STACK_SIZE, stream, 8,
      &state->task_handle, AUDIO_TASK_CORE);
  if (task_ret != pdPASS || !state->task_handle) {
    ESP_LOGE(TAG, "Failed to create receiver task");
    if (state->control_socket > 0) {
      close(state->control_socket);
      state->control_socket = 0;
    }
    close(state->data_socket);
    state->data_socket = 0;
    stream->running = false;
    return ESP_FAIL;
  }

  if (state->control_socket > 0) {
    state->control_task_handle = NULL;
    task_ret = xTaskCreatePinnedToCore(
        control_receiver_task, "ctrl_recv", AUDIO_CTRL_STACK_SIZE, stream, 7,
        &state->control_task_handle, AUDIO_TASK_CORE);
    if (task_ret != pdPASS || !state->control_task_handle) {
      ESP_LOGE(TAG, "Failed to create control receiver task");
      close(state->control_socket);
      state->control_socket = 0;
      stream->running = false;
      close(state->data_socket);
      state->data_socket = 0;
      realtime_wait_for_tasks_stopped(state, 20);
      return ESP_FAIL;
    }
  }

  return ESP_OK;
}

static void realtime_stop(audio_stream_t *stream) {
  audio_receiver_state_t *state = audio_stream_state(stream);
  if (!stream->running && !state->task_handle && !state->control_task_handle) {
    return;
  }

  stream->running = false;

  if (state->data_socket > 0) {
    close(state->data_socket);
    state->data_socket = 0;
  }
  if (state->control_socket > 0) {
    close(state->control_socket);
    state->control_socket = 0;
  }

  if (!realtime_wait_for_tasks_stopped(state, 20)) {
    ESP_LOGW(TAG, "Audio receiver task did not exit within timeout");
  }
}

static uint16_t realtime_get_port(audio_stream_t *stream) {
  audio_receiver_state_t *state = audio_stream_state(stream);
  return state->data_port;
}

static bool realtime_is_running(audio_stream_t *stream) {
  return stream->running;
}

static void realtime_destroy(audio_stream_t *stream) {
  if (!stream) {
    return;
  }

  realtime_stop(stream);
  audio_receiver_state_t *state = audio_stream_state(stream);
  if (state->task_handle || state->control_task_handle) {
    ESP_LOGW(TAG, "Leaking realtime stream because task shutdown timed out");
    return;
  }
  free(stream);
}

const audio_stream_ops_t audio_stream_realtime_ops = {
    .start = realtime_start,
    .stop = realtime_stop,
    .receive_packet = NULL,
    .decrypt_payload = NULL,
    .get_port = realtime_get_port,
    .is_running = realtime_is_running,
    .destroy = realtime_destroy};
