#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "audio_receiver_internal.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "audio_crypto.h"
#include "network/socket_utils.h"

#define RTP_HEADER_SIZE          12
#define AUDIO_RECV_STACK_SIZE    12288
#define AUDIO_CTRL_STACK_SIZE    8192
#define STACK_LOG_INTERVAL_US    5000000
#define RESEND_ERROR_BACKOFF_US  100000  // 100ms backoff after sendto failure
#define MAX_RESEND_GAP           100     // Don't request retransmit for gaps > 100

#if CONFIG_FREERTOS_UNICORE
#define AUDIO_TASK_CORE 0
#else
#define AUDIO_TASK_CORE 1
#endif

typedef struct __attribute__((packed)) {
  uint8_t flags;
  uint8_t type;
  uint16_t seq;
  uint32_t timestamp;
  uint32_t ssrc;
} rtp_header_t;

static const char *TAG = "audio_rt";

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
    header_len += 4 + ext_len * 4;
  }

  uint8_t csrc_count = hdr->flags & 0x0F;
  header_len += csrc_count * 4;

  if (len <= header_len) {
    return NULL;
  }

  *payload_len = len - header_len;
  return packet + header_len;
}

/* Send an AirPlay NACK (retransmission request) for missing sequence numbers.
   Packet format: 0x80 0xD5 <seq_count_minus_1:u16> <first_seq:u16> <count:u16>
   Sent to the client's control port via our control socket. */
static void send_resend_request(audio_receiver_state_t *state,
                                uint16_t first_seq, uint16_t count) {
  if (!state->retransmit_enabled || state->control_socket <= 0) {
    return;
  }

  /* Backoff: skip if we recently had a sendto error */
  int64_t now = esp_timer_get_time();
  if (state->last_resend_error_time_us > 0 &&
      (now - state->last_resend_error_time_us) < RESEND_ERROR_BACKOFF_US) {
    return;
  }

  uint8_t nack[8];
  nack[0] = 0x80;
  nack[1] = 0xD5;
  nack[2] = (uint8_t)((count - 1) >> 8);
  nack[3] = (uint8_t)((count - 1) & 0xFF);
  nack[4] = (uint8_t)(first_seq >> 8);
  nack[5] = (uint8_t)(first_seq & 0xFF);
  nack[6] = (uint8_t)(count >> 8);
  nack[7] = (uint8_t)(count & 0xFF);

  int ret = sendto(state->control_socket, nack, sizeof(nack), 0,
                   (struct sockaddr *)&state->client_control_addr,
                   sizeof(state->client_control_addr));
  if (ret < 0) {
    state->last_resend_error_time_us = now;
    ESP_LOGD(TAG, "NACK sendto failed: %d", errno);
  } else {
    state->last_resend_error_time_us = 0;
    ESP_LOGD(TAG, "NACK sent: seq=%u count=%u", first_seq, count);
  }
}

static bool realtime_receive_packet(audio_stream_t *stream, uint8_t *packet,
                                    struct sockaddr_in *src_addr,
                                    socklen_t *addr_len) {
  audio_receiver_state_t *state = audio_stream_state(stream);

  int len = recvfrom(state->data_socket, packet, MAX_RTP_PACKET_SIZE, 0,
                     (struct sockaddr *)src_addr, addr_len);
  if (len < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
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

  const uint8_t *rtp_data = packet;
  size_t rtp_len = (size_t)len;

  /* Retransmit packets (type 0x56) have a 4-byte outer header before the
     inner RTP packet. Strip it and parse the inner RTP normally. */
  bool is_retransmit = (rtp_len >= 16 && rtp_data[1] == 0x56);
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

  /* Skip gap detection and sequence tracking for retransmits — their seq
     is old and would corrupt last_seq, causing spurious NACKs. */
  if (!is_retransmit) {
    if (state->stats.packets_decoded > 0) {
      uint16_t expected_seq = (state->stats.last_seq + 1) & 0xFFFF;
      if (seq != expected_seq) {
        int gap = (int)seq - (int)expected_seq;
        if (gap < 0) {
          gap += 65536;
        }
        if (gap > 0 && gap < MAX_RESEND_GAP) {
          state->stats.packets_dropped += gap;
          send_resend_request(state, expected_seq, (uint16_t)gap);
        }
      }
    }

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
      return true;
    }
    audio_data = state->decrypt_buffer;
    audio_len = (size_t)decrypted_len;
  }

  if (!audio_stream_process_frame(state, timestamp, audio_data, audio_len)) {
    state->stats.packets_dropped++;
  }

  return true;
}

static void receiver_task(void *pvParameters) {
  audio_stream_t *stream = (audio_stream_t *)pvParameters;
  audio_receiver_state_t *state = audio_stream_state(stream);

  uint8_t *packet = (uint8_t *)malloc(MAX_RTP_PACKET_SIZE);
  if (!packet) {
    ESP_LOGE(TAG, "Failed to allocate packet buffer");
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

  free(packet);
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

  uint8_t *packet = (uint8_t *)malloc(MAX_RTP_PACKET_SIZE);
  if (!packet) {
    ESP_LOGE(TAG, "Failed to allocate control packet buffer");
    state->control_task_handle = NULL;
    vTaskDelete(NULL);
    return;
  }
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  while (stream->running) {
    int len = recvfrom(state->control_socket, packet, MAX_RTP_PACKET_SIZE, 0,
                       (struct sockaddr *)&src_addr, &addr_len);

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

    uint8_t packet_type = packet[1];

    switch (packet_type) {
    case 0xD4: // AirPlay 1 sync packet (NTP timing)
    case 0x54: // Same as 0xD4 but without extension bit
      // Format: [4] current RTP, [8] NTP secs, [12] NTP frac, [16] next RTP
      if (len >= 20) {
        uint32_t rtp_timestamp = nctoh32(packet + 16);
        uint64_t ntp_secs = nctoh32(packet + 8);
        uint64_t ntp_frac = nctoh32(packet + 12);
        uint64_t network_time_ns =
            (ntp_secs * 1000000000ULL) + ((ntp_frac * 1000000000ULL) >> 32);
        audio_receiver_set_anchor_time(0, network_time_ns, rtp_timestamp);
      }
      break;

    case 0xD7: // AirPlay 2 anchor timing packet (PTP timing)
      // Format: [4] RTP frame, [8] PTP time ns, [20] clock ID
      if (len >= 28) {
        uint32_t frame_1 = nctoh32(packet + 4);
        uint64_t network_time_ns = nctoh64(packet + 8);
        uint64_t clock_id = nctoh64(packet + 20);

        audio_receiver_set_anchor_time(clock_id, network_time_ns,
                                       frame_1 - 11035);
      }
      break;

    case 0xD6: { // Retransmit response — forward inner RTP to data socket
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

  free(packet);
  state->control_task_handle = NULL;
  vTaskDelete(NULL);
}

static esp_err_t realtime_start(audio_stream_t *stream, uint16_t port) {
  audio_receiver_state_t *state = audio_stream_state(stream);
  if (stream->running) {
    ESP_LOGI(TAG, "Audio receiver already running on port %u",
             state->data_port);
    return ESP_OK;
  }

  uint16_t bound_port = port;
  state->data_socket = socket_utils_bind_udp(port, 1, 131072, &bound_port);
  if (state->data_socket < 0) {
    return ESP_FAIL;
  }
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
  BaseType_t ret = xTaskCreatePinnedToCore(
      receiver_task, "audio_recv", AUDIO_RECV_STACK_SIZE, stream, 8,
      &state->task_handle, AUDIO_TASK_CORE);
  if (ret != pdPASS) {
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
    ret = xTaskCreatePinnedToCore(control_receiver_task, "ctrl_recv",
                                  AUDIO_CTRL_STACK_SIZE, stream, 7,
                                  &state->control_task_handle, AUDIO_TASK_CORE);
    if (ret != pdPASS) {
      ESP_LOGW(TAG, "Failed to create control receiver task");
      close(state->control_socket);
      state->control_socket = 0;
    }
  }

  return ESP_OK;
}

static void realtime_stop(audio_stream_t *stream) {
  audio_receiver_state_t *state = audio_stream_state(stream);
  if (!stream->running) {
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

  if (state->task_handle) {
    vTaskDelay(pdMS_TO_TICKS(200));
    state->task_handle = NULL;
  }
  if (state->control_task_handle) {
    vTaskDelay(pdMS_TO_TICKS(100));
    state->control_task_handle = NULL;
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
