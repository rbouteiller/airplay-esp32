// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// AirPlay 2 remote control over the event channel, see rtsp_events.h.

#include "rtsp_events.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "sodium.h"

#include "plist.h"
#include "rtsp_handlers.h"

static const char *TAG = "rtsp_events";

#define EVENT_BLOCK_MAX   1024 // plaintext per encrypted block, as on RTSP
#define EVENT_MSG_MAX     2048 // request (header + plist)
#define EVENT_RESP_MAX    1024 // response, only the status line is used
#define EVENT_ARCHIVE_MAX 512

static uint8_t s_write_key[32];
static uint8_t s_read_key[32];
static uint64_t s_write_nonce;
static uint64_t s_read_nonce;
static bool s_keys_valid;
static char s_group_uuid[64];

// Keys, group UUID and nonces change only under the event socket lock, the
// same lock post_command() holds while it uses them
void rtsp_events_setup(const hap_session_t *session, const char *group_uuid) {
  bool keys_valid = session && session->event_keys_valid;
  rtsp_event_client_lock();
  s_keys_valid = keys_valid;
  if (keys_valid) {
    memcpy(s_write_key, session->event_write_key, sizeof(s_write_key));
    memcpy(s_read_key, session->event_read_key, sizeof(s_read_key));
  }
  strlcpy(s_group_uuid, group_uuid ? group_uuid : "", sizeof(s_group_uuid));
  s_write_nonce = 0;
  s_read_nonce = 0;
  rtsp_event_client_unlock();
  ESP_LOGI(TAG, "Event channel: keys %s, group %s",
           keys_valid ? "ok" : "missing",
           group_uuid && group_uuid[0] ? group_uuid : "missing");
}

void rtsp_events_on_client(void) {
  s_write_nonce = 0;
  s_read_nonce = 0;
}

void rtsp_events_clear(void) {
  s_keys_valid = false;
  sodium_memzero(s_write_key, sizeof(s_write_key));
  sodium_memzero(s_read_key, sizeof(s_read_key));
  s_group_uuid[0] = '\0';
}

bool rtsp_events_ready(void) {
  return s_keys_valid && s_group_uuid[0] != '\0' &&
         rtsp_event_client_connected();
}

static bool send_all(int sock, const uint8_t *data, size_t len) {
  while (len > 0) {
    ssize_t r = send(sock, data, len, 0);
    if (r <= 0) {
      return false;
    }
    data += r;
    len -= (size_t)r;
  }
  return true;
}

// The socket has SO_RCVTIMEO (rtsp_handlers.c): a timeout ends the exchange.
// A partial block cannot be resumed, the nonces would be out of step, so the
// channel is given up until the next session.
static bool recv_all(int sock, uint8_t *data, size_t len) {
  while (len > 0) {
    ssize_t r = recv(sock, data, len, 0);
    if (r <= 0) {
      return false;
    }
    data += r;
    len -= (size_t)r;
  }
  return true;
}

static bool write_encrypted(int sock, const uint8_t *data, size_t len) {
  uint8_t *block = malloc(EVENT_BLOCK_MAX + 16);
  if (!block) {
    return false;
  }
  bool ok = true;
  while (ok && len > 0) {
    uint16_t n = len > EVENT_BLOCK_MAX ? EVENT_BLOCK_MAX : (uint16_t)len;
    uint8_t aad[2] = {(uint8_t)n, (uint8_t)(n >> 8)};
    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, &s_write_nonce, 8);
    unsigned long long ct_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        block, &ct_len, data, n, aad, sizeof(aad), NULL, nonce, s_write_key);
    s_write_nonce++;
    ok = send_all(sock, aad, sizeof(aad)) &&
         send_all(sock, block, (size_t)ct_len);
    data += n;
    len -= n;
  }
  free(block);
  return ok;
}

// One encrypted block into out (capacity at least EVENT_BLOCK_MAX)
static int read_block(int sock, uint8_t *out) {
  uint8_t aad[2];
  if (!recv_all(sock, aad, sizeof(aad))) {
    return -1;
  }
  uint16_t n = (uint16_t)(aad[0] | (aad[1] << 8));
  if (n == 0 || n > EVENT_BLOCK_MAX) {
    ESP_LOGW(TAG, "Invalid block length %u", n);
    return -1;
  }
  uint8_t *cipher = malloc((size_t)n + 16);
  if (!cipher) {
    return -1;
  }
  int result = -1;
  if (recv_all(sock, cipher, (size_t)n + 16)) {
    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, &s_read_nonce, 8);
    unsigned long long pt_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &pt_len, NULL, cipher, (size_t)n + 16, aad, sizeof(aad), nonce,
            s_read_key) == 0) {
      s_read_nonce++;
      result = (int)pt_len;
    } else {
      ESP_LOGW(TAG, "Response does not decrypt (wrong event keys?)");
    }
  }
  free(cipher);
  return result;
}

// Reads the whole response (header and Content-Length body) so the next one
// starts on a block boundary. true: status 2xx.
static bool read_response(int sock) {
  uint8_t *resp = malloc(EVENT_RESP_MAX + EVENT_BLOCK_MAX + 1);
  if (!resp) {
    // The response stays unread, the next command would take it for its own
    ESP_LOGW(TAG, "No memory for the response, event channel given up");
    s_keys_valid = false;
    return false;
  }
  size_t have = 0;
  bool complete = false;
  while (!complete && have <= EVENT_RESP_MAX) {
    int n = read_block(sock, resp + have);
    if (n < 0) {
      break;
    }
    have += (size_t)n;
    resp[have] = '\0';
    const char *end = strstr((const char *)resp, "\r\n\r\n");
    if (end) {
      size_t header_len = (size_t)(end - (const char *)resp) + 4;
      size_t body_len = 0;
      const char *cl = strcasestr((const char *)resp, "Content-Length:");
      if (cl && cl < end) {
        body_len = (size_t)strtoul(cl + 15, NULL, 10);
      }
      complete = have >= header_len + body_len;
    }
  }

  bool ok = false;
  if (!complete) {
    ESP_LOGW(TAG, "No complete response, event channel given up");
    s_keys_valid = false;
  } else if (have >= 12 && strncmp((const char *)resp, "RTSP/1.", 7) == 0) {
    int status = atoi((const char *)resp + 9);
    ok = status >= 200 && status < 300;
    if (!ok) {
      ESP_LOGW(TAG, "Sender answered %d", status);
    }
  } else {
    // Not a response: ours may still follow, as above
    ESP_LOGW(TAG, "Invalid response, event channel given up");
    s_keys_valid = false;
  }
  free(resp);
  return ok;
}

// POST /command with the plist, then the response, under the socket lock
static bool post_command(const uint8_t *plist, size_t plist_len) {
  uint8_t *msg = malloc(EVENT_MSG_MAX);
  if (!msg) {
    return false;
  }
  int header_len = snprintf((char *)msg, EVENT_MSG_MAX,
                            "POST /command RTSP/1.0\r\n"
                            "Content-Length: %u\r\n"
                            "Content-Type: application/x-apple-binary-plist\r\n"
                            "\r\n",
                            (unsigned)plist_len);
  bool ok = false;
  if (header_len > 0 && (size_t)header_len + plist_len <= EVENT_MSG_MAX) {
    memcpy(msg + header_len, plist, plist_len);
    int sock = rtsp_event_client_lock();
    if (sock >= 0 && s_keys_valid) {
      if (write_encrypted(sock, msg, (size_t)header_len + plist_len)) {
        ok = read_response(sock);
      } else {
        // The write nonce has moved on, the sender may hold half a block:
        // the next command would not decrypt, so give up as on a bad read
        ESP_LOGW(TAG, "Send failed, event channel given up");
        s_keys_valid = false;
      }
    }
    rtsp_event_client_unlock();
  }
  free(msg);
  return ok;
}

static void random_uuid(char *out, size_t len) {
  uint8_t b[16];
  esp_fill_random(b, sizeof(b));
  b[6] = (b[6] & 0x0F) | 0x40; // version 4
  b[8] = (b[8] & 0x3F) | 0x80; // variant
  snprintf(out, len,
           "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-"
           "%02X%02X%02X%02X%02X%02X",
           b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10],
           b[11], b[12], b[13], b[14], b[15]);
}

bool rtsp_events_send_command(unsigned int command) {
  if (!rtsp_events_ready()) {
    return false;
  }
  uint8_t *buf = malloc(EVENT_ARCHIVE_MAX + EVENT_MSG_MAX);
  if (!buf) {
    return false;
  }
  uint8_t *archive = buf;
  uint8_t *plist = buf + EVENT_ARCHIVE_MAX;
  char command_id[40];
  random_uuid(command_id, sizeof(command_id));
  char group_uuid[sizeof(s_group_uuid)];
  rtsp_event_client_lock();
  strlcpy(group_uuid, s_group_uuid, sizeof(group_uuid));
  rtsp_event_client_unlock();
  size_t archive_len =
      bplist_build_group_archive(archive, EVENT_ARCHIVE_MAX, group_uuid);
  size_t plist_len = archive_len ? bplist_build_media_remote_command(
                                       plist, EVENT_MSG_MAX - 256, command,
                                       command_id, archive, archive_len)
                                 : 0;
  bool ok = plist_len > 0 && post_command(plist, plist_len);
  ESP_LOGI(TAG, "Command %u %s", command, ok ? "sent" : "failed");
  free(buf);
  return ok;
}

bool rtsp_events_send_volume(double unit_volume) {
  if (!rtsp_events_ready()) {
    return false;
  }
  if (unit_volume < 0.0) {
    unit_volume = 0.0;
  } else if (unit_volume > 1.0) {
    unit_volume = 1.0;
  }
  uint8_t plist[256];
  size_t plist_len =
      bplist_build_volume_command(plist, sizeof(plist), unit_volume);
  bool ok = plist_len > 0 && post_command(plist, plist_len);
  ESP_LOGI(TAG, "Volume %.2f %s", unit_volume, ok ? "sent" : "failed");
  return ok;
}
