// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "sendspin_psk.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "sodium.h"

static const char *TAG = "sendspin-psk";

#define PSK_NVS_NAMESPACE "sendspin"
#define PSK_NVS_KEY_PAIR  "pair_psk"
#define PSK_NVS_KEY_RECS  "pair_recs"
#define PSK_NVS_KEY_PIN   "pair_pin"

/* server_id is the base64url of a 32-byte key, so 43 characters plus a NUL. */
#define PSK_SERVER_ID_MAX 44

typedef struct {
  char server_id[PSK_SERVER_ID_MAX];
  uint8_t psk[SENDSPIN_PSK_LEN];
} psk_record_t;

static uint8_t s_pairing_psk[SENDSPIN_PSK_LEN];
static char s_pairing_psk_id[SENDSPIN_PSK_ID_LEN + 1];
static char s_token[SENDSPIN_PSK_TOKEN_LEN + 1];
static char s_static_pin[SENDSPIN_PSK_PIN_LEN + 1];

/* Ordered oldest first, so a full table drops from the front. */
static psk_record_t s_records[SENDSPIN_PSK_MAX_RECORDS];
static size_t s_record_count = 0;
static char s_record_ids[SENDSPIN_PSK_MAX_RECORDS][SENDSPIN_PSK_ID_LEN + 1];

/* ------------------------------------------------------------------ */
/*  Pairing token                                                      */
/* ------------------------------------------------------------------ */

/* RFC 4648 base32, padding stripped, then every '2' transliterated to '9'.
 * The alphabet is chosen so a token survives being read aloud or typed, and
 * so it renders in a QR code's compact alphanumeric mode. */
static size_t psk_base32(const uint8_t *in, size_t len, char *out,
                         size_t out_cap) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  size_t written = 0;
  uint32_t buffer = 0;
  int bits = 0;

  for (size_t i = 0; i < len; i++) {
    buffer = (buffer << 8) | in[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      if (written + 1 >= out_cap) {
        return 0;
      }
      out[written++] = alphabet[(buffer >> bits) & 0x1F];
    }
  }
  if (bits > 0) {
    if (written + 1 >= out_cap) {
      return 0;
    }
    out[written++] = alphabet[(buffer << (5 - bits)) & 0x1F];
  }

  for (size_t i = 0; i < written; i++) {
    if (out[i] == '2') {
      out[i] = '9';
    }
  }
  out[written] = '\0';
  return written;
}

static void psk_build_token(const uint8_t client_pub[SENDSPIN_PSK_LEN]) {
  uint8_t payload[SENDSPIN_PSK_LEN * 2];
  memcpy(payload, client_pub, SENDSPIN_PSK_LEN);
  memcpy(payload + SENDSPIN_PSK_LEN, s_pairing_psk, SENDSPIN_PSK_LEN);

  memcpy(s_token, "SP:0", 4);
  const size_t n =
      psk_base32(payload, sizeof(payload), s_token + 4, sizeof(s_token) - 4);
  sodium_memzero(payload, sizeof(payload));
  if (n == 0) {
    s_token[0] = '\0';
  }
}

const char *sendspin_psk_token(void) {
  return s_token;
}

const char *sendspin_psk_static_pin(void) {
  return s_static_pin;
}

/* Rejection-free uniform digits: randombytes_uniform() already removes the
 * modulo bias that a plain rand() % 10 would introduce, and a biased PIN is a
 * smaller search space for whoever is guessing it. */
static void psk_generate_pin(void) {
  for (size_t i = 0; i < SENDSPIN_PSK_PIN_LEN; i++) {
    s_static_pin[i] = (char)('0' + randombytes_uniform(10));
  }
  s_static_pin[SENDSPIN_PSK_PIN_LEN] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Persistence                                                        */
/* ------------------------------------------------------------------ */

static void psk_index_records(void) {
  for (size_t i = 0; i < s_record_count; i++) {
    sendspin_noise_psk_id(s_records[i].psk, s_record_ids[i]);
  }
}

static esp_err_t psk_save_records(void) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(PSK_NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    return err;
  }
  if (s_record_count == 0) {
    err = nvs_erase_key(nvs, PSK_NVS_KEY_RECS);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
      err = ESP_OK;
    }
  } else {
    err = nvs_set_blob(nvs, PSK_NVS_KEY_RECS, s_records,
                       s_record_count * sizeof(psk_record_t));
  }
  if (err == ESP_OK) {
    err = nvs_commit(nvs);
  }
  nvs_close(nvs);
  return err;
}

esp_err_t sendspin_psk_init(const uint8_t client_pub[SENDSPIN_PSK_LEN]) {
  nvs_handle_t nvs;
  esp_err_t err = nvs_open(PSK_NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    return err;
  }

  size_t len = sizeof(s_pairing_psk);
  err = nvs_get_blob(nvs, PSK_NVS_KEY_PAIR, s_pairing_psk, &len);
  if (err != ESP_OK || len != sizeof(s_pairing_psk)) {
    /* Must be per-device and from a CSPRNG: a default shared across a
     * product line would let anyone holding one token adopt all of them. */
    randombytes_buf(s_pairing_psk, sizeof(s_pairing_psk));
    err = nvs_set_blob(nvs, PSK_NVS_KEY_PAIR, s_pairing_psk,
                       sizeof(s_pairing_psk));
    if (err == ESP_OK) {
      err = nvs_commit(nvs);
    }
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "pairing PSK not persisted: %s", esp_err_to_name(err));
    }
    ESP_LOGI(TAG, "generated a new pairing PSK");
  }

  /* The static PIN has to survive reboots: it is printed on the device's own
   * page and an operator may be part way through typing it. */
  len = sizeof(s_static_pin);
  err = nvs_get_str(nvs, PSK_NVS_KEY_PIN, s_static_pin, &len);
  if (err != ESP_OK || strlen(s_static_pin) != SENDSPIN_PSK_PIN_LEN) {
    psk_generate_pin();
    err = nvs_set_str(nvs, PSK_NVS_KEY_PIN, s_static_pin);
    if (err == ESP_OK) {
      err = nvs_commit(nvs);
    }
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "static PIN not persisted: %s", esp_err_to_name(err));
    }
  }

  len = sizeof(s_records);
  err = nvs_get_blob(nvs, PSK_NVS_KEY_RECS, s_records, &len);
  if (err == ESP_OK && len % sizeof(psk_record_t) == 0) {
    s_record_count = len / sizeof(psk_record_t);
  } else {
    s_record_count = 0;
  }
  nvs_close(nvs);

  sendspin_noise_psk_id(s_pairing_psk, s_pairing_psk_id);
  psk_index_records();
  psk_build_token(client_pub);

  ESP_LOGI(TAG, "paired with %u server%s", (unsigned)s_record_count,
           s_record_count == 1 ? "" : "s");
  return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Lookup                                                             */
/* ------------------------------------------------------------------ */

const uint8_t *sendspin_psk_lookup(const char *psk_id,
                                   sendspin_psk_kind_t *kind_out) {
  if (!psk_id) {
    return NULL;
  }

  /* sodium_memcmp rather than strcmp: the comparison is against a secret's
   * identifier, and an attacker gets to choose what it is compared with. */
  if (strlen(psk_id) == SENDSPIN_PSK_ID_LEN) {
    for (size_t i = 0; i < s_record_count; i++) {
      if (sodium_memcmp(psk_id, s_record_ids[i], SENDSPIN_PSK_ID_LEN) == 0) {
        if (kind_out) {
          *kind_out = SENDSPIN_PSK_LONG_TERM;
        }
        return s_records[i].psk;
      }
    }
    if (sodium_memcmp(psk_id, s_pairing_psk_id, SENDSPIN_PSK_ID_LEN) == 0) {
      if (kind_out) {
        *kind_out = SENDSPIN_PSK_PAIRING;
      }
      return s_pairing_psk;
    }
  }

  if (strcmp(psk_id, sendspin_noise_sentinel_psk_id()) == 0) {
    if (kind_out) {
      *kind_out = SENDSPIN_PSK_SENTINEL;
    }
    return sendspin_noise_sentinel_psk();
  }
  return NULL;
}

void sendspin_psk_generate(uint8_t psk[SENDSPIN_PSK_LEN]) {
  randombytes_buf(psk, SENDSPIN_PSK_LEN);
}

esp_err_t sendspin_psk_add_record(const char *server_id,
                                  const uint8_t psk[SENDSPIN_PSK_LEN]) {
  if (!server_id || !psk) {
    return ESP_ERR_INVALID_ARG;
  }

  size_t slot = s_record_count;
  for (size_t i = 0; i < s_record_count; i++) {
    if (strcmp(s_records[i].server_id, server_id) == 0) {
      slot = i;
      break;
    }
  }

  if (slot == s_record_count) {
    if (s_record_count == SENDSPIN_PSK_MAX_RECORDS) {
      memmove(&s_records[0], &s_records[1],
              (SENDSPIN_PSK_MAX_RECORDS - 1) * sizeof(psk_record_t));
      slot = SENDSPIN_PSK_MAX_RECORDS - 1;
    } else {
      s_record_count++;
    }
  }

  snprintf(s_records[slot].server_id, sizeof(s_records[slot].server_id), "%s",
           server_id);
  memcpy(s_records[slot].psk, psk, SENDSPIN_PSK_LEN);
  psk_index_records();

  const esp_err_t err = psk_save_records();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "pairing record not persisted: %s", esp_err_to_name(err));
  }
  return err;
}

size_t sendspin_psk_record_count(void) {
  return s_record_count;
}

esp_err_t sendspin_psk_forget_all(void) {
  sodium_memzero(s_records, sizeof(s_records));
  s_record_count = 0;
  return psk_save_records();
}
