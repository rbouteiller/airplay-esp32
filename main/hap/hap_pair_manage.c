// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* POST /pair-add, /pair-remove and /pair-list (HAP 5.10-5.12).
 *
 * The Home app adds the speaker by encrypting the connection with a transient
 * pair-setup and then sending /pair-add for the home's controllers; home hubs
 * later manage them over pair-verified sessions. Each request is a single
 * M1 -> M2 exchange; the response is State M2, plus an Error on refusal. */

#include <stdlib.h>
#include <string.h>

#include "hap.h"
#include "hap_pairings.h"
#include "tlv8.h"

#include "esp_log.h"

static const char *TAG = "hap_manage";

#define PAIR_MANAGE_M1 1
#define PAIR_MANAGE_M2 2

_Static_assert(HAP_CONTROLLER_ID_MAX == HAP_PAIRING_ID_MAX,
               "session and store identifiers must have the same limit");

static esp_err_t respond(uint8_t error, uint8_t *output, size_t output_capacity,
                         size_t *output_len) {
  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, output, output_capacity);
  if (!tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_MANAGE_M2)) {
    return ESP_ERR_NO_MEM;
  }
  if (error && !tlv8_encode_byte(&enc, TLV_TYPE_ERROR, error)) {
    return ESP_ERR_NO_MEM;
  }
  *output_len = tlv8_encoder_size(&enc);
  return ESP_OK;
}

static bool request_is(const uint8_t *input, size_t input_len, uint8_t method) {
  size_t len = 0;
  const uint8_t *state = tlv8_find(input, input_len, TLV_TYPE_STATE, &len);
  if (!state || len != 1 || state[0] != PAIR_MANAGE_M1) {
    return false;
  }
  const uint8_t *m = tlv8_find(input, input_len, TLV_TYPE_METHOD, &len);
  return m && len == 1 && m[0] == method;
}

/* Only an admin may manage pairings (HAP 5.10.2 step 2). Admin here means one
 * of:
 *  - a stored admin controller that pair-verified on this session;
 *  - a peer that proved the setup code in a transient pair-setup, which is
 *    what a full pair-setup demands of a new admin and is the session the
 *    Home app sends /pair-add on (shairport-sync accepts any session);
 *  - anyone, while the accessory has no admin at all.
 * A pair-verified controller that is unknown, or only a user, is refused. */
static bool session_is_admin(const hap_session_t *session) {
  if (hap_pairings_admin_count() == 0 || session->setup_code_proven) {
    return true;
  }
  if (!session->controller_verified) {
    return false;
  }
  uint8_t perms = 0;
  return hap_pairings_find(session->controller_id, session->controller_id_len,
                           NULL, &perms) &&
         (perms & HAP_PERM_ADMIN);
}

static void log_refusal(const char *what, const hap_session_t *session) {
  if (session->controller_id_len > 0) {
    ESP_LOGW(TAG, "%s refused: controller %.*s is not a verified admin", what,
             (int)session->controller_id_len,
             (const char *)session->controller_id);
  } else {
    ESP_LOGW(TAG,
             "%s refused: session neither verified an admin nor proved "
             "the setup code",
             what);
  }
}

esp_err_t hap_pair_add(hap_session_t *session, const uint8_t *input,
                       size_t input_len, uint8_t *output,
                       size_t output_capacity, size_t *output_len) {
  if (!session || !input || !output || !output_len) {
    return ESP_ERR_INVALID_ARG;
  }
  if (!request_is(input, input_len, TLV_METHOD_ADD_PAIRING)) {
    ESP_LOGW(TAG, "Malformed pair-add request");
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }
  if (!session_is_admin(session)) {
    log_refusal("pair-add", session);
    return respond(TLV_ERROR_AUTHENTICATION, output, output_capacity,
                   output_len);
  }

  size_t id_len = 0;
  size_t pk_len = 0;
  size_t perm_len = 0;
  const uint8_t *id = tlv8_find(input, input_len, TLV_TYPE_IDENTIFIER, &id_len);
  const uint8_t *pk = tlv8_find(input, input_len, TLV_TYPE_PUBLIC_KEY, &pk_len);
  const uint8_t *perm =
      tlv8_find(input, input_len, TLV_TYPE_PERMISSIONS, &perm_len);
  if (!id || id_len == 0 || id_len >= HAP_PAIRING_ID_MAX || !pk ||
      pk_len != 32 || !perm || perm_len != 1) {
    ESP_LOGW(TAG, "pair-add is missing identifier, key or permissions");
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }

  // The permissions are the *new* controller's: a home hub adds members with
  // 0 (user). Only the sender has to be an admin.
  const uint8_t perms = perm[0] & HAP_PERM_ADMIN;
  esp_err_t err;
  if (session->setup_code_proven) {
    // The Home app adding the speaker to a home. Whatever is stored belongs
    // to a home it was removed from while offline (left as it is, that home
    // would keep admin rights and its slots), unless this setup claimed it a
    // moment ago. Having proved the setup code, as a pair-setup does, a
    // controller that was reset may come back with a new key.
    err = hap_pairings_claim(id, id_len, pk, perms, session->pairings_claimed);
    if (err == ESP_OK) {
      session->pairings_claimed = true;
    }
  } else {
    err = hap_pairings_add(id, id_len, pk, perms);
  }
  switch (err) {
  case ESP_OK:
    return respond(0, output, output_capacity, output_len);
  case ESP_ERR_INVALID_STATE:
    ESP_LOGW(TAG, "pair-add: %.*s is already paired with another key",
             (int)id_len, (const char *)id);
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  case ESP_ERR_NO_MEM:
    ESP_LOGW(TAG, "pair-add: no room for %.*s", (int)id_len, (const char *)id);
    return respond(TLV_ERROR_MAX_PEERS, output, output_capacity, output_len);
  default:
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }
}

esp_err_t hap_pair_remove(hap_session_t *session, const uint8_t *input,
                          size_t input_len, uint8_t *output,
                          size_t output_capacity, size_t *output_len) {
  if (!session || !input || !output || !output_len) {
    return ESP_ERR_INVALID_ARG;
  }
  if (!request_is(input, input_len, TLV_METHOD_REMOVE_PAIRING)) {
    ESP_LOGW(TAG, "Malformed pair-remove request");
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }
  if (!session_is_admin(session)) {
    log_refusal("pair-remove", session);
    return respond(TLV_ERROR_AUTHENTICATION, output, output_capacity,
                   output_len);
  }

  size_t id_len = 0;
  const uint8_t *id = tlv8_find(input, input_len, TLV_TYPE_IDENTIFIER, &id_len);
  if (!id || id_len == 0 || id_len >= HAP_PAIRING_ID_MAX) {
    ESP_LOGW(TAG, "pair-remove is missing the identifier");
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }

  // Removing a pairing that does not exist succeeds (HAP 5.11.2 step 3).
  esp_err_t err = hap_pairings_remove(id, id_len);
  if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }

  // A session must not keep rights its controller no longer has.
  if (session->controller_id_len == id_len &&
      memcmp(session->controller_id, id, id_len) == 0) {
    session->controller_verified = false;
  }
  return respond(0, output, output_capacity, output_len);
}

esp_err_t hap_pair_list(hap_session_t *session, const uint8_t *input,
                        size_t input_len, uint8_t *output,
                        size_t output_capacity, size_t *output_len) {
  if (!session || !input || !output || !output_len) {
    return ESP_ERR_INVALID_ARG;
  }
  if (!request_is(input, input_len, TLV_METHOD_LIST_PAIRINGS)) {
    ESP_LOGW(TAG, "Malformed pair-list request");
    return respond(TLV_ERROR_UNKNOWN, output, output_capacity, output_len);
  }
  if (!session_is_admin(session)) {
    log_refusal("pair-list", session);
    return respond(TLV_ERROR_AUTHENTICATION, output, output_capacity,
                   output_len);
  }

  hap_pairing_t *pairings = calloc(HAP_PAIRINGS_MAX, sizeof(*pairings));
  if (!pairings) {
    return ESP_ERR_NO_MEM;
  }
  size_t n = hap_pairings_snapshot(pairings, HAP_PAIRINGS_MAX);

  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, output, output_capacity);
  bool ok = tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_MANAGE_M2);
  for (size_t i = 0; ok && i < n; i++) {
    if (i > 0) {
      ok = tlv8_encode(&enc, TLV_TYPE_SEPARATOR, NULL, 0);
    }
    ok = ok &&
         tlv8_encode(&enc, TLV_TYPE_IDENTIFIER, (const uint8_t *)pairings[i].id,
                     pairings[i].id_len) &&
         tlv8_encode(&enc, TLV_TYPE_PUBLIC_KEY, pairings[i].ltpk,
                     sizeof(pairings[i].ltpk)) &&
         tlv8_encode_byte(&enc, TLV_TYPE_PERMISSIONS, pairings[i].perms);
  }
  free(pairings);

  if (!ok) {
    return ESP_ERR_NO_MEM;
  }
  *output_len = tlv8_encoder_size(&enc);
  return ESP_OK;
}
