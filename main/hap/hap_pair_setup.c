// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <string.h>

#include "hap.h"
#include "hap_internal.h"
#include "hap_pairings.h"
#include "srp.h"
#include "tlv8.h"

#include "esp_log.h"
#include "sodium.h"

static const char *TAG = "hap_setup";

#define PAIR_SETUP_M1 1
#define PAIR_SETUP_M2 2
#define PAIR_SETUP_M3 3
#define PAIR_SETUP_M4 4
#define PAIR_SETUP_M5 5
#define PAIR_SETUP_M6 6

// Large enough for the M5/M6 sub-TLV: identifier, 32-byte key, 64-byte
// signature, their headers and the 16-byte tag.
#define SETUP_EXCHANGE_MAX 256

static esp_err_t error_response(uint8_t state, uint8_t error, uint8_t *output,
                                size_t output_capacity, size_t *output_len) {
  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, output, output_capacity);
  if (!tlv8_encode_byte(&enc, TLV_TYPE_STATE, state) ||
      !tlv8_encode_byte(&enc, TLV_TYPE_ERROR, error)) {
    return ESP_ERR_NO_MEM;
  }
  *output_len = tlv8_encoder_size(&enc);
  return ESP_OK;
}

esp_err_t hap_pair_setup_m1(hap_session_t *session, const uint8_t *input,
                            size_t input_len, uint8_t *output,
                            size_t output_capacity, size_t *output_len) {
  size_t state_len = 0;
  size_t flags_len = 0;
  const uint8_t *state =
      tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);
  const uint8_t *flags =
      tlv8_find(input, input_len, TLV_TYPE_FLAGS, &flags_len);

  if (!state || state_len != 1 || state[0] != PAIR_SETUP_M1) {
    ESP_LOGE(TAG, "Invalid pair-setup M1 state");
    return ESP_ERR_INVALID_ARG;
  }

  // kTLVType_Flags is a little-endian integer; transient is bit 4.
  bool transient = false;
  if (flags && flags_len >= 1) {
    transient = (flags[0] & TLV_FLAG_TRANSIENT) != 0;
  }
  session->pair_setup_transient = transient;
  session->pair_setup_state = 0;
  session->setup_code_proven = false;
  session->pairings_claimed = false;

  if (session->srp) {
    srp_session_free(session->srp);
  }
  session->srp = srp_session_create();
  if (!session->srp) {
    ESP_LOGE(TAG, "Failed to create SRP session");
    return ESP_ERR_NO_MEM;
  }

  // An already-paired accessory should strictly answer Unavailable here
  // (HAP 5.6.2). It does not: an AirPlay speaker removed from a home while it
  // was offline still holds that home's pairings, and refusing would leave it
  // impossible to add back without a reset. Every pair-setup that completes
  // adds its controller as one more admin; with the store full, it starts a
  // new pairing set instead (hap_pairings_claim()).
  if (!transient) {
    ESP_LOGI(TAG, "Non-transient pair-setup (HomeKit), %u controller(s) paired",
             (unsigned)hap_pairings_count());
  }

  esp_err_t err = srp_start(session->srp, "Pair-Setup", HAP_SETUP_CODE);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start SRP: %d", err);
    return err;
  }

  size_t pk_len = 0;
  const uint8_t *salt = srp_get_salt(session->srp);
  const uint8_t *pk = srp_get_public_key(session->srp, &pk_len);

  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, output, output_capacity);
  if (!tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M2) ||
      !tlv8_encode(&enc, TLV_TYPE_SALT, salt, SRP_SALT_BYTES) ||
      !tlv8_encode(&enc, TLV_TYPE_PUBLIC_KEY, pk, pk_len)) {
    return ESP_ERR_NO_MEM;
  }

  *output_len = tlv8_encoder_size(&enc);
  session->pair_setup_state = PAIR_SETUP_M2;
  return ESP_OK;
}

esp_err_t hap_pair_setup_m3(hap_session_t *session, const uint8_t *input,
                            size_t input_len, uint8_t *output,
                            size_t output_capacity, size_t *output_len) {
  if (!session->srp || session->pair_setup_state != PAIR_SETUP_M2) {
    ESP_LOGE(TAG, "Pair-setup M3 out of sequence");
    return ESP_ERR_INVALID_STATE;
  }

  size_t state_len = 0;
  size_t pk_len = 0;
  size_t proof_len = 0;
  const uint8_t *state =
      tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);

  if (!state || state_len != 1 || state[0] != PAIR_SETUP_M3) {
    ESP_LOGE(TAG, "Invalid pair-setup M3 state");
    return ESP_ERR_INVALID_ARG;
  }

  uint8_t client_pk[512];
  if (!tlv8_decode_concat(input, input_len, TLV_TYPE_PUBLIC_KEY, client_pk,
                          sizeof(client_pk), &pk_len)) {
    ESP_LOGE(TAG, "Missing client public key in M3");
    return ESP_ERR_INVALID_ARG;
  }

  uint8_t client_proof[64];
  if (!tlv8_decode_concat(input, input_len, TLV_TYPE_PROOF, client_proof,
                          sizeof(client_proof), &proof_len)) {
    ESP_LOGE(TAG, "Missing client proof in M3");
    return ESP_ERR_INVALID_ARG;
  }

  esp_err_t err = srp_verify_client(session->srp, client_pk, pk_len,
                                    client_proof, proof_len);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Client verification failed (wrong setup code?)");
    session->pair_setup_state = 0;
    return error_response(PAIR_SETUP_M4, TLV_ERROR_AUTHENTICATION, output,
                          output_capacity, output_len);
  }

  if (session->pair_setup_transient) {
    size_t srp_key_len = 0;
    const uint8_t *srp_key = srp_get_session_key(session->srp, &srp_key_len);
    if (!srp_key || srp_key_len == 0) {
      ESP_LOGE(TAG, "Missing SRP session key for transient pairing");
      return ESP_ERR_INVALID_STATE;
    }

    memcpy(session->shared_secret, srp_key, 32);
    hap_hkdf_sha512((uint8_t *)"Control-Salt", 12, srp_key, srp_key_len,
                    (uint8_t *)"Control-Read-Encryption-Key", 27,
                    session->encrypt_key, 32);
    hap_hkdf_sha512((uint8_t *)"Control-Salt", 12, srp_key, srp_key_len,
                    (uint8_t *)"Control-Write-Encryption-Key", 28,
                    session->decrypt_key, 32);
    session->encrypt_nonce = 0;
    session->decrypt_nonce = 0;
    hap_derive_event_keys(session, srp_key, srp_key_len);
    session->session_established = true;
    session->setup_code_proven = true;
    session->pairings_claimed = false;
  }

  const uint8_t *server_proof = srp_get_proof(session->srp);

  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, output, output_capacity);
  if (!tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M4) ||
      !tlv8_encode(&enc, TLV_TYPE_PROOF, server_proof, SRP_PROOF_BYTES)) {
    return ESP_ERR_NO_MEM;
  }

  *output_len = tlv8_encoder_size(&enc);
  session->pair_setup_state = PAIR_SETUP_M4;

  return ESP_OK;
}

/* HAP 5.6.6: M5 carries the controller's pairing identifier, long-term key
 * and a signature over (ControllerX || identifier || key), encrypted under a
 * key derived from the SRP secret. The accessory checks the signature, stores
 * the controller as an admin, and answers M6 with its own identifier, key and
 * signature over (AccessoryX || identifier || key) the same way. */
esp_err_t hap_pair_setup_m5(hap_session_t *session, const uint8_t *input,
                            size_t input_len, uint8_t *output,
                            size_t output_capacity, size_t *output_len) {
  if (!session->srp || session->pair_setup_state != PAIR_SETUP_M4 ||
      session->pair_setup_transient) {
    ESP_LOGE(TAG, "Pair-setup M5 out of sequence");
    return ESP_ERR_INVALID_STATE;
  }

  size_t state_len = 0;
  const uint8_t *state =
      tlv8_find(input, input_len, TLV_TYPE_STATE, &state_len);
  if (!state || state_len != 1 || state[0] != PAIR_SETUP_M5) {
    ESP_LOGE(TAG, "Invalid pair-setup M5 state");
    return ESP_ERR_INVALID_ARG;
  }
  // Whatever happens next, this exchange is over.
  session->pair_setup_state = 0;

  uint8_t encrypted[SETUP_EXCHANGE_MAX];
  size_t encrypted_len = 0;
  if (!tlv8_decode_concat(input, input_len, TLV_TYPE_ENCRYPTED_DATA, encrypted,
                          sizeof(encrypted), &encrypted_len) ||
      encrypted_len < crypto_aead_chacha20poly1305_ietf_ABYTES) {
    ESP_LOGE(TAG, "Missing encrypted data in M5");
    return error_response(PAIR_SETUP_M6, TLV_ERROR_AUTHENTICATION, output,
                          output_capacity, output_len);
  }

  size_t srp_key_len = 0;
  const uint8_t *srp_key = srp_get_session_key(session->srp, &srp_key_len);
  if (!srp_key || srp_key_len == 0) {
    ESP_LOGE(TAG, "Missing SRP session key");
    return ESP_ERR_INVALID_STATE;
  }

  uint8_t setup_key[32];
  hap_hkdf_sha512((const uint8_t *)"Pair-Setup-Encrypt-Salt", 23, srp_key,
                  srp_key_len, (const uint8_t *)"Pair-Setup-Encrypt-Info", 23,
                  setup_key, sizeof(setup_key));

  uint8_t nonce5[12] = {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '5'};
  uint8_t decrypted[SETUP_EXCHANGE_MAX];
  unsigned long long decrypted_len = 0;

  if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL,
                                                encrypted, encrypted_len, NULL,
                                                0, nonce5, setup_key) != 0) {
    ESP_LOGE(TAG, "M5 decryption failed");
    sodium_memzero(setup_key, sizeof(setup_key));
    return error_response(PAIR_SETUP_M6, TLV_ERROR_AUTHENTICATION, output,
                          output_capacity, output_len);
  }

  size_t id_len = 0;
  size_t ltpk_len = 0;
  size_t sig_len = 0;
  const uint8_t *controller_id =
      tlv8_find(decrypted, (size_t)decrypted_len, TLV_TYPE_IDENTIFIER, &id_len);
  const uint8_t *controller_ltpk = tlv8_find(decrypted, (size_t)decrypted_len,
                                             TLV_TYPE_PUBLIC_KEY, &ltpk_len);
  const uint8_t *controller_sig =
      tlv8_find(decrypted, (size_t)decrypted_len, TLV_TYPE_SIGNATURE, &sig_len);
  if (!controller_id || id_len == 0 || id_len >= HAP_PAIRING_ID_MAX ||
      !controller_ltpk || ltpk_len != crypto_sign_PUBLICKEYBYTES ||
      !controller_sig || sig_len != crypto_sign_BYTES) {
    ESP_LOGE(TAG, "M5 sub-TLV is missing identifier, key or signature");
    sodium_memzero(setup_key, sizeof(setup_key));
    return error_response(PAIR_SETUP_M6, TLV_ERROR_AUTHENTICATION, output,
                          output_capacity, output_len);
  }

  // ControllerInfo = ControllerX || ControllerPairingID || ControllerLTPK
  uint8_t info[32 + HAP_PAIRING_ID_MAX + crypto_sign_PUBLICKEYBYTES];
  hap_hkdf_sha512((const uint8_t *)"Pair-Setup-Controller-Sign-Salt", 31,
                  srp_key, srp_key_len,
                  (const uint8_t *)"Pair-Setup-Controller-Sign-Info", 31, info,
                  32);
  memcpy(info + 32, controller_id, id_len);
  memcpy(info + 32 + id_len, controller_ltpk, crypto_sign_PUBLICKEYBYTES);
  size_t info_len = 32 + id_len + crypto_sign_PUBLICKEYBYTES;

  if (crypto_sign_verify_detached(controller_sig, info, info_len,
                                  controller_ltpk) != 0) {
    ESP_LOGE(TAG, "M5 controller signature does not verify");
    sodium_memzero(setup_key, sizeof(setup_key));
    return error_response(PAIR_SETUP_M6, TLV_ERROR_AUTHENTICATION, output,
                          output_capacity, output_len);
  }

  // put, not add: a controller that was reset comes back under the same
  // identifier with a new key, and it has just proved the setup code. Replaced
  // in place, so the accessory never passes through "no admin" (which would
  // unpair it) on the way.
  esp_err_t err =
      hap_pairings_put(controller_id, id_len, controller_ltpk, HAP_PERM_ADMIN);
  if (err == ESP_ERR_NO_MEM) {
    // Full, most likely with homes the speaker was removed from while it was
    // offline. It has just proved the setup code: start over with it.
    err = hap_pairings_claim(controller_id, id_len, controller_ltpk,
                             HAP_PERM_ADMIN, false);
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to store controller pairing: %s",
             esp_err_to_name(err));
    sodium_memzero(setup_key, sizeof(setup_key));
    return error_response(PAIR_SETUP_M6,
                          err == ESP_ERR_NO_MEM ? TLV_ERROR_MAX_PEERS
                                                : TLV_ERROR_UNKNOWN,
                          output, output_capacity, output_len);
  }

  // AccessoryInfo = AccessoryX || AccessoryPairingID || AccessoryLTPK
  // Signed and sent as bytes, without a terminator.
  const size_t accessory_id_len = strlen(hap_get_device_id());
  const uint8_t *accessory_id = (const uint8_t *)hap_get_device_id();
  hap_hkdf_sha512((const uint8_t *)"Pair-Setup-Accessory-Sign-Salt", 30,
                  srp_key, srp_key_len,
                  (const uint8_t *)"Pair-Setup-Accessory-Sign-Info", 30, info,
                  32);
  memcpy(info + 32, accessory_id, accessory_id_len);
  memcpy(info + 32 + accessory_id_len, session->device_public_key,
         HAP_ED25519_PUBLIC_KEY_SIZE);
  info_len = 32 + accessory_id_len + HAP_ED25519_PUBLIC_KEY_SIZE;

  uint8_t signature[crypto_sign_BYTES];
  crypto_sign_detached(signature, NULL, info, info_len,
                       session->device_secret_key);

  uint8_t sub_tlv[SETUP_EXCHANGE_MAX];
  tlv8_encoder_t sub;
  tlv8_encoder_init(&sub, sub_tlv, sizeof(sub_tlv));
  if (!tlv8_encode(&sub, TLV_TYPE_IDENTIFIER, accessory_id, accessory_id_len) ||
      !tlv8_encode(&sub, TLV_TYPE_PUBLIC_KEY, session->device_public_key,
                   HAP_ED25519_PUBLIC_KEY_SIZE) ||
      !tlv8_encode(&sub, TLV_TYPE_SIGNATURE, signature, sizeof(signature))) {
    sodium_memzero(setup_key, sizeof(setup_key));
    return ESP_ERR_NO_MEM;
  }

  uint8_t nonce6[12] = {0, 0, 0, 0, 'P', 'S', '-', 'M', 's', 'g', '0', '6'};
  unsigned long long sealed_len = 0;
  crypto_aead_chacha20poly1305_ietf_encrypt(encrypted, &sealed_len, sub_tlv,
                                            tlv8_encoder_size(&sub), NULL, 0,
                                            NULL, nonce6, setup_key);
  sodium_memzero(setup_key, sizeof(setup_key));

  tlv8_encoder_t enc;
  tlv8_encoder_init(&enc, output, output_capacity);
  if (!tlv8_encode_byte(&enc, TLV_TYPE_STATE, PAIR_SETUP_M6) ||
      !tlv8_encode(&enc, TLV_TYPE_ENCRYPTED_DATA, encrypted,
                   (size_t)sealed_len)) {
    return ESP_ERR_NO_MEM;
  }
  *output_len = tlv8_encoder_size(&enc);
  session->pair_setup_state = PAIR_SETUP_M6;

  ESP_LOGI(TAG, "HomeKit pair-setup complete for controller %.*s", (int)id_len,
           (const char *)controller_id);

  session->encrypt_nonce = 0;
  session->decrypt_nonce = 0;
  return ESP_OK;
}
