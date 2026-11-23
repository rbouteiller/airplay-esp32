// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdio.h>
#include <string.h>

#include "hap.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sodium.h"

#include "hap_pairings.h"
#include "srp.h"

static const char *TAG = "hap";

#define NVS_NAMESPACE  "airplay"
#define NVS_KEY_PUBLIC "ed25519_pub"
#define NVS_KEY_SECRET "ed25519_sec"

static uint8_t g_device_public_key[HAP_ED25519_PUBLIC_KEY_SIZE];
static uint8_t g_device_secret_key[HAP_ED25519_SECRET_KEY_SIZE];
static bool g_initialized = false;
static char g_device_id[18];
static char g_pi[37];
static char g_psi[37];

// A UUID (RFC 4122 variant, version 4 layout) from SHA-512(label || pk), so it
// is stable for as long as the long-term key is and changes with it: a new
// key is a new accessory as far as a controller is concerned.
static void derive_uuid(const char *label, char out[37]) {
  crypto_hash_sha512_state state;
  uint8_t hash[crypto_hash_sha512_BYTES];
  crypto_hash_sha512_init(&state);
  crypto_hash_sha512_update(&state, (const uint8_t *)label, strlen(label));
  crypto_hash_sha512_update(&state, g_device_public_key,
                            sizeof(g_device_public_key));
  crypto_hash_sha512_final(&state, hash);

  hash[6] = (hash[6] & 0x0F) | 0x40;
  hash[8] = (hash[8] & 0x3F) | 0x80;
  snprintf(out, 37,
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
           "%02x%02x%02x%02x%02x%02x",
           hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6],
           hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
           hash[14], hash[15]);
}

esp_err_t hap_init(void) {
  if (g_initialized) {
    return ESP_OK;
  }

  if (sodium_init() < 0) {
    ESP_LOGE(TAG, "Failed to initialize libsodium");
    return ESP_FAIL;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS: %s", esp_err_to_name(err));
    return err;
  }

  size_t pub_len = HAP_ED25519_PUBLIC_KEY_SIZE;
  size_t sec_len = HAP_ED25519_SECRET_KEY_SIZE;

  err = nvs_get_blob(nvs, NVS_KEY_PUBLIC, g_device_public_key, &pub_len);
  if (err == ESP_OK) {
    err = nvs_get_blob(nvs, NVS_KEY_SECRET, g_device_secret_key, &sec_len);
  }

  if (err != ESP_OK || pub_len != HAP_ED25519_PUBLIC_KEY_SIZE ||
      sec_len != HAP_ED25519_SECRET_KEY_SIZE) {
    crypto_sign_keypair(g_device_public_key, g_device_secret_key);

    err = nvs_set_blob(nvs, NVS_KEY_PUBLIC, g_device_public_key,
                       HAP_ED25519_PUBLIC_KEY_SIZE);
    if (err == ESP_OK) {
      err = nvs_set_blob(nvs, NVS_KEY_SECRET, g_device_secret_key,
                         HAP_ED25519_SECRET_KEY_SIZE);
    }
    if (err == ESP_OK) {
      err = nvs_commit(nvs);
    }
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to store keypair in NVS: %s", esp_err_to_name(err));
      nvs_close(nvs);
      return err;
    }
  }

  nvs_close(nvs);

  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  snprintf(g_device_id, sizeof(g_device_id), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  derive_uuid("AirPlay-pi", g_pi);
  derive_uuid("AirPlay-psi", g_psi);

  err = hap_pairings_init();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to load HomeKit pairings: %s", esp_err_to_name(err));
    return err;
  }

  g_initialized = true;
  return ESP_OK;
}

const uint8_t *hap_get_public_key(void) {
  return g_device_public_key;
}

const char *hap_get_device_id(void) {
  return g_device_id;
}

const char *hap_get_pi(void) {
  return g_pi;
}

const char *hap_get_psi(void) {
  return g_psi;
}

hap_session_t *hap_session_create(void) {
  hap_session_t *session = calloc(1, sizeof(hap_session_t));
  if (!session) {
    return NULL;
  }

  memcpy(session->device_public_key, g_device_public_key,
         HAP_ED25519_PUBLIC_KEY_SIZE);
  memcpy(session->device_secret_key, g_device_secret_key,
         HAP_ED25519_SECRET_KEY_SIZE);

  crypto_box_keypair(session->session_public_key, session->session_secret_key);

  session->pair_verify_state = 0;
  session->session_established = false;
  session->pair_setup_transient = false;
  session->encrypt_nonce = 0;
  session->decrypt_nonce = 0;

  return session;
}

void hap_session_free(hap_session_t *session) {
  if (!session) {
    return;
  }

  if (session->srp) {
    srp_session_free(session->srp);
    session->srp = NULL;
  }

  sodium_memzero(session->device_secret_key,
                 sizeof(session->device_secret_key));
  sodium_memzero(session->session_secret_key,
                 sizeof(session->session_secret_key));
  sodium_memzero(session->shared_secret, sizeof(session->shared_secret));
  sodium_memzero(session->encrypt_key, sizeof(session->encrypt_key));
  sodium_memzero(session->decrypt_key, sizeof(session->decrypt_key));
  free(session);
}
