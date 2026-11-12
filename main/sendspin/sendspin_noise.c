// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "sendspin_noise.h"

#include <string.h>

#include "esp_log.h"
#include "sodium.h"

static const char *TAG = "sendspin-noise";

#define NOISE_PROTOCOL_NAME "Noise_KKpsk2_25519_ChaChaPoly_SHA256"

/* Both are the UTF-8 bytes of the literal label, with no separator and no NUL
 * terminator, exactly as the specification writes them. */
#define SENTINEL_PSK_LABEL "sendspin-sentinel-psk-v1"
#define PSK_ID_LABEL       "sendspin-psk-id-v1"

static uint8_t s_sentinel_psk[SENDSPIN_NOISE_KEY_LEN];
static char s_sentinel_psk_id[SENDSPIN_NOISE_PSK_ID_LEN + 1];
static bool s_constants_ready = false;

/* ------------------------------------------------------------------ */
/*  Primitives                                                         */
/* ------------------------------------------------------------------ */

static void noise_hmac(const uint8_t key[32], const uint8_t *data, size_t len,
                       uint8_t out[32]) {
  crypto_auth_hmacsha256_state st;
  crypto_auth_hmacsha256_init(&st, key, SENDSPIN_NOISE_KEY_LEN);
  crypto_auth_hmacsha256_update(&st, data, len);
  crypto_auth_hmacsha256_final(&st, out);
}

/* HKDF as Noise defines it: three chained HMACs, each feeding the next. Any
 * of the outputs may be NULL if the caller wants fewer than three. */
static void noise_hkdf(const uint8_t ck[32], const uint8_t *ikm, size_t ikm_len,
                       uint8_t *out1, uint8_t *out2, uint8_t *out3) {
  static const uint8_t empty[1] = {0};
  uint8_t temp_key[32];
  uint8_t buf[33];
  uint8_t o1[32];
  uint8_t o2[32];

  noise_hmac(ck, ikm ? ikm : empty, ikm_len, temp_key);

  buf[0] = 1;
  noise_hmac(temp_key, buf, 1, o1);
  if (out1) {
    memcpy(out1, o1, 32);
  }

  if (out2 || out3) {
    memcpy(buf, o1, 32);
    buf[32] = 2;
    noise_hmac(temp_key, buf, 33, o2);
    if (out2) {
      memcpy(out2, o2, 32);
    }
  }

  if (out3) {
    memcpy(buf, o2, 32);
    buf[32] = 3;
    noise_hmac(temp_key, buf, 33, out3);
  }

  sodium_memzero(temp_key, sizeof(temp_key));
  sodium_memzero(buf, sizeof(buf));
  sodium_memzero(o1, sizeof(o1));
  sodium_memzero(o2, sizeof(o2));
}

/* Noise's ChaChaPoly nonce: 32 bits of zeros, then n little-endian. */
static void noise_nonce(uint64_t n, uint8_t out[12]) {
  memset(out, 0, 4);
  for (int i = 0; i < 8; i++) {
    out[4 + i] = (uint8_t)(n >> (8 * i));
  }
}

static void noise_cipher_init(sendspin_noise_cipher_t *c,
                              const uint8_t key[32]) {
  if (key) {
    memcpy(c->k, key, SENDSPIN_NOISE_KEY_LEN);
    c->has_key = true;
  } else {
    sodium_memzero(c->k, sizeof(c->k));
    c->has_key = false;
  }
  c->n = 0;
}

/* Every payload in KKpsk2 is preceded by at least one MixKey, so a keyless
 * CipherState here means the caller lost track of the handshake rather than
 * that a cleartext payload is due. */
static esp_err_t noise_cipher_encrypt(sendspin_noise_cipher_t *c,
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *plain, size_t len,
                                      uint8_t *out, size_t *out_len) {
  if (!c->has_key) {
    return ESP_ERR_INVALID_STATE;
  }
  uint8_t nonce[12];
  noise_nonce(c->n, nonce);
  unsigned long long clen = 0;
  if (crypto_aead_chacha20poly1305_ietf_encrypt(
          out, &clen, plain, len, ad, ad_len, NULL, nonce, c->k) != 0) {
    return ESP_FAIL;
  }
  c->n++;
  *out_len = (size_t)clen;
  return ESP_OK;
}

static esp_err_t noise_cipher_decrypt(sendspin_noise_cipher_t *c,
                                      const uint8_t *ad, size_t ad_len,
                                      const uint8_t *cipher, size_t len,
                                      uint8_t *out, size_t *out_len) {
  if (!c->has_key) {
    return ESP_ERR_INVALID_STATE;
  }
  if (len < SENDSPIN_NOISE_TAG_LEN) {
    return ESP_ERR_INVALID_SIZE;
  }
  uint8_t nonce[12];
  noise_nonce(c->n, nonce);
  unsigned long long mlen = 0;
  if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &mlen, NULL, cipher, len,
                                                ad, ad_len, nonce, c->k) != 0) {
    return ESP_FAIL;
  }
  c->n++;
  *out_len = (size_t)mlen;
  return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  SymmetricState                                                     */
/* ------------------------------------------------------------------ */

static void noise_mix_hash(sendspin_noise_t *ns, const uint8_t *data,
                           size_t len) {
  crypto_hash_sha256_state st;
  crypto_hash_sha256_init(&st);
  crypto_hash_sha256_update(&st, ns->h, sizeof(ns->h));
  crypto_hash_sha256_update(&st, data, len);
  crypto_hash_sha256_final(&st, ns->h);
}

static void noise_mix_key(sendspin_noise_t *ns, const uint8_t *ikm,
                          size_t ikm_len) {
  uint8_t temp_k[32];
  noise_hkdf(ns->ck, ikm, ikm_len, ns->ck, temp_k, NULL);
  noise_cipher_init(&ns->handshake_cipher, temp_k);
  sodium_memzero(temp_k, sizeof(temp_k));
}

static void noise_mix_key_and_hash(sendspin_noise_t *ns, const uint8_t *ikm,
                                   size_t ikm_len) {
  uint8_t temp_h[32];
  uint8_t temp_k[32];
  noise_hkdf(ns->ck, ikm, ikm_len, ns->ck, temp_h, temp_k);
  noise_mix_hash(ns, temp_h, sizeof(temp_h));
  noise_cipher_init(&ns->handshake_cipher, temp_k);
  sodium_memzero(temp_h, sizeof(temp_h));
  sodium_memzero(temp_k, sizeof(temp_k));
}

/* The running hash is the associated data, so every handshake message
 * authenticates everything that came before it. */
static esp_err_t noise_encrypt_and_hash(sendspin_noise_t *ns,
                                        const uint8_t *plain, size_t len,
                                        uint8_t *out, size_t *out_len) {
  esp_err_t err = noise_cipher_encrypt(&ns->handshake_cipher, ns->h,
                                       sizeof(ns->h), plain, len, out, out_len);
  if (err != ESP_OK) {
    return err;
  }
  noise_mix_hash(ns, out, *out_len);
  return ESP_OK;
}

static esp_err_t noise_decrypt_and_hash(sendspin_noise_t *ns,
                                        const uint8_t *cipher, size_t len,
                                        uint8_t *out, size_t *out_len) {
  esp_err_t err = noise_cipher_decrypt(
      &ns->handshake_cipher, ns->h, sizeof(ns->h), cipher, len, out, out_len);
  if (err != ESP_OK) {
    return err;
  }
  noise_mix_hash(ns, cipher, len);
  return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

static void noise_derive_constants(void) {
  if (s_constants_ready) {
    return;
  }
  crypto_hash_sha256(s_sentinel_psk, (const uint8_t *)SENTINEL_PSK_LABEL,
                     strlen(SENTINEL_PSK_LABEL));
  sendspin_noise_psk_id(s_sentinel_psk, s_sentinel_psk_id);
  s_constants_ready = true;
}

void sendspin_noise_psk_id(const uint8_t psk[SENDSPIN_NOISE_KEY_LEN],
                           char out[SENDSPIN_NOISE_PSK_ID_LEN + 1]) {
  uint8_t id[32];
  crypto_hash_sha256_state st;
  crypto_hash_sha256_init(&st);
  crypto_hash_sha256_update(&st, (const uint8_t *)PSK_ID_LABEL,
                            strlen(PSK_ID_LABEL));
  crypto_hash_sha256_update(&st, psk, SENDSPIN_NOISE_KEY_LEN);
  crypto_hash_sha256_final(&st, id);

  sodium_bin2base64(out, SENDSPIN_NOISE_PSK_ID_LEN + 1, id, sizeof(id),
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}

const uint8_t *sendspin_noise_sentinel_psk(void) {
  noise_derive_constants();
  return s_sentinel_psk;
}

const char *sendspin_noise_sentinel_psk_id(void) {
  noise_derive_constants();
  return s_sentinel_psk_id;
}

/* ------------------------------------------------------------------ */
/*  Handshake                                                          */
/* ------------------------------------------------------------------ */

esp_err_t sendspin_noise_start(sendspin_noise_t *ns,
                               const uint8_t client_priv[32],
                               const uint8_t client_pub[32],
                               const uint8_t server_pub[32],
                               const uint8_t *prologue, size_t prologue_len) {
  if (!ns || !client_priv || !client_pub || !server_pub) {
    return ESP_ERR_INVALID_ARG;
  }
  noise_derive_constants();
  sendspin_noise_reset(ns);

  /* InitializeSymmetric: the protocol name is longer than the hash, so it is
   * hashed rather than zero-padded. */
  crypto_hash_sha256(ns->h, (const uint8_t *)NOISE_PROTOCOL_NAME,
                     strlen(NOISE_PROTOCOL_NAME));
  memcpy(ns->ck, ns->h, sizeof(ns->ck));
  noise_cipher_init(&ns->handshake_cipher, NULL);

  noise_mix_hash(ns, prologue, prologue_len);

  /* KK pre-messages, initiator first. The server is the initiator. */
  noise_mix_hash(ns, server_pub, SENDSPIN_NOISE_KEY_LEN);
  noise_mix_hash(ns, client_pub, SENDSPIN_NOISE_KEY_LEN);

  memcpy(ns->s_priv, client_priv, SENDSPIN_NOISE_KEY_LEN);
  memcpy(ns->s_pub, client_pub, SENDSPIN_NOISE_KEY_LEN);
  memcpy(ns->rs, server_pub, SENDSPIN_NOISE_KEY_LEN);
  return ESP_OK;
}

esp_err_t sendspin_noise_read_message1(sendspin_noise_t *ns, const uint8_t *msg,
                                       size_t msg_len, uint8_t *payload_out,
                                       size_t payload_cap,
                                       size_t *payload_len) {
  if (!ns || !msg) {
    return ESP_ERR_INVALID_ARG;
  }
  /* e (32 bytes) then an encrypted payload, which is at least a tag. */
  if (msg_len < SENDSPIN_NOISE_KEY_LEN + SENDSPIN_NOISE_TAG_LEN) {
    return ESP_ERR_INVALID_SIZE;
  }
  const size_t cipher_len = msg_len - SENDSPIN_NOISE_KEY_LEN;
  if (cipher_len - SENDSPIN_NOISE_TAG_LEN > payload_cap) {
    return ESP_ERR_INVALID_SIZE;
  }

  /* "e": the psk modifier makes every ephemeral feed the chaining key as
   * well as the hash, so a session has fresh entropy even before any DH. */
  memcpy(ns->re, msg, SENDSPIN_NOISE_KEY_LEN);
  noise_mix_hash(ns, ns->re, SENDSPIN_NOISE_KEY_LEN);
  noise_mix_key(ns, ns->re, SENDSPIN_NOISE_KEY_LEN);

  uint8_t dh[32];
  /* "es": responder side is our static against their ephemeral. */
  if (crypto_scalarmult_curve25519(dh, ns->s_priv, ns->re) != 0) {
    sodium_memzero(dh, sizeof(dh));
    return ESP_FAIL;
  }
  noise_mix_key(ns, dh, sizeof(dh));

  /* "ss" */
  if (crypto_scalarmult_curve25519(dh, ns->s_priv, ns->rs) != 0) {
    sodium_memzero(dh, sizeof(dh));
    return ESP_FAIL;
  }
  noise_mix_key(ns, dh, sizeof(dh));
  sodium_memzero(dh, sizeof(dh));

  return noise_decrypt_and_hash(ns, msg + SENDSPIN_NOISE_KEY_LEN, cipher_len,
                                payload_out, payload_len);
}

esp_err_t sendspin_noise_write_message2(sendspin_noise_t *ns,
                                        const uint8_t psk[32],
                                        const uint8_t *payload,
                                        size_t payload_len, uint8_t *out,
                                        size_t out_cap, size_t *out_len) {
  if (!ns || !psk || !out) {
    return ESP_ERR_INVALID_ARG;
  }
  if (out_cap < SENDSPIN_NOISE_KEY_LEN + payload_len + SENDSPIN_NOISE_TAG_LEN) {
    return ESP_ERR_INVALID_SIZE;
  }

  /* "e" */
  randombytes_buf(ns->e_priv, sizeof(ns->e_priv));
  if (crypto_scalarmult_curve25519_base(ns->e_pub, ns->e_priv) != 0) {
    return ESP_FAIL;
  }
  memcpy(out, ns->e_pub, SENDSPIN_NOISE_KEY_LEN);
  noise_mix_hash(ns, ns->e_pub, SENDSPIN_NOISE_KEY_LEN);
  noise_mix_key(ns, ns->e_pub, SENDSPIN_NOISE_KEY_LEN);

  uint8_t dh[32];
  /* "ee" */
  if (crypto_scalarmult_curve25519(dh, ns->e_priv, ns->re) != 0) {
    sodium_memzero(dh, sizeof(dh));
    return ESP_FAIL;
  }
  noise_mix_key(ns, dh, sizeof(dh));

  /* "se": responder side is our ephemeral against their static. */
  if (crypto_scalarmult_curve25519(dh, ns->e_priv, ns->rs) != 0) {
    sodium_memzero(dh, sizeof(dh));
    return ESP_FAIL;
  }
  noise_mix_key(ns, dh, sizeof(dh));
  sodium_memzero(dh, sizeof(dh));

  /* "psk" */
  noise_mix_key_and_hash(ns, psk, SENDSPIN_NOISE_KEY_LEN);

  size_t written = 0;
  esp_err_t err = noise_encrypt_and_hash(
      ns, payload, payload_len, out + SENDSPIN_NOISE_KEY_LEN, &written);
  if (err != ESP_OK) {
    return err;
  }
  *out_len = SENDSPIN_NOISE_KEY_LEN + written;

  /* Split. The first cipher carries initiator-to-responder traffic, which is
   * the direction we receive on. */
  uint8_t k1[32];
  uint8_t k2[32];
  noise_hkdf(ns->ck, NULL, 0, k1, k2, NULL);
  noise_cipher_init(&ns->recv, k1);
  noise_cipher_init(&ns->send, k2);
  sodium_memzero(k1, sizeof(k1));
  sodium_memzero(k2, sizeof(k2));

  sodium_memzero(ns->e_priv, sizeof(ns->e_priv));
  sodium_memzero(&ns->handshake_cipher, sizeof(ns->handshake_cipher));
  ns->transport = true;
  ESP_LOGI(TAG, "handshake complete, transport mode");
  return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Transport                                                          */
/* ------------------------------------------------------------------ */

esp_err_t sendspin_noise_encrypt(sendspin_noise_t *ns, const uint8_t *plain,
                                 size_t len, uint8_t *out, size_t out_cap,
                                 size_t *out_len) {
  if (!ns || !ns->transport) {
    return ESP_ERR_INVALID_STATE;
  }
  if (out_cap < len + SENDSPIN_NOISE_TAG_LEN) {
    return ESP_ERR_INVALID_SIZE;
  }
  return noise_cipher_encrypt(&ns->send, NULL, 0, plain, len, out, out_len);
}

esp_err_t sendspin_noise_decrypt(sendspin_noise_t *ns, const uint8_t *cipher,
                                 size_t len, uint8_t *out, size_t out_cap,
                                 size_t *out_len) {
  if (!ns || !ns->transport) {
    return ESP_ERR_INVALID_STATE;
  }
  if (len < SENDSPIN_NOISE_TAG_LEN || len - SENDSPIN_NOISE_TAG_LEN > out_cap) {
    return ESP_ERR_INVALID_SIZE;
  }
  return noise_cipher_decrypt(&ns->recv, NULL, 0, cipher, len, out, out_len);
}

void sendspin_noise_reset(sendspin_noise_t *ns) {
  if (ns) {
    sodium_memzero(ns, sizeof(*ns));
  }
}
