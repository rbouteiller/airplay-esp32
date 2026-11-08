// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <string.h>

#include "audio_crypto.h"

#include "psa/crypto.h"
#include "sodium.h"

// The AES-CBC key is fixed for the life of a stream (set once from
// audio_receiver_set_encryption); re-importing it into PSA on every packet
// would cost more than the AES op itself, so cache the imported key.
static mbedtls_svc_key_id_t s_cbc_key_id;
static bool s_cbc_key_valid = false;
static uint8_t s_cbc_key_cached[16];

static int get_cbc_key(const uint8_t key[16], mbedtls_svc_key_id_t *out_key) {
  if (s_cbc_key_valid && memcmp(s_cbc_key_cached, key, 16) == 0) {
    *out_key = s_cbc_key_id;
    return 0;
  }

  if (s_cbc_key_valid) {
    psa_destroy_key(s_cbc_key_id);
    s_cbc_key_valid = false;
  }

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
  if (psa_import_key(&attr, key, 16, &s_cbc_key_id) != PSA_SUCCESS) {
    return -1;
  }

  memcpy(s_cbc_key_cached, key, 16);
  s_cbc_key_valid = true;
  *out_key = s_cbc_key_id;
  return 0;
}

int audio_crypto_decrypt_rtp(const audio_encrypt_t *encrypt,
                             const uint8_t *input, size_t input_len,
                             uint8_t *output, size_t output_capacity,
                             const uint8_t *full_packet,
                             size_t full_packet_len) {
  if (!encrypt || !input || !output) {
    return -1;
  }

  if (encrypt->type == AUDIO_ENCRYPT_NONE) {
    if (input_len > output_capacity) {
      return -1;
    }
    memcpy(output, input, input_len);
    return (int)input_len;
  }

  if (encrypt->type == AUDIO_ENCRYPT_AES_CBC) {
    if (input_len > output_capacity) {
      return -1;
    }

    uint8_t iv[16];
    memcpy(iv, encrypt->iv, sizeof(iv));

    size_t num_blocks = input_len / 16;
    size_t remainder = input_len % 16;
    size_t encrypted_len = num_blocks * 16;

    if (encrypted_len > 0) {
      psa_crypto_init();

      mbedtls_svc_key_id_t key_id;
      if (get_cbc_key(encrypt->key, &key_id) != 0) {
        return -1;
      }

      psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
      psa_status_t status =
          psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
      if (status == PSA_SUCCESS) {
        status = psa_cipher_set_iv(&op, iv, sizeof(iv));
      }

      size_t out_len = 0;
      if (status == PSA_SUCCESS) {
        status = psa_cipher_update(&op, input, encrypted_len, output,
                                   output_capacity, &out_len);
      }

      size_t finish_len = 0;
      uint8_t finish_buf[16];
      if (status == PSA_SUCCESS) {
        status = psa_cipher_finish(&op, finish_buf, sizeof(finish_buf),
                                   &finish_len);
      }

      psa_cipher_abort(&op);

      if (status != PSA_SUCCESS) {
        return -1;
      }

      if (finish_len > 0) {
        memcpy(output + out_len, finish_buf, finish_len);
      }
    }

    if (remainder > 0) {
      memcpy(output + encrypted_len, input + encrypted_len, remainder);
    }

    return (int)input_len;
  }

  if (encrypt->type == AUDIO_ENCRYPT_CHACHA20_POLY1305) {
    // AirPlay 2 RTP: nonce = 4 zero bytes + last 8 bytes of packet,
    // AAD = RTP timestamp + SSRC (bytes 4-11 of the full packet).
    if (!full_packet || full_packet_len < 12) {
      return -1;
    }

    if (input_len < crypto_aead_chacha20poly1305_ietf_ABYTES + 8) {
      return -1;
    }

    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, full_packet + full_packet_len - 8, 8);

    const uint8_t *aad = full_packet + 4;
    size_t aad_len = 8;

    size_t ciphertext_len = input_len - 8;

    unsigned long long decrypted_len = 0;
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
        output, &decrypted_len, NULL, input, ciphertext_len, aad, aad_len,
        nonce, encrypt->key);
    if (ret != 0) {
      return -1;
    }

    return (int)decrypted_len;
  }

  return -1;
}

int audio_crypto_decrypt_buffered(const audio_encrypt_t *encrypt,
                                  const uint8_t *packet, size_t packet_len,
                                  uint8_t *output, size_t output_capacity) {
  if (!packet || !output) {
    return -1;
  }

  if (!encrypt || encrypt->type != AUDIO_ENCRYPT_CHACHA20_POLY1305) {
    if (packet_len <= 12) {
      return -1;
    }
    size_t payload_len = packet_len - 12;
    if (payload_len > output_capacity) {
      return -1;
    }
    memcpy(output, packet + 12, payload_len);
    return (int)payload_len;
  }

  if (packet_len < 36) {
    return -1;
  }

  // Buffered audio: AAD is bytes 4-11 (timestamp + SSRC), nonce in last 8
  // bytes.
  uint8_t nonce[12] = {0};
  memcpy(nonce + 4, packet + packet_len - 8, 8);

  const uint8_t *aad = packet + 4;
  size_t aad_len = 8;

  const uint8_t *ciphertext = packet + 12;
  size_t ciphertext_len = packet_len - 12 - 8;

  if (ciphertext_len >
      output_capacity + crypto_aead_chacha20poly1305_ietf_ABYTES) {
    return -1;
  }

  unsigned long long decrypted_len = 0;
  int ret = crypto_aead_chacha20poly1305_ietf_decrypt(
      output, &decrypted_len, NULL, ciphertext, ciphertext_len, aad, aad_len,
      nonce, encrypt->key);
  if (ret != 0) {
    return -1;
  }

  return (int)decrypted_len;
}
