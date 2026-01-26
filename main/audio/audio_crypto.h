#pragma once

#include <stddef.h>
#include <stdint.h>

#include "audio_receiver.h"

int audio_crypto_decrypt_rtp(const audio_encrypt_t *encrypt,
                             const uint8_t *input, size_t input_len,
                             uint8_t *output, size_t output_capacity,
                             const uint8_t *full_packet,
                             size_t full_packet_len);

int audio_crypto_decrypt_buffered(const audio_encrypt_t *encrypt,
                                  const uint8_t *packet, size_t packet_len,
                                  uint8_t *output, size_t output_capacity);
