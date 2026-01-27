#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * TLV8 encoder/decoder for HAP protocol
 * Type-Length-Value format where Length is max 255 bytes
 * Longer values are split across multiple TLVs with same type
 */

// HAP TLV types for pair-verify
#define TLV_TYPE_METHOD         0x00
#define TLV_TYPE_IDENTIFIER     0x01
#define TLV_TYPE_SALT           0x02
#define TLV_TYPE_PUBLIC_KEY     0x03
#define TLV_TYPE_PROOF          0x04
#define TLV_TYPE_ENCRYPTED_DATA 0x05
#define TLV_TYPE_STATE          0x06
#define TLV_TYPE_ERROR          0x07
#define TLV_TYPE_SIGNATURE      0x0A

// HAP Error codes
#define TLV_ERROR_UNKNOWN        0x01
#define TLV_ERROR_AUTHENTICATION 0x02
#define TLV_ERROR_BACKOFF        0x03
#define TLV_ERROR_MAX_PEERS      0x04
#define TLV_ERROR_MAX_TRIES      0x05
#define TLV_ERROR_UNAVAILABLE    0x06
#define TLV_ERROR_BUSY           0x07

// Pair-verify states
#define PAIR_VERIFY_STATE_M1 0x01
#define PAIR_VERIFY_STATE_M2 0x02
#define PAIR_VERIFY_STATE_M3 0x03
#define PAIR_VERIFY_STATE_M4 0x04

typedef struct {
  uint8_t *buffer;
  size_t size;
  size_t capacity;
} tlv8_encoder_t;

typedef struct {
  const uint8_t *data;
  size_t len;
} tlv8_value_t;

/**
 * Initialize TLV8 encoder
 */
void tlv8_encoder_init(tlv8_encoder_t *enc, uint8_t *buffer, size_t capacity);

/**
 * Add a TLV to the encoder
 * Handles values > 255 bytes by splitting into multiple TLVs
 */
bool tlv8_encode(tlv8_encoder_t *enc, uint8_t type, const uint8_t *value,
                 size_t len);

/**
 * Add a single byte TLV
 */
bool tlv8_encode_byte(tlv8_encoder_t *enc, uint8_t type, uint8_t value);

/**
 * Get encoded size
 */
size_t tlv8_encoder_size(const tlv8_encoder_t *enc);

/**
 * Find a TLV by type in encoded data
 * Returns pointer to value and sets len, or NULL if not found
 * For split TLVs, only returns first chunk (use tlv8_decode_concat for full
 * value)
 */
const uint8_t *tlv8_find(const uint8_t *data, size_t data_len, uint8_t type,
                         size_t *value_len);

/**
 * Decode and concatenate split TLVs of same type
 * @param data Input TLV data
 * @param data_len Length of input data
 * @param type TLV type to find
 * @param out_buffer Output buffer for concatenated value
 * @param out_capacity Capacity of output buffer
 * @param out_len Actual length of decoded value
 * @return true if found, false otherwise
 */
bool tlv8_decode_concat(const uint8_t *data, size_t data_len, uint8_t type,
                        uint8_t *out_buffer, size_t out_capacity,
                        size_t *out_len);
