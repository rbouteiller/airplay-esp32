#include <string.h>
#include "tlv8.h"

void tlv8_encoder_init(tlv8_encoder_t *enc, uint8_t *buffer, size_t capacity)
{
    enc->buffer = buffer;
    enc->size = 0;
    enc->capacity = capacity;
}

bool tlv8_encode(tlv8_encoder_t *enc, uint8_t type, const uint8_t *value, size_t len)
{
    size_t offset = 0;

    while (offset < len || (offset == 0 && len == 0)) {
        size_t chunk_len = len - offset;
        if (chunk_len > 255) {
            chunk_len = 255;
        }

        // Check if we have space
        if (enc->size + 2 + chunk_len > enc->capacity) {
            return false;
        }

        enc->buffer[enc->size++] = type;
        enc->buffer[enc->size++] = (uint8_t)chunk_len;

        if (chunk_len > 0) {
            memcpy(enc->buffer + enc->size, value + offset, chunk_len);
            enc->size += chunk_len;
        }

        offset += chunk_len;

        // For zero-length values, only write one TLV
        if (len == 0) {
            break;
        }
    }

    return true;
}

bool tlv8_encode_byte(tlv8_encoder_t *enc, uint8_t type, uint8_t value)
{
    return tlv8_encode(enc, type, &value, 1);
}

size_t tlv8_encoder_size(const tlv8_encoder_t *enc)
{
    return enc->size;
}

const uint8_t *tlv8_find(const uint8_t *data, size_t data_len, uint8_t type, size_t *value_len)
{
    size_t offset = 0;

    while (offset + 2 <= data_len) {
        uint8_t t = data[offset];
        uint8_t l = data[offset + 1];

        if (offset + 2 + l > data_len) {
            break;  // Invalid TLV
        }

        if (t == type) {
            *value_len = l;
            return data + offset + 2;
        }

        offset += 2 + l;
    }

    *value_len = 0;
    return NULL;
}

bool tlv8_decode_concat(const uint8_t *data, size_t data_len, uint8_t type,
                        uint8_t *out_buffer, size_t out_capacity, size_t *out_len)
{
    size_t offset = 0;
    size_t out_offset = 0;
    bool found = false;
    bool in_sequence = false;

    while (offset + 2 <= data_len) {
        uint8_t t = data[offset];
        uint8_t l = data[offset + 1];

        if (offset + 2 + l > data_len) {
            break;  // Invalid TLV
        }

        if (t == type) {
            found = true;
            in_sequence = true;

            if (out_offset + l > out_capacity) {
                return false;  // Buffer too small
            }

            memcpy(out_buffer + out_offset, data + offset + 2, l);
            out_offset += l;
        } else if (in_sequence) {
            // Different type encountered after our type - stop concatenating
            break;
        }

        offset += 2 + l;
    }

    *out_len = out_offset;
    return found;
}
