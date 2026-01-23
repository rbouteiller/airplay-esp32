#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "plist.h"

// Base64 encoding table
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 decoding table (6-bit values, 255 = invalid)
static const uint8_t b64_decode_table[256] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};

static void plist_append(plist_t *p, const char *str)
{
    size_t len = strlen(str);
    if (p->size + len < p->capacity) {
        memcpy(p->buffer + p->size, str, len);
        p->size += len;
        p->buffer[p->size] = '\0';
    }
}

void plist_init(plist_t *p, char *buffer, size_t capacity)
{
    p->buffer = buffer;
    p->size = 0;
    p->capacity = capacity;
    p->buffer[0] = '\0';
}

void plist_begin(plist_t *p)
{
    plist_append(p, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    plist_append(p, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                    "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    plist_append(p, "<plist version=\"1.0\">\n");
}

void plist_dict_begin(plist_t *p)
{
    plist_append(p, "<dict>\n");
}

void plist_dict_string(plist_t *p, const char *key, const char *value)
{
    size_t remaining = p->capacity - p->size;
    int len = snprintf(p->buffer + p->size, remaining,
                       "<key>%s</key>\n<string>%s</string>\n", key, value);
    if (len > 0 && (size_t)len < remaining) {
        p->size += len;
    }
}

void plist_dict_int(plist_t *p, const char *key, int64_t value)
{
    size_t remaining = p->capacity - p->size;
    int len = snprintf(p->buffer + p->size, remaining,
                       "<key>%s</key>\n<integer>%" PRId64 "</integer>\n", key, value);
    if (len > 0 && (size_t)len < remaining) {
        p->size += len;
    }
}

void plist_dict_uint(plist_t *p, const char *key, uint64_t value)
{
    size_t remaining = p->capacity - p->size;
    int len = snprintf(p->buffer + p->size, remaining,
                       "<key>%s</key>\n<integer>%" PRIu64 "</integer>\n", key, value);
    if (len > 0 && (size_t)len < remaining) {
        p->size += len;
    }
}

void plist_dict_bool(plist_t *p, const char *key, bool value)
{
    size_t remaining = p->capacity - p->size;
    int len = snprintf(p->buffer + p->size, remaining,
                       "<key>%s</key>\n<%s/>\n", key, value ? "true" : "false");
    if (len > 0 && (size_t)len < remaining) {
        p->size += len;
    }
}

void plist_dict_data(plist_t *p, const char *key, const uint8_t *data, size_t len)
{
    // Calculate base64 output size
    size_t b64_len = ((len + 2) / 3) * 4;
    size_t remaining = p->capacity - p->size;

    if (remaining < strlen(key) + b64_len + 50) {
        return;  // Not enough space
    }

    int written = snprintf(p->buffer + p->size, remaining, "<key>%s</key>\n<data>", key);
    if (written > 0) {
        p->size += written;
    }

    // Base64 encode
    for (size_t i = 0; i < len; i += 3) {
        uint32_t octet_a = i < len ? data[i] : 0;
        uint32_t octet_b = i + 1 < len ? data[i + 1] : 0;
        uint32_t octet_c = i + 2 < len ? data[i + 2] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        if (p->size + 4 < p->capacity) {
            p->buffer[p->size++] = b64_table[(triple >> 18) & 0x3F];
            p->buffer[p->size++] = b64_table[(triple >> 12) & 0x3F];
            p->buffer[p->size++] = (i + 1 < len) ? b64_table[(triple >> 6) & 0x3F] : '=';
            p->buffer[p->size++] = (i + 2 < len) ? b64_table[triple & 0x3F] : '=';
        }
    }

    plist_append(p, "</data>\n");
}

void plist_dict_data_hex(plist_t *p, const char *key, const uint8_t *data, size_t len)
{
    // Just use the base64 data encoding
    plist_dict_data(p, key, data, len);
}

void plist_dict_end(plist_t *p)
{
    plist_append(p, "</dict>\n");
}

void plist_dict_array_begin(plist_t *p, const char *key)
{
    size_t remaining = p->capacity - p->size;
    int len = snprintf(p->buffer + p->size, remaining,
                       "<key>%s</key>\n<array>\n", key);
    if (len > 0 && (size_t)len < remaining) {
        p->size += len;
    }
}

void plist_array_begin(plist_t *p)
{
    plist_append(p, "<array>\n");
}

void plist_array_end(plist_t *p)
{
    plist_append(p, "</array>\n");
}

void plist_array_int(plist_t *p, int64_t value)
{
    size_t remaining = p->capacity - p->size;
    int len = snprintf(p->buffer + p->size, remaining,
                       "<integer>%" PRId64 "</integer>\n", value);
    if (len > 0 && (size_t)len < remaining) {
        p->size += len;
    }
}

size_t plist_end(plist_t *p)
{
    plist_append(p, "</plist>\n");
    return p->size;
}

// Base64 decode utility
int base64_decode(const char *input, size_t input_len, uint8_t *output, size_t output_capacity)
{
    if (!input || !output || output_capacity == 0) {
        return -1;
    }

    // Skip whitespace and calculate actual input length
    size_t actual_len = 0;
    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            actual_len++;
        }
    }

    // Check output capacity (rough estimate)
    size_t output_len = (actual_len * 3) / 4;
    if (output_len > output_capacity) {
        return -1;
    }

    size_t j = 0;  // Output index
    uint32_t accum = 0;
    int bits = 0;

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];

        // Skip whitespace
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }

        // Handle padding
        if (c == '=') {
            break;
        }

        uint8_t val = b64_decode_table[(uint8_t)c];
        if (val == 255) {
            return -1;  // Invalid character
        }

        accum = (accum << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            if (j >= output_capacity) {
                return -1;
            }
            output[j++] = (accum >> bits) & 0xFF;
        }
    }

    return (int)j;
}

// ========================================
// Binary plist parser
// ========================================

// Binary plist object types (high nibble of marker byte)
#define BPLIST_NULL     0x00
#define BPLIST_BOOL     0x00  // 0x08 = false, 0x09 = true
#define BPLIST_INT      0x10
#define BPLIST_REAL     0x20
#define BPLIST_DATE     0x30
#define BPLIST_DATA     0x40
#define BPLIST_STRING   0x50  // ASCII string
#define BPLIST_UNICODE  0x60  // UTF-16 string
#define BPLIST_UID      0x80
#define BPLIST_ARRAY    0xA0
#define BPLIST_SET      0xC0
#define BPLIST_DICT     0xD0

// Read big-endian integer of variable size
static uint64_t read_be_int(const uint8_t *data, size_t bytes)
{
    uint64_t val = 0;
    for (size_t i = 0; i < bytes; i++) {
        val = (val << 8) | data[i];
    }
    return val;
}

// Parse binary plist trailer to get offsets
static bool bplist_parse_trailer(const uint8_t *plist, size_t plist_len,
                                  uint8_t *offset_size, uint8_t *ref_size,
                                  uint64_t *num_objects, uint64_t *top_object,
                                  uint64_t *offset_table_offset)
{
    if (plist_len < 32) return false;

    // Trailer is last 32 bytes
    const uint8_t *trailer = plist + plist_len - 32;

    // Bytes 0-5: unused
    // Byte 6: offset int size
    // Byte 7: object ref size
    // Bytes 8-15: number of objects
    // Bytes 16-23: top object
    // Bytes 24-31: offset table offset

    *offset_size = trailer[6];
    *ref_size = trailer[7];
    *num_objects = read_be_int(trailer + 8, 8);
    *top_object = read_be_int(trailer + 16, 8);
    *offset_table_offset = read_be_int(trailer + 24, 8);

    return (*offset_size > 0 && *offset_size <= 8 &&
            *ref_size > 0 && *ref_size <= 8 &&
            *offset_table_offset < plist_len);
}

// Get object offset from offset table
static uint64_t bplist_get_offset(const uint8_t *plist, uint64_t offset_table_offset,
                                   uint8_t offset_size, uint64_t obj_idx)
{
    const uint8_t *entry = plist + offset_table_offset + obj_idx * offset_size;
    return read_be_int(entry, offset_size);
}

// Read string at given offset
static bool bplist_read_string(const uint8_t *plist, size_t plist_len, uint64_t offset,
                                char *out, size_t out_capacity)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    uint8_t type = marker & 0xF0;
    size_t len = marker & 0x0F;
    size_t pos = offset + 1;

    // Handle extended length
    if (len == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        if ((len_marker & 0xF0) != BPLIST_INT) return false;
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        len = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    }

    if (type == BPLIST_STRING) {
        // ASCII string
        if (pos + len > plist_len || len >= out_capacity) return false;
        memcpy(out, plist + pos, len);
        out[len] = '\0';
        return true;
    }

    if (type == BPLIST_UNICODE) {
        // UTF-16BE string; accept only ASCII subset for keys
        size_t bytes = len * 2;
        if (pos + bytes > plist_len || len >= out_capacity) return false;
        for (size_t i = 0; i < len; i++) {
            uint16_t code = (uint16_t)(plist[pos + i * 2] << 8) | plist[pos + i * 2 + 1];
            if (code > 0x7F) {
                return false;
            }
            out[i] = (char)code;
        }
        out[len] = '\0';
        return true;
    }

    return false;
}

// Read data at given offset
static bool bplist_read_data(const uint8_t *plist, size_t plist_len, uint64_t offset,
                              uint8_t *out, size_t out_capacity, size_t *out_len)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    uint8_t type = marker & 0xF0;
    size_t len = marker & 0x0F;
    size_t pos = offset + 1;

    // Handle extended length
    if (len == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        if ((len_marker & 0xF0) != BPLIST_INT) return false;
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        len = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    }

    if (type == BPLIST_DATA) {
        if (pos + len > plist_len || len > out_capacity) return false;
        memcpy(out, plist + pos, len);
        *out_len = len;
        return true;
    }

    return false;
}

static bool bplist_read_data_len(const uint8_t *plist, size_t plist_len, uint64_t offset,
                                 size_t *out_len)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    uint8_t type = marker & 0xF0;
    size_t len = marker & 0x0F;
    size_t pos = offset + 1;

    if (len == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        if ((len_marker & 0xF0) != BPLIST_INT) return false;
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        len = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    }

    if (type == BPLIST_DATA) {
        if (pos + len > plist_len) return false;
        *out_len = len;
        return true;
    }

    return false;
}

static bool bplist_read_string_len(const uint8_t *plist, size_t plist_len, uint64_t offset,
                                   size_t *out_len)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    uint8_t type = marker & 0xF0;
    size_t len = marker & 0x0F;
    size_t pos = offset + 1;

    if (len == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        if ((len_marker & 0xF0) != BPLIST_INT) return false;
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        len = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    }

    if (type == BPLIST_STRING) {
        if (pos + len > plist_len) return false;
        *out_len = len;
        return true;
    }
    if (type == BPLIST_UNICODE) {
        size_t bytes = len * 2;
        if (pos + bytes > plist_len) return false;
        *out_len = len;
        return true;
    }

    return false;
}

// Read integer at given offset
static bool bplist_read_int(const uint8_t *plist, size_t plist_len, uint64_t offset,
                             int64_t *out)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    uint8_t type = marker & 0xF0;

    if (type == BPLIST_INT) {
        size_t len = 1 << (marker & 0x0F);
        if (offset + 1 + len > plist_len) return false;
        *out = (int64_t)read_be_int(plist + offset + 1, len);
        return true;
    }

    return false;
}

static bool bplist_parse_count(const uint8_t *plist, size_t plist_len, uint64_t offset,
                               size_t *count, size_t *header_len)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    size_t info = marker & 0x0F;
    size_t pos = offset + 1;

    if (info == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        *count = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    } else {
        *count = info;
    }

    *header_len = pos - offset;
    return true;
}

static bool bplist_find_data_recursive(const uint8_t *plist, size_t plist_len,
                                       uint64_t obj_idx,
                                       uint64_t offset_table_offset,
                                       uint8_t offset_size,
                                       uint8_t ref_size,
                                       const char *key,
                                       uint8_t *out_data, size_t out_capacity, size_t *out_len,
                                       int depth)
{
    if (depth > 12) {
        return false;
    }

    uint64_t obj_offset = bplist_get_offset(plist, offset_table_offset, offset_size, obj_idx);
    if (obj_offset >= plist_len) return false;

    uint8_t marker = plist[obj_offset];
    uint8_t type = marker & 0xF0;

    if (type == BPLIST_DICT) {
        size_t dict_size = 0;
        size_t header_len = 0;
        if (!bplist_parse_count(plist, plist_len, obj_offset, &dict_size, &header_len)) {
            return false;
        }

        size_t pos = obj_offset + header_len;
        if (pos + dict_size * 2 * ref_size > plist_len) return false;

        const uint8_t *key_refs = plist + pos;
        const uint8_t *val_refs = plist + pos + dict_size * ref_size;

        for (size_t i = 0; i < dict_size; i++) {
            uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
            uint64_t key_offset = bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);
            uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);

            char found_key[64];
            if (bplist_read_string(plist, plist_len, key_offset, found_key, sizeof(found_key))) {
                if (strcmp(found_key, key) == 0) {
                    uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
                    if (bplist_read_data(plist, plist_len, val_offset, out_data, out_capacity, out_len)) {
                        return true;
                    }
                }
            }

            if (bplist_find_data_recursive(plist, plist_len, val_idx, offset_table_offset,
                                           offset_size, ref_size, key, out_data, out_capacity,
                                           out_len, depth + 1)) {
                return true;
            }
        }
    } else if (type == BPLIST_ARRAY || type == BPLIST_SET) {
        size_t array_size = 0;
        size_t header_len = 0;
        if (!bplist_parse_count(plist, plist_len, obj_offset, &array_size, &header_len)) {
            return false;
        }

        size_t pos = obj_offset + header_len;
        if (pos + array_size * ref_size > plist_len) return false;

        for (size_t i = 0; i < array_size; i++) {
            uint64_t elem_idx = read_be_int(plist + pos + i * ref_size, ref_size);
            if (bplist_find_data_recursive(plist, plist_len, elem_idx, offset_table_offset,
                                           offset_size, ref_size, key, out_data, out_capacity,
                                           out_len, depth + 1)) {
                return true;
            }
        }
    }

    return false;
}

static bool bplist_dict_get_value_idx(const uint8_t *plist, size_t plist_len,
                                      uint64_t dict_idx,
                                      uint64_t offset_table_offset,
                                      uint8_t offset_size,
                                      uint8_t ref_size,
                                      const char *key,
                                      uint64_t *val_idx_out)
{
    uint64_t dict_offset = bplist_get_offset(plist, offset_table_offset, offset_size, dict_idx);
    if (dict_offset >= plist_len) return false;

    uint8_t marker = plist[dict_offset];
    if ((marker & 0xF0) != BPLIST_DICT) return false;

    size_t dict_size = 0;
    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, dict_offset, &dict_size, &header_len)) {
        return false;
    }

    size_t pos = dict_offset + header_len;
    if (pos + dict_size * 2 * ref_size > plist_len) return false;

    const uint8_t *key_refs = plist + pos;
    const uint8_t *val_refs = plist + pos + dict_size * ref_size;

    for (size_t i = 0; i < dict_size; i++) {
        uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
        uint64_t key_offset = bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

        char found_key[64];
        if (bplist_read_string(plist, plist_len, key_offset, found_key, sizeof(found_key))) {
            if (strcmp(found_key, key) == 0) {
                *val_idx_out = read_be_int(val_refs + i * ref_size, ref_size);
                return true;
            }
        }
    }

    return false;
}

static bool bplist_dict_get_data(const uint8_t *plist, size_t plist_len,
                                 uint64_t dict_idx,
                                 uint64_t offset_table_offset,
                                 uint8_t offset_size,
                                 uint8_t ref_size,
                                 const char *key,
                                 uint8_t *out_data, size_t out_capacity, size_t *out_len)
{
    uint64_t val_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, dict_idx, offset_table_offset,
                                   offset_size, ref_size, key, &val_idx)) {
        return false;
    }

    uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
    return bplist_read_data(plist, plist_len, val_offset, out_data, out_capacity, out_len);
}

static bool bplist_dict_get_data_len(const uint8_t *plist, size_t plist_len,
                                     uint64_t dict_idx,
                                     uint64_t offset_table_offset,
                                     uint8_t offset_size,
                                     uint8_t ref_size,
                                     const char *key,
                                     size_t *out_len)
{
    uint64_t val_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, dict_idx, offset_table_offset,
                                   offset_size, ref_size, key, &val_idx)) {
        return false;
    }

    uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
    return bplist_read_data_len(plist, plist_len, val_offset, out_len);
}

static bool bplist_dict_get_int(const uint8_t *plist, size_t plist_len,
                                uint64_t dict_idx,
                                uint64_t offset_table_offset,
                                uint8_t offset_size,
                                uint8_t ref_size,
                                const char *key,
                                int64_t *out_value)
{
    uint64_t val_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, dict_idx, offset_table_offset,
                                   offset_size, ref_size, key, &val_idx)) {
        return false;
    }

    uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
    return bplist_read_int(plist, plist_len, val_offset, out_value);
}

bool bplist_get_streams_count(const uint8_t *plist, size_t plist_len, size_t *count)
{
    if (!count) return false;
    *count = 0;

    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }
    (void)num_objects;

    uint64_t streams_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, top_object, offset_table_offset,
                                   offset_size, ref_size, "streams", &streams_idx)) {
        return false;
    }

    uint64_t streams_offset = bplist_get_offset(plist, offset_table_offset, offset_size, streams_idx);
    if (streams_offset >= plist_len) return false;

    uint8_t marker = plist[streams_offset];
    uint8_t type = marker & 0xF0;
    if (type != BPLIST_ARRAY && type != BPLIST_SET) {
        return false;
    }

    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, streams_offset, count, &header_len)) {
        return false;
    }

    size_t pos = streams_offset + header_len;
    if (pos + (*count) * ref_size > plist_len) return false;

    return true;
}

bool bplist_get_stream_info(const uint8_t *plist, size_t plist_len,
                            size_t index, int64_t *type,
                            size_t *ekey_len, size_t *eiv_len, size_t *shk_len)
{
    if (type) *type = -1;
    if (ekey_len) *ekey_len = 0;
    if (eiv_len) *eiv_len = 0;
    if (shk_len) *shk_len = 0;

    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }
    (void)num_objects;

    uint64_t streams_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, top_object, offset_table_offset,
                                   offset_size, ref_size, "streams", &streams_idx)) {
        return false;
    }

    uint64_t streams_offset = bplist_get_offset(plist, offset_table_offset, offset_size, streams_idx);
    if (streams_offset >= plist_len) return false;

    uint8_t marker = plist[streams_offset];
    uint8_t stream_type = marker & 0xF0;
    if (stream_type != BPLIST_ARRAY && stream_type != BPLIST_SET) {
        return false;
    }

    size_t array_size = 0;
    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, streams_offset, &array_size, &header_len)) {
        return false;
    }

    if (index >= array_size) {
        return false;
    }

    size_t pos = streams_offset + header_len;
    if (pos + array_size * ref_size > plist_len) return false;

    uint64_t elem_idx = read_be_int(plist + pos + index * ref_size, ref_size);
    if (type) {
        (void)bplist_dict_get_int(plist, plist_len, elem_idx, offset_table_offset,
                                  offset_size, ref_size, "type", type);
    }
    if (ekey_len) {
        (void)bplist_dict_get_data_len(plist, plist_len, elem_idx, offset_table_offset,
                                       offset_size, ref_size, "ekey", ekey_len);
    }
    if (eiv_len) {
        (void)bplist_dict_get_data_len(plist, plist_len, elem_idx, offset_table_offset,
                                       offset_size, ref_size, "eiv", eiv_len);
    }
    if (shk_len) {
        (void)bplist_dict_get_data_len(plist, plist_len, elem_idx, offset_table_offset,
                                       offset_size, ref_size, "shk", shk_len);
    }

    return true;
}

bool bplist_get_stream_kv_info(const uint8_t *plist, size_t plist_len,
                               size_t index, bplist_kv_info_t *out,
                               size_t out_capacity, size_t *out_count)
{
    if (out_count) *out_count = 0;
    if (!out || out_capacity == 0 || !out_count) return false;

    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }
    (void)num_objects;

    uint64_t streams_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, top_object, offset_table_offset,
                                   offset_size, ref_size, "streams", &streams_idx)) {
        return false;
    }

    uint64_t streams_offset = bplist_get_offset(plist, offset_table_offset, offset_size, streams_idx);
    if (streams_offset >= plist_len) return false;

    uint8_t marker = plist[streams_offset];
    uint8_t stream_type = marker & 0xF0;
    if (stream_type != BPLIST_ARRAY && stream_type != BPLIST_SET) {
        return false;
    }

    size_t array_size = 0;
    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, streams_offset, &array_size, &header_len)) {
        return false;
    }

    if (index >= array_size) {
        return false;
    }

    size_t pos = streams_offset + header_len;
    if (pos + array_size * ref_size > plist_len) return false;

    uint64_t elem_idx = read_be_int(plist + pos + index * ref_size, ref_size);
    uint64_t elem_offset = bplist_get_offset(plist, offset_table_offset, offset_size, elem_idx);
    if (elem_offset >= plist_len) return false;

    uint8_t elem_marker = plist[elem_offset];
    if ((elem_marker & 0xF0) != BPLIST_DICT) return false;

    size_t dict_size = 0;
    size_t dict_header_len = 0;
    if (!bplist_parse_count(plist, plist_len, elem_offset, &dict_size, &dict_header_len)) {
        return false;
    }

    size_t dict_pos = elem_offset + dict_header_len;
    if (dict_pos + dict_size * 2 * ref_size > plist_len) return false;

    const uint8_t *key_refs = plist + dict_pos;
    const uint8_t *val_refs = plist + dict_pos + dict_size * ref_size;

    size_t count = 0;
    for (size_t i = 0; i < dict_size && count < out_capacity; i++) {
        uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
        uint64_t key_offset = bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

        char key_buf[64];
        if (!bplist_read_string(plist, plist_len, key_offset, key_buf, sizeof(key_buf))) {
            continue;
        }

        uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
        uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
        if (val_offset >= plist_len) continue;

        bplist_kv_info_t *info = &out[count];
        memset(info, 0, sizeof(*info));
        strncpy(info->key, key_buf, sizeof(info->key) - 1);

        uint8_t val_marker = plist[val_offset];
        uint8_t val_type = val_marker & 0xF0;

        if (val_type == BPLIST_INT) {
            info->value_type = BPLIST_VALUE_INT;
            (void)bplist_read_int(plist, plist_len, val_offset, &info->int_value);
        } else if (val_type == BPLIST_DATA) {
            info->value_type = BPLIST_VALUE_DATA;
            (void)bplist_read_data_len(plist, plist_len, val_offset, &info->value_len);
        } else if (val_type == BPLIST_STRING || val_type == BPLIST_UNICODE) {
            info->value_type = BPLIST_VALUE_STRING;
            (void)bplist_read_string_len(plist, plist_len, val_offset, &info->value_len);
        } else if (val_type == BPLIST_UID) {
            info->value_type = BPLIST_VALUE_UID;
        } else if (val_type == BPLIST_ARRAY || val_type == BPLIST_SET) {
            info->value_type = BPLIST_VALUE_ARRAY;
        } else if (val_type == BPLIST_DICT) {
            info->value_type = BPLIST_VALUE_DICT;
        } else {
            info->value_type = BPLIST_VALUE_UNKNOWN;
        }

        count++;
    }

    *out_count = count;
    return true;
}

bool bplist_find_stream_crypto(const uint8_t *plist, size_t plist_len,
                               int64_t stream_type,
                               uint8_t *ekey, size_t ekey_capacity, size_t *ekey_len,
                               uint8_t *eiv, size_t eiv_capacity, size_t *eiv_len,
                               uint8_t *shk, size_t shk_capacity, size_t *shk_len)
{
    if (ekey_len) *ekey_len = 0;
    if (eiv_len) *eiv_len = 0;
    if (shk_len) *shk_len = 0;

    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }
    (void)num_objects;

    uint64_t streams_idx = 0;
    if (!bplist_dict_get_value_idx(plist, plist_len, top_object, offset_table_offset,
                                   offset_size, ref_size, "streams", &streams_idx)) {
        return false;
    }

    uint64_t streams_offset = bplist_get_offset(plist, offset_table_offset, offset_size, streams_idx);
    if (streams_offset >= plist_len) return false;

    uint8_t marker = plist[streams_offset];
    uint8_t type = marker & 0xF0;
    if (type != BPLIST_ARRAY && type != BPLIST_SET) {
        return false;
    }

    size_t array_size = 0;
    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, streams_offset, &array_size, &header_len)) {
        return false;
    }

    size_t pos = streams_offset + header_len;
    if (pos + array_size * ref_size > plist_len) return false;

    for (size_t i = 0; i < array_size; i++) {
        uint64_t elem_idx = read_be_int(plist + pos + i * ref_size, ref_size);
        int64_t found_type = -1;
        if (bplist_dict_get_int(plist, plist_len, elem_idx, offset_table_offset,
                                offset_size, ref_size, "type", &found_type) &&
            found_type == stream_type) {
            bool found = false;
            if (ekey && ekey_len) {
                if (bplist_dict_get_data(plist, plist_len, elem_idx, offset_table_offset,
                                         offset_size, ref_size, "ekey", ekey, ekey_capacity, ekey_len)) {
                    found = true;
                }
            }
            if (eiv && eiv_len) {
                if (bplist_dict_get_data(plist, plist_len, elem_idx, offset_table_offset,
                                         offset_size, ref_size, "eiv", eiv, eiv_capacity, eiv_len)) {
                    found = true;
                }
            }
            if (shk && shk_len) {
                if (bplist_dict_get_data(plist, plist_len, elem_idx, offset_table_offset,
                                         offset_size, ref_size, "shk", shk, shk_capacity, shk_len)) {
                    found = true;
                }
            }
            return found;
        }
    }

    return false;
}

bool bplist_find_data(const uint8_t *plist, size_t plist_len,
                      const char *key, uint8_t *out_data, size_t out_capacity, size_t *out_len)
{
    // Check header
    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    // Parse trailer
    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }

    // Get top object (should be dict)
    uint64_t top_offset = bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
    if (top_offset >= plist_len) return false;

    uint8_t marker = plist[top_offset];
    if ((marker & 0xF0) != BPLIST_DICT) {
        return false;  // Top object must be dict
    }

    // Get dict size
    size_t dict_size = marker & 0x0F;
    size_t pos = top_offset + 1;

    // Handle extended length
    if (dict_size == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        dict_size = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    }

    // Dict contains 2*dict_size references: first half are keys, second half are values
    if (pos + dict_size * 2 * ref_size > plist_len) return false;

    const uint8_t *key_refs = plist + pos;
    const uint8_t *val_refs = plist + pos + dict_size * ref_size;

    // Search for key
    for (size_t i = 0; i < dict_size; i++) {
        uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
        uint64_t key_offset = bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

        char found_key[64];
        if (bplist_read_string(plist, plist_len, key_offset, found_key, sizeof(found_key))) {
            if (strcmp(found_key, key) == 0) {
                // Found the key, now get the value
                uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
                uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
                return bplist_read_data(plist, plist_len, val_offset, out_data, out_capacity, out_len);
            }
        }
    }

    return false;
}

bool bplist_find_data_deep(const uint8_t *plist, size_t plist_len,
                           const char *key, uint8_t *out_data, size_t out_capacity, size_t *out_len)
{
    // Check header
    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    // Parse trailer
    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }

    (void)num_objects;
    return bplist_find_data_recursive(plist, plist_len, top_object, offset_table_offset,
                                      offset_size, ref_size, key, out_data, out_capacity,
                                      out_len, 0);
}

bool bplist_find_int(const uint8_t *plist, size_t plist_len,
                     const char *key, int64_t *out_value)
{
    // Check header
    if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
        return false;
    }

    // Parse trailer
    uint8_t offset_size, ref_size;
    uint64_t num_objects, top_object, offset_table_offset;
    if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                               &num_objects, &top_object, &offset_table_offset)) {
        return false;
    }

    // Get top object (should be dict)
    uint64_t top_offset = bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
    if (top_offset >= plist_len) return false;

    uint8_t marker = plist[top_offset];
    if ((marker & 0xF0) != BPLIST_DICT) {
        return false;
    }

    size_t dict_size = marker & 0x0F;
    size_t pos = top_offset + 1;

    if (dict_size == 0x0F) {
        if (pos >= plist_len) return false;
        uint8_t len_marker = plist[pos++];
        size_t len_bytes = 1 << (len_marker & 0x0F);
        if (pos + len_bytes > plist_len) return false;
        dict_size = (size_t)read_be_int(plist + pos, len_bytes);
        pos += len_bytes;
    }

    if (pos + dict_size * 2 * ref_size > plist_len) return false;

    const uint8_t *key_refs = plist + pos;
    const uint8_t *val_refs = plist + pos + dict_size * ref_size;

    for (size_t i = 0; i < dict_size; i++) {
        uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
        uint64_t key_offset = bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

        char found_key[64];
        if (bplist_read_string(plist, plist_len, key_offset, found_key, sizeof(found_key))) {
            if (strcmp(found_key, key) == 0) {
                uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
                uint64_t val_offset = bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
                return bplist_read_int(plist, plist_len, val_offset, out_value);
            }
        }
    }

    return false;
}
