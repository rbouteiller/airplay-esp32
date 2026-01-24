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

// Read real/float at given offset
static bool bplist_read_real(const uint8_t *plist, size_t plist_len, uint64_t offset,
                              double *out)
{
    if (offset >= plist_len) return false;

    uint8_t marker = plist[offset];
    uint8_t type = marker & 0xF0;

    if (type == BPLIST_REAL) {
        size_t len = 1 << (marker & 0x0F);
        if (offset + 1 + len > plist_len) return false;

        if (len == 4) {
            // 32-bit float (big-endian)
            uint32_t bits = (uint32_t)read_be_int(plist + offset + 1, 4);
            float f;
            memcpy(&f, &bits, sizeof(f));
            *out = (double)f;
            return true;
        } else if (len == 8) {
            // 64-bit double (big-endian)
            uint64_t bits = read_be_int(plist + offset + 1, 8);
            memcpy(out, &bits, sizeof(*out));
            return true;
        }
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

bool bplist_find_real(const uint8_t *plist, size_t plist_len,
                      const char *key, double *out_value)
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
                // Try reading as real first, fall back to int
                if (bplist_read_real(plist, plist_len, val_offset, out_value)) {
                    return true;
                }
                // Try as integer and convert to double
                int64_t int_val;
                if (bplist_read_int(plist, plist_len, val_offset, &int_val)) {
                    *out_value = (double)int_val;
                    return true;
                }
                return false;
            }
        }
    }

    return false;
}

// ========================================
// Binary plist builders
// ========================================

size_t bplist_build_initial_setup(uint8_t *out, size_t capacity, uint16_t event_port)
{
    if (capacity < 100) {
        return 0;
    }

    size_t pos = 0;
    memcpy(out + pos, "bplist00", 8);
    pos += 8;

    size_t offsets[10];
    size_t obj = 0;

    // Object 0: "eventPort" string
    offsets[obj++] = pos;
    out[pos++] = 0x59;  // ASCII string, length 9
    memcpy(out + pos, "eventPort", 9);
    pos += 9;

    // Object 1: "timingPort" string
    offsets[obj++] = pos;
    out[pos++] = 0x5A;  // ASCII string, length 10
    memcpy(out + pos, "timingPort", 10);
    pos += 10;

    // Object 2: event port value (2-byte int)
    offsets[obj++] = pos;
    out[pos++] = 0x11;  // 2-byte int
    out[pos++] = (event_port >> 8) & 0xFF;
    out[pos++] = event_port & 0xFF;

    // Object 3: timing port value (0)
    offsets[obj++] = pos;
    out[pos++] = 0x10;  // 1-byte int
    out[pos++] = 0;

    // Object 4: root dict with 2 entries
    offsets[obj++] = pos;
    out[pos++] = 0xD2;  // dict with 2 entries
    out[pos++] = 0;     // key ref: eventPort
    out[pos++] = 1;     // key ref: timingPort
    out[pos++] = 2;     // val ref: event port value
    out[pos++] = 3;     // val ref: timing port value

    // Offset table
    size_t offset_table_offset = pos;
    for (size_t i = 0; i < obj; i++) {
        if (offsets[i] > 0xFF) {
            return 0;
        }
        out[pos++] = (uint8_t)offsets[i];
    }

    // Trailer (32 bytes)
    memset(out + pos, 0, 6);
    pos += 6;
    out[pos++] = 1;  // offset int size
    out[pos++] = 1;  // object ref size

    for (int i = 0; i < 7; i++)
        out[pos++] = 0;
    out[pos++] = (uint8_t)obj;  // num objects

    for (int i = 0; i < 7; i++)
        out[pos++] = 0;
    out[pos++] = 4;  // top object (root dict)

    for (int i = 0; i < 7; i++)
        out[pos++] = 0;
    out[pos++] = (uint8_t)offset_table_offset;

    return pos;
}

size_t bplist_build_stream_setup(uint8_t *out, size_t capacity,
                                 int64_t stream_type, uint16_t data_port,
                                 uint16_t control_port, uint32_t audio_buffer_size)
{
    if (capacity < 200) {
        return 0;
    }

    size_t pos = 0;
    memcpy(out + pos, "bplist00", 8);
    pos += 8;

    size_t offsets[16];
    size_t obj = 0;

    // Object 0: "streams" string
    offsets[obj++] = pos;
    out[pos++] = 0x57;  // ASCII string, length 7
    memcpy(out + pos, "streams", 7);
    pos += 7;

    // Object 1: "type" string
    offsets[obj++] = pos;
    out[pos++] = 0x54;  // ASCII string, length 4
    memcpy(out + pos, "type", 4);
    pos += 4;

    // Object 2: "dataPort" string
    offsets[obj++] = pos;
    out[pos++] = 0x58;  // ASCII string, length 8
    memcpy(out + pos, "dataPort", 8);
    pos += 8;

    // Object 3: "controlPort" string
    offsets[obj++] = pos;
    out[pos++] = 0x5B;  // ASCII string, length 11
    memcpy(out + pos, "controlPort", 11);
    pos += 11;

    // Object 4: "audioBufferSize" string (extended length)
    offsets[obj++] = pos;
    out[pos++] = 0x5F;  // ASCII string, extended length
    out[pos++] = 0x10;  // 1-byte length marker
    out[pos++] = 15;    // length = 15
    memcpy(out + pos, "audioBufferSize", 15);
    pos += 15;

    // Object 5: stream type value
    offsets[obj++] = pos;
    out[pos++] = 0x10;  // 1-byte int
    out[pos++] = (uint8_t)stream_type;

    // Object 6: data port value
    offsets[obj++] = pos;
    out[pos++] = 0x11;  // 2-byte int
    out[pos++] = (data_port >> 8) & 0xFF;
    out[pos++] = data_port & 0xFF;

    // Object 7: control port value
    offsets[obj++] = pos;
    out[pos++] = 0x11;  // 2-byte int
    out[pos++] = (control_port >> 8) & 0xFF;
    out[pos++] = control_port & 0xFF;

    // Object 8: audio buffer size value
    offsets[obj++] = pos;
    out[pos++] = 0x12;  // 4-byte int
    out[pos++] = (audio_buffer_size >> 24) & 0xFF;
    out[pos++] = (audio_buffer_size >> 16) & 0xFF;
    out[pos++] = (audio_buffer_size >> 8) & 0xFF;
    out[pos++] = audio_buffer_size & 0xFF;

    // Object 9: stream dict
    offsets[obj++] = pos;
    if (stream_type == 103) {
        // Buffered stream: type, dataPort, audioBufferSize, controlPort
        out[pos++] = 0xD4;  // dict with 4 entries
        out[pos++] = 1;     // key: type
        out[pos++] = 2;     // key: dataPort
        out[pos++] = 4;     // key: audioBufferSize
        out[pos++] = 3;     // key: controlPort
        out[pos++] = 5;     // val: type
        out[pos++] = 6;     // val: dataPort
        out[pos++] = 8;     // val: audioBufferSize
        out[pos++] = 7;     // val: controlPort
    } else {
        // Realtime stream: type, dataPort, controlPort
        out[pos++] = 0xD3;  // dict with 3 entries
        out[pos++] = 1;     // key: type
        out[pos++] = 2;     // key: dataPort
        out[pos++] = 3;     // key: controlPort
        out[pos++] = 5;     // val: type
        out[pos++] = 6;     // val: dataPort
        out[pos++] = 7;     // val: controlPort
    }

    // Object 10: streams array with 1 element
    offsets[obj++] = pos;
    out[pos++] = 0xA1;  // array with 1 element
    out[pos++] = 9;     // ref to stream dict

    // Object 11: root dict
    offsets[obj++] = pos;
    out[pos++] = 0xD1;  // dict with 1 entry
    out[pos++] = 0;     // key: streams
    out[pos++] = 10;    // val: streams array

    // Offset table
    size_t offset_table_offset = pos;
    for (size_t i = 0; i < obj; i++) {
        if (offsets[i] > 0xFF) {
            return 0;
        }
        out[pos++] = (uint8_t)offsets[i];
    }

    // Trailer (32 bytes)
    memset(out + pos, 0, 6);
    pos += 6;
    out[pos++] = 1;  // offset int size
    out[pos++] = 1;  // object ref size

    for (int i = 0; i < 7; i++)
        out[pos++] = 0;
    out[pos++] = (uint8_t)obj;  // num objects

    for (int i = 0; i < 7; i++)
        out[pos++] = 0;
    out[pos++] = 11;  // top object (root dict)

    for (int i = 0; i < 7; i++)
        out[pos++] = 0;
    out[pos++] = (uint8_t)offset_table_offset;

    return pos;
}
