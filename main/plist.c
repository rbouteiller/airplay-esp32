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
