#include <string.h>

#include "base64.h"

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const uint8_t b64_decode_table[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,  255,
    255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255,
    255, 0,   255, 255, 255, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
    10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
    25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,
    34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255};

size_t base64_encoded_length(size_t input_len) {
  return ((input_len + 2) / 3) * 4;
}

int base64_encode(const uint8_t *input, size_t input_len, char *output,
                  size_t output_capacity) {
  if (!input || !output) {
    return -1;
  }

  size_t out_len = base64_encoded_length(input_len);
  if (out_len > output_capacity) {
    return -1;
  }

  size_t pos = 0;
  for (size_t i = 0; i < input_len; i += 3) {
    uint32_t octet_a = i < input_len ? input[i] : 0;
    uint32_t octet_b = i + 1 < input_len ? input[i + 1] : 0;
    uint32_t octet_c = i + 2 < input_len ? input[i + 2] : 0;

    uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    output[pos++] = b64_table[(triple >> 18) & 0x3F];
    output[pos++] = b64_table[(triple >> 12) & 0x3F];
    output[pos++] = (i + 1 < input_len) ? b64_table[(triple >> 6) & 0x3F] : '=';
    output[pos++] = (i + 2 < input_len) ? b64_table[triple & 0x3F] : '=';
  }

  return (int)out_len;
}

int base64_decode(const char *input, size_t input_len, uint8_t *output,
                  size_t output_capacity) {
  if (!input || !output || output_capacity == 0) {
    return -1;
  }

  size_t actual_len = 0;
  for (size_t i = 0; i < input_len; i++) {
    char c = input[i];
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
      actual_len++;
    }
  }

  size_t output_len = (actual_len * 3) / 4;
  if (output_len > output_capacity) {
    return -1;
  }

  size_t j = 0;
  uint32_t accum = 0;
  int bits = 0;

  for (size_t i = 0; i < input_len; i++) {
    char c = input[i];

    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      continue;
    }

    if (c == '=') {
      break;
    }

    uint8_t val = b64_decode_table[(uint8_t)c];
    if (val == 255) {
      return -1;
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
