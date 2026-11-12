// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Build the real /info response with an exactly allocated UTF-8 input. The
 * Python runner decodes it independently with plistlib. Sanitizers also check
 * every smaller output capacity and truncated UTF-8 input for overreads. */
#include "plist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int hex_digit(char ch) {
  if (ch >= '0' && ch <= '9') {
    return (unsigned int)(ch - '0');
  }
  if (ch >= 'a' && ch <= 'f') {
    return (unsigned int)(ch - 'a' + 10);
  }
  fprintf(stderr, "Invalid hex input\n");
  exit(1);
}

static size_t build_info(uint8_t *out, size_t capacity, const char *name) {
  const uint8_t key[32] = {0};
  return bplist_build_info_response(out, capacity, "12:34:56:78:9A:BC", name,
                                    key, sizeof(key), 0x1e5a7ffff7ULL, 1);
}

int main(int argc, char **argv) {
  if (argc != 2 || strlen(argv[1]) % 2 != 0) {
    return 1;
  }
  size_t name_bytes = strlen(argv[1]) / 2;
  char *name = malloc(name_bytes + 1);
  uint8_t *reference = malloc(4096);
  if (!name || !reference) {
    free(name);
    free(reference);
    return 1;
  }
  for (size_t i = 0; i < name_bytes; i++) {
    name[i] = (char)((hex_digit(argv[1][i * 2]) << 4) |
                     hex_digit(argv[1][i * 2 + 1]));
  }
  name[name_bytes] = '\0';
  size_t length = build_info(reference, 4096, name);
  if (length == 0) {
    free(name);
    free(reference);
    return 2; // Invalid UTF-8 or a name that exceeds the plist length limit.
  }

  for (size_t capacity = 0; capacity <= length + 1; capacity++) {
    uint8_t *out = malloc(capacity ? capacity : 1);
    if (!out) {
      free(name);
      free(reference);
      return 1;
    }
    size_t actual = build_info(out, capacity, name);
    bool valid = capacity < length
                     ? actual == 0
                     : actual == length && memcmp(out, reference, length) == 0;
    free(out);
    if (!valid) {
      fprintf(stderr, "Wrong result at capacity %zu: %zu (need %zu)\n",
              capacity, actual, length);
      free(name);
      free(reference);
      return 1;
    }
  }

  bool written = fwrite(reference, 1, length, stdout) == length;
  free(name);
  free(reference);
  return written ? 0 : 1;
}
