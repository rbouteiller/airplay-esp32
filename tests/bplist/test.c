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

#define TEST_PI  "1f0b0a39-6a4e-4d1c-9e5a-2b8f3c7d6e10"
#define TEST_PSI "8c2d4e6f-0a1b-4c3d-8e5f-60718293a4b5"

static size_t build_info(uint8_t *out, size_t capacity, const char *name) {
  const uint8_t key[32] = {0};
  return bplist_build_info_response(
      out, capacity, "12:34:56:78:9A:BC", name, "airplay-esp32", key,
      sizeof(key), 0x1e5a7ffff7ULL, 1, 0x404, TEST_PI, TEST_PSI);
}

static size_t build_configure(uint8_t *out, size_t capacity) {
  uint8_t key[32];
  for (size_t i = 0; i < sizeof(key); i++) {
    key[i] = (uint8_t)i;
  }
  return bplist_build_configure_response(out, capacity, TEST_PI, true, key,
                                         sizeof(key), "Café", 2);
}

/* Every capacity below the full length must fail cleanly, and the full one
 * must reproduce the reference byte for byte. */
static bool check_capacities(size_t (*build)(uint8_t *, size_t),
                             const uint8_t *reference, size_t length) {
  for (size_t capacity = 0; capacity <= length + 1; capacity++) {
    uint8_t *out = malloc(capacity ? capacity : 1);
    if (!out) {
      return false;
    }
    size_t actual = build(out, capacity);
    bool valid = capacity < length
                     ? actual == 0
                     : actual == length && memcmp(out, reference, length) == 0;
    free(out);
    if (!valid) {
      fprintf(stderr, "Wrong result at capacity %zu: %zu (need %zu)\n",
              capacity, actual, length);
      return false;
    }
  }
  return true;
}

/* Read a POST /configure body on stdin and print what the parser finds in
 * its ConfigurationDictionary, one "key=value" per line ("-" when absent).
 * Every truncation of the input is parsed too, for the sanitizers. */
static int parse_configure(void) {
  static uint8_t body[8192];
  size_t len = fread(body, 1, sizeof(body), stdin);
  static const char dict[] = "ConfigurationDictionary";

  for (size_t cut = 0; cut < len; cut++) {
    uint8_t *copy = malloc(cut ? cut : 1);
    memcpy(copy, body, cut);
    bool b;
    int64_t i;
    char str[65];
    (void)bplist_find_nested_bool(copy, cut, dict, "Enable_HK_Access_Control",
                                  &b);
    (void)bplist_find_nested_int(copy, cut, dict, "Access_Control_Level", &i);
    (void)bplist_find_nested_string(copy, cut, dict, "Password", str,
                                    sizeof(str));
    free(copy);
  }

  bool enable = false;
  int64_t level = 0;
  char password[65];
  char name[65];
  if (bplist_find_nested_bool(body, len, dict, "Enable_HK_Access_Control",
                              &enable)) {
    printf("enable=%d\n", enable);
  } else {
    printf("enable=-\n");
  }
  if (bplist_find_nested_int(body, len, dict, "Access_Control_Level", &level)) {
    printf("level=%lld\n", (long long)level);
  } else {
    printf("level=-\n");
  }
  if (bplist_find_nested_string(body, len, dict, "Password", password,
                                sizeof(password))) {
    printf("password=%s\n", password);
  } else {
    printf("password=-\n");
  }
  if (bplist_find_nested_string(body, len, NULL, "Device_Name", name,
                                sizeof(name))) {
    printf("toplevel_name=%s\n", name);
  } else {
    printf("toplevel_name=-\n");
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "parse-configure") == 0) {
    return parse_configure();
  }
  if (argc == 2 && strcmp(argv[1], "configure") == 0) {
    uint8_t reference[512];
    size_t length = build_configure(reference, sizeof(reference));
    if (length == 0 || !check_capacities(build_configure, reference, length)) {
      return 1;
    }
    return fwrite(reference, 1, length, stdout) == length ? 0 : 1;
  }
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
