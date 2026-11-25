// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Build the AirPlay 2 remote control plists (event channel) and write one to
 * stdout for the Python runner, which decodes it with plistlib. As in test.c,
 * every smaller output capacity must fail cleanly under the sanitizers.
 *
 *   remote_test archive <group-uuid>
 *   remote_test command <number> <group-uuid>
 *   remote_test volume <0.0-1.0>
 */
#include "plist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_ID "11111111-2222-4333-8444-555555555555"

typedef struct {
  const char *mode;
  const char *uuid;
  unsigned int command;
  double volume;
} request_t;

static size_t build(const request_t *req, uint8_t *out, size_t capacity) {
  if (strcmp(req->mode, "archive") == 0) {
    return bplist_build_group_archive(out, capacity, req->uuid);
  }
  if (strcmp(req->mode, "volume") == 0) {
    return bplist_build_volume_command(out, capacity, req->volume);
  }
  uint8_t archive[512];
  size_t archive_len =
      bplist_build_group_archive(archive, sizeof(archive), req->uuid);
  if (archive_len == 0) {
    return 0;
  }
  return bplist_build_media_remote_command(out, capacity, req->command,
                                           COMMAND_ID, archive, archive_len);
}

int main(int argc, char **argv) {
  request_t req = {0};
  if (argc == 3 && strcmp(argv[1], "archive") == 0) {
    req = (request_t){.mode = "archive", .uuid = argv[2]};
  } else if (argc == 4 && strcmp(argv[1], "command") == 0) {
    req = (request_t){.mode = "command",
                      .command = (unsigned int)strtoul(argv[2], NULL, 10),
                      .uuid = argv[3]};
  } else if (argc == 3 && strcmp(argv[1], "volume") == 0) {
    req = (request_t){.mode = "volume", .volume = strtod(argv[2], NULL)};
  } else {
    return 1;
  }

  uint8_t *reference = malloc(4096);
  if (!reference) {
    return 1;
  }
  size_t length = build(&req, reference, 4096);
  if (length == 0) {
    free(reference);
    return 2;
  }

  for (size_t capacity = 0; capacity <= length + 1; capacity++) {
    uint8_t *out = malloc(capacity ? capacity : 1);
    if (!out) {
      free(reference);
      return 1;
    }
    size_t actual = build(&req, out, capacity);
    bool valid = capacity < length
                     ? actual == 0
                     : actual == length && memcmp(out, reference, length) == 0;
    free(out);
    if (!valid) {
      fprintf(stderr, "Wrong result at capacity %zu: %zu (need %zu)\n",
              capacity, actual, length);
      free(reference);
      return 1;
    }
  }

  bool written = fwrite(reference, 1, length, stdout) == length;
  free(reference);
  return written ? 0 : 1;
}
