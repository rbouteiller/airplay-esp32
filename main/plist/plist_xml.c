#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "plist.h"

static void plist_append(plist_t *p, const char *str) {
  size_t len = strlen(str);
  if (p->size + len < p->capacity) {
    memcpy(p->buffer + p->size, str, len);
    p->size += len;
    p->buffer[p->size] = '\0';
  }
}

void plist_init(plist_t *p, char *buffer, size_t capacity) {
  p->buffer = buffer;
  p->size = 0;
  p->capacity = capacity;
  p->buffer[0] = '\0';
}

void plist_begin(plist_t *p) {
  plist_append(p, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  plist_append(p, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
                  "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
  plist_append(p, "<plist version=\"1.0\">\n");
}

void plist_dict_begin(plist_t *p) {
  plist_append(p, "<dict>\n");
}

void plist_dict_string(plist_t *p, const char *key, const char *value) {
  size_t remaining = p->capacity - p->size;
  int len = snprintf(p->buffer + p->size, remaining,
                     "<key>%s</key>\n<string>%s</string>\n", key, value);
  if (len > 0 && (size_t)len < remaining) {
    p->size += (size_t)len;
  }
}

void plist_dict_int(plist_t *p, const char *key, int64_t value) {
  size_t remaining = p->capacity - p->size;
  int len =
      snprintf(p->buffer + p->size, remaining,
               "<key>%s</key>\n<integer>%" PRId64 "</integer>\n", key, value);
  if (len > 0 && (size_t)len < remaining) {
    p->size += (size_t)len;
  }
}

void plist_dict_uint(plist_t *p, const char *key, uint64_t value) {
  size_t remaining = p->capacity - p->size;
  int len =
      snprintf(p->buffer + p->size, remaining,
               "<key>%s</key>\n<integer>%" PRIu64 "</integer>\n", key, value);
  if (len > 0 && (size_t)len < remaining) {
    p->size += (size_t)len;
  }
}

void plist_dict_bool(plist_t *p, const char *key, bool value) {
  size_t remaining = p->capacity - p->size;
  int len = snprintf(p->buffer + p->size, remaining, "<key>%s</key>\n<%s/>\n",
                     key, value ? "true" : "false");
  if (len > 0 && (size_t)len < remaining) {
    p->size += (size_t)len;
  }
}

void plist_dict_data(plist_t *p, const char *key, const uint8_t *data,
                     size_t len) {
  size_t b64_len = base64_encoded_length(len);
  size_t remaining = p->capacity - p->size;

  if (remaining < strlen(key) + b64_len + 50) {
    return;
  }

  int written =
      snprintf(p->buffer + p->size, remaining, "<key>%s</key>\n<data>", key);
  if (written > 0) {
    p->size += (size_t)written;
  }

  int encoded =
      base64_encode(data, len, p->buffer + p->size, p->capacity - p->size);
  if (encoded < 0) {
    return;
  }
  p->size += (size_t)encoded;
  p->buffer[p->size] = '\0';

  plist_append(p, "</data>\n");
}

void plist_dict_data_hex(plist_t *p, const char *key, const uint8_t *data,
                         size_t len) {
  plist_dict_data(p, key, data, len);
}

void plist_dict_end(plist_t *p) {
  plist_append(p, "</dict>\n");
}

void plist_dict_array_begin(plist_t *p, const char *key) {
  size_t remaining = p->capacity - p->size;
  int len =
      snprintf(p->buffer + p->size, remaining, "<key>%s</key>\n<array>\n", key);
  if (len > 0 && (size_t)len < remaining) {
    p->size += (size_t)len;
  }
}

void plist_array_begin(plist_t *p) {
  plist_append(p, "<array>\n");
}

void plist_array_end(plist_t *p) {
  plist_append(p, "</array>\n");
}

void plist_array_int(plist_t *p, int64_t value) {
  size_t remaining = p->capacity - p->size;
  int len = snprintf(p->buffer + p->size, remaining,
                     "<integer>%" PRId64 "</integer>\n", value);
  if (len > 0 && (size_t)len < remaining) {
    p->size += (size_t)len;
  }
}

size_t plist_end(plist_t *p) {
  plist_append(p, "</plist>\n");
  return p->size;
}
