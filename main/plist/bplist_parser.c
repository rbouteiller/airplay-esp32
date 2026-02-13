#include <inttypes.h>
#include <string.h>

#include "plist.h"

// Binary plist object types (high nibble of marker byte)
#define BPLIST_NULL    0x00
#define BPLIST_BOOL    0x00
#define BPLIST_INT     0x10
#define BPLIST_REAL    0x20
#define BPLIST_DATE    0x30
#define BPLIST_DATA    0x40
#define BPLIST_STRING  0x50
#define BPLIST_UNICODE 0x60
#define BPLIST_UID     0x80
#define BPLIST_ARRAY   0xA0
#define BPLIST_SET     0xC0
#define BPLIST_DICT    0xD0

static uint64_t read_be_int(const uint8_t *data, size_t bytes) {
  uint64_t val = 0;
  for (size_t i = 0; i < bytes; i++) {
    val = (val << 8) | data[i];
  }
  return val;
}

static bool bplist_parse_trailer(const uint8_t *plist, size_t plist_len,
                                 uint8_t *offset_size, uint8_t *ref_size,
                                 uint64_t *num_objects, uint64_t *top_object,
                                 uint64_t *offset_table_offset) {
  if (plist_len < 32) {
    return false;
  }

  const uint8_t *trailer = plist + plist_len - 32;

  *offset_size = trailer[6];
  *ref_size = trailer[7];
  *num_objects = read_be_int(trailer + 8, 8);
  *top_object = read_be_int(trailer + 16, 8);
  *offset_table_offset = read_be_int(trailer + 24, 8);

  return (*offset_size > 0 && *offset_size <= 8 && *ref_size > 0 &&
          *ref_size <= 8 && *offset_table_offset < plist_len);
}

static uint64_t bplist_get_offset(const uint8_t *plist,
                                  uint64_t offset_table_offset,
                                  uint8_t offset_size, uint64_t obj_idx) {
  const uint8_t *entry = plist + offset_table_offset + obj_idx * offset_size;
  return read_be_int(entry, offset_size);
}

static bool bplist_read_string(const uint8_t *plist, size_t plist_len,
                               uint64_t offset, char *out,
                               size_t out_capacity) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;
  size_t len = marker & 0x0F;
  size_t pos = offset + 1;

  if (len == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    if ((len_marker & 0xF0) != BPLIST_INT) {
      return false;
    }
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    len = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (type == BPLIST_STRING) {
    if (pos + len > plist_len || len >= out_capacity) {
      return false;
    }
    memcpy(out, plist + pos, len);
    out[len] = '\0';
    return true;
  }

  if (type == BPLIST_UNICODE) {
    size_t bytes = len * 2;
    if (pos + bytes > plist_len || len >= out_capacity) {
      return false;
    }
    for (size_t i = 0; i < len; i++) {
      uint16_t code =
          (uint16_t)(plist[pos + i * 2] << 8) | plist[pos + i * 2 + 1];
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

static bool bplist_read_data(const uint8_t *plist, size_t plist_len,
                             uint64_t offset, uint8_t *out, size_t out_capacity,
                             size_t *out_len) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;
  size_t len = marker & 0x0F;
  size_t pos = offset + 1;

  if (len == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    if ((len_marker & 0xF0) != BPLIST_INT) {
      return false;
    }
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    len = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (type == BPLIST_DATA) {
    if (pos + len > plist_len || len > out_capacity) {
      return false;
    }
    memcpy(out, plist + pos, len);
    *out_len = len;
    return true;
  }

  return false;
}

static bool bplist_read_data_len(const uint8_t *plist, size_t plist_len,
                                 uint64_t offset, size_t *out_len) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;
  size_t len = marker & 0x0F;
  size_t pos = offset + 1;

  if (len == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    if ((len_marker & 0xF0) != BPLIST_INT) {
      return false;
    }
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    len = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (type == BPLIST_DATA) {
    if (pos + len > plist_len) {
      return false;
    }
    *out_len = len;
    return true;
  }

  return false;
}

static bool bplist_read_string_len(const uint8_t *plist, size_t plist_len,
                                   uint64_t offset, size_t *out_len) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;
  size_t len = marker & 0x0F;
  size_t pos = offset + 1;

  if (len == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    if ((len_marker & 0xF0) != BPLIST_INT) {
      return false;
    }
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    len = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (type == BPLIST_STRING) {
    if (pos + len > plist_len) {
      return false;
    }
    *out_len = len;
    return true;
  }
  if (type == BPLIST_UNICODE) {
    size_t bytes = len * 2;
    if (pos + bytes > plist_len) {
      return false;
    }
    *out_len = len;
    return true;
  }

  return false;
}

static bool bplist_read_int(const uint8_t *plist, size_t plist_len,
                            uint64_t offset, int64_t *out) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;

  if (type == BPLIST_INT) {
    size_t len = 1 << (marker & 0x0F);
    if (offset + 1 + len > plist_len) {
      return false;
    }
    *out = (int64_t)read_be_int(plist + offset + 1, len);
    return true;
  }

  return false;
}

static bool bplist_read_real(const uint8_t *plist, size_t plist_len,
                             uint64_t offset, double *out) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;

  if (type == BPLIST_REAL) {
    size_t len = 1 << (marker & 0x0F);
    if (offset + 1 + len > plist_len) {
      return false;
    }

    if (len == 4) {
      uint32_t bits = (uint32_t)read_be_int(plist + offset + 1, 4);
      float f;
      memcpy(&f, &bits, sizeof(f));
      *out = (double)f;
      return true;
    } else if (len == 8) {
      uint64_t bits = read_be_int(plist + offset + 1, 8);
      memcpy(out, &bits, sizeof(*out));
      return true;
    }
  }

  return false;
}

static bool bplist_parse_count(const uint8_t *plist, size_t plist_len,
                               uint64_t offset, size_t *count,
                               size_t *header_len) {
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  size_t info = marker & 0x0F;
  size_t pos = offset + 1;

  if (info == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    *count = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  } else {
    *count = info;
  }

  *header_len = pos - offset;
  return true;
}

static bool bplist_find_data_in_dict(const uint8_t *plist, size_t plist_len,
                                     uint64_t dict_offset,
                                     uint64_t offset_table_offset,
                                     uint8_t offset_size, uint8_t ref_size,
                                     const char *key, uint8_t *out_data,
                                     size_t out_capacity, size_t *out_len) {
  if (dict_offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[dict_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = 0;
  size_t header_len = 0;
  if (!bplist_parse_count(plist, plist_len, dict_offset, &dict_size,
                          &header_len)) {
    return false;
  }

  size_t pos = dict_offset + header_len;
  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    char found_key[64];
    if (bplist_read_string(plist, plist_len, key_offset, found_key,
                           sizeof(found_key))) {
      if (strcmp(found_key, key) == 0) {
        uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
        uint64_t val_offset =
            bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
        return bplist_read_data(plist, plist_len, val_offset, out_data,
                                out_capacity, out_len);
      }
    }
  }

  return false;
}

static bool bplist_find_data_recursive(const uint8_t *plist, size_t plist_len,
                                       uint64_t obj_idx,
                                       uint64_t offset_table_offset,
                                       uint8_t offset_size, uint8_t ref_size,
                                       const char *key, uint8_t *out_data,
                                       size_t out_capacity, size_t *out_len,
                                       int depth) {
  if (depth > 10) {
    return false;
  }

  uint64_t offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, obj_idx);
  if (offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[offset];
  uint8_t type = marker & 0xF0;

  if (type == BPLIST_DICT) {
    size_t dict_size = 0;
    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, offset, &dict_size,
                            &header_len)) {
      return false;
    }

    size_t pos = offset + header_len;
    if (pos + dict_size * 2 * ref_size > plist_len) {
      return false;
    }

    const uint8_t *key_refs = plist + pos;
    const uint8_t *val_refs = plist + pos + dict_size * ref_size;

    for (size_t i = 0; i < dict_size; i++) {
      uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
      uint64_t key_offset =
          bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

      char found_key[64];
      if (bplist_read_string(plist, plist_len, key_offset, found_key,
                             sizeof(found_key))) {
        if (strcmp(found_key, key) == 0) {
          uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
          uint64_t val_offset = bplist_get_offset(plist, offset_table_offset,
                                                  offset_size, val_idx);
          return bplist_read_data(plist, plist_len, val_offset, out_data,
                                  out_capacity, out_len);
        }
      }
    }

    for (size_t i = 0; i < dict_size; i++) {
      uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
      if (bplist_find_data_recursive(
              plist, plist_len, val_idx, offset_table_offset, offset_size,
              ref_size, key, out_data, out_capacity, out_len, depth + 1)) {
        return true;
      }
    }
  } else if (type == BPLIST_ARRAY || type == BPLIST_SET) {
    size_t count = 0;
    size_t header_len = 0;
    if (!bplist_parse_count(plist, plist_len, offset, &count, &header_len)) {
      return false;
    }

    size_t pos = offset + header_len;
    if (pos + count * ref_size > plist_len) {
      return false;
    }

    for (size_t i = 0; i < count; i++) {
      uint64_t idx = read_be_int(plist + pos + i * ref_size, ref_size);
      if (bplist_find_data_recursive(plist, plist_len, idx, offset_table_offset,
                                     offset_size, ref_size, key, out_data,
                                     out_capacity, out_len, depth + 1)) {
        return true;
      }
    }
  }

  return false;
}

bool bplist_find_data(const uint8_t *plist, size_t plist_len, const char *key,
                      uint8_t *out_data, size_t out_capacity, size_t *out_len) {
  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  return bplist_find_data_in_dict(plist, plist_len, top_offset,
                                  offset_table_offset, offset_size, ref_size,
                                  key, out_data, out_capacity, out_len);
}

bool bplist_find_data_deep(const uint8_t *plist, size_t plist_len,
                           const char *key, uint8_t *out_data,
                           size_t out_capacity, size_t *out_len) {
  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  (void)num_objects;
  return bplist_find_data_recursive(plist, plist_len, top_object,
                                    offset_table_offset, offset_size, ref_size,
                                    key, out_data, out_capacity, out_len, 0);
}

bool bplist_find_int(const uint8_t *plist, size_t plist_len, const char *key,
                     int64_t *out_value) {
  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[top_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = marker & 0x0F;
  size_t pos = top_offset + 1;

  if (dict_size == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    dict_size = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    char found_key[64];
    if (bplist_read_string(plist, plist_len, key_offset, found_key,
                           sizeof(found_key))) {
      if (strcmp(found_key, key) == 0) {
        uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
        uint64_t val_offset =
            bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
        return bplist_read_int(plist, plist_len, val_offset, out_value);
      }
    }
  }

  return false;
}

bool bplist_find_real(const uint8_t *plist, size_t plist_len, const char *key,
                      double *out_value) {
  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[top_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = marker & 0x0F;
  size_t pos = top_offset + 1;

  if (dict_size == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    dict_size = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    char found_key[64];
    if (bplist_read_string(plist, plist_len, key_offset, found_key,
                           sizeof(found_key))) {
      if (strcmp(found_key, key) == 0) {
        uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
        uint64_t val_offset =
            bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
        if (bplist_read_real(plist, plist_len, val_offset, out_value)) {
          return true;
        }
        int64_t int_val = 0;
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

bool bplist_find_string(const uint8_t *plist, size_t plist_len, const char *key,
                        char *out_str, size_t out_capacity) {
  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  uint8_t marker = plist[top_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = marker & 0x0F;
  size_t pos = top_offset + 1;

  if (dict_size == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    dict_size = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    char found_key[64];
    if (bplist_read_string(plist, plist_len, key_offset, found_key,
                           sizeof(found_key))) {
      if (strcmp(found_key, key) == 0) {
        uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
        uint64_t val_offset =
            bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);
        return bplist_read_string(plist, plist_len, val_offset, out_str,
                                  out_capacity);
      }
    }
  }

  return false;
}

bool bplist_get_streams_count(const uint8_t *plist, size_t plist_len,
                              size_t *count) {
  if (!count) {
    return false;
  }

  *count = 0;

  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  size_t streams_key_len = 0;
  uint64_t streams_key_offset = 0;
  for (uint64_t i = 0; i < num_objects; i++) {
    uint64_t offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, i);
    if (offset >= plist_len) {
      continue;
    }
    char key[16];
    if (bplist_read_string(plist, plist_len, offset, key, sizeof(key))) {
      if (strcmp(key, "streams") == 0) {
        streams_key_offset = offset;
        if (!bplist_read_string_len(plist, plist_len, offset,
                                    &streams_key_len)) {
          return false;
        }
        break;
      }
    }
  }

  if (streams_key_len == 0) {
    return false;
  }

  uint64_t top_dict_offset = top_offset;
  uint8_t marker = plist[top_dict_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = marker & 0x0F;
  size_t pos = top_dict_offset + 1;
  if (dict_size == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    dict_size = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    if (key_offset == streams_key_offset) {
      uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
      uint64_t val_offset =
          bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);

      uint8_t val_marker = plist[val_offset];
      if ((val_marker & 0xF0) != BPLIST_ARRAY) {
        return false;
      }

      size_t array_count = 0;
      size_t header_len = 0;
      if (!bplist_parse_count(plist, plist_len, val_offset, &array_count,
                              &header_len)) {
        return false;
      }

      *count = array_count;
      return true;
    }
  }

  return false;
}

bool bplist_get_stream_info(const uint8_t *plist, size_t plist_len,
                            size_t index, int64_t *type, size_t *ekey_len,
                            size_t *eiv_len, size_t *shk_len) {
  if (!type) {
    return false;
  }

  *type = -1;
  if (ekey_len) {
    *ekey_len = 0;
  }
  if (eiv_len) {
    *eiv_len = 0;
  }
  if (shk_len) {
    *shk_len = 0;
  }

  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  size_t streams_key_len = 0;
  uint64_t streams_key_offset = 0;
  for (uint64_t i = 0; i < num_objects; i++) {
    uint64_t offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, i);
    if (offset >= plist_len) {
      continue;
    }
    char key[16];
    if (bplist_read_string(plist, plist_len, offset, key, sizeof(key))) {
      if (strcmp(key, "streams") == 0) {
        streams_key_offset = offset;
        if (!bplist_read_string_len(plist, plist_len, offset,
                                    &streams_key_len)) {
          return false;
        }
        break;
      }
    }
  }

  if (streams_key_len == 0) {
    return false;
  }

  uint64_t top_dict_offset = top_offset;
  uint8_t marker = plist[top_dict_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = marker & 0x0F;
  size_t pos = top_dict_offset + 1;
  if (dict_size == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    dict_size = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    if (key_offset == streams_key_offset) {
      uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
      uint64_t val_offset =
          bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);

      uint8_t val_marker = plist[val_offset];
      if ((val_marker & 0xF0) != BPLIST_ARRAY) {
        return false;
      }

      size_t array_count = 0;
      size_t header_len = 0;
      if (!bplist_parse_count(plist, plist_len, val_offset, &array_count,
                              &header_len)) {
        return false;
      }

      if (index >= array_count) {
        return false;
      }

      size_t array_pos = val_offset + header_len;
      if (array_pos + array_count * ref_size > plist_len) {
        return false;
      }

      uint64_t stream_idx =
          read_be_int(plist + array_pos + index * ref_size, ref_size);
      uint64_t stream_offset = bplist_get_offset(plist, offset_table_offset,
                                                 offset_size, stream_idx);

      uint8_t stream_marker = plist[stream_offset];
      if ((stream_marker & 0xF0) != BPLIST_DICT) {
        return false;
      }

      size_t stream_dict_size = 0;
      size_t stream_header_len = 0;
      if (!bplist_parse_count(plist, plist_len, stream_offset,
                              &stream_dict_size, &stream_header_len)) {
        return false;
      }

      size_t stream_pos = stream_offset + stream_header_len;
      if (stream_pos + stream_dict_size * 2 * ref_size > plist_len) {
        return false;
      }

      const uint8_t *stream_key_refs = plist + stream_pos;
      const uint8_t *stream_val_refs =
          plist + stream_pos + stream_dict_size * ref_size;

      for (size_t j = 0; j < stream_dict_size; j++) {
        uint64_t stream_key_idx =
            read_be_int(stream_key_refs + j * ref_size, ref_size);
        uint64_t stream_key_offset = bplist_get_offset(
            plist, offset_table_offset, offset_size, stream_key_idx);

        char stream_key[32];
        if (!bplist_read_string(plist, plist_len, stream_key_offset, stream_key,
                                sizeof(stream_key))) {
          continue;
        }

        uint64_t stream_val_idx =
            read_be_int(stream_val_refs + j * ref_size, ref_size);
        uint64_t stream_val_offset = bplist_get_offset(
            plist, offset_table_offset, offset_size, stream_val_idx);

        if (strcmp(stream_key, "type") == 0) {
          int64_t type_val = 0;
          if (bplist_read_int(plist, plist_len, stream_val_offset, &type_val)) {
            *type = type_val;
          }
        } else if (strcmp(stream_key, "ekey") == 0 && ekey_len) {
          bplist_read_data_len(plist, plist_len, stream_val_offset, ekey_len);
        } else if (strcmp(stream_key, "eiv") == 0 && eiv_len) {
          bplist_read_data_len(plist, plist_len, stream_val_offset, eiv_len);
        } else if (strcmp(stream_key, "shk") == 0 && shk_len) {
          bplist_read_data_len(plist, plist_len, stream_val_offset, shk_len);
        }
      }

      return (*type != -1);
    }
  }

  return false;
}

bool bplist_get_stream_kv_info(const uint8_t *plist, size_t plist_len,
                               size_t index, bplist_kv_info_t *out,
                               size_t out_capacity, size_t *out_count) {
  if (!out || out_capacity == 0 || !out_count) {
    return false;
  }

  *out_count = 0;

  if (plist_len < 40 || memcmp(plist, "bplist00", 8) != 0) {
    return false;
  }

  uint8_t offset_size = 0;
  uint8_t ref_size = 0;
  uint64_t num_objects = 0;
  uint64_t top_object = 0;
  uint64_t offset_table_offset = 0;
  if (!bplist_parse_trailer(plist, plist_len, &offset_size, &ref_size,
                            &num_objects, &top_object, &offset_table_offset)) {
    return false;
  }

  uint64_t top_offset =
      bplist_get_offset(plist, offset_table_offset, offset_size, top_object);
  if (top_offset >= plist_len) {
    return false;
  }

  size_t streams_key_len = 0;
  uint64_t streams_key_offset = 0;
  for (uint64_t i = 0; i < num_objects; i++) {
    uint64_t offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, i);
    if (offset >= plist_len) {
      continue;
    }
    char key[16];
    if (bplist_read_string(plist, plist_len, offset, key, sizeof(key))) {
      if (strcmp(key, "streams") == 0) {
        streams_key_offset = offset;
        if (!bplist_read_string_len(plist, plist_len, offset,
                                    &streams_key_len)) {
          return false;
        }
        break;
      }
    }
  }

  if (streams_key_len == 0) {
    return false;
  }

  uint64_t top_dict_offset = top_offset;
  uint8_t marker = plist[top_dict_offset];
  if ((marker & 0xF0) != BPLIST_DICT) {
    return false;
  }

  size_t dict_size = marker & 0x0F;
  size_t pos = top_dict_offset + 1;
  if (dict_size == 0x0F) {
    if (pos >= plist_len) {
      return false;
    }
    uint8_t len_marker = plist[pos++];
    size_t len_bytes = 1 << (len_marker & 0x0F);
    if (pos + len_bytes > plist_len) {
      return false;
    }
    dict_size = (size_t)read_be_int(plist + pos, len_bytes);
    pos += len_bytes;
  }

  if (pos + dict_size * 2 * ref_size > plist_len) {
    return false;
  }

  const uint8_t *key_refs = plist + pos;
  const uint8_t *val_refs = plist + pos + dict_size * ref_size;

  for (size_t i = 0; i < dict_size; i++) {
    uint64_t key_idx = read_be_int(key_refs + i * ref_size, ref_size);
    uint64_t key_offset =
        bplist_get_offset(plist, offset_table_offset, offset_size, key_idx);

    if (key_offset == streams_key_offset) {
      uint64_t val_idx = read_be_int(val_refs + i * ref_size, ref_size);
      uint64_t val_offset =
          bplist_get_offset(plist, offset_table_offset, offset_size, val_idx);

      uint8_t val_marker = plist[val_offset];
      if ((val_marker & 0xF0) != BPLIST_ARRAY) {
        return false;
      }

      size_t array_count = 0;
      size_t header_len = 0;
      if (!bplist_parse_count(plist, plist_len, val_offset, &array_count,
                              &header_len)) {
        return false;
      }

      if (index >= array_count) {
        return false;
      }

      size_t array_pos = val_offset + header_len;
      if (array_pos + array_count * ref_size > plist_len) {
        return false;
      }

      uint64_t stream_idx =
          read_be_int(plist + array_pos + index * ref_size, ref_size);
      uint64_t stream_offset = bplist_get_offset(plist, offset_table_offset,
                                                 offset_size, stream_idx);

      uint8_t stream_marker = plist[stream_offset];
      if ((stream_marker & 0xF0) != BPLIST_DICT) {
        return false;
      }

      size_t stream_dict_size = 0;
      size_t stream_header_len = 0;
      if (!bplist_parse_count(plist, plist_len, stream_offset,
                              &stream_dict_size, &stream_header_len)) {
        return false;
      }

      size_t stream_pos = stream_offset + stream_header_len;
      if (stream_pos + stream_dict_size * 2 * ref_size > plist_len) {
        return false;
      }

      const uint8_t *stream_key_refs = plist + stream_pos;
      const uint8_t *stream_val_refs =
          plist + stream_pos + stream_dict_size * ref_size;

      for (size_t j = 0; j < stream_dict_size && *out_count < out_capacity;
           j++) {
        uint64_t stream_key_idx =
            read_be_int(stream_key_refs + j * ref_size, ref_size);
        uint64_t stream_key_offset = bplist_get_offset(
            plist, offset_table_offset, offset_size, stream_key_idx);

        char stream_key[64];
        if (!bplist_read_string(plist, plist_len, stream_key_offset, stream_key,
                                sizeof(stream_key))) {
          continue;
        }

        uint64_t stream_val_idx =
            read_be_int(stream_val_refs + j * ref_size, ref_size);
        uint64_t stream_val_offset = bplist_get_offset(
            plist, offset_table_offset, offset_size, stream_val_idx);

        bplist_kv_info_t *info = &out[*out_count];
        memset(info, 0, sizeof(*info));
        strncpy(info->key, stream_key, sizeof(info->key) - 1);

        uint8_t stream_val_marker = plist[stream_val_offset];
        uint8_t stream_val_type = stream_val_marker & 0xF0;

        if (stream_val_type == BPLIST_INT) {
          info->value_type = BPLIST_VALUE_INT;
          int64_t int_val = 0;
          if (bplist_read_int(plist, plist_len, stream_val_offset, &int_val)) {
            info->int_value = int_val;
          }
        } else if (stream_val_type == BPLIST_DATA) {
          info->value_type = BPLIST_VALUE_DATA;
          size_t len = 0;
          if (bplist_read_data_len(plist, plist_len, stream_val_offset, &len)) {
            info->value_len = len;
          }
        } else if (stream_val_type == BPLIST_STRING ||
                   stream_val_type == BPLIST_UNICODE) {
          info->value_type = BPLIST_VALUE_STRING;
          size_t len = 0;
          if (bplist_read_string_len(plist, plist_len, stream_val_offset,
                                     &len)) {
            info->value_len = len;
          }
        } else if (stream_val_type == BPLIST_UID) {
          info->value_type = BPLIST_VALUE_UID;
        } else if (stream_val_type == BPLIST_ARRAY) {
          info->value_type = BPLIST_VALUE_ARRAY;
        } else if (stream_val_type == BPLIST_DICT) {
          info->value_type = BPLIST_VALUE_DICT;
        }

        (*out_count)++;
      }

      return (*out_count > 0);
    }
  }

  return false;
}

bool bplist_find_stream_crypto(const uint8_t *plist, size_t plist_len,
                               int64_t stream_type, uint8_t *ekey,
                               size_t ekey_capacity, size_t *ekey_len,
                               uint8_t *eiv, size_t eiv_capacity,
                               size_t *eiv_len, uint8_t *shk,
                               size_t shk_capacity, size_t *shk_len) {
  bool found = false;

  if (ekey_len) {
    *ekey_len = 0;
  }
  if (eiv_len) {
    *eiv_len = 0;
  }
  if (shk_len) {
    *shk_len = 0;
  }

  size_t stream_count = 0;
  if (!bplist_get_streams_count(plist, plist_len, &stream_count)) {
    return false;
  }

  for (size_t i = 0; i < stream_count; i++) {
    int64_t type = -1;
    size_t local_ekey_len = 0;
    size_t local_eiv_len = 0;
    size_t local_shk_len = 0;

    if (!bplist_get_stream_info(plist, plist_len, i, &type, &local_ekey_len,
                                &local_eiv_len, &local_shk_len)) {
      continue;
    }

    if (type != stream_type) {
      continue;
    }

    uint8_t temp_buf[512];
    size_t temp_len = 0;

    if (ekey && local_ekey_len > 0 && ekey_len) {
      if (bplist_find_data(plist, plist_len, "ekey", temp_buf, sizeof(temp_buf),
                           &temp_len)) {
        size_t copy_len = temp_len < ekey_capacity ? temp_len : ekey_capacity;
        memcpy(ekey, temp_buf, copy_len);
        *ekey_len = copy_len;
        found = true;
      }
    }

    if (eiv && local_eiv_len > 0 && eiv_len) {
      if (bplist_find_data(plist, plist_len, "eiv", temp_buf, sizeof(temp_buf),
                           &temp_len)) {
        size_t copy_len = temp_len < eiv_capacity ? temp_len : eiv_capacity;
        memcpy(eiv, temp_buf, copy_len);
        *eiv_len = copy_len;
        found = true;
      }
    }

    if (shk && local_shk_len > 0 && shk_len) {
      if (bplist_find_data(plist, plist_len, "shk", temp_buf, sizeof(temp_buf),
                           &temp_len)) {
        size_t copy_len = temp_len < shk_capacity ? temp_len : shk_capacity;
        memcpy(shk, temp_buf, copy_len);
        *shk_len = copy_len;
        found = true;
      }
    }

    break;
  }

  return found;
}
