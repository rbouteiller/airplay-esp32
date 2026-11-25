// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "audio_stream.h"
#include "plist.h"

/* No terminator. */
static const uint8_t BPLIST_MAGIC[8] = {'b', 'p', 'l', 'i', 's', 't', '0', '0'};

static bool bplist_has_room(size_t pos, size_t need, size_t capacity) {
  return pos <= capacity && need <= capacity - pos;
}

static bool bplist_write_u64(uint8_t *out, size_t capacity, size_t *pos,
                             uint64_t value) {
  if (!bplist_has_room(*pos, 8, capacity)) {
    return false;
  }
  for (int i = 7; i >= 0; i--) {
    out[(*pos)++] = (uint8_t)(value >> (i * 8));
  }
  return true;
}

static bool bplist_write_length(uint8_t *out, size_t capacity, size_t *pos,
                                uint8_t marker_base, size_t length) {
  if (length < 15) {
    if (!bplist_has_room(*pos, 1, capacity)) {
      return false;
    }
    out[(*pos)++] = marker_base | (uint8_t)length;
    return true;
  }
  if (length <= UINT8_MAX) {
    if (!bplist_has_room(*pos, 3, capacity)) {
      return false;
    }
    out[(*pos)++] = marker_base | 0x0F;
    out[(*pos)++] = 0x10;
    out[(*pos)++] = (uint8_t)length;
    return true;
  }
  // 2-byte lengths (the group UUID archive is ~300 bytes)
  if (length > UINT16_MAX || !bplist_has_room(*pos, 4, capacity)) {
    return false;
  }
  out[(*pos)++] = marker_base | 0x0F;
  out[(*pos)++] = 0x11;
  out[(*pos)++] = (uint8_t)(length >> 8);
  out[(*pos)++] = (uint8_t)length;
  return true;
}

static bool bplist_write_ascii_string(uint8_t *out, size_t capacity,
                                      size_t *pos, const char *value) {
  size_t len = strlen(value);
  if (!bplist_write_length(out, capacity, pos, 0x50, len) ||
      !bplist_has_room(*pos, len, capacity)) {
    return false;
  }
  // Length-prefixed, no terminator.
  // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
  memcpy(out + *pos, value, len);
  *pos += len;
  return true;
}

static bool bplist_utf8_next(const char **cursor, uint32_t *codepoint) {
  const uint8_t *s = (const uint8_t *)*cursor;
  uint32_t cp;
  size_t n;

  if (s[0] < 0x80) {
    cp = s[0];
    n = 1;
  } else if ((s[0] & 0xE0) == 0xC0) {
    if (s[1] == 0 || (s[1] & 0xC0) != 0x80) {
      return false;
    }
    cp = ((uint32_t)(s[0] & 0x1F) << 6) | (uint32_t)(s[1] & 0x3F);
    if (cp < 0x80) {
      return false;
    }
    n = 2;
  } else if ((s[0] & 0xF0) == 0xE0) {
    if (s[1] == 0 || s[2] == 0 || (s[1] & 0xC0) != 0x80 ||
        (s[2] & 0xC0) != 0x80) {
      return false;
    }
    cp = ((uint32_t)(s[0] & 0x0F) << 12) | ((uint32_t)(s[1] & 0x3F) << 6) |
         (uint32_t)(s[2] & 0x3F);
    if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) {
      return false;
    }
    n = 3;
  } else if ((s[0] & 0xF8) == 0xF0) {
    if (s[1] == 0 || s[2] == 0 || s[3] == 0 || (s[1] & 0xC0) != 0x80 ||
        (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) {
      return false;
    }
    cp = ((uint32_t)(s[0] & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
         ((uint32_t)(s[2] & 0x3F) << 6) | (uint32_t)(s[3] & 0x3F);
    if (cp < 0x10000 || cp > 0x10FFFF) {
      return false;
    }
    n = 4;
  } else {
    return false;
  }

  *cursor += n;
  *codepoint = cp;
  return true;
}

static bool bplist_write_utf8_string(uint8_t *out, size_t capacity, size_t *pos,
                                     const char *value) {
  bool ascii_only = true;
  for (const uint8_t *p = (const uint8_t *)value; *p; p++) {
    if (*p & 0x80) {
      ascii_only = false;
      break;
    }
  }
  if (ascii_only) {
    return bplist_write_ascii_string(out, capacity, pos, value);
  }

  size_t utf16_units = 0;
  const char *p = value;
  while (*p) {
    uint32_t cp;
    if (!bplist_utf8_next(&p, &cp)) {
      return false;
    }
    utf16_units += (cp <= 0xFFFF) ? 1 : 2;
  }

  if (!bplist_write_length(out, capacity, pos, 0x60, utf16_units) ||
      !bplist_has_room(*pos, utf16_units * 2, capacity)) {
    return false;
  }

  p = value;
  while (*p) {
    uint32_t cp;
    if (!bplist_utf8_next(&p, &cp)) {
      return false;
    }

    if (cp <= 0xFFFF) {
      out[(*pos)++] = (uint8_t)(cp >> 8);
      out[(*pos)++] = (uint8_t)cp;
    } else {
      cp -= 0x10000;
      uint16_t high = (uint16_t)(0xD800 + (cp >> 10));
      uint16_t low = (uint16_t)(0xDC00 + (cp & 0x3FF));
      out[(*pos)++] = (uint8_t)(high >> 8);
      out[(*pos)++] = (uint8_t)high;
      out[(*pos)++] = (uint8_t)(low >> 8);
      out[(*pos)++] = (uint8_t)low;
    }
  }
  return true;
}

static bool bplist_write_data(uint8_t *out, size_t capacity, size_t *pos,
                              const uint8_t *data, size_t len) {
  if (!bplist_write_length(out, capacity, pos, 0x40, len) ||
      !bplist_has_room(*pos, len, capacity)) {
    return false;
  }
  memcpy(out + *pos, data, len);
  *pos += len;
  return true;
}

static bool bplist_write_int(uint8_t *out, size_t capacity, size_t *pos,
                             uint64_t value) {
  uint8_t marker;
  size_t bytes;
  if (value <= UINT8_MAX) {
    marker = 0x10;
    bytes = 1;
  } else if (value <= UINT16_MAX) {
    marker = 0x11;
    bytes = 2;
  } else if (value <= UINT32_MAX) {
    marker = 0x12;
    bytes = 4;
  } else {
    marker = 0x13;
    bytes = 8;
  }

  if (!bplist_has_room(*pos, 1 + bytes, capacity)) {
    return false;
  }
  out[(*pos)++] = marker;
  for (int i = (int)bytes - 1; i >= 0; i--) {
    out[(*pos)++] = (uint8_t)(value >> (i * 8));
  }
  return true;
}

static bool bplist_write_refs(uint8_t *out, size_t capacity, size_t *pos,
                              const uint8_t *refs, size_t count) {
  if (!bplist_has_room(*pos, count, capacity)) {
    return false;
  }
  memcpy(out + *pos, refs, count);
  *pos += count;
  return true;
}

static bool bplist_write_array(uint8_t *out, size_t capacity, size_t *pos,
                               const uint8_t *refs, size_t count) {
  return bplist_write_length(out, capacity, pos, 0xA0, count) &&
         bplist_write_refs(out, capacity, pos, refs, count);
}

static bool bplist_write_dict(uint8_t *out, size_t capacity, size_t *pos,
                              const uint8_t *keys, const uint8_t *values,
                              size_t count) {
  return bplist_write_length(out, capacity, pos, 0xD0, count) &&
         bplist_write_refs(out, capacity, pos, keys, count) &&
         bplist_write_refs(out, capacity, pos, values, count);
}

static bool bplist_finish(uint8_t *out, size_t capacity, size_t *pos,
                          const size_t *offsets, size_t object_count,
                          size_t top_object) {
  size_t offset_table_offset = *pos;
  for (size_t i = 0; i < object_count; i++) {
    if (offsets[i] > UINT16_MAX || !bplist_has_room(*pos, 2, capacity)) {
      return false;
    }
    out[(*pos)++] = (uint8_t)(offsets[i] >> 8);
    out[(*pos)++] = (uint8_t)offsets[i];
  }

  if (!bplist_has_room(*pos, 32, capacity)) {
    return false;
  }
  memset(out + *pos, 0, 6);
  *pos += 6;
  out[(*pos)++] = 2; // offset size
  out[(*pos)++] = 1; // object ref size

  if (!bplist_write_u64(out, capacity, pos, object_count) ||
      !bplist_write_u64(out, capacity, pos, top_object) ||
      !bplist_write_u64(out, capacity, pos, offset_table_offset)) {
    return false;
  }
  return true;
}

size_t bplist_build_initial_setup(uint8_t *out, size_t capacity,
                                  uint16_t event_port) {
  if (capacity < 100) {
    return 0;
  }

  size_t pos = 0;
  memcpy(out + pos, BPLIST_MAGIC, sizeof(BPLIST_MAGIC));
  pos += 8;

  size_t offsets[10];
  size_t obj = 0;

  offsets[obj++] = pos;
  out[pos++] = 0x59;
  memcpy(out + pos, "eventPort", 9);
  pos += 9;

  offsets[obj++] = pos;
  out[pos++] = 0x5A;
  memcpy(out + pos, "timingPort", 10);
  pos += 10;

  offsets[obj++] = pos;
  out[pos++] = 0x11;
  out[pos++] = (event_port >> 8) & 0xFF;
  out[pos++] = event_port & 0xFF;

  offsets[obj++] = pos;
  out[pos++] = 0x10;
  out[pos++] = 0;

  offsets[obj++] = pos;
  out[pos++] = 0xD2;
  out[pos++] = 0;
  out[pos++] = 1;
  out[pos++] = 2;
  out[pos++] = 3;

  size_t offset_table_offset = pos;
  for (size_t i = 0; i < obj; i++) {
    if (offsets[i] > 0xFF) {
      return 0;
    }
    out[pos++] = (uint8_t)offsets[i];
  }

  memset(out + pos, 0, 6);
  pos += 6;
  out[pos++] = 1;
  out[pos++] = 1;

  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = (uint8_t)obj;

  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = 4;

  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = (uint8_t)offset_table_offset;

  return pos;
}

size_t bplist_build_stream_setup(uint8_t *out, size_t capacity,
                                 int64_t stream_type, uint16_t data_port,
                                 uint16_t control_port,
                                 uint32_t audio_buffer_size) {
  if (capacity < 200) {
    return 0;
  }

  size_t pos = 0;
  memcpy(out + pos, BPLIST_MAGIC, sizeof(BPLIST_MAGIC));
  pos += 8;

  size_t offsets[16];
  size_t obj = 0;

  offsets[obj++] = pos;
  out[pos++] = 0x57;
  memcpy(out + pos, "streams", 7);
  pos += 7;

  offsets[obj++] = pos;
  out[pos++] = 0x54;
  memcpy(out + pos, "type", 4);
  pos += 4;

  offsets[obj++] = pos;
  out[pos++] = 0x58;
  memcpy(out + pos, "dataPort", 8);
  pos += 8;

  offsets[obj++] = pos;
  out[pos++] = 0x5B;
  memcpy(out + pos, "controlPort", 11);
  pos += 11;

  offsets[obj++] = pos;
  out[pos++] = 0x5F;
  out[pos++] = 0x10;
  out[pos++] = 15;
  memcpy(out + pos, "audioBufferSize", 15);
  pos += 15;

  offsets[obj++] = pos;
  out[pos++] = 0x10;
  out[pos++] = (uint8_t)stream_type;

  offsets[obj++] = pos;
  out[pos++] = 0x11;
  out[pos++] = (data_port >> 8) & 0xFF;
  out[pos++] = data_port & 0xFF;

  offsets[obj++] = pos;
  out[pos++] = 0x11;
  out[pos++] = (control_port >> 8) & 0xFF;
  out[pos++] = control_port & 0xFF;

  offsets[obj++] = pos;
  out[pos++] = 0x12;
  out[pos++] = (audio_buffer_size >> 24) & 0xFF;
  out[pos++] = (audio_buffer_size >> 16) & 0xFF;
  out[pos++] = (audio_buffer_size >> 8) & 0xFF;
  out[pos++] = audio_buffer_size & 0xFF;

  offsets[obj++] = pos;
  if (audio_stream_uses_buffer((audio_stream_type_t)stream_type)) {
    out[pos++] = 0xD4;
    out[pos++] = 1;
    out[pos++] = 2;
    out[pos++] = 4;
    out[pos++] = 3;
    out[pos++] = 5;
    out[pos++] = 6;
    out[pos++] = 8;
    out[pos++] = 7;
  } else {
    out[pos++] = 0xD3;
    out[pos++] = 1;
    out[pos++] = 2;
    out[pos++] = 3;
    out[pos++] = 5;
    out[pos++] = 6;
    out[pos++] = 7;
  }

  offsets[obj++] = pos;
  out[pos++] = 0xA1;
  out[pos++] = 9;

  offsets[obj++] = pos;
  out[pos++] = 0xD1;
  out[pos++] = 0;
  out[pos++] = 10;

  size_t offset_table_offset = pos;
  for (size_t i = 0; i < obj; i++) {
    if (offsets[i] > 0xFF) {
      return 0;
    }
    out[pos++] = (uint8_t)offsets[i];
  }

  memset(out + pos, 0, 6);
  pos += 6;
  out[pos++] = 1;
  out[pos++] = 1;

  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = (uint8_t)obj;

  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = 11;

  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = (uint8_t)offset_table_offset;

  return pos;
}

size_t bplist_build_feedback_response(uint8_t *out, size_t capacity,
                                      int64_t stream_type, double sample_rate) {
  // Feedback response for buffered audio streams (type 103)
  // Format: { streams: [ { type: 103, sr: 44100.0 } ] }
  // This acts as a keepalive mechanism to prevent iPhone from
  // sending TEARDOWN during extended pause
  if (capacity < 100) {
    return 0;
  }

  size_t pos = 0;
  memcpy(out + pos, BPLIST_MAGIC, sizeof(BPLIST_MAGIC));
  pos += 8;

  size_t offsets[10];
  size_t obj = 0;

  // Object 0: "streams" key string
  offsets[obj++] = pos;
  out[pos++] = 0x57; // String, length 7
  memcpy(out + pos, "streams", 7);
  pos += 7;

  // Object 1: "type" key string
  offsets[obj++] = pos;
  out[pos++] = 0x54; // String, length 4
  memcpy(out + pos, "type", 4);
  pos += 4;

  // Object 2: "sr" key string (sample rate)
  offsets[obj++] = pos;
  out[pos++] = 0x52; // String, length 2
  memcpy(out + pos, "sr", 2);
  pos += 2;

  // Object 3: type value (103 for buffered audio)
  offsets[obj++] = pos;
  out[pos++] = 0x10; // Int, 1 byte
  out[pos++] = (uint8_t)stream_type;

  // Object 4: sample rate value as double
  // IEEE 754 double-precision big-endian
  offsets[obj++] = pos;
  out[pos++] = 0x23; // Real, 8 bytes (double)
  union {
    double d;
    uint8_t bytes[8];
  } sr;
  sr.d = sample_rate;
  // Convert to big-endian
  for (int i = 7; i >= 0; i--) {
    out[pos++] = sr.bytes[i];
  }

  // Object 5: stream dict { type: 3, sr: 4 }
  offsets[obj++] = pos;
  out[pos++] = 0xD2; // Dict, 2 key-value pairs
  out[pos++] = 1;    // Key: object 1 (type)
  out[pos++] = 2;    // Key: object 2 (sr)
  out[pos++] = 3;    // Value: object 3 (type value)
  out[pos++] = 4;    // Value: object 4 (sr value)

  // Object 6: streams array [ object 5 ]
  offsets[obj++] = pos;
  out[pos++] = 0xA1; // Array, 1 element
  out[pos++] = 5;    // Contains object 5 (stream dict)

  // Object 7: top-level dict { streams: 6 }
  offsets[obj++] = pos;
  out[pos++] = 0xD1; // Dict, 1 key-value pair
  out[pos++] = 0;    // Key: object 0 (streams)
  out[pos++] = 6;    // Value: object 6 (streams array)

  // Offset table
  size_t offset_table_offset = pos;
  for (size_t i = 0; i < obj; i++) {
    if (offsets[i] > 0xFF) {
      return 0;
    }
    out[pos++] = (uint8_t)offsets[i];
  }

  // Trailer: 6 unused bytes, then metadata
  memset(out + pos, 0, 6);
  pos += 6;
  out[pos++] = 1; // Offset size
  out[pos++] = 1; // Object ref size

  // Number of objects (8 bytes big-endian)
  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = (uint8_t)obj;

  // Top object index (8 bytes big-endian)
  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = 7; // Top object is object 7

  // Offset table offset (8 bytes big-endian)
  for (int i = 0; i < 7; i++) {
    out[pos++] = 0;
  }
  out[pos++] = (uint8_t)offset_table_offset;

  return pos;
}

size_t bplist_build_info_response(
    uint8_t *out, size_t capacity, const char *device_id,
    const char *device_name, const char *model, const uint8_t *public_key,
    size_t public_key_len, uint64_t features, int64_t protocol_version,
    uint32_t status_flags, const char *pi, const char *psi) {
  if (!out || !device_id || !device_name || !model || !public_key ||
      public_key_len == 0 || !pi || !psi || capacity < 512) {
    return 0;
  }

  size_t pos = 0;
  size_t offsets[41];
  size_t obj = 0;

#define ADD_OFFSET()                                   \
  do {                                                 \
    if (obj >= sizeof(offsets) / sizeof(offsets[0])) { \
      return 0;                                        \
    }                                                  \
    offsets[obj++] = pos;                              \
  } while (0)

  if (!bplist_has_room(pos, 8, capacity)) {
    return 0;
  }
  memcpy(out + pos, BPLIST_MAGIC, sizeof(BPLIST_MAGIC));
  pos += 8;

  ADD_OFFSET(); // 0: "deviceid"
  if (!bplist_write_ascii_string(out, capacity, &pos, "deviceid")) {
    return 0;
  }
  ADD_OFFSET(); // 1: device id
  if (!bplist_write_ascii_string(out, capacity, &pos, device_id)) {
    return 0;
  }
  ADD_OFFSET(); // 2: "features"
  if (!bplist_write_ascii_string(out, capacity, &pos, "features")) {
    return 0;
  }
  ADD_OFFSET(); // 3: features
  if (!bplist_write_int(out, capacity, &pos, features)) {
    return 0;
  }
  ADD_OFFSET(); // 4: "model"
  if (!bplist_write_ascii_string(out, capacity, &pos, "model")) {
    return 0;
  }
  ADD_OFFSET(); // 5: model
  if (!bplist_write_ascii_string(out, capacity, &pos, model)) {
    return 0;
  }
  ADD_OFFSET(); // 6: "protovers"
  if (!bplist_write_ascii_string(out, capacity, &pos, "protovers")) {
    return 0;
  }
  ADD_OFFSET(); // 7: protocol version string
  if (!bplist_write_ascii_string(out, capacity, &pos, "1.1")) {
    return 0;
  }
  ADD_OFFSET(); // 8: "srcvers"
  if (!bplist_write_ascii_string(out, capacity, &pos, "srcvers")) {
    return 0;
  }
  ADD_OFFSET(); // 9: source version string
  if (!bplist_write_ascii_string(out, capacity, &pos, "377.40.00")) {
    return 0;
  }
  ADD_OFFSET(); // 10: "vv"
  if (!bplist_write_ascii_string(out, capacity, &pos, "vv")) {
    return 0;
  }
  ADD_OFFSET(); // 11: vv value
  if (!bplist_write_int(out, capacity, &pos, (uint64_t)protocol_version)) {
    return 0;
  }
  ADD_OFFSET(); // 12: "statusFlags"
  if (!bplist_write_ascii_string(out, capacity, &pos, "statusFlags")) {
    return 0;
  }
  ADD_OFFSET(); // 13: statusFlags value
  if (!bplist_write_int(out, capacity, &pos, status_flags)) {
    return 0;
  }
  ADD_OFFSET(); // 14: "pk"
  if (!bplist_write_ascii_string(out, capacity, &pos, "pk")) {
    return 0;
  }
  ADD_OFFSET(); // 15: public key
  if (!bplist_write_data(out, capacity, &pos, public_key, public_key_len)) {
    return 0;
  }
  ADD_OFFSET(); // 16: "pi"
  if (!bplist_write_ascii_string(out, capacity, &pos, "pi")) {
    return 0;
  }
  ADD_OFFSET(); // 17: pairing identifier
  if (!bplist_write_ascii_string(out, capacity, &pos, pi)) {
    return 0;
  }
  ADD_OFFSET(); // 18: "name"
  if (!bplist_write_ascii_string(out, capacity, &pos, "name")) {
    return 0;
  }
  ADD_OFFSET(); // 19: device name
  if (!bplist_write_utf8_string(out, capacity, &pos, device_name)) {
    return 0;
  }
  ADD_OFFSET(); // 20: "audioFormats"
  if (!bplist_write_ascii_string(out, capacity, &pos, "audioFormats")) {
    return 0;
  }
  ADD_OFFSET(); // 21: "type"
  if (!bplist_write_ascii_string(out, capacity, &pos, "type")) {
    return 0;
  }
  ADD_OFFSET(); // 22: "audioInputFormats"
  if (!bplist_write_ascii_string(out, capacity, &pos, "audioInputFormats")) {
    return 0;
  }
  ADD_OFFSET(); // 23: "audioOutputFormats"
  if (!bplist_write_ascii_string(out, capacity, &pos, "audioOutputFormats")) {
    return 0;
  }
  ADD_OFFSET(); // 24: stream type 96
  if (!bplist_write_int(out, capacity, &pos, 96)) {
    return 0;
  }
  ADD_OFFSET(); // 25: format mask
  if (!bplist_write_int(out, capacity, &pos, 0x01000000)) {
    return 0;
  }
  ADD_OFFSET(); // 26: audio format dict
  {
    const uint8_t keys[] = {21, 22, 23};
    const uint8_t values[] = {24, 25, 25};
    if (!bplist_write_dict(out, capacity, &pos, keys, values, 3)) {
      return 0;
    }
  }
  ADD_OFFSET(); // 27: audioFormats array
  {
    const uint8_t refs[] = {26};
    if (!bplist_write_array(out, capacity, &pos, refs, 1)) {
      return 0;
    }
  }
  ADD_OFFSET(); // 28: "audioLatencies"
  if (!bplist_write_ascii_string(out, capacity, &pos, "audioLatencies")) {
    return 0;
  }
  ADD_OFFSET(); // 29: "audioType"
  if (!bplist_write_ascii_string(out, capacity, &pos, "audioType")) {
    return 0;
  }
  ADD_OFFSET(); // 30: "inputLatencyMicros"
  if (!bplist_write_ascii_string(out, capacity, &pos, "inputLatencyMicros")) {
    return 0;
  }
  ADD_OFFSET(); // 31: "outputLatencyMicros"
  if (!bplist_write_ascii_string(out, capacity, &pos, "outputLatencyMicros")) {
    return 0;
  }
  ADD_OFFSET(); // 32: stream type 103
  if (!bplist_write_int(out, capacity, &pos, 103)) {
    return 0;
  }
  ADD_OFFSET(); // 33: audio type
  if (!bplist_write_int(out, capacity, &pos, 0x64)) {
    return 0;
  }
  ADD_OFFSET(); // 34: zero latency
  if (!bplist_write_int(out, capacity, &pos, 0)) {
    return 0;
  }
  ADD_OFFSET(); // 35: latency dict for realtime stream
  {
    const uint8_t keys[] = {21, 29, 30, 31};
    const uint8_t values[] = {24, 33, 34, 34};
    if (!bplist_write_dict(out, capacity, &pos, keys, values, 4)) {
      return 0;
    }
  }
  ADD_OFFSET(); // 36: latency dict for buffered stream
  {
    const uint8_t keys[] = {21, 29, 30, 31};
    const uint8_t values[] = {32, 33, 34, 34};
    if (!bplist_write_dict(out, capacity, &pos, keys, values, 4)) {
      return 0;
    }
  }
  ADD_OFFSET(); // 37: audioLatencies array
  {
    const uint8_t refs[] = {35, 36};
    if (!bplist_write_array(out, capacity, &pos, refs, 2)) {
      return 0;
    }
  }
  ADD_OFFSET(); // 38: "psi"
  if (!bplist_write_ascii_string(out, capacity, &pos, "psi")) {
    return 0;
  }
  ADD_OFFSET(); // 39: public system identifier
  if (!bplist_write_ascii_string(out, capacity, &pos, psi)) {
    return 0;
  }
  ADD_OFFSET(); // 40: top-level info dict
  {
    const uint8_t keys[] = {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 28, 38};
    const uint8_t values[] = {1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 27, 37, 39};
    if (!bplist_write_dict(out, capacity, &pos, keys, values, 13)) {
      return 0;
    }
  }

#undef ADD_OFFSET

  if (obj != sizeof(offsets) / sizeof(offsets[0]) ||
      !bplist_finish(out, capacity, &pos, offsets, obj, 40)) {
    return 0;
  }

  return pos;
}

size_t bplist_build_configure_response(
    uint8_t *out, size_t capacity, const char *identifier, bool access_control,
    const uint8_t *public_key, size_t public_key_len, const char *device_name,
    uint8_t access_control_level) {
  if (!out || !identifier || !device_name || !public_key ||
      public_key_len == 0) {
    return 0;
  }

  size_t pos = 0;
  size_t offsets[11];
  size_t obj = 0;

#define ADD_OFFSET()                                   \
  do {                                                 \
    if (obj >= sizeof(offsets) / sizeof(offsets[0])) { \
      return 0;                                        \
    }                                                  \
    offsets[obj++] = pos;                              \
  } while (0)

  if (!bplist_has_room(pos, 8, capacity)) {
    return 0;
  }
  memcpy(out + pos, BPLIST_MAGIC, sizeof(BPLIST_MAGIC));
  pos += 8;

  ADD_OFFSET(); // 0
  if (!bplist_write_ascii_string(out, capacity, &pos, "Identifier")) {
    return 0;
  }
  ADD_OFFSET(); // 1
  if (!bplist_write_ascii_string(out, capacity, &pos, identifier)) {
    return 0;
  }
  ADD_OFFSET(); // 2
  if (!bplist_write_ascii_string(out, capacity, &pos,
                                 "Enable_HK_Access_Control")) {
    return 0;
  }
  ADD_OFFSET(); // 3
  if (!bplist_has_room(pos, 1, capacity)) {
    return 0;
  }
  out[pos++] = access_control ? 0x09 : 0x08;
  ADD_OFFSET(); // 4
  if (!bplist_write_ascii_string(out, capacity, &pos, "PublicKey")) {
    return 0;
  }
  ADD_OFFSET(); // 5
  if (!bplist_write_data(out, capacity, &pos, public_key, public_key_len)) {
    return 0;
  }
  ADD_OFFSET(); // 6
  if (!bplist_write_ascii_string(out, capacity, &pos, "Device_Name")) {
    return 0;
  }
  ADD_OFFSET(); // 7
  if (!bplist_write_utf8_string(out, capacity, &pos, device_name)) {
    return 0;
  }
  ADD_OFFSET(); // 8
  if (!bplist_write_ascii_string(out, capacity, &pos, "Access_Control_Level")) {
    return 0;
  }
  ADD_OFFSET(); // 9
  if (!bplist_write_int(out, capacity, &pos, access_control_level)) {
    return 0;
  }
  ADD_OFFSET(); // 10: top-level dict
  {
    const uint8_t keys[] = {0, 2, 4, 6, 8};
    const uint8_t values[] = {1, 3, 5, 7, 9};
    if (!bplist_write_dict(out, capacity, &pos, keys, values, 5)) {
      return 0;
    }
  }

#undef ADD_OFFSET

  if (obj != sizeof(offsets) / sizeof(offsets[0]) ||
      !bplist_finish(out, capacity, &pos, offsets, obj, 10)) {
    return 0;
  }
  return pos;
}

// ========================================
// AirPlay 2 remote control over the event channel
// (format from Shairport Sync, remote/remote.c)
// ========================================

static bool bplist_write_real(uint8_t *out, size_t capacity, size_t *pos,
                              double value) {
  if (!bplist_has_room(*pos, 9, capacity)) {
    return false;
  }
  uint64_t bits;
  memcpy(&bits, &value, sizeof(bits));
  out[(*pos)++] = 0x23; // 8-byte real
  return bplist_write_u64(out, capacity, pos, bits);
}

static bool bplist_write_uid(uint8_t *out, size_t capacity, size_t *pos,
                             uint8_t value) {
  if (!bplist_has_room(*pos, 2, capacity)) {
    return false;
  }
  out[(*pos)++] = 0x80; // UID, 1 byte
  out[(*pos)++] = value;
  return true;
}

static bool bplist_write_true(uint8_t *out, size_t capacity, size_t *pos) {
  if (!bplist_has_room(*pos, 1, capacity)) {
    return false;
  }
  out[(*pos)++] = 0x09;
  return true;
}

static bool bplist_begin(uint8_t *out, size_t capacity, size_t *pos) {
  if (capacity < sizeof(BPLIST_MAGIC)) {
    return false;
  }
  memcpy(out, BPLIST_MAGIC, sizeof(BPLIST_MAGIC));
  *pos = sizeof(BPLIST_MAGIC);
  return true;
}

size_t bplist_build_group_archive(uint8_t *out, size_t capacity,
                                  const char *group_uuid) {
  // NSKeyedArchiver: NSMutableArray with one element, the group UUID
  enum {
    O_TOP,
    K_VERSION,
    K_ARCHIVER,
    K_TOP,
    K_OBJECTS,
    V_VERSION,
    V_ARCHIVER,
    V_TOP,
    V_OBJECTS,
    K_ROOT,
    UID_1,
    S_NULL,
    ARRAY_OBJ,
    S_UUID,
    CLASS_OBJ,
    K_NS_OBJECTS,
    K_CLASS,
    NS_OBJECTS,
    UID_3,
    K_CLASSNAME,
    K_CLASSES,
    S_MUTABLE_ARRAY,
    CLASSES,
    UID_2,
    S_ARRAY,
    S_OBJECT,
    COUNT
  };
  size_t offsets[COUNT];
  size_t pos;
  bool ok = bplist_begin(out, capacity, &pos);
#define AT(i) (offsets[i] = pos)
  if (ok) {
    const uint8_t top_k[] = {K_VERSION, K_ARCHIVER, K_TOP, K_OBJECTS};
    const uint8_t top_v[] = {V_VERSION, V_ARCHIVER, V_TOP, V_OBJECTS};
    const uint8_t root_k[] = {K_ROOT}, root_v[] = {UID_1};
    const uint8_t objects[] = {S_NULL, ARRAY_OBJ, S_UUID, CLASS_OBJ};
    const uint8_t arr_k[] = {K_NS_OBJECTS, K_CLASS};
    const uint8_t arr_v[] = {NS_OBJECTS, UID_3};
    const uint8_t cls_k[] = {K_CLASSNAME, K_CLASSES};
    const uint8_t cls_v[] = {S_MUTABLE_ARRAY, CLASSES};
    const uint8_t ns_objects[] = {UID_2};
    const uint8_t classes[] = {S_MUTABLE_ARRAY, S_ARRAY, S_OBJECT};
    ok =
        (AT(O_TOP), bplist_write_dict(out, capacity, &pos, top_k, top_v, 4)) &&
        (AT(K_VERSION),
         bplist_write_ascii_string(out, capacity, &pos, "$version")) &&
        (AT(K_ARCHIVER),
         bplist_write_ascii_string(out, capacity, &pos, "$archiver")) &&
        (AT(K_TOP), bplist_write_ascii_string(out, capacity, &pos, "$top")) &&
        (AT(K_OBJECTS),
         bplist_write_ascii_string(out, capacity, &pos, "$objects")) &&
        (AT(V_VERSION), bplist_write_int(out, capacity, &pos, 100000)) &&
        (AT(V_ARCHIVER),
         bplist_write_ascii_string(out, capacity, &pos, "NSKeyedArchiver")) &&
        (AT(V_TOP),
         bplist_write_dict(out, capacity, &pos, root_k, root_v, 1)) &&
        (AT(V_OBJECTS), bplist_write_array(out, capacity, &pos, objects, 4)) &&
        (AT(K_ROOT), bplist_write_ascii_string(out, capacity, &pos, "root")) &&
        (AT(UID_1), bplist_write_uid(out, capacity, &pos, 1)) &&
        (AT(S_NULL), bplist_write_ascii_string(out, capacity, &pos, "$null")) &&
        (AT(ARRAY_OBJ),
         bplist_write_dict(out, capacity, &pos, arr_k, arr_v, 2)) &&
        (AT(S_UUID),
         bplist_write_ascii_string(out, capacity, &pos, group_uuid)) &&
        (AT(CLASS_OBJ),
         bplist_write_dict(out, capacity, &pos, cls_k, cls_v, 2)) &&
        (AT(K_NS_OBJECTS),
         bplist_write_ascii_string(out, capacity, &pos, "NS.objects")) &&
        (AT(K_CLASS),
         bplist_write_ascii_string(out, capacity, &pos, "$class")) &&
        (AT(NS_OBJECTS),
         bplist_write_array(out, capacity, &pos, ns_objects, 1)) &&
        (AT(UID_3), bplist_write_uid(out, capacity, &pos, 3)) &&
        (AT(K_CLASSNAME),
         bplist_write_ascii_string(out, capacity, &pos, "$classname")) &&
        (AT(K_CLASSES),
         bplist_write_ascii_string(out, capacity, &pos, "$classes")) &&
        (AT(S_MUTABLE_ARRAY),
         bplist_write_ascii_string(out, capacity, &pos, "NSMutableArray")) &&
        (AT(CLASSES), bplist_write_array(out, capacity, &pos, classes, 3)) &&
        (AT(UID_2), bplist_write_uid(out, capacity, &pos, 2)) &&
        (AT(S_ARRAY),
         bplist_write_ascii_string(out, capacity, &pos, "NSArray")) &&
        (AT(S_OBJECT),
         bplist_write_ascii_string(out, capacity, &pos, "NSObject")) &&
        bplist_finish(out, capacity, &pos, offsets, COUNT, O_TOP);
  }
#undef AT
  return ok ? pos : 0;
}

size_t bplist_build_media_remote_command(uint8_t *out, size_t capacity,
                                         unsigned int command,
                                         const char *command_id,
                                         const uint8_t *archive,
                                         size_t archive_len) {
  enum {
    O_TOP,
    K_COMMAND,
    K_TYPE,
    K_PARAMS,
    V_COMMAND,
    V_TYPE,
    V_PARAMS,
    K_SEND_OPTIONS,
    K_COMMAND_ID,
    K_REDIRECTING,
    K_DESTINATIONS,
    V_SEND_OPTIONS,
    V_COMMAND_ID,
    V_REDIRECTING,
    V_DESTINATIONS,
    COUNT
  };
  char command_str[12];
  snprintf(command_str, sizeof(command_str), "%u", command);
  size_t offsets[COUNT];
  size_t pos;
  bool ok = bplist_begin(out, capacity, &pos);
#define AT(i) (offsets[i] = pos)
  if (ok) {
    const uint8_t top_k[] = {K_COMMAND, K_TYPE, K_PARAMS};
    const uint8_t top_v[] = {V_COMMAND, V_TYPE, V_PARAMS};
    const uint8_t par_k[] = {K_SEND_OPTIONS, K_COMMAND_ID, K_REDIRECTING,
                             K_DESTINATIONS};
    const uint8_t par_v[] = {V_SEND_OPTIONS, V_COMMAND_ID, V_REDIRECTING,
                             V_DESTINATIONS};
    ok =
        (AT(O_TOP), bplist_write_dict(out, capacity, &pos, top_k, top_v, 3)) &&
        (AT(K_COMMAND), bplist_write_ascii_string(
                            out, capacity, &pos, "modernMediaRemoteCommand")) &&
        (AT(K_TYPE), bplist_write_ascii_string(out, capacity, &pos, "type")) &&
        (AT(K_PARAMS),
         bplist_write_ascii_string(out, capacity, &pos, "params")) &&
        (AT(V_COMMAND),
         bplist_write_ascii_string(out, capacity, &pos, command_str)) &&
        (AT(V_TYPE), bplist_write_ascii_string(out, capacity, &pos,
                                               "sendMediaRemoteCommand")) &&
        (AT(V_PARAMS),
         bplist_write_dict(out, capacity, &pos, par_k, par_v, 4)) &&
        (AT(K_SEND_OPTIONS),
         bplist_write_ascii_string(out, capacity, &pos,
                                   "kMRMediaRemoteOptionSendOptionsNumber")) &&
        (AT(K_COMMAND_ID),
         bplist_write_ascii_string(out, capacity, &pos,
                                   "kMRMediaRemoteOptionCommandID")) &&
        (AT(K_REDIRECTING), bplist_write_ascii_string(
                                out, capacity, &pos,
                                "kMRMediaRemoteOptionIsRedirectingCommand")) &&
        (AT(K_DESTINATIONS),
         bplist_write_ascii_string(
             out, capacity, &pos,
             "kMRMediaRemoteOptionDestinationDeviceUIDs")) &&
        (AT(V_SEND_OPTIONS), bplist_write_int(out, capacity, &pos, 0)) &&
        (AT(V_COMMAND_ID),
         bplist_write_ascii_string(out, capacity, &pos, command_id)) &&
        (AT(V_REDIRECTING), bplist_write_true(out, capacity, &pos)) &&
        (AT(V_DESTINATIONS),
         bplist_write_data(out, capacity, &pos, archive, archive_len)) &&
        bplist_finish(out, capacity, &pos, offsets, COUNT, O_TOP);
  }
#undef AT
  return ok ? pos : 0;
}

size_t bplist_build_volume_command(uint8_t *out, size_t capacity,
                                   double volume) {
  enum {
    O_TOP,
    K_VALUE,
    K_VOLUME,
    K_TYPE,
    K_PARAMS,
    V_VALUE,
    V_VOLUME,
    V_TYPE,
    V_PARAMS,
    COUNT
  };
  size_t offsets[COUNT];
  size_t pos;
  bool ok = bplist_begin(out, capacity, &pos);
#define AT(i) (offsets[i] = pos)
  if (ok) {
    const uint8_t top_k[] = {K_VALUE, K_VOLUME, K_TYPE, K_PARAMS};
    const uint8_t top_v[] = {V_VALUE, V_VOLUME, V_TYPE, V_PARAMS};
    const uint8_t par_k[] = {K_VOLUME}, par_v[] = {V_VOLUME};
    ok =
        (AT(O_TOP), bplist_write_dict(out, capacity, &pos, top_k, top_v, 4)) &&
        (AT(K_VALUE),
         bplist_write_ascii_string(out, capacity, &pos, "value")) &&
        (AT(K_VOLUME),
         bplist_write_ascii_string(out, capacity, &pos, "volume")) &&
        (AT(K_TYPE), bplist_write_ascii_string(out, capacity, &pos, "type")) &&
        (AT(K_PARAMS),
         bplist_write_ascii_string(out, capacity, &pos, "params")) &&
        (AT(V_VALUE), bplist_write_ascii_string(out, capacity, &pos, "dvlc")) &&
        (AT(V_VOLUME), bplist_write_real(out, capacity, &pos, volume)) &&
        (AT(V_TYPE), bplist_write_ascii_string(out, capacity, &pos,
                                               "sendMediaRemoteCommand")) &&
        (AT(V_PARAMS),
         bplist_write_dict(out, capacity, &pos, par_k, par_v, 1)) &&
        bplist_finish(out, capacity, &pos, offsets, COUNT, O_TOP);
  }
#undef AT
  return ok ? pos : 0;
}
