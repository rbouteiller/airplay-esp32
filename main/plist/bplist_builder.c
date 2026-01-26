#include <string.h>

#include "audio_stream.h"
#include "plist.h"

size_t bplist_build_initial_setup(uint8_t *out, size_t capacity,
                                  uint16_t event_port) {
  if (capacity < 100) {
    return 0;
  }

  size_t pos = 0;
  memcpy(out + pos, "bplist00", 8);
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
  memcpy(out + pos, "bplist00", 8);
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
