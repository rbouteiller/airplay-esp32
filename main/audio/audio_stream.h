#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "audio_receiver.h"

typedef struct audio_stream audio_stream_t;

typedef struct {
  esp_err_t (*start)(audio_stream_t *stream, uint16_t port);
  void (*stop)(audio_stream_t *stream);
  bool (*receive_packet)(audio_stream_t *stream);
  int (*decrypt_payload)(audio_stream_t *stream, const uint8_t *in,
                         size_t in_len, uint8_t *out, size_t out_cap);
  uint16_t (*get_port)(audio_stream_t *stream);
  bool (*is_running)(audio_stream_t *stream);
  void (*destroy)(audio_stream_t *stream);
} audio_stream_ops_t;

struct audio_stream {
  const audio_stream_ops_t *ops;
  audio_stream_type_t type;
  bool running;
  audio_format_t format;
  audio_encrypt_t encrypt;
  void *ctx;
};

audio_stream_t *audio_stream_create_realtime(void);
audio_stream_t *audio_stream_create_buffered(void);
void audio_stream_destroy(audio_stream_t *stream);
bool audio_stream_uses_buffer(audio_stream_type_t type);
