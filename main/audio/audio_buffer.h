#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/ringbuf.h"

#include "audio_receiver.h"

#define AAC_FRAMES_PER_PACKET  352
#define AUDIO_MAX_CHANNELS     2
#define AUDIO_BYTES_PER_SAMPLE 2
#define MAX_SAMPLES_PER_FRAME  4096

typedef struct __attribute__((packed)) {
  uint32_t rtp_timestamp;
  uint16_t samples_per_channel;
  uint8_t channels;
  uint8_t reserved;
} audio_frame_header_t;

// ESP32S3 can access 8M SPIRAM directly
// Others require himem API to use. See
// https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/himem.html
// Reduce buffers for non-s3 targets
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define MAX_RING_BUFFER_FRAMES 5000
#else
#define MAX_RING_BUFFER_FRAMES 2500
#endif
// BYTES_PER_FRAME = 8 + 1408 = 1416
#define BYTES_PER_FRAME           \
  (sizeof(audio_frame_header_t) + \
   (AAC_FRAMES_PER_PACKET * AUDIO_MAX_CHANNELS * AUDIO_BYTES_PER_SAMPLE))
#define AUDIO_BUFFER_SIZE (MAX_RING_BUFFER_FRAMES * BYTES_PER_FRAME)
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define MAX_BUFFER_FRAMES 5000
#else
#define MAX_BUFFER_FRAMES 2500
#endif

typedef struct {
  RingbufHandle_t ring;
  int buffered_frames;
  portMUX_TYPE lock;
  uint8_t *frame_buffer;
  int16_t *decode_buffer;
  size_t decode_capacity_samples;
} audio_buffer_t;

esp_err_t audio_buffer_init(audio_buffer_t *buffer);
void audio_buffer_deinit(audio_buffer_t *buffer);
void audio_buffer_flush(audio_buffer_t *buffer);
int audio_buffer_get_frame_count(audio_buffer_t *buffer);
bool audio_buffer_take(audio_buffer_t *buffer, void **item, size_t *item_size,
                       TickType_t ticks);
void audio_buffer_return(audio_buffer_t *buffer, void *item);
int16_t *audio_buffer_get_decode_buffer(audio_buffer_t *buffer,
                                        size_t *capacity_samples);
bool audio_buffer_queue_decoded(audio_buffer_t *buffer, audio_stats_t *stats,
                                uint32_t timestamp, const int16_t *pcm_data,
                                size_t samples, int channels);
