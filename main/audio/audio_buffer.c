#include <stdlib.h>
#include <string.h>

#include "audio_buffer.h"

#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "audio_buf";

static void audio_buffer_adjust_frames(audio_buffer_t *buffer, int delta) {
  portENTER_CRITICAL(&buffer->lock);
  buffer->buffered_frames += delta;
  if (buffer->buffered_frames < 0) {
    buffer->buffered_frames = 0;
  }
  portEXIT_CRITICAL(&buffer->lock);
}

static void audio_buffer_drain(audio_buffer_t *buffer, int frames_to_drain) {
  for (int i = 0; i < frames_to_drain; i++) {
    size_t item_size = 0;
    void *item = xRingbufferReceive(buffer->ring, &item_size, 0);
    if (!item) {
      break;
    }
    vRingbufferReturnItem(buffer->ring, item);
    audio_buffer_adjust_frames(buffer, -1);
  }
}

static bool audio_buffer_queue_chunk(audio_buffer_t *buffer, audio_stats_t *stats,
                                    uint32_t timestamp, const int16_t *pcm_data,
                                    size_t samples, int channels) {
  if (samples == 0) {
    return false;
  }

  int current_frames = audio_buffer_get_frame_count(buffer);
  if (current_frames > MAX_BUFFER_FRAMES) {
    int to_drain = current_frames - MAX_BUFFER_FRAMES + 10;
    audio_buffer_drain(buffer, to_drain);
  }

  audio_frame_header_t *hdr = (audio_frame_header_t *)buffer->frame_buffer;
  hdr->rtp_timestamp = timestamp;
  hdr->samples_per_channel = (uint16_t)samples;
  hdr->channels = (uint8_t)channels;
  hdr->reserved = 0;

  size_t pcm_bytes = samples * channels * sizeof(int16_t);
  int16_t *dest = (int16_t *)(hdr + 1);
  memmove(dest, pcm_data, pcm_bytes);

  size_t total_bytes = sizeof(*hdr) + pcm_bytes;

  BaseType_t ret = xRingbufferSend(buffer->ring, buffer->frame_buffer,
                                   total_bytes, pdMS_TO_TICKS(10));
  if (ret != pdTRUE) {
    if (stats) {
      stats->buffer_underruns++;
    }
    return false;
  }

  if (stats) {
    stats->packets_decoded++;
  }
  audio_buffer_adjust_frames(buffer, 1);
  return true;
}

esp_err_t audio_buffer_init(audio_buffer_t *buffer) {
  if (!buffer) {
    return ESP_ERR_INVALID_ARG;
  }

  portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
  buffer->lock = lock;
  buffer->buffered_frames = 0;

  buffer->ring = xRingbufferCreateWithCaps(
      AUDIO_BUFFER_SIZE, RINGBUF_TYPE_NOSPLIT,
      MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!buffer->ring) {
    ESP_LOGW(TAG, "PSRAM not available, using smaller buffer");
    buffer->ring =
        xRingbufferCreate(1024 * 1024, RINGBUF_TYPE_NOSPLIT);
  }
  if (!buffer->ring) {
    ESP_LOGE(TAG, "Failed to create ring buffer");
    return ESP_ERR_NO_MEM;
  }

  size_t max_pcm_bytes = MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS *
                         sizeof(int16_t);
  buffer->frame_buffer =
      (uint8_t *)malloc(sizeof(audio_frame_header_t) + max_pcm_bytes);
  if (!buffer->frame_buffer) {
    ESP_LOGE(TAG, "Failed to allocate frame buffer");
    vRingbufferDelete(buffer->ring);
    buffer->ring = NULL;
    return ESP_ERR_NO_MEM;
  }

  buffer->decode_buffer =
      (int16_t *)(buffer->frame_buffer + sizeof(audio_frame_header_t));
  buffer->decode_capacity_samples = MAX_SAMPLES_PER_FRAME;

  ESP_LOGI(TAG, "Ring buffer created: %zu bytes for %d frames",
           (size_t)AUDIO_BUFFER_SIZE, MAX_RING_BUFFER_FRAMES);

  return ESP_OK;
}

void audio_buffer_deinit(audio_buffer_t *buffer) {
  if (!buffer) {
    return;
  }

  if (buffer->ring) {
    vRingbufferDelete(buffer->ring);
    buffer->ring = NULL;
  }

  if (buffer->frame_buffer) {
    free(buffer->frame_buffer);
    buffer->frame_buffer = NULL;
    buffer->decode_buffer = NULL;
    buffer->decode_capacity_samples = 0;
  }

  buffer->buffered_frames = 0;
}

void audio_buffer_flush(audio_buffer_t *buffer) {
  if (!buffer || !buffer->ring) {
    return;
  }

  size_t bytes_read = 0;
  void *data = NULL;
  while ((data = xRingbufferReceive(buffer->ring, &bytes_read, 0)) != NULL) {
    vRingbufferReturnItem(buffer->ring, data);
  }

  portENTER_CRITICAL(&buffer->lock);
  buffer->buffered_frames = 0;
  portEXIT_CRITICAL(&buffer->lock);
}

int audio_buffer_get_frame_count(audio_buffer_t *buffer) {
  if (!buffer) {
    return 0;
  }

  int frames = 0;
  portENTER_CRITICAL(&buffer->lock);
  frames = buffer->buffered_frames;
  portEXIT_CRITICAL(&buffer->lock);
  return frames;
}

bool audio_buffer_take(audio_buffer_t *buffer, void **item, size_t *item_size,
                       TickType_t ticks) {
  if (!buffer || !buffer->ring || !item || !item_size) {
    return false;
  }

  *item = xRingbufferReceive(buffer->ring, item_size, ticks);
  if (!*item) {
    return false;
  }

  audio_buffer_adjust_frames(buffer, -1);
  return true;
}

void audio_buffer_return(audio_buffer_t *buffer, void *item) {
  if (!buffer || !buffer->ring || !item) {
    return;
  }

  vRingbufferReturnItem(buffer->ring, item);
}

int16_t *audio_buffer_get_decode_buffer(audio_buffer_t *buffer,
                                        size_t *capacity_samples) {
  if (!buffer) {
    return NULL;
  }

  if (capacity_samples) {
    *capacity_samples = buffer->decode_capacity_samples;
  }
  return buffer->decode_buffer;
}

bool audio_buffer_queue_decoded(audio_buffer_t *buffer, audio_stats_t *stats,
                                uint32_t timestamp, const int16_t *pcm_data,
                                size_t samples, int channels) {
  if (!buffer || !pcm_data || samples == 0) {
    return false;
  }

  if (channels <= 0) {
    channels = 2;
  }

  size_t offset = 0;
  uint32_t chunk_timestamp = timestamp;

  while (offset < samples) {
    size_t chunk_samples = samples - offset;
    if (chunk_samples > AAC_FRAMES_PER_PACKET) {
      chunk_samples = AAC_FRAMES_PER_PACKET;
    }

    if (!audio_buffer_queue_chunk(buffer, stats, chunk_timestamp,
                                  pcm_data + (offset * channels),
                                  chunk_samples, channels)) {
      return false;
    }

    offset += chunk_samples;
    chunk_timestamp += chunk_samples;
  }

  return true;
}
