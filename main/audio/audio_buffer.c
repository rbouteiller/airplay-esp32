#include <stdlib.h>
#include <string.h>

#include "audio_buffer.h"
#include "audio_receiver.h"

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

// High water mark - start blocking when buffer is this full
#define BUFFER_HIGH_WATER_FRAMES ((MAX_BUFFER_FRAMES * 80) / 100)

static bool audio_buffer_queue_chunk(audio_buffer_t *buffer,
                                     audio_stats_t *stats, uint32_t timestamp,
                                     const int16_t *pcm_data, size_t samples,
                                     int channels) {
  if (samples == 0) {
    return false;
  }

  int current_frames = audio_buffer_get_frame_count(buffer);
  bool is_paused = !audio_receiver_is_playing();

  // Flow control: if buffer is above high water mark, block until space
  // available. This creates backpressure to match producer speed to consumer
  // speed.
  TickType_t send_timeout = pdMS_TO_TICKS(10); // Normal: 10ms timeout

  if (current_frames > BUFFER_HIGH_WATER_FRAMES) {
    static bool was_throttling = false;
    if (!was_throttling) {
      ESP_LOGI(TAG, "Buffer high (%d/%d frames), throttling producer%s",
               current_frames, MAX_BUFFER_FRAMES, is_paused ? " (paused)" : "");
      was_throttling = true;
    }
    // Use much longer timeout to let consumer drain the buffer
    // When paused, consumer won't drain - we'll handle overflow below
    send_timeout = is_paused ? pdMS_TO_TICKS(100) : pdMS_TO_TICKS(5000);
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
                                   total_bytes, send_timeout);
  if (ret != pdTRUE) {
    // Ring buffer is full after waiting
    int frame_count = audio_buffer_get_frame_count(buffer);

    // When paused, don't drain - just drop incoming frames to avoid overflow
    // The buffered data should be preserved for resume
    if (is_paused) {
      static int paused_drop_count = 0;
      paused_drop_count++;
      if (paused_drop_count % 100 == 1) {
        ESP_LOGW(
            TAG,
            "Paused: dropping incoming frame #%d (buffer full at %d frames)",
            paused_drop_count, frame_count);
      }
      return false; // Drop this frame, keep buffer intact
    }

    ESP_LOGW(TAG,
             "Ringbuf full after %ldms wait (frames=%d), forcing drain of 100 "
             "frames, ts=%lu",
             (long)(send_timeout * portTICK_PERIOD_MS), frame_count,
             (unsigned long)timestamp);
    audio_buffer_drain(buffer, 100);

    // Retry after drain
    ret = xRingbufferSend(buffer->ring, buffer->frame_buffer, total_bytes,
                          pdMS_TO_TICKS(100));
    if (ret != pdTRUE) {
      if (stats) {
        stats->buffer_overruns++;
      }
      ESP_LOGE(TAG,
               "Failed to queue chunk after drain: ringbuf still full, "
               "frames=%d, ts=%lu, overruns=%lu",
               audio_buffer_get_frame_count(buffer), (unsigned long)timestamp,
               stats ? (unsigned long)stats->buffer_overruns : 0);

      return false;
    }
    ESP_LOGI(TAG, "Queue succeeded after drain");
  }

  if (stats) {
    stats->packets_decoded++;
  }
  audio_buffer_adjust_frames(buffer, 1);

  // Periodic status logging (every 500 frames)
  static int queue_count = 0;
  if (++queue_count % 500 == 0) {
    ESP_LOGI(TAG, "Buffer status: frames=%d, decoded=%lu",
             audio_buffer_get_frame_count(buffer),
             stats ? (unsigned long)stats->packets_decoded : 0);
  }
  return true;
}

esp_err_t audio_buffer_init(audio_buffer_t *buffer) {
  if (!buffer) {
    return ESP_ERR_INVALID_ARG;
  }

  portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
  buffer->lock = lock;
  buffer->buffered_frames = 0;

  buffer->ring =
      xRingbufferCreateWithCaps(AUDIO_BUFFER_SIZE, RINGBUF_TYPE_NOSPLIT,
                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!buffer->ring) {
    ESP_LOGW(TAG, "PSRAM not available, using smaller buffer");
    buffer->ring = xRingbufferCreate(1024 * 1024, RINGBUF_TYPE_NOSPLIT);
  }
  if (!buffer->ring) {
    ESP_LOGE(TAG, "Failed to create ring buffer");
    return ESP_ERR_NO_MEM;
  }

  size_t max_pcm_bytes =
      MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS * sizeof(int16_t);
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
    static int underrun_count = 0;
    underrun_count++;
    // Log every 100 underruns to avoid spam
    if (underrun_count % 100 == 1) {
      ESP_LOGW(TAG, "Buffer underrun #%d (frames=%d)", underrun_count,
               audio_buffer_get_frame_count(buffer));
    }
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
                                  pcm_data + (offset * channels), chunk_samples,
                                  channels)) {
      return false;
    }

    offset += chunk_samples;
    chunk_timestamp += chunk_samples;
  }

  return true;
}
