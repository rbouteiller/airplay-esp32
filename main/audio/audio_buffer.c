#include <stdlib.h>
#include <string.h>

#include "audio_buffer.h"

#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "audio_buf";

/* ---------- helpers for the slot pool ---------- */

static inline uint8_t *slot_ptr(audio_buffer_t *b, uint16_t slot) {
  return b->pool + (size_t)slot * b->slot_size;
}

static inline uint32_t slot_timestamp(audio_buffer_t *b, uint16_t slot) {
  return ((audio_frame_header_t *)slot_ptr(b, slot))->rtp_timestamp;
}

/* RTP timestamp comparison that handles 32-bit wraparound.
   Returns negative if a < b, 0 if equal, positive if a > b. */
static inline int32_t ts_cmp(uint32_t a, uint32_t b) {
  return (int32_t)(a - b);
}

/* Binary search: find the index in sorted[] where a frame with `timestamp`
   should be inserted to keep ascending order. */
static int sorted_insert_pos(audio_buffer_t *b, uint32_t timestamp) {
  int lo = 0, hi = b->count;
  while (lo < hi) {
    int mid = lo + (hi - lo) / 2;
    if (ts_cmp(slot_timestamp(b, b->sorted[mid]), timestamp) < 0) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  return lo;
}

/* ---------- queue_chunk (insert) ---------- */

static bool audio_buffer_queue_chunk(audio_buffer_t *buffer,
                                     audio_stats_t *stats, uint32_t timestamp,
                                     const int16_t *pcm_data, size_t samples,
                                     int channels) {
  if (samples == 0) {
    return false;
  }

  portENTER_CRITICAL(&buffer->lock);

  /* Overflow protection: drain oldest frames if at capacity */
  while (buffer->count >= buffer->capacity && buffer->count > 0) {
    uint16_t victim = buffer->sorted[0];
    memmove(&buffer->sorted[0], &buffer->sorted[1],
            (buffer->count - 1) * sizeof(uint16_t));
    buffer->count--;
    buffer->free_stack[buffer->free_top++] = victim;
    /* Take one token from the semaphore to keep it in sync */
    xSemaphoreTakeFromISR(buffer->data_ready, NULL);
  }

  if (buffer->free_top == 0) {
    portEXIT_CRITICAL(&buffer->lock);
    if (stats) {
      stats->buffer_underruns++;
    }
    return false;
  }

  /* Pop a free slot */
  uint16_t slot = buffer->free_stack[--buffer->free_top];

  /* Build frame into pool slot */
  uint8_t *dest = slot_ptr(buffer, slot);
  audio_frame_header_t *hdr = (audio_frame_header_t *)dest;
  hdr->rtp_timestamp = timestamp;
  hdr->samples_per_channel = (uint16_t)samples;
  hdr->channels = (uint8_t)channels;
  hdr->reserved = 0;

  size_t pcm_bytes = samples * channels * sizeof(int16_t);
  memcpy(dest + sizeof(audio_frame_header_t), pcm_data, pcm_bytes);

  /* Binary search for insertion position */
  int pos = sorted_insert_pos(buffer, timestamp);

  /* Shift indices to make room */
  if (pos < buffer->count) {
    memmove(&buffer->sorted[pos + 1], &buffer->sorted[pos],
            (buffer->count - pos) * sizeof(uint16_t));
  }
  buffer->sorted[pos] = slot;
  buffer->count++;

  portEXIT_CRITICAL(&buffer->lock);

  /* Signal consumer */
  xSemaphoreGive(buffer->data_ready);

  if (stats) {
    stats->packets_decoded++;
  }
  return true;
}

/* ---------- init / deinit ---------- */

esp_err_t audio_buffer_init(audio_buffer_t *buffer) {
  if (!buffer) {
    return ESP_ERR_INVALID_ARG;
  }

  memset(buffer, 0, sizeof(*buffer));

  portMUX_TYPE lock = portMUX_INITIALIZER_UNLOCKED;
  buffer->lock = lock;
  buffer->capacity = MAX_RING_BUFFER_FRAMES;
  buffer->slot_size = BYTES_PER_FRAME;
  buffer->count = 0;

  /* Pool in PSRAM */
  buffer->pool =
      (uint8_t *)heap_caps_malloc((size_t)buffer->capacity * buffer->slot_size,
                                  MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!buffer->pool) {
    ESP_LOGE(TAG, "Failed to allocate pool in PSRAM");
    return ESP_ERR_NO_MEM;
  }

  /* Sorted index array + free stack (internal RAM is fine, they're small) */
  buffer->sorted = (uint16_t *)malloc(buffer->capacity * sizeof(uint16_t));
  buffer->free_stack = (uint16_t *)malloc(buffer->capacity * sizeof(uint16_t));
  if (!buffer->sorted || !buffer->free_stack) {
    ESP_LOGE(TAG, "Failed to allocate index arrays");
    audio_buffer_deinit(buffer);
    return ESP_ERR_NO_MEM;
  }

  /* Initialise free stack: all slots available */
  buffer->free_top = buffer->capacity;
  for (int i = 0; i < buffer->capacity; i++) {
    buffer->free_stack[i] = (uint16_t)i;
  }

  /* Counting semaphore: max = capacity, initial = 0 */
  buffer->data_ready = xSemaphoreCreateCounting(buffer->capacity, 0);
  if (!buffer->data_ready) {
    ESP_LOGE(TAG, "Failed to create semaphore");
    audio_buffer_deinit(buffer);
    return ESP_ERR_NO_MEM;
  }

  /* Temp assembly / decode buffer (same as before) */
  size_t max_pcm_bytes =
      (size_t)MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS * sizeof(int16_t);
  buffer->frame_buffer =
      (uint8_t *)malloc(sizeof(audio_frame_header_t) + max_pcm_bytes);
  if (!buffer->frame_buffer) {
    ESP_LOGE(TAG, "Failed to allocate frame buffer");
    audio_buffer_deinit(buffer);
    return ESP_ERR_NO_MEM;
  }
  buffer->decode_buffer =
      (int16_t *)(buffer->frame_buffer + sizeof(audio_frame_header_t));
  buffer->decode_capacity_samples = MAX_SAMPLES_PER_FRAME;

  ESP_LOGI(TAG, "Sorted buffer created: %d slots × %zu bytes = %zu bytes",
           buffer->capacity, buffer->slot_size,
           (size_t)buffer->capacity * buffer->slot_size);

  return ESP_OK;
}

void audio_buffer_deinit(audio_buffer_t *buffer) {
  if (!buffer) {
    return;
  }

  if (buffer->data_ready) {
    vSemaphoreDelete(buffer->data_ready);
    buffer->data_ready = NULL;
  }
  if (buffer->pool) {
    heap_caps_free(buffer->pool);
    buffer->pool = NULL;
  }
  free(buffer->sorted);
  buffer->sorted = NULL;
  free(buffer->free_stack);
  buffer->free_stack = NULL;

  if (buffer->frame_buffer) {
    free(buffer->frame_buffer);
    buffer->frame_buffer = NULL;
    buffer->decode_buffer = NULL;
    buffer->decode_capacity_samples = 0;
  }

  buffer->count = 0;
  buffer->free_top = 0;
}

/* ---------- flush ---------- */

void audio_buffer_flush(audio_buffer_t *buffer) {
  if (!buffer || !buffer->pool) {
    return;
  }

  portENTER_CRITICAL(&buffer->lock);

  /* Return all active slots to free stack */
  for (int i = 0; i < buffer->count; i++) {
    buffer->free_stack[buffer->free_top++] = buffer->sorted[i];
  }
  buffer->count = 0;

  portEXIT_CRITICAL(&buffer->lock);

  /* Drain the semaphore */
  while (xSemaphoreTake(buffer->data_ready, 0) == pdTRUE) {
  }
}

/* ---------- frame count ---------- */

int audio_buffer_get_frame_count(audio_buffer_t *buffer) {
  if (!buffer) {
    return 0;
  }

  int frames = 0;
  portENTER_CRITICAL(&buffer->lock);
  frames = buffer->count;
  portEXIT_CRITICAL(&buffer->lock);
  return frames;
}

/* ---------- nearly full check (for back-pressure) ---------- */

bool audio_buffer_is_nearly_full(audio_buffer_t *buffer) {
  if (!buffer) {
    return false;
  }

  int count = 0;
  portENTER_CRITICAL(&buffer->lock);
  count = buffer->count;
  portEXIT_CRITICAL(&buffer->lock);

  // Consider buffer "nearly full" when > 90% capacity
  return count > (buffer->capacity * 9 / 10);
}

/* ---------- take (consumer) ---------- */

bool audio_buffer_take(audio_buffer_t *buffer, void **item, size_t *item_size,
                       TickType_t ticks) {
  if (!buffer || !buffer->pool || !item || !item_size) {
    return false;
  }

  /* Block until a frame is available */
  if (xSemaphoreTake(buffer->data_ready, ticks) != pdTRUE) {
    return false;
  }

  portENTER_CRITICAL(&buffer->lock);

  if (buffer->count == 0) {
    /* Shouldn't happen if semaphore is in sync, but guard anyway */
    portEXIT_CRITICAL(&buffer->lock);
    return false;
  }

  uint16_t slot = buffer->sorted[0];

  /* Shift remaining indices left */
  if (buffer->count > 1) {
    memmove(&buffer->sorted[0], &buffer->sorted[1],
            (buffer->count - 1) * sizeof(uint16_t));
  }
  buffer->count--;

  portEXIT_CRITICAL(&buffer->lock);

  uint8_t *ptr = slot_ptr(buffer, slot);
  audio_frame_header_t *hdr = (audio_frame_header_t *)ptr;
  *item = ptr;
  *item_size = sizeof(audio_frame_header_t) + (size_t)hdr->samples_per_channel *
                                                  hdr->channels *
                                                  sizeof(int16_t);

  return true;
}

/* ---------- return (consumer gives back slot) ---------- */

void audio_buffer_return(audio_buffer_t *buffer, void *item) {
  if (!buffer || !buffer->pool || !item) {
    return;
  }

  uint16_t slot =
      (uint16_t)(((uint8_t *)item - buffer->pool) / buffer->slot_size);

  portENTER_CRITICAL(&buffer->lock);
  buffer->free_stack[buffer->free_top++] = slot;
  portEXIT_CRITICAL(&buffer->lock);
}

/* ---------- decode buffer accessor ---------- */

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

/* ---------- queue decoded (splits large frames into chunks) ---------- */

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
