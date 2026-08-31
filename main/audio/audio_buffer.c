#include <stdlib.h>
#include <string.h>

#include "audio_buffer.h"

#include "esp_log.h"

static const char *TAG = "audio_buf";

/* ---------- init / deinit ---------- */

esp_err_t audio_buffer_init(audio_buffer_t *buffer) {
  if (!buffer) {
    return ESP_ERR_INVALID_ARG;
  }

  memset(buffer, 0, sizeof(*buffer));

  const size_t capacity_samples =
      (size_t)MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS;
  buffer->decode_buffer = (int16_t *)malloc(capacity_samples * sizeof(int16_t));
  if (!buffer->decode_buffer) {
    ESP_LOGE(TAG, "Failed to allocate decode buffer");
    return ESP_ERR_NO_MEM;
  }
  buffer->decode_capacity_samples = MAX_SAMPLES_PER_FRAME;

  return ESP_OK;
}

void audio_buffer_deinit(audio_buffer_t *buffer) {
  if (!buffer) {
    return;
  }

  free(buffer->decode_buffer);
  buffer->decode_buffer = NULL;
  buffer->decode_capacity_samples = 0;
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
