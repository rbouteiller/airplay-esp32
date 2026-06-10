#include "software_eq.h"

#include "eq_events.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "settings.h"
#include <inttypes.h>
#include <math.h>
#include <string.h>

static const char *TAG = "software_eq";

#define EQ_MIN_DB  -15.0f
#define EQ_MAX_DB  15.0f
#define EQ_EPSILON 0.05f
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#ifndef CONFIG_DAC_TAS58XX

typedef struct {
  float b0;
  float b1;
  float b2;
  float a1;
  float a2;
  float zl1;
  float zl2;
  float zr1;
  float zr2;
} biquad_t;

static const float s_freqs[SETTINGS_EQ_BANDS] = {
    20.0f,   31.5f,   50.0f,   80.0f,   125.0f,
    200.0f,  315.0f,  500.0f,  800.0f,  1250.0f,
    2000.0f, 3150.0f, 5000.0f, 8000.0f, 16000.0f,
};

static biquad_t s_bands[SETTINGS_EQ_BANDS];
static float s_gains[SETTINGS_EQ_BANDS];
static uint32_t s_sample_rate = 44100;
static bool s_initialized;
static bool s_active;
static SemaphoreHandle_t s_mutex;

static float clamp_gain(float gain_db) {
  if (gain_db > EQ_MAX_DB) {
    return EQ_MAX_DB;
  }
  if (gain_db < EQ_MIN_DB) {
    return EQ_MIN_DB;
  }
  return gain_db;
}

static int16_t clamp_i16(float sample) {
  if (sample > 32767.0f) {
    return 32767;
  }
  if (sample < -32768.0f) {
    return -32768;
  }
  return (int16_t)lrintf(sample);
}

static void clear_state_locked(void) {
  for (int i = 0; i < SETTINGS_EQ_BANDS; i++) {
    s_bands[i].zl1 = 0.0f;
    s_bands[i].zl2 = 0.0f;
    s_bands[i].zr1 = 0.0f;
    s_bands[i].zr2 = 0.0f;
  }
}

static void update_coefficients_locked(void) {
  s_active = false;

  for (int i = 0; i < SETTINGS_EQ_BANDS; i++) {
    float gain_db = clamp_gain(s_gains[i]);
    s_gains[i] = gain_db;
    if (fabsf(gain_db) > EQ_EPSILON) {
      s_active = true;
    }

    float freq = s_freqs[i];
    if (freq > ((float)s_sample_rate * 0.45f)) {
      freq = (float)s_sample_rate * 0.45f;
    }

    const float q = 1.41421356f;
    const float a = powf(10.0f, gain_db / 40.0f);
    const float w0 = 2.0f * (float)M_PI * freq / (float)s_sample_rate;
    const float alpha = sinf(w0) / (2.0f * q);
    const float cos_w0 = cosf(w0);

    const float b0 = 1.0f + alpha * a;
    const float b1 = -2.0f * cos_w0;
    const float b2 = 1.0f - alpha * a;
    const float a0 = 1.0f + alpha / a;
    const float a1 = -2.0f * cos_w0;
    const float a2 = 1.0f - alpha / a;

    s_bands[i].b0 = b0 / a0;
    s_bands[i].b1 = b1 / a0;
    s_bands[i].b2 = b2 / a0;
    s_bands[i].a1 = a1 / a0;
    s_bands[i].a2 = a2 / a0;
  }

  clear_state_locked();
}

static void set_gains(const float gains_db[SETTINGS_EQ_BANDS]) {
  if (!s_initialized || !gains_db) {
    return;
  }

  if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
    ESP_LOGW(TAG, "Timed out updating EQ gains");
    return;
  }

  memcpy(s_gains, gains_db, sizeof(s_gains));
  update_coefficients_locked();
  xSemaphoreGive(s_mutex);
}

static void on_eq_event(eq_event_t event, const eq_event_data_t *data,
                        void *user_data) {
  (void)user_data;

  switch (event) {
  case EQ_EVENT_ALL_BANDS_SET:
    if (data) {
      settings_set_eq_gains(data->all_bands.gains_db);
      set_gains(data->all_bands.gains_db);
      ESP_LOGI(TAG, "Software EQ updated and saved");
    }
    break;

  case EQ_EVENT_BAND_CHANGED:
    if (data && data->band_changed.band >= 0 &&
        data->band_changed.band < SETTINGS_EQ_BANDS) {
      float gains[SETTINGS_EQ_BANDS];
      if (settings_get_eq_gains(gains) != ESP_OK) {
        memset(gains, 0, sizeof(gains));
      }
      gains[data->band_changed.band] = data->band_changed.gain_db;
      settings_set_eq_gains(gains);
      set_gains(gains);
    }
    break;

  case EQ_EVENT_FLAT: {
    float gains[SETTINGS_EQ_BANDS] = {0};
    settings_clear_eq();
    set_gains(gains);
    ESP_LOGI(TAG, "Software EQ reset to flat");
    break;
  }
  }
}

esp_err_t software_eq_init(uint32_t sample_rate) {
  if (s_initialized) {
    software_eq_set_sample_rate(sample_rate);
    return ESP_OK;
  }

  s_mutex = xSemaphoreCreateMutex();
  if (!s_mutex) {
    return ESP_ERR_NO_MEM;
  }

  s_sample_rate = sample_rate > 0 ? sample_rate : 44100;
  s_initialized = true;

  float gains[SETTINGS_EQ_BANDS] = {0};
  if (settings_get_eq_gains(gains) != ESP_OK) {
    memset(gains, 0, sizeof(gains));
  }
  set_gains(gains);
  eq_events_register(on_eq_event, NULL);
  ESP_LOGI(TAG, "Software EQ ready at %" PRIu32 " Hz", s_sample_rate);
  return ESP_OK;
}

void software_eq_set_sample_rate(uint32_t sample_rate) {
  if (!s_initialized || sample_rate == 0) {
    return;
  }

  if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
    return;
  }

  if (sample_rate != s_sample_rate) {
    s_sample_rate = sample_rate;
    update_coefficients_locked();
    ESP_LOGI(TAG, "Software EQ sample rate set to %" PRIu32 " Hz",
             s_sample_rate);
  }
  xSemaphoreGive(s_mutex);
}

void software_eq_process(int16_t *pcm, size_t frame_count) {
  if (!s_initialized || !s_active || !pcm || frame_count == 0) {
    return;
  }

  if (xSemaphoreTake(s_mutex, 0) != pdTRUE) {
    return;
  }

  for (size_t frame = 0; frame < frame_count; frame++) {
    float left = (float)pcm[frame * 2];
    float right = (float)pcm[frame * 2 + 1];

    for (int band = 0; band < SETTINGS_EQ_BANDS; band++) {
      biquad_t *bq = &s_bands[band];

      float x = left;
      left = bq->b0 * x + bq->zl1;
      bq->zl1 = bq->b1 * x - bq->a1 * left + bq->zl2;
      bq->zl2 = bq->b2 * x - bq->a2 * left;

      x = right;
      right = bq->b0 * x + bq->zr1;
      bq->zr1 = bq->b1 * x - bq->a1 * right + bq->zr2;
      bq->zr2 = bq->b2 * x - bq->a2 * right;
    }

    pcm[frame * 2] = clamp_i16(left);
    pcm[frame * 2 + 1] = clamp_i16(right);
  }

  xSemaphoreGive(s_mutex);
}

void software_eq_clear_state(void) {
  if (!s_initialized) {
    return;
  }

  if (xSemaphoreTake(s_mutex, 0) == pdTRUE) {
    clear_state_locked();
    xSemaphoreGive(s_mutex);
  }
}

bool software_eq_is_active(void) {
  return s_initialized && s_active;
}

#else

esp_err_t software_eq_init(uint32_t sample_rate) {
  (void)sample_rate;
  return ESP_OK;
}

void software_eq_set_sample_rate(uint32_t sample_rate) {
  (void)sample_rate;
}

void software_eq_process(int16_t *pcm, size_t frame_count) {
  (void)pcm;
  (void)frame_count;
}

void software_eq_clear_state(void) {}

bool software_eq_is_active(void) { return false; }

#endif
