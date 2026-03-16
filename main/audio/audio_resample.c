#include "audio_resample.h"

#include "sdkconfig.h"

#if CONFIG_OUTPUT_SAMPLE_RATE_HZ != 44100

#include "resampler.h"

#include "esp_log.h"
#include <stdlib.h>

static const char *TAG = "audio_resample";

/* Taps must be a multiple of 4 (resampler requirement).
 * Rounded down from Kconfig value if needed. */
#define RESAMPLER_NUM_TAPS (CONFIG_RESAMPLER_TAPS & ~3)

static Resample *resampler;
static uint32_t current_input_rate;
static uint32_t current_output_rate;
static int current_channels;
static double fixed_ratio;
static bool active;

/* Persistent float conversion buffers (heap-allocated once) */
static float *float_in;
static float *float_out;
static size_t float_in_cap;  /* in samples (frames * channels) */
static size_t float_out_cap;

static void ensure_float_bufs(size_t in_samples, size_t out_samples) {
  if (in_samples > float_in_cap) {
    free(float_in);
    float_in_cap = in_samples;
    float_in = malloc(float_in_cap * sizeof(float));
  }
  if (out_samples > float_out_cap) {
    free(float_out);
    float_out_cap = out_samples;
    float_out = malloc(float_out_cap * sizeof(float));
  }
}

bool audio_resample_init(uint32_t input_rate, uint32_t output_rate,
                         int channels) {
  audio_resample_destroy();

  if (input_rate == output_rate) {
    active = false;
    ESP_LOGI(TAG, "No resampling needed (rate=%lu)", (unsigned long)input_rate);
    return true;
  }

  current_input_rate = input_rate;
  current_output_rate = output_rate;
  current_channels = channels;
  fixed_ratio = (double)output_rate / (double)input_rate;

  /* Compute the exact filter count for interpolation-free resampling.
   * For 44100→48000: gcd=300, exact_filters=160.
   * Memory: 161 filters × RESAMPLER_NUM_TAPS × 4 bytes. */
  unsigned long g = input_rate;
  unsigned long b = output_rate;
  while (b) {
    unsigned long t = b;
    b = g % b;
    g = t;
  }
  int exact_filters = (int)(output_rate / g);
  int max_filters = exact_filters;
  if (max_filters > 1024) {
    max_filters = 1024;
  }

  int flags = SUBSAMPLE_INTERPOLATE | INCLUDE_LOWPASS | BLACKMAN_HARRIS;

  resampler = resampleFixedRatioInit(
      channels, RESAMPLER_NUM_TAPS, max_filters,
      (double)input_rate, (double)output_rate,
      0, /* 0 = auto lowpass freq */
      flags);

  if (!resampler) {
    ESP_LOGE(TAG, "Failed to allocate resampler");
    return false;
  }

  /* Pre-allocate float buffers for typical frame size (352 + margin) */
  size_t typical_in = 400 * (size_t)channels;
  size_t typical_out =
      (size_t)(400.0 * fixed_ratio + 16) * (size_t)channels;
  ensure_float_bufs(typical_in, typical_out);

  if (!float_in || !float_out) {
    ESP_LOGE(TAG, "Failed to allocate conversion buffers");
    audio_resample_destroy();
    return false;
  }

  active = true;
  ESP_LOGI(TAG, "Resampler: %lu -> %lu Hz, taps=%d, filters=%d, interp=%s",
           (unsigned long)input_rate, (unsigned long)output_rate,
           RESAMPLER_NUM_TAPS, resampleGetNumFilters(resampler),
           resampleInterpolationUsed(resampler) ? "ON" : "OFF");
  return true;
}

size_t audio_resample_process(const int16_t *in, size_t in_frames,
                              int16_t *out, size_t out_capacity) {
  if (!resampler || !active) {
    return 0;
  }

  size_t in_samples = in_frames * (size_t)current_channels;
  size_t out_samples = out_capacity * (size_t)current_channels;
  ensure_float_bufs(in_samples, out_samples);

  /* int16 → float [-1.0, 1.0) */
  for (size_t i = 0; i < in_samples; i++) {
    float_in[i] = (float)in[i] * (1.0f / 32768.0f);
  }

  ResampleResult result = resampleProcessInterleaved(
      resampler, float_in, (int)in_frames,
      float_out, (int)out_capacity, fixed_ratio);

  /* float → int16 with clamp */
  size_t out_total = (size_t)result.output_generated * (size_t)current_channels;
  for (size_t i = 0; i < out_total; i++) {
    float s = float_out[i] * 32768.0f;
    if (s > 32767.0f) {
      s = 32767.0f;
    } else if (s < -32768.0f) {
      s = -32768.0f;
    }
    out[i] = (int16_t)s;
  }

  return result.output_generated;
}

bool audio_resample_is_active(void) { return active; }

void audio_resample_reset(void) {
  if (!resampler) {
    return;
  }
  resampleReset(resampler);
}

void audio_resample_destroy(void) {
  if (resampler) {
    resampleFree(resampler);
    resampler = NULL;
  }
  free(float_in);
  float_in = NULL;
  float_in_cap = 0;
  free(float_out);
  float_out = NULL;
  float_out_cap = 0;
  active = false;
}

size_t audio_resample_max_output(size_t in_frames) {
  if (!active || current_input_rate == 0) {
    return in_frames;
  }
  return (size_t)((double)in_frames * fixed_ratio + 2);
}

#else /* CONFIG_OUTPUT_SAMPLE_RATE_HZ == 44100 — no resampling needed */

bool audio_resample_init(uint32_t input_rate, uint32_t output_rate,
                         int channels) {
  (void)input_rate;
  (void)output_rate;
  (void)channels;
  return true;
}

size_t audio_resample_process(const int16_t *in, size_t in_frames,
                              int16_t *out, size_t out_capacity) {
  (void)in;
  (void)out;
  (void)out_capacity;
  return in_frames;
}

bool audio_resample_is_active(void) { return false; }
void audio_resample_reset(void) {}
void audio_resample_destroy(void) {}

size_t audio_resample_max_output(size_t in_frames) { return in_frames; }

#endif
