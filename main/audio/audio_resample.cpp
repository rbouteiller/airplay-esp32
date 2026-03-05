#include "audio_resample.h"

#include "sdkconfig.h"

#if CONFIG_OUTPUT_SAMPLE_RATE_HZ != 44100

#include "resampler.h"

#include "esp_log.h"

static const char *TAG = "audio_resample";

static esp_audio_libs::resampler::Resampler *resampler = nullptr;
static uint32_t current_input_rate = 0;
static uint32_t current_output_rate = 0;
static int current_channels = 0;
static int current_quality = 0;
static bool active = false;

extern "C" bool audio_resample_init(uint32_t input_rate, uint32_t output_rate,
                                    int channels, int quality) {
  audio_resample_destroy();

  if (input_rate == output_rate) {
    active = false;
    ESP_LOGI(TAG, "No resampling needed (rate=%lu)", (unsigned long)input_rate);
    return true;
  }

  current_input_rate = input_rate;
  current_output_rate = output_rate;
  current_channels = channels;
  current_quality = quality;

  // Buffer sizes: max frames per call (352 + margin) * channels
  size_t max_in_samples = 400 * channels;
  // Output can be larger due to upsampling ratio + margin
  size_t max_out_samples =
      (size_t)(400.0f * (float)output_rate / (float)input_rate + 32) *
      channels;

  resampler = new (std::nothrow)
      esp_audio_libs::resampler::Resampler(max_in_samples, max_out_samples);
  if (!resampler) {
    ESP_LOGE(TAG, "Failed to allocate resampler");
    return false;
  }

  esp_audio_libs::resampler::ResamplerConfiguration config = {};
  config.source_sample_rate = (float)input_rate;
  config.target_sample_rate = (float)output_rate;
  config.source_bits_per_sample = 16;
  config.target_bits_per_sample = 16;
  config.channels = (uint8_t)channels;
  config.use_pre_or_post_filter = true;
  config.subsample_interpolate = true;
  config.number_of_taps = (uint16_t)quality;
  config.number_of_filters = (uint16_t)quality;

  if (!resampler->initialize(config)) {
    ESP_LOGE(TAG, "Failed to initialize resampler");
    delete resampler;
    resampler = nullptr;
    return false;
  }

  active = true;
  ESP_LOGI(TAG, "Resampler initialized: %lu -> %lu Hz, quality=%d",
           (unsigned long)input_rate, (unsigned long)output_rate, quality);
  return true;
}

extern "C" size_t audio_resample_process(const int16_t *in, size_t in_frames,
                                         int16_t *out, size_t out_capacity) {
  if (!resampler || !active) {
    return 0;
  }

  auto result = resampler->resample(
      reinterpret_cast<const uint8_t *>(in),
      reinterpret_cast<uint8_t *>(out), in_frames, out_capacity, 0.0f);

  return result.frames_generated;
}

extern "C" bool audio_resample_is_active(void) { return active; }

extern "C" void audio_resample_reset(void) {
  if (!resampler) {
    return;
  }
  // Re-initialize to reset filter state
  audio_resample_init(current_input_rate, current_output_rate,
                      current_channels, current_quality);
}

extern "C" void audio_resample_destroy(void) {
  if (resampler) {
    delete resampler;
    resampler = nullptr;
  }
  active = false;
}

extern "C" size_t audio_resample_max_output(size_t in_frames) {
  if (!active || current_input_rate == 0) {
    return in_frames;
  }
  return (size_t)((float)in_frames * (float)current_output_rate /
                      (float)current_input_rate +
                  2);
}

#else /* CONFIG_OUTPUT_SAMPLE_RATE_HZ == 44100 — no resampling needed */

extern "C" bool audio_resample_init(uint32_t input_rate, uint32_t output_rate,
                                    int channels, int quality) {
  (void)input_rate;
  (void)output_rate;
  (void)channels;
  (void)quality;
  return true;
}

extern "C" size_t audio_resample_process(const int16_t *in, size_t in_frames,
                                         int16_t *out, size_t out_capacity) {
  (void)in;
  (void)out;
  (void)out_capacity;
  return in_frames;
}

extern "C" bool audio_resample_is_active(void) { return false; }
extern "C" void audio_resample_reset(void) {}
extern "C" void audio_resample_destroy(void) {}

extern "C" size_t audio_resample_max_output(size_t in_frames) {
  return in_frames;
}

#endif
