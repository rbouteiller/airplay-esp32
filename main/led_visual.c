#include "led_visual.h"

#include "esp_log.h"
#include "esp_timer.h"

#include <math.h>

#define TAG             "led_visual"
#define SILENCE_THRESH  200
#define UPDATE_INTERVAL_US (1000000 / 30) // ~30 Hz

static int64_t s_last_update_us;

#if CONFIG_LED_RGB_GPIO >= 0

#include "led_strip.h"

static led_strip_handle_t s_strip;

static void led_rgb_init(void) {
  led_strip_config_t strip_cfg = {
      .strip_gpio_num = CONFIG_LED_RGB_GPIO,
      .max_leds = 1,
      .led_model = LED_MODEL_WS2812,
      .flags.invert_out = false,
  };
  led_strip_rmt_config_t rmt_cfg = {
      .clk_src = RMT_CLK_SRC_DEFAULT,
      .resolution_hz = 10 * 1000 * 1000, // 10 MHz
      .flags.with_dma = false,
  };

  esp_err_t err = led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &s_strip);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "LED strip init failed: %s", esp_err_to_name(err));
    s_strip = NULL;
    return;
  }

  led_strip_clear(s_strip);
  ESP_LOGI(TAG, "RGB LED initialized on GPIO %d", CONFIG_LED_RGB_GPIO);
}

static void led_rgb_update(float norm, float bass_ratio) {
  if (!s_strip) {
    return;
  }

  if (norm <= 0.0f) {
    led_strip_clear(s_strip);
    led_strip_refresh(s_strip);
    return;
  }

  uint8_t val = (uint8_t)(norm * 255.0f);
  if (val < 1) {
    val = 1;
  }

  // Map to HSV hue: 170 (blue, quiet) -> 85 (green, medium) -> 0 (red, loud)
  uint16_t hue = (uint16_t)(170.0f * (1.0f - norm));

  // Shift towards purple/magenta when bassy
  if (bass_ratio > 0.3f) {
    hue = (uint16_t)(hue + (uint16_t)(bass_ratio * 60.0f));
    if (hue > 255) {
      hue = 255;
    }
  }

  // High saturation, reduce slightly at very high energy for warm white
  uint8_t sat = 255;
  if (norm > 0.85f) {
    sat = (uint8_t)(255 - (uint8_t)((norm - 0.85f) / 0.15f * 80.0f));
  }

  led_strip_set_pixel_hsv(s_strip, 0, hue, sat, val);
  led_strip_refresh(s_strip);
}

#else
static void led_rgb_init(void) {}
static void led_rgb_update(float norm, float bass_ratio) {
  (void)norm;
  (void)bass_ratio;
}
#endif

#if CONFIG_LED_GREEN_GPIO >= 0

#include "driver/ledc.h"

#define GREEN_LED_CHANNEL LEDC_CHANNEL_0
#define GREEN_LED_TIMER   LEDC_TIMER_0
#define GREEN_LED_FREQ_HZ 5000
#define GREEN_LED_RES     LEDC_TIMER_8_BIT

static bool s_green_led_ready;

static void led_green_init(void) {
  ledc_timer_config_t timer_cfg = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .timer_num = GREEN_LED_TIMER,
      .duty_resolution = GREEN_LED_RES,
      .freq_hz = GREEN_LED_FREQ_HZ,
      .clk_cfg = LEDC_AUTO_CLK,
  };
  if (ledc_timer_config(&timer_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "Green LED timer init failed");
    return;
  }

  ledc_channel_config_t ch_cfg = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = GREEN_LED_CHANNEL,
      .timer_sel = GREEN_LED_TIMER,
      .intr_type = LEDC_INTR_DISABLE,
      .gpio_num = CONFIG_LED_GREEN_GPIO,
      .duty = 0,
      .hpoint = 0,
  };
  if (ledc_channel_config(&ch_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "Green LED channel init failed");
    return;
  }

  s_green_led_ready = true;
  ESP_LOGI(TAG, "Green LED initialized on GPIO %d", CONFIG_LED_GREEN_GPIO);
}

static void led_green_update(float norm) {
  if (!s_green_led_ready) {
    return;
  }

  uint32_t duty = (uint32_t)(norm * 255.0f);
  if (duty > 255) {
    duty = 255;
  }

  ledc_set_duty(LEDC_LOW_SPEED_MODE, GREEN_LED_CHANNEL, duty);
  ledc_update_duty(LEDC_LOW_SPEED_MODE, GREEN_LED_CHANNEL);
}

#else
static void led_green_init(void) {}
static void led_green_update(float norm) { (void)norm; }
#endif

void led_visual_init(void) {
  led_rgb_init();
  led_green_init();
}

void led_visual_update(const int16_t *pcm, size_t stereo_samples) {
  if (stereo_samples == 0) {
    return;
  }

  // Rate limit to ~30 Hz
  int64_t now = esp_timer_get_time();
  if (now - s_last_update_us < UPDATE_INTERVAL_US) {
    return;
  }
  s_last_update_us = now;

  size_t total = stereo_samples * 2; // L+R interleaved

  // Compute RMS energy
  uint64_t sum_sq = 0;
  for (size_t i = 0; i < total; i++) {
    int32_t s = pcm[i];
    sum_sq += (uint64_t)(s * s);
  }
  float rms = sqrtf((float)sum_sq / (float)total);

  // Simple bass energy: average absolute difference between consecutive
  // samples (low-frequency content produces smaller differences)
  uint64_t diff_sum = 0;
  for (size_t i = 2; i < total; i += 2) { // step by 2 = mono channel
    int32_t d = (int32_t)pcm[i] - (int32_t)pcm[i - 2];
    diff_sum += (uint64_t)(d < 0 ? -d : d);
  }
  float high_energy = (float)diff_sum / ((float)total / 2.0f);

  // Bass ratio: when high_energy is low relative to rms, content is bassy
  float bass_ratio = 0.0f;
  if (rms > SILENCE_THRESH) {
    bass_ratio = 1.0f - (high_energy / (rms * 2.0f + 1.0f));
    if (bass_ratio < 0.0f) {
      bass_ratio = 0.0f;
    }
    if (bass_ratio > 1.0f) {
      bass_ratio = 1.0f;
    }
  }

  // Normalized energy (0.0 = silence, 1.0 = loud)
  float norm = 0.0f;
  if (rms >= SILENCE_THRESH) {
    norm = (rms - SILENCE_THRESH) / (16000.0f - SILENCE_THRESH);
    if (norm > 1.0f) {
      norm = 1.0f;
    }
  }

  led_rgb_update(norm, bass_ratio);
  led_green_update(norm);
}
