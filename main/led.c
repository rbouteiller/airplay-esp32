#include "led.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include "rtsp_events.h"

#if CONFIG_LED_STATUS_GPIO >= 0 || CONFIG_LED_ERROR_GPIO >= 0
#include "driver/ledc.h"
#endif

#include <math.h>

static const char *TAG = "led";

// ============================================================================
// Configuration helpers - map Kconfig to led_mode_t
// ============================================================================

static led_mode_t get_status_mode_playing(void) {
#if defined(CONFIG_LED_STATUS_PLAYING_VU)
  return LED_VU;
#elif defined(CONFIG_LED_STATUS_PLAYING_BLINK_FAST)
  return LED_BLINK_FAST;
#else
  return LED_STEADY;
#endif
}

static led_mode_t get_status_mode_paused(void) {
#if defined(CONFIG_LED_STATUS_PAUSED_OFF)
  return LED_OFF;
#elif defined(CONFIG_LED_STATUS_PAUSED_STEADY)
  return LED_STEADY;
#elif defined(CONFIG_LED_STATUS_PAUSED_BLINK_SLOW)
  return LED_BLINK_SLOW;
#else
  return LED_BLINK_MEDIUM;
#endif
}

static led_mode_t get_status_mode_standby(void) {
#if defined(CONFIG_LED_STATUS_STANDBY_OFF)
  return LED_OFF;
#elif defined(CONFIG_LED_STATUS_STANDBY_BLINK_MEDIUM)
  return LED_BLINK_MEDIUM;
#else
  return LED_BLINK_SLOW;
#endif
}

static led_mode_t get_rgb_mode_playing(void) {
#if defined(CONFIG_LED_RGB_PLAYING_OFF)
  return LED_OFF;
#elif defined(CONFIG_LED_RGB_PLAYING_STEADY)
  return LED_STEADY;
#else
  return LED_VU;
#endif
}

static led_mode_t get_rgb_mode_paused(void) {
#if defined(CONFIG_LED_RGB_PAUSED_OFF)
  return LED_OFF;
#else
  return LED_STEADY;
#endif
}

static led_mode_t get_rgb_mode_standby(void) {
#if defined(CONFIG_LED_RGB_STANDBY_STEADY)
  return LED_STEADY;
#else
  return LED_OFF;
#endif
}

// ============================================================================
// Status LED (single color via LEDC PWM)
// ============================================================================

#if CONFIG_LED_STATUS_GPIO >= 0

#define STATUS_LED_CHANNEL LEDC_CHANNEL_0
#define STATUS_LED_TIMER   LEDC_TIMER_0

static led_mode_t s_status_mode = LED_OFF;
static TimerHandle_t s_status_timer = NULL;
static bool s_status_on = false;
static uint8_t s_status_duty = CONFIG_LED_STATUS_BRIGHTNESS;

static void status_led_set_duty(uint8_t duty) {
  ledc_set_duty(LEDC_LOW_SPEED_MODE, STATUS_LED_CHANNEL, duty);
  ledc_update_duty(LEDC_LOW_SPEED_MODE, STATUS_LED_CHANNEL);
}

static void status_timer_cb(TimerHandle_t xTimer) {
  (void)xTimer;
  s_status_on = !s_status_on;
  status_led_set_duty(s_status_on ? s_status_duty : 0);

  uint32_t period_ms;
  switch (s_status_mode) {
  case LED_BLINK_SLOW:
    period_ms = s_status_on ? 100 : 2500;
    break;
  case LED_BLINK_MEDIUM:
    period_ms = 500;
    break;
  case LED_BLINK_FAST:
    period_ms = 250;
    break;
  default:
    return;
  }

  TickType_t ticks = pdMS_TO_TICKS(period_ms);
  if (ticks == 0) {
    ticks = 1;
  }
  xTimerChangePeriod(s_status_timer, ticks, 10);
}

static void status_led_init(void) {
  ledc_timer_config_t timer_cfg = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .timer_num = STATUS_LED_TIMER,
      .duty_resolution = LEDC_TIMER_8_BIT,
      .freq_hz = 1000,
      .clk_cfg = LEDC_AUTO_CLK,
  };
  if (ledc_timer_config(&timer_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "Status LED timer init failed");
    return;
  }

  ledc_channel_config_t ch_cfg = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = STATUS_LED_CHANNEL,
      .timer_sel = STATUS_LED_TIMER,
      .intr_type = LEDC_INTR_DISABLE,
      .gpio_num = CONFIG_LED_STATUS_GPIO,
      .duty = 0,
      .hpoint = 0,
      .flags = {.output_invert = true},
  };
  if (ledc_channel_config(&ch_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "Status LED channel init failed");
    return;
  }

  s_status_timer = xTimerCreate("status_led", pdMS_TO_TICKS(500), pdFALSE, NULL,
                                status_timer_cb);

  ESP_LOGI(TAG, "Status LED initialized on GPIO %d", CONFIG_LED_STATUS_GPIO);
}

static void status_led_set_mode(led_mode_t mode) {
  if (mode == s_status_mode) {
    return;
  }
  s_status_mode = mode;

  if (s_status_timer && xTimerIsTimerActive(s_status_timer)) {
    xTimerStop(s_status_timer, 10);
  }

  switch (mode) {
  case LED_OFF:
    status_led_set_duty(0);
    break;
  case LED_STEADY:
    status_led_set_duty(s_status_duty);
    break;
  case LED_BLINK_SLOW:
  case LED_BLINK_MEDIUM:
  case LED_BLINK_FAST:
    s_status_on = true;
    status_led_set_duty(s_status_duty);
    if (s_status_timer) {
      xTimerStart(s_status_timer, 10);
    }
    break;
  case LED_VU:
    // VU mode handled by led_audio_feed
    break;
  }
}

static void status_led_set_vu(float norm) {
  if (s_status_mode != LED_VU) {
    return;
  }
  uint8_t duty = (uint8_t)(norm * 255.0f);
  status_led_set_duty(duty);
}

#else
static void status_led_init(void) {
}
static void status_led_set_mode(led_mode_t mode) {
  (void)mode;
}
static void status_led_set_vu(float norm) {
  (void)norm;
}
#endif

// ============================================================================
// Error LED (simple on/off via LEDC)
// ============================================================================

#if CONFIG_LED_ERROR_GPIO >= 0

#define ERROR_LED_CHANNEL LEDC_CHANNEL_1
#define ERROR_LED_TIMER   LEDC_TIMER_1

static void error_led_init(void) {
  ledc_timer_config_t timer_cfg = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .timer_num = ERROR_LED_TIMER,
      .duty_resolution = LEDC_TIMER_8_BIT,
      .freq_hz = 1000,
      .clk_cfg = LEDC_AUTO_CLK,
  };
  if (ledc_timer_config(&timer_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "Error LED timer init failed");
    return;
  }

  ledc_channel_config_t ch_cfg = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = ERROR_LED_CHANNEL,
      .timer_sel = ERROR_LED_TIMER,
      .intr_type = LEDC_INTR_DISABLE,
      .gpio_num = CONFIG_LED_ERROR_GPIO,
      .duty = 0,
      .hpoint = 0,
      .flags = {.output_invert = true},
  };
  if (ledc_channel_config(&ch_cfg) != ESP_OK) {
    ESP_LOGE(TAG, "Error LED channel init failed");
    return;
  }
  ESP_LOGI(TAG, "Error LED initialized on GPIO %d", CONFIG_LED_ERROR_GPIO);
}

static void error_led_set(bool on) {
  ledc_set_duty(LEDC_LOW_SPEED_MODE, ERROR_LED_CHANNEL,
                on ? CONFIG_LED_STATUS_BRIGHTNESS : 0);
  ledc_update_duty(LEDC_LOW_SPEED_MODE, ERROR_LED_CHANNEL);
}

#else
static void error_led_init(void) {
}
static void error_led_set(bool on) {
  (void)on;
}
#endif

// ============================================================================
// RGB LED (WS2812 via led_strip)
// ============================================================================

#if CONFIG_LED_RGB_GPIO >= 0

#include "led_strip.h"

static led_strip_handle_t s_rgb_strip = NULL;
static led_mode_t s_rgb_mode = LED_OFF;

static void rgb_led_init(void) {
  led_strip_config_t strip_cfg = {
      .strip_gpio_num = CONFIG_LED_RGB_GPIO,
      .max_leds = 1,
      .led_model = LED_MODEL_WS2812,
      .flags.invert_out = false,
  };
  led_strip_rmt_config_t rmt_cfg = {
      .clk_src = RMT_CLK_SRC_DEFAULT,
      .resolution_hz = 10 * 1000 * 1000,
      .flags.with_dma = false,
  };

  if (led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &s_rgb_strip) != ESP_OK) {
    ESP_LOGE(TAG, "RGB LED init failed");
    s_rgb_strip = NULL;
    return;
  }

  led_strip_clear(s_rgb_strip);
  ESP_LOGI(TAG, "RGB LED initialized on GPIO %d", CONFIG_LED_RGB_GPIO);
}

static void rgb_led_set_color(uint8_t r, uint8_t g, uint8_t b) {
  if (!s_rgb_strip) {
    return;
  }
  led_strip_set_pixel(s_rgb_strip, 0, r, g, b);
  led_strip_refresh(s_rgb_strip);
}

static void rgb_led_clear(void) {
  if (!s_rgb_strip) {
    return;
  }
  led_strip_clear(s_rgb_strip);
  led_strip_refresh(s_rgb_strip);
}

static void rgb_led_set_mode(led_mode_t mode) {
  s_rgb_mode = mode;

  switch (mode) {
  case LED_OFF:
    rgb_led_clear();
    break;
  case LED_STEADY: {
    // Color depends on current state - handled by on_rtsp_event
    break;
  }
  case LED_VU:
    // Handled by led_audio_feed
    break;
  default:
    break;
  }
}

static void rgb_led_set_vu(float norm, float bass_ratio) {
  if (s_rgb_mode != LED_VU || !s_rgb_strip) {
    return;
  }

  if (norm <= 0.0f) {
    rgb_led_clear();
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

  led_strip_set_pixel_hsv(s_rgb_strip, 0, hue, sat, val);
  led_strip_refresh(s_rgb_strip);
}

#else
static void rgb_led_init(void) {
}
static void rgb_led_set_mode(led_mode_t mode) {
  (void)mode;
}
static void rgb_led_set_color(uint8_t r, uint8_t g, uint8_t b) {
  (void)r;
  (void)g;
  (void)b;
}
static void rgb_led_clear(void) {
}
static void rgb_led_set_vu(float norm, float bass_ratio) {
  (void)norm;
  (void)bass_ratio;
}
#endif

// ============================================================================
// RTSP Event Handler
// ============================================================================

typedef enum {
  STATE_STANDBY,
  STATE_PAUSED,
  STATE_PLAYING,
  STATE_ERROR,
} led_state_t;

static led_state_t s_current_state = STATE_STANDBY;

static void apply_state(led_state_t state) {
  s_current_state = state;

  switch (state) {
  case STATE_PLAYING:
    status_led_set_mode(get_status_mode_playing());
    rgb_led_set_mode(get_rgb_mode_playing());
    error_led_set(false);
    break;

  case STATE_PAUSED:
    status_led_set_mode(get_status_mode_paused());
    rgb_led_set_mode(get_rgb_mode_paused());
    if (get_rgb_mode_paused() == LED_STEADY) {
#ifdef CONFIG_LED_RGB_COLOR_PAUSED
      uint32_t c = CONFIG_LED_RGB_COLOR_PAUSED;
      rgb_led_set_color((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF);
#else
      rgb_led_set_color(0, 0, 0x33);
#endif
    }
    error_led_set(false);
    break;

  case STATE_STANDBY:
    status_led_set_mode(get_status_mode_standby());
    rgb_led_set_mode(get_rgb_mode_standby());
    if (get_rgb_mode_standby() == LED_STEADY) {
#ifdef CONFIG_LED_RGB_COLOR_STANDBY
      uint32_t c = CONFIG_LED_RGB_COLOR_STANDBY;
      rgb_led_set_color((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF);
#else
      rgb_led_set_color(0, 0x11, 0);
#endif
    }
    error_led_set(false);
    break;

  case STATE_ERROR:
#if CONFIG_LED_ERROR_GPIO >= 0
    // Dedicated error LED - turn off status to avoid mixed signals
    status_led_set_mode(LED_OFF);
#else
    // No error LED - use status LED to indicate error
    status_led_set_mode(LED_BLINK_FAST);
#endif
    rgb_led_set_color(0x80, 0, 0);
    error_led_set(true);
    break;
  }
}

static void on_rtsp_event(rtsp_event_t event, void *user_data) {
  (void)user_data;

  switch (event) {
  case RTSP_EVENT_CLIENT_CONNECTED:
    apply_state(STATE_PAUSED);
    break;
  case RTSP_EVENT_PLAYING:
    apply_state(STATE_PLAYING);
    break;
  case RTSP_EVENT_PAUSED:
    apply_state(STATE_PAUSED);
    break;
  case RTSP_EVENT_DISCONNECTED:
    apply_state(STATE_STANDBY);
    break;
  }
}

// ============================================================================
// Audio VU Processing
// ============================================================================

#define SILENCE_THRESH     200
#define UPDATE_INTERVAL_US (1000000 / 30) // ~30 Hz

static int64_t s_last_update_us = 0;

void led_audio_feed(const int16_t *pcm, size_t stereo_samples) {
  if (stereo_samples == 0 || s_current_state != STATE_PLAYING) {
    return;
  }

  // Rate limit to ~30 Hz
  int64_t now = esp_timer_get_time();
  if (now - s_last_update_us < UPDATE_INTERVAL_US) {
    return;
  }
  s_last_update_us = now;

  size_t total = stereo_samples * 2;

  // Compute RMS energy
  uint64_t sum_sq = 0;
  for (size_t i = 0; i < total; i++) {
    int32_t s = pcm[i];
    sum_sq += (uint64_t)(s * s);
  }
  float rms = sqrtf((float)sum_sq / (float)total);

  // Simple bass energy estimate
  uint64_t diff_sum = 0;
  for (size_t i = 2; i < total; i += 2) {
    int32_t d = (int32_t)pcm[i] - (int32_t)pcm[i - 2];
    diff_sum += (uint64_t)(d < 0 ? -d : d);
  }
  float high_energy = (float)diff_sum / ((float)total / 2.0f);

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

  float norm = 0.0f;
  if (rms >= SILENCE_THRESH) {
    norm = (rms - SILENCE_THRESH) / (16000.0f - SILENCE_THRESH);
    if (norm > 1.0f) {
      norm = 1.0f;
    }
  }

  status_led_set_vu(norm);
  rgb_led_set_vu(norm, bass_ratio);
}

// ============================================================================
// Public API
// ============================================================================

void led_init(void) {
  status_led_init();
  error_led_init();
  rgb_led_init();

  rtsp_events_register(on_rtsp_event, NULL);

  // Start in standby
  apply_state(STATE_STANDBY);

  ESP_LOGI(TAG, "LED subsystem initialized");
}

void led_set_error(bool error) {
  if (error) {
    apply_state(STATE_ERROR);
  } else {
    // Return to appropriate state based on current playback
    apply_state(STATE_STANDBY);
  }
}
