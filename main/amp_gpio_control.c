#include "amp_gpio_control.h"

#include "rtsp_events.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <stdint.h>

static const char *TAG = "amp_gpio";

#define AMP_GPIO_SD   CONFIG_AMP_GPIO_SD_GPIO
#define AMP_GPIO_MUTE CONFIG_AMP_GPIO_MUTE_GPIO

#define AMP_GPIO_SD_ENABLED   (AMP_GPIO_SD >= 0)
#define AMP_GPIO_MUTE_ENABLED (AMP_GPIO_MUTE >= 0)
#define AMP_GPIO_ANY_ENABLED  (AMP_GPIO_SD_ENABLED || AMP_GPIO_MUTE_ENABLED)

#if defined(CONFIG_AMP_GPIO_CONTROL) && AMP_GPIO_ANY_ENABLED
#define AMP_GPIO_ACTIVE 1
#else
#define AMP_GPIO_ACTIVE 0
#endif

#if AMP_GPIO_ACTIVE

static bool s_playing = false;

static void wait_for_amplifier(uint32_t delay_ms) {
  if (delay_ms != 0) {
    vTaskDelay(pdMS_TO_TICKS(delay_ms));
  }
}

static void apply_playing_state(bool playing) {
  if (s_playing == playing) {
    return;
  }

  if (playing) {
    if (AMP_GPIO_SD_ENABLED) {
      gpio_set_level(AMP_GPIO_SD, CONFIG_AMP_GPIO_SD_PLAYING_LEVEL);
    }
    if (AMP_GPIO_SD_ENABLED && AMP_GPIO_MUTE_ENABLED) {
      wait_for_amplifier(CONFIG_AMP_GPIO_ENABLE_DELAY_MS);
    }
    if (AMP_GPIO_MUTE_ENABLED) {
      gpio_set_level(AMP_GPIO_MUTE, CONFIG_AMP_GPIO_MUTE_PLAYING_LEVEL);
    }
  } else {
    if (AMP_GPIO_MUTE_ENABLED) {
      gpio_set_level(AMP_GPIO_MUTE, !CONFIG_AMP_GPIO_MUTE_PLAYING_LEVEL);
    }
    if (AMP_GPIO_SD_ENABLED && AMP_GPIO_MUTE_ENABLED) {
      wait_for_amplifier(CONFIG_AMP_GPIO_SHUTDOWN_DELAY_MS);
    }
    if (AMP_GPIO_SD_ENABLED) {
      gpio_set_level(AMP_GPIO_SD, !CONFIG_AMP_GPIO_SD_PLAYING_LEVEL);
    }
  }

  s_playing = playing;
  ESP_LOGI(TAG, "Amplifier outputs: %s", playing ? "playing" : "idle");
}

static esp_err_t configure_gpios(void) {
  gpio_config_t config = {
      .pin_bit_mask = 0,
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };

  if (AMP_GPIO_SD_ENABLED) {
    config.pin_bit_mask |= 1ULL << AMP_GPIO_SD;
  }
  if (AMP_GPIO_MUTE_ENABLED) {
    config.pin_bit_mask |= 1ULL << AMP_GPIO_MUTE;
  }

  esp_err_t err = gpio_config(&config);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to configure amplifier GPIOs: %s",
             esp_err_to_name(err));
    return err;
  }

  if (AMP_GPIO_SD_ENABLED) {
    gpio_set_level(AMP_GPIO_SD, !CONFIG_AMP_GPIO_SD_PLAYING_LEVEL);
  }
  if (AMP_GPIO_MUTE_ENABLED) {
    gpio_set_level(AMP_GPIO_MUTE, !CONFIG_AMP_GPIO_MUTE_PLAYING_LEVEL);
  }

  return ESP_OK;
}

static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data) {
  (void)data;
  (void)user_data;

  switch (event) {
  case RTSP_EVENT_PLAYING:
    apply_playing_state(true);
    break;
  case RTSP_EVENT_PAUSED:
  case RTSP_EVENT_DISCONNECTED:
    apply_playing_state(false);
    break;
  case RTSP_EVENT_CLIENT_CONNECTED:
  case RTSP_EVENT_METADATA:
    break;
  }
}
#endif

esp_err_t amp_gpio_control_init(void) {
#if !AMP_GPIO_ACTIVE
  return ESP_OK;
#else
  esp_err_t err = configure_gpios();
  if (err != ESP_OK) {
    return err;
  }

  if (rtsp_events_register(on_rtsp_event, NULL) != 0) {
    return ESP_ERR_NO_MEM;
  }

  ESP_LOGI(TAG,
           "Amplifier control ready (SD=%d playing=%d, MUTE=%d playing=%d)",
           AMP_GPIO_SD, CONFIG_AMP_GPIO_SD_PLAYING_LEVEL, AMP_GPIO_MUTE,
           CONFIG_AMP_GPIO_MUTE_PLAYING_LEVEL);
  return ESP_OK;
#endif
}

void amp_gpio_control_set_playing(bool playing) {
#if AMP_GPIO_ACTIVE
  apply_playing_state(playing);
#else
  (void)playing;
#endif
}
