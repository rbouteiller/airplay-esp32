#include "squeezeamp.h"

#include "dac_tas57xx.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_log.h"
#include "rtsp_events.h"

#define I2C_PORT_0 0

static const char TAG[] = "SqueezeAMP";

static esp_err_t init_gpio(void);

static void on_rtsp_event(rtsp_event_t event, void *user_data) {
  (void)user_data;
  switch (event) {
  case RTSP_EVENT_CLIENT_CONNECTED:
  case RTSP_EVENT_PAUSED:
    tas57xx_set_power_mode(TAS57XX_AMP_STANDBY);
    break;
  case RTSP_EVENT_PLAYING:
    tas57xx_set_power_mode(TAS57XX_AMP_ON);
    break;
  case RTSP_EVENT_DISCONNECTED:
    tas57xx_enable_speaker(true);
    tas57xx_set_power_mode(TAS57XX_AMP_OFF);
    break;
  }
}

esp_err_t squeezeamp_init(void) {
  esp_err_t err = ESP_OK;

  // Initialize I2C for DAC control
  err = tas57xx_init(I2C_PORT_0, CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize TAS57xx: %s", esp_err_to_name(err));
    return err;
  }

  // Configure other GPIO (SPDIF, etc.)
  err = init_gpio();
  if (err != ESP_OK) {
    return err;
  }

  // Register for RTSP events to control DAC power
  rtsp_events_register(on_rtsp_event, NULL);

  // Start in standby
  tas57xx_enable_speaker(true);
  tas57xx_set_power_mode(TAS57XX_AMP_OFF);

  ESP_LOGI(TAG, "SqueezeAMP DAC initialized");
  return ESP_OK;
}

static esp_err_t init_gpio(void) {
#if CONFIG_SPDIF_DO_IO >= 0
  gpio_config_t spdif_gpio_cfg = {
      .pin_bit_mask = (1ULL << CONFIG_SPDIF_DO_IO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  esp_err_t err = gpio_config(&spdif_gpio_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure SPDIF GPIO");
  gpio_set_level(CONFIG_SPDIF_DO_IO, 0);
#endif
  return ESP_OK;
}

esp_err_t squeezeamp_deinit(void) {
  rtsp_events_unregister(on_rtsp_event);
  tas57xx_enable_speaker(false);
  tas57xx_set_power_mode(TAS57XX_AMP_OFF);
  return ESP_OK;
}
