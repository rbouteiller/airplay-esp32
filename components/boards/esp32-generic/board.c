/**
 * @file board.c
 * @brief ESP32 Generic board implementation
 *
 * Minimal implementation for generic ESP32 dev boards with external I2S DAC.
 * No board-specific initialization required.
 */

#include "iot_board.h"

#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_log.h"

static const char TAG[] = "ESP32-Generic";

static bool s_board_initialized = false;

#ifdef CONFIG_MUTE_GPIO
static esp_err_t init_mute_gpio(void) {
  if (CONFIG_MUTE_GPIO < 0) {
    return ESP_OK;
  }

  gpio_config_t io_conf = {
      .pin_bit_mask = (1ULL << CONFIG_MUTE_GPIO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  esp_err_t err = gpio_config(&io_conf);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure mute GPIO");

  // Initialize to unmuted state — set opposite of active level
  gpio_set_level(CONFIG_MUTE_GPIO, !CONFIG_MUTE_GPIO_LEVEL);

  ESP_LOGI(TAG, "Mute GPIO %d initialized (active %s, init %s)",
           CONFIG_MUTE_GPIO, CONFIG_MUTE_GPIO_LEVEL ? "high" : "low",
           CONFIG_MUTE_GPIO_LEVEL ? "low" : "high");
  return ESP_OK;
}
#endif

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  (void)id;
  return NULL;
}

esp_err_t iot_board_init(void) {
  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

#ifdef CONFIG_MUTE_GPIO
  esp_err_t err = init_mute_gpio();
  if (err != ESP_OK) {
    return err;
  }
#endif

  s_board_initialized = true;
  ESP_LOGI(TAG, "Generic board initialized (no board-specific init needed)");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  s_board_initialized = false;
  return ESP_OK;
}
