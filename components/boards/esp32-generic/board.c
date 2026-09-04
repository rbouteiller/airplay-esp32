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

#ifdef CONFIG_DAC_ES8388
#include "dac.h"
#include "dac_es8388.h"
#include "driver/i2c_master.h"
#include "settings.h"
#endif

static const char TAG[] = "ESP32-Generic";

static bool s_board_initialized = false;

#ifdef CONFIG_DAC_ES8388
static i2c_master_bus_handle_t s_i2c_dac_bus_handle = NULL;

static esp_err_t init_es8388(void) {
  if (CONFIG_DAC_I2C_SDA < 0 || CONFIG_DAC_I2C_SCL < 0) {
    ESP_LOGW(TAG, "DAC_ES8388 enabled but DAC_I2C_SDA/SCL not set — skipping");
    return ESP_OK;
  }

  i2c_master_bus_config_t i2c_cfg = {
      .i2c_port = 0,
      .sda_io_num = CONFIG_DAC_I2C_SDA,
      .scl_io_num = CONFIG_DAC_I2C_SCL,
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .glitch_ignore_cnt = 7,
      .flags.enable_internal_pullup = true,
  };
  esp_err_t err = i2c_new_master_bus(&i2c_cfg, &s_i2c_dac_bus_handle);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to initialize DAC I2C bus");
  ESP_LOGI(TAG, "DAC I2C bus initialized: sda=%d, scl=%d", CONFIG_DAC_I2C_SDA,
           CONFIG_DAC_I2C_SCL);

  dac_register(&dac_es8388_ops);
  err = dac_init(s_i2c_dac_bus_handle);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to initialize ES8388 DAC");

  // Restore saved volume — the codec boots at 0dB until programmed.
  float vol_db;
  if (ESP_OK == settings_get_volume(&vol_db)) {
    dac_set_volume(vol_db);
  }

  return ESP_OK;
}
#endif

// -1 disables the pin, and the runtime test that used to guard this came too
// late: the shift below is a constant the compiler folds either way.
#if defined(CONFIG_MUTE_GPIO) && CONFIG_MUTE_GPIO >= 0
static esp_err_t init_mute_gpio(void) {
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

#if defined(CONFIG_MUTE_GPIO) && CONFIG_MUTE_GPIO >= 0
  esp_err_t err = init_mute_gpio();
  if (err != ESP_OK) {
    return err;
  }
#endif

#ifdef CONFIG_DAC_ES8388
  esp_err_t es8388_err = init_es8388();
  if (es8388_err != ESP_OK) {
    return es8388_err;
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
