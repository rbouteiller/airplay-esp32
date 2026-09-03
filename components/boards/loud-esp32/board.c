/**
 * @file board.c
 * @brief Board implementation for the CONFIG_DAC_ENABLE_GPIO family:
 *        Loud-ESP32(-S3), Loud-Esparagus, Esparagus-Echo (MAX98357A) and
 *        Amped-ESP32(-S3) (PCM5100 + TPA3110/TPA3128).
 *
 * None of these amps have I2C control — each is a plain I2S input with a
 * single active-high enable/unmute pin (SD_MODE on the MAX98357A, UNMUTE
 * on the TPA3110/TPA3128). This registers a minimal DAC driver whose only
 * job is toggling that one pin from playback events (mirroring how
 * Esparagus Audio Brick drives TAS58xx power modes over I2C), plus the
 * same shared-SPI-bus bring-up as the other Ethernet+display boards in
 * this family.
 */

#include "iot_board.h"

#include "dac.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_log.h"
#include "playback_events.h"

#ifdef CONFIG_ETH_W5500_ENABLED
#include "driver/spi_master.h"
#endif

static const char TAG[] = "LoudEsp32";

static bool s_board_initialized = false;

#ifdef CONFIG_ETH_W5500_ENABLED
static bool s_spi_bus_initialized = false;
#endif

static void on_playback_event(playback_source_t source, playback_event_t event,
                              const playback_event_data_t *data,
                              void *user_data);

static esp_err_t max98357_init(void *i2c_bus) {
  (void)i2c_bus;
#if BOARD_DAC_ENABLE_GPIO >= 0
  gpio_config_t io_conf = {
      .pin_bit_mask = (1ULL << BOARD_DAC_ENABLE_GPIO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  esp_err_t err = gpio_config(&io_conf);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure DAC enable GPIO");

  // Start muted — the amp only unmutes while actually playing.
  gpio_set_level(BOARD_DAC_ENABLE_GPIO, 0);
  ESP_LOGI(TAG, "DAC enable GPIO %d initialized (muted)",
           BOARD_DAC_ENABLE_GPIO);
#endif
  return ESP_OK;
}

static void max98357_set_power_mode(dac_power_mode_t mode) {
#if BOARD_DAC_ENABLE_GPIO >= 0
  gpio_set_level(BOARD_DAC_ENABLE_GPIO, mode == DAC_POWER_ON ? 1 : 0);
#else
  (void)mode;
#endif
}

static const dac_ops_t max98357_ops = {
    .init = max98357_init,
    .set_power_mode = max98357_set_power_mode,
};

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
  case BOARD_SPI_ETH_ID:
  case BOARD_SPI_DISP_ID:
    // Display and Ethernet share the same SPI bus on this board
#ifdef CONFIG_ETH_W5500_ENABLED
    return s_spi_bus_initialized ? (board_res_handle_t)(intptr_t)BOARD_SPI_HOST
                                 : NULL;
#else
    return NULL;
#endif
  default:
    return NULL;
  }
}

esp_err_t iot_board_init(void) {
  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  // Initialize SPI bus (shared between W5500 and display)
  spi_bus_config_t spi_bus_cfg = {
      .mosi_io_num = BOARD_SPI_MOSI_GPIO,
      .miso_io_num = BOARD_SPI_MISO_GPIO,
      .sclk_io_num = BOARD_SPI_CLK_GPIO,
      .quadwp_io_num = -1,
      .quadhd_io_num = -1,
  };
  esp_err_t err =
      spi_bus_initialize(BOARD_SPI_HOST, &spi_bus_cfg, SPI_DMA_CH_AUTO);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(err));
    return err;
  }
  s_spi_bus_initialized = true;
  ESP_LOGI(TAG, "SPI bus initialized: mosi=%d, miso=%d, clk=%d",
           BOARD_SPI_MOSI_GPIO, BOARD_SPI_MISO_GPIO, BOARD_SPI_CLK_GPIO);
#endif

  dac_register(&max98357_ops);
  esp_err_t dac_err = dac_init(NULL);
  if (dac_err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC enable GPIO: %s",
             esp_err_to_name(dac_err));
    return dac_err;
  }

  playback_events_register(on_playback_event, NULL);

  s_board_initialized = true;
  ESP_LOGI(TAG, "Loud-ESP32 initialized");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  if (!s_board_initialized) {
    return ESP_OK;
  }

  playback_events_unregister(on_playback_event);
  dac_set_power_mode(DAC_POWER_OFF);

#ifdef CONFIG_ETH_W5500_ENABLED
  if (s_spi_bus_initialized) {
    spi_bus_free(BOARD_SPI_HOST);
    s_spi_bus_initialized = false;
  }
#endif

  s_board_initialized = false;
  return ESP_OK;
}

static void on_playback_event(playback_source_t source, playback_event_t event,
                              const playback_event_data_t *data,
                              void *user_data) {
  (void)source;
  (void)data;
  (void)user_data;

  switch (event) {
  case PLAYBACK_EVENT_CONNECTED:
  case PLAYBACK_EVENT_PAUSED:
    dac_set_power_mode(DAC_POWER_STANDBY);
    break;
  case PLAYBACK_EVENT_PLAYING:
    dac_set_power_mode(DAC_POWER_ON);
    break;
  case PLAYBACK_EVENT_DISCONNECTED:
    dac_set_power_mode(DAC_POWER_OFF);
    break;
  case PLAYBACK_EVENT_METADATA:
    break;
  }
}
