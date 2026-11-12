/**
 * @file board.c
 * @brief Board implementation for Amped-Esparagus-Plus-S3
 *
 * ESP32-S3 with a PCM5122 I2C-controlled DAC feeding a TPA3118 amplifier.
 * Uses the shared dac_pcm51xx driver (also used by Sonocotta HiFi-ESP32-Plus
 * / Amped-ESP32-Plus): it owns the DAC's I2C register control (power,
 * volume, mute) and drives CONFIG_DAC_ENABLE_GPIO high only while playing,
 * so this board does not touch that pin itself — see dac_pcm51xx.h.
 */

#include "iot_board.h"

#include "dac.h"
#include "dac_pcm51xx.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "playback_events.h"

#ifdef CONFIG_ETH_W5500_ENABLED
#include "driver/spi_master.h"
#endif

static const char TAG[] = "AmpedEsparagusPlusS3";

static bool s_board_initialized = false;
static i2c_master_bus_handle_t s_i2c_bus_handle = NULL;

#ifdef CONFIG_ETH_W5500_ENABLED
static bool s_spi_bus_initialized = false;
#endif

static void on_playback_event(playback_source_t source, playback_event_t event,
                              const playback_event_data_t *data,
                              void *user_data);
static void i2c_bus_recover(int sda_gpio, int scl_gpio);

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
  case BOARD_I2C_DAC_ID:
    return (board_res_handle_t)s_i2c_bus_handle;
  case BOARD_SPI_ETH_ID:
  case BOARD_SPI_DISP_ID:
    // Ethernet and display share the same SPI bus on this board.
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

  // The PCM5122 has no reset pin wired on this board, so it stays powered
  // (and can stay mid-transaction) across an MCU-only reset — a crash
  // recovery, OTA reboot, or `pio run -t upload`. If that leaves it holding
  // SDA low, clock it out by hand before the I2C driver claims the pins.
  i2c_bus_recover(BOARD_I2C_SDA_GPIO, BOARD_I2C_SCL_GPIO);

  // Initialize I2C bus (board owns the bus lifetime)
  i2c_master_bus_config_t i2c_cfg = {
      .i2c_port = BOARD_I2C_PORT,
      .sda_io_num = BOARD_I2C_SDA_GPIO,
      .scl_io_num = BOARD_I2C_SCL_GPIO,
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .glitch_ignore_cnt = 7,
      .flags.enable_internal_pullup = true,
  };
  esp_err_t err = i2c_new_master_bus(&i2c_cfg, &s_i2c_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize I2C bus: %s", esp_err_to_name(err));
    return err;
  }
  ESP_LOGI(TAG, "I2C bus %d initialized: sda=%d, scl=%d", BOARD_I2C_PORT,
           BOARD_I2C_SDA_GPIO, BOARD_I2C_SCL_GPIO);

  dac_register(&dac_pcm51xx_ops);
  err = dac_init(s_i2c_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC: %s", esp_err_to_name(err));
    return err;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  // Initialize SPI bus (shared between W5500 Ethernet and the display)
  spi_bus_config_t spi_bus_cfg = {
      .mosi_io_num = BOARD_SPI_MOSI_GPIO,
      .miso_io_num = BOARD_SPI_MISO_GPIO,
      .sclk_io_num = BOARD_SPI_CLK_GPIO,
      .quadwp_io_num = -1,
      .quadhd_io_num = -1,
  };
  err = spi_bus_initialize(BOARD_SPI_HOST, &spi_bus_cfg, SPI_DMA_CH_AUTO);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(err));
    return err;
  }
  s_spi_bus_initialized = true;
  ESP_LOGI(TAG, "SPI bus initialized: mosi=%d, miso=%d, clk=%d",
           BOARD_SPI_MOSI_GPIO, BOARD_SPI_MISO_GPIO, BOARD_SPI_CLK_GPIO);
#endif

  playback_events_register(on_playback_event, NULL);

  // Start powered down; the DAC (and its enable pin) only come up while
  // actually playing.
  dac_set_power_mode(DAC_POWER_OFF);

  s_board_initialized = true;
  ESP_LOGI(TAG, "Amped-Esparagus-Plus-S3 initialized");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  if (!s_board_initialized) {
    return ESP_OK;
  }

  playback_events_unregister(on_playback_event);

  dac_set_power_mode(DAC_POWER_OFF);
  dac_deinit();

  if (s_i2c_bus_handle != NULL) {
    i2c_del_master_bus(s_i2c_bus_handle);
    s_i2c_bus_handle = NULL;
  }

#ifdef CONFIG_ETH_W5500_ENABLED
  if (s_spi_bus_initialized) {
    spi_bus_free(BOARD_SPI_HOST);
    s_spi_bus_initialized = false;
  }
#endif

  s_board_initialized = false;
  return ESP_OK;
}

// Bit-bang up to 9 SCL pulses (one per bit a wedged slave could be holding
// SDA for) followed by a STOP condition, using plain GPIO before the I2C
// driver owns the pins. Standard I2C bus recovery (NXP UM10204 §3.1.16).
static void i2c_bus_recover(int sda_gpio, int scl_gpio) {
  gpio_config_t scl_cfg = {
      .pin_bit_mask = 1ULL << scl_gpio,
      .mode = GPIO_MODE_OUTPUT_OD,
      .pull_up_en = GPIO_PULLUP_ENABLE,
  };
  gpio_config(&scl_cfg);
  gpio_config_t sda_cfg = {
      .pin_bit_mask = 1ULL << sda_gpio,
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_ENABLE,
  };
  gpio_config(&sda_cfg);
  gpio_set_level(scl_gpio, 1);
  esp_rom_delay_us(5);

  if (gpio_get_level(sda_gpio) == 1) {
    return; // bus already idle
  }

  ESP_LOGW(TAG, "I2C SDA held low at boot — recovering the bus");
  for (int i = 0; i < 9 && gpio_get_level(sda_gpio) == 0; i++) {
    gpio_set_level(scl_gpio, 0);
    esp_rom_delay_us(5);
    gpio_set_level(scl_gpio, 1);
    esp_rom_delay_us(5);
  }

  // STOP condition: SDA rises while SCL is high.
  gpio_set_direction(sda_gpio, GPIO_MODE_OUTPUT_OD);
  gpio_set_level(sda_gpio, 0);
  esp_rom_delay_us(5);
  gpio_set_level(scl_gpio, 1);
  esp_rom_delay_us(5);
  gpio_set_level(sda_gpio, 1);
  esp_rom_delay_us(5);

  ESP_LOGI(TAG, "I2C bus recovery: SDA now %s",
           gpio_get_level(sda_gpio) ? "released" : "still stuck low");
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
