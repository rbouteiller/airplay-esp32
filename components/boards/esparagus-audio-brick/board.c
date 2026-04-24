/**
 * @file board.c
 * @brief Board implementation for the esparagus audio brick
 *
 * Features:
 *  - DAC control via TAS58xx
 *  - Speaker fault auto-mute and recovery
 */

#include "iot_board.h"

#include "dac.h"
#include "dac_tas58xx.h"
#include "dac_tas58xx_eq.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "eq_events.h"
#include "esp_attr.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led.h"
#include "rtsp_events.h"
#include "settings.h"

#if defined(CONFIG_ETH_W5500_ENABLED) || defined(CONFIG_DISPLAY_BUS_SPI)
#include "driver/spi_master.h"
#endif

#define ISR_HANDLER_TASK_STACK_SIZE 4096
#define ISR_HANDLER_TASK_PRIORITY   5

// Notification bits for speaker fault task
#define SPKFAULT_NOTIFY_FAULT (1 << 0)
#define SPKFAULT_NOTIFY_CLEAR (1 << 1)

static const char TAG[] = "EsparagusBrick";

static bool s_board_initialized = false;
static TaskHandle_t gpio_task_handle = NULL;
static volatile bool speaker_fault_active = false;
static i2c_master_bus_handle_t s_i2c_bus_handle = NULL;

#if defined(CONFIG_ETH_W5500_ENABLED) || defined(CONFIG_DISPLAY_BUS_SPI)
static bool s_spi_bus_initialized = false;
#endif

static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data);
static void on_eq_event(eq_event_t event, const eq_event_data_t *data,
                        void *user_data);
static esp_err_t init_spkfault_gpio(void);
static void restore_eq_from_nvs(void);

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
  case BOARD_I2C_DAC_ID:
  case BOARD_I2C_DISP_ID:
    return (board_res_handle_t)s_i2c_bus_handle;
  case BOARD_SPI_ETH_ID:
  case BOARD_SPI_DISP_ID:
    // Display and Ethernet share the same SPI bus on this board
#if defined(CONFIG_ETH_W5500_ENABLED) || defined(CONFIG_DISPLAY_BUS_SPI)
    return s_spi_bus_initialized ? (board_res_handle_t)(intptr_t)BOARD_SPI_HOST
                                 : NULL;
#else
    return NULL;
#endif
  default:
    return NULL;
  }
}

// Speaker fault ISR — notifies the handler task, no I2C calls from ISR
static void IRAM_ATTR spkfault_isr_handler(void *arg) {
  (void)arg;
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;

  int level = gpio_get_level(BOARD_SPKFAULT_GPIO);
  uint32_t notify_bit =
      (level == 0) ? SPKFAULT_NOTIFY_FAULT : SPKFAULT_NOTIFY_CLEAR;

  if (gpio_task_handle != NULL) {
    xTaskNotifyFromISR(gpio_task_handle, notify_bit, eSetBits,
                       &xHigherPriorityTaskWoken);
  }
  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

// Task to handle speaker fault events (runs I2C-safe operations)
static void spkfault_task(void *arg) {
  (void)arg;
  uint32_t notification;

  ESP_LOGI(TAG, "Speaker fault monitor task started");

  while (true) {
    if (xTaskNotifyWait(0, UINT32_MAX, &notification, portMAX_DELAY) ==
        pdTRUE) {
      if (notification & SPKFAULT_NOTIFY_FAULT) {
        if (!speaker_fault_active) {
          speaker_fault_active = true;
          ESP_LOGW(TAG, "Speaker fault detected — muting output");
          dac_enable_speaker(false);
          led_set_error(true);
        }
      }

      if (notification & SPKFAULT_NOTIFY_CLEAR) {
        if (speaker_fault_active) {
          speaker_fault_active = false;
          ESP_LOGI(TAG, "Speaker fault cleared — re-enabling output");
          dac_enable_speaker(true);
          led_set_error(false);
        }
      }
    }
  }
}

esp_err_t iot_board_init(void) {
  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

  // Register and initialize DAC
  dac_register(&dac_tas58xx_ops);

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

#if defined(CONFIG_ETH_W5500_ENABLED) || defined(CONFIG_DISPLAY_BUS_SPI)
  // Initialize SPI bus (shared between W5500 and display)
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

  err = dac_init(s_i2c_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC: %s", esp_err_to_name(err));
    return err;
  }

  // Register for RTSP events to control DAC power
  rtsp_events_register(on_rtsp_event, NULL);

  // Register for EQ events to persist + apply to DAC
  eq_events_register(on_eq_event, NULL);

  // Configure speaker fault detection
  err = init_spkfault_gpio();
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Speaker fault detection not available");
  }

  // Start in standby
  dac_set_power_mode(DAC_POWER_OFF);

  // Restore saved volume
  float vol_db;
  if (ESP_OK == settings_get_volume(&vol_db)) {
    dac_set_volume(vol_db);
  }

  s_board_initialized = true;
  ESP_LOGI(TAG, "Esparagus Brick initialized");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  if (!s_board_initialized) {
    return ESP_OK;
  }

#if BOARD_SPKFAULT_GPIO >= 0
  gpio_isr_handler_remove(BOARD_SPKFAULT_GPIO);
#endif
  if (gpio_task_handle != NULL) {
    vTaskDelete(gpio_task_handle);
    gpio_task_handle = NULL;
  }
  rtsp_events_unregister(on_rtsp_event);
  eq_events_unregister(on_eq_event);

  dac_enable_speaker(false);
  dac_set_power_mode(DAC_POWER_OFF);

  // Tear down I2C bus (after DAC is deinitialized)
  if (s_i2c_bus_handle != NULL) {
    i2c_del_master_bus(s_i2c_bus_handle);
    s_i2c_bus_handle = NULL;
  }

#if defined(CONFIG_ETH_W5500_ENABLED) || defined(CONFIG_DISPLAY_BUS_SPI)
  if (s_spi_bus_initialized) {
    spi_bus_free(BOARD_SPI_HOST);
    s_spi_bus_initialized = false;
  }
#endif

  s_board_initialized = false;
  return ESP_OK;
}

static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data) {
  (void)data;
  (void)user_data;

  switch (event) {
  case RTSP_EVENT_CLIENT_CONNECTED:
  case RTSP_EVENT_PAUSED:
    dac_set_power_mode(DAC_POWER_STANDBY);
    break;
  case RTSP_EVENT_PLAYING:
    dac_set_power_mode(DAC_POWER_ON);
    restore_eq_from_nvs();
    break;
  case RTSP_EVENT_DISCONNECTED:
    dac_set_power_mode(DAC_POWER_OFF);
    break;
  case RTSP_EVENT_METADATA:
    break;
  }
}

static esp_err_t init_spkfault_gpio(void) {
#if BOARD_SPKFAULT_GPIO >= 0
  esp_err_t err = board_gpio_isr_init();
  if (err != ESP_OK) {
    return err;
  }

  // Create handler task
  BaseType_t ret =
      xTaskCreate(spkfault_task, "spkfault", ISR_HANDLER_TASK_STACK_SIZE, NULL,
                  ISR_HANDLER_TASK_PRIORITY, &gpio_task_handle);
  if (ret != pdPASS) {
    ESP_LOGE(TAG, "Failed to create speaker fault task");
    return ESP_ERR_NO_MEM;
  }

  // GPIO 34-39 on ESP32 are input-only with no internal pull-up;
  // an external pull-up is required on the speaker fault pin.
  gpio_config_t spkfault_cfg = {
      .pin_bit_mask = (1ULL << BOARD_SPKFAULT_GPIO),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE,
  };
  err = gpio_config(&spkfault_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure speaker fault GPIO");

  err = gpio_isr_handler_add(BOARD_SPKFAULT_GPIO, spkfault_isr_handler, NULL);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to add speaker fault ISR handler");

  // Check initial state
  int level = gpio_get_level(BOARD_SPKFAULT_GPIO);
  if (level == 0) {
    ESP_LOGW(TAG, "Speaker fault already active at startup");
    xTaskNotify(gpio_task_handle, SPKFAULT_NOTIFY_FAULT, eSetBits);
  }

  ESP_LOGI(TAG, "Speaker fault detection enabled on GPIO %d",
           BOARD_SPKFAULT_GPIO);
  return ESP_OK;
#else
  return ESP_ERR_NOT_FOUND;
#endif
}

/* ------------------------------------------------------------------ */
/*  EQ event handling                                                  */
/* ------------------------------------------------------------------ */

/**
 * EQ event listener — persists gains to NVS and applies to hardware.
 */
static void on_eq_event(eq_event_t event, const eq_event_data_t *data,
                        void *user_data) {
  (void)user_data;

  switch (event) {
  case EQ_EVENT_ALL_BANDS_SET:
    if (data) {
      /* Persist to NVS */
      settings_set_eq_gains(data->all_bands.gains_db);
      /* Apply to DAC hardware */
      tas58xx_eq_set_all(data->all_bands.gains_db);
      ESP_LOGI(TAG, "EQ: all bands updated and saved");
    }
    break;

  case EQ_EVENT_BAND_CHANGED:
    if (data) {
      /* Apply single band to hardware */
      tas58xx_eq_set_band(data->band_changed.band, data->band_changed.gain_db);
      /* Read-modify-write NVS cache */
      float gains[SETTINGS_EQ_BANDS];
      if (settings_get_eq_gains(gains) != ESP_OK) {
        memset(gains, 0, sizeof(gains));
      }
      gains[data->band_changed.band] = data->band_changed.gain_db;
      settings_set_eq_gains(gains);
    }
    break;

  case EQ_EVENT_FLAT:
    tas58xx_eq_flat();
    settings_clear_eq();
    ESP_LOGI(TAG, "EQ: reset to flat");
    break;
  }
}

/**
 * Restore saved EQ gains from NVS and apply to the DAC.
 * Called after DAC enters PLAY (PLL locked, biquads accessible).
 */
static void restore_eq_from_nvs(void) {
  float gains[SETTINGS_EQ_BANDS];
  if (settings_get_eq_gains(gains) == ESP_OK) {
    esp_err_t err = tas58xx_eq_set_all(gains);
    if (err == ESP_OK) {
      ESP_LOGI(TAG, "EQ: restored %d bands from NVS", SETTINGS_EQ_BANDS);
    } else {
      ESP_LOGW(TAG, "EQ: failed to restore from NVS: %s", esp_err_to_name(err));
    }
  } else {
    ESP_LOGD(TAG, "EQ: no saved gains, using default (flat)");
  }
}