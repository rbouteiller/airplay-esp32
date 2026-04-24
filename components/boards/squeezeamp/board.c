/**
 * @file board.c
 * @brief SqueezeAMP board implementation
 *
 * Initializes the TAS57xx DAC and handles RTSP events to control DAC power.
 *
 * Features
 *  - DAC control via TAS57xx
 *  - Speaker fault auto-mute and recovery
 *  - Headphone jack detection to disable speakers
 *
 * LED handling is done by the led.c module.
 *
 * SqueezeAmp GPIO Pin Assignment
 * ┌─────────────────────────────────────────────────────────────┐
 * │  Function              │  GPIO  │  Direction  │  Notes      │
 * ├─────────────────────────────────────────────────────────────┤
 * │  I2S Bit Clock (BCK)   │   33   │  Output     │  Audio      │
 * │  I2S Word Select (WS)  │   25   │  Output     │  Audio      │
 * │  I2S Data Out (DO)     │   32   │  Output     │  Audio      │
 * ├─────────────────────────────────────────────────────────────┤
 * │  SPDIF Data Out        │   15   │  Output     │  Optical    │
 * ├─────────────────────────────────────────────────────────────┤
 * │  DAC I2C SDA           │   27   │  Bidir      │  TAS57xx    │
 * │  DAC I2C SCL           │   26   │  Output     │  TAS57xx    │
 * │  Mute Control          │   14   │  Output     │  Active Low │
 * ├─────────────────────────────────────────────────────────────┤
 * │  Speaker Fault         │    2   │  Input      │  Protection │
 * │  Jack Detection        │   34   │  Input      │  Headphone  │
 * ├─────────────────────────────────────────────────────────────┤
 * │  Status LED            │   12   │  Output     │  Green      │
 * │  Error LED             │   13   │  Output     │  Red        │
 * ├─────────────────────────────────────────────────────────────┤
 * │  Battery Monitor       │    7   │  ADC Input  │  Voltage    │
 * └─────────────────────────────────────────────────────────────┘
 */

#include "iot_board.h"

#include "dac.h"
#include "dac_tas57xx.h"
#include "settings.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rtsp_events.h"
#include "led.h"
#include "soc/gpio_struct.h"

#define ISR_HANDLER_TASK_STACK_SIZE 4096
#define ISR_HANDLER_TASK_PRIORITY   5
#define JACK_DEBOUNCE_MS            200

// Notification bits for speaker fault task
#define SPKFAULT_NOTIFY_FAULT (1 << 0)
#define SPKFAULT_NOTIFY_CLEAR (1 << 1)
#define JACK_NOTIFY_CHANGED   (1 << 2)

static const char TAG[] = "SqueezeAMP";

static bool s_board_initialized = false;
static TaskHandle_t gpio_task_handle = NULL;
static volatile bool speaker_fault_active = false;
static volatile bool headphone_inserted = false;
static i2c_master_bus_handle_t s_i2c_dac_bus_handle = NULL;
static i2c_master_bus_handle_t s_i2c_disp_bus_handle = NULL;

static esp_err_t init_mute_gpio(void);
static esp_err_t init_spkfault_gpio(void);
static esp_err_t init_jack_gpio(void);
static esp_err_t init_gpio_isr_task(void);
static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data);

// Speaker fault ISR - just notifies the task, no I2C calls
static void IRAM_ATTR spkfault_isr_handler(void *arg) {
  (void)arg;
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;

  // Check current GPIO level to determine fault or clear
  int level = gpio_get_level(BOARD_SPKFAULT_GPIO);
  uint32_t notify_bit =
      (level == 0) ? SPKFAULT_NOTIFY_FAULT : SPKFAULT_NOTIFY_CLEAR;

  if (gpio_task_handle != NULL) {
    xTaskNotifyFromISR(gpio_task_handle, notify_bit, eSetBits,
                       &xHigherPriorityTaskWoken);
  }

  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

// Headphone jack ISR - notifies the task (debounced in task)
static void IRAM_ATTR jack_isr_handler(void *arg) {
  (void)arg;
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;

  if (gpio_task_handle != NULL) {
    xTaskNotifyFromISR(gpio_task_handle, JACK_NOTIFY_CHANGED, eSetBits,
                       &xHigherPriorityTaskWoken);
  }

  portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}

// Task to handle speaker fault and jack events (runs I2C-safe operations)
static void spkfault_task(void *arg) {
  (void)arg;
  uint32_t notification;

  ESP_LOGI(TAG, "GPIO events task started");

  while (true) {
    if (xTaskNotifyWait(0, UINT32_MAX, &notification, portMAX_DELAY) ==
        pdTRUE) {
      // Handle speaker fault
      if (notification & SPKFAULT_NOTIFY_FAULT) {
        if (!speaker_fault_active) {
          speaker_fault_active = true;
          ESP_LOGW(TAG, "Speaker fault detected");
          dac_enable_speaker(false);
          led_set_error(true);
        }
      }

      if (notification & SPKFAULT_NOTIFY_CLEAR) {
        if (speaker_fault_active) {
          speaker_fault_active = false;
          ESP_LOGI(TAG, "Speaker fault cleared");
          // Only re-enable speaker if no headphone inserted
          if (!headphone_inserted) {
            dac_enable_speaker(true);
          }
          led_set_error(false);
        }
      }

      // Handle headphone jack with debounce
      if (notification & JACK_NOTIFY_CHANGED) {
        // Wait for debounce period
        vTaskDelay(pdMS_TO_TICKS(JACK_DEBOUNCE_MS));

        // Read stable state after debounce
        bool jack_inserted = (gpio_get_level(BOARD_JACK_GPIO) == 0);

        if (jack_inserted && !headphone_inserted) {
          headphone_inserted = true;
          dac_enable_speaker(false);
        } else if (!jack_inserted && headphone_inserted) {
          headphone_inserted = false;
          // Only re-enable speaker if no fault active
          if (!speaker_fault_active) {
            dac_enable_speaker(true);
          }
        }
      }
    }
  }
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
    break;
  case RTSP_EVENT_DISCONNECTED:
    dac_set_power_mode(DAC_POWER_OFF);
    break;
  case RTSP_EVENT_METADATA:
    break;
  }
}

const char *iot_board_get_info(void) {
  return BOARD_NAME;
}

bool iot_board_is_init(void) {
  return s_board_initialized;
}

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
  case BOARD_I2C_DAC_ID:
    return (board_res_handle_t)s_i2c_dac_bus_handle;
  case BOARD_I2C_DISP_ID:
    return (board_res_handle_t)s_i2c_disp_bus_handle;
  default:
    return NULL;
  }
}

esp_err_t iot_board_init(void) {
  esp_err_t err = ESP_OK;

  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

  // Initialize DAC I2C bus
  i2c_master_bus_config_t i2c_cfg = {
      .i2c_port = BOARD_I2C_PORT,
      .sda_io_num = BOARD_I2C_SDA_GPIO,
      .scl_io_num = BOARD_I2C_SCL_GPIO,
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .glitch_ignore_cnt = 7,
      .flags.enable_internal_pullup = true,
  };
  err = i2c_new_master_bus(&i2c_cfg, &s_i2c_dac_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC I2C bus: %s", esp_err_to_name(err));
    return err;
  }
  ESP_LOGI(TAG, "DAC I2C bus %d initialized: sda=%d, scl=%d", BOARD_I2C_PORT,
           BOARD_I2C_SDA_GPIO, BOARD_I2C_SCL_GPIO);

#if defined(CONFIG_DISPLAY_ENABLED) && defined(CONFIG_DISPLAY_BUS_I2C)
  // Initialize display I2C bus — share with DAC bus if pins are identical,
  // otherwise bring up a second controller on BOARD_I2C_DISP_PORT.
  if (CONFIG_DISPLAY_I2C_SDA == BOARD_I2C_SDA_GPIO &&
      CONFIG_DISPLAY_I2C_SCL == BOARD_I2C_SCL_GPIO) {
    s_i2c_disp_bus_handle = s_i2c_dac_bus_handle;
    ESP_LOGI(TAG, "Display sharing DAC I2C bus");
  } else {
    i2c_master_bus_config_t disp_i2c_cfg = {
        .i2c_port = BOARD_I2C_DISP_PORT,
        .sda_io_num = CONFIG_DISPLAY_I2C_SDA,
        .scl_io_num = CONFIG_DISPLAY_I2C_SCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    err = i2c_new_master_bus(&disp_i2c_cfg, &s_i2c_disp_bus_handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to initialize display I2C bus: %s",
               esp_err_to_name(err));
      return err;
    }
    ESP_LOGI(TAG, "Display I2C bus %d initialized: sda=%d, scl=%d",
             BOARD_I2C_DISP_PORT, CONFIG_DISPLAY_I2C_SDA,
             CONFIG_DISPLAY_I2C_SCL);
  }
#endif

  // Register and initialize DAC
  dac_register(&dac_tas57xx_ops);

  err = dac_init(s_i2c_dac_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC: %s", esp_err_to_name(err));
    return err;
  }

  // Restore saved volume
  float vol_db;
  if (ESP_OK == settings_get_volume(&vol_db)) {
    dac_set_volume(vol_db);
  }

  // Configure mute GPIO
  err = init_mute_gpio();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize mute GPIO: %s", esp_err_to_name(err));
    return err;
  }

  // Create GPIO ISR service and event handler task
  err = init_gpio_isr_task();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize GPIO ISR task: %s",
             esp_err_to_name(err));
    return err;
  }

  // Configure speaker fault detection
  err = init_spkfault_gpio();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize speaker fault GPIO: %s",
             esp_err_to_name(err));
    return err;
  }

  // Configure headphone jack detection
  err = init_jack_gpio();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize jack GPIO: %s", esp_err_to_name(err));
    return err;
  }

  // Register for RTSP events to control DAC power
  rtsp_events_register(on_rtsp_event, NULL);

  // Start in standby
  dac_set_power_mode(DAC_POWER_OFF);

  s_board_initialized = true;
  ESP_LOGI(TAG, "SqueezeAMP initialized");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  if (!s_board_initialized) {
    return ESP_OK;
  }

  gpio_isr_handler_remove(BOARD_JACK_GPIO);
  gpio_isr_handler_remove(BOARD_SPKFAULT_GPIO);
  if (gpio_task_handle != NULL) {
    vTaskDelete(gpio_task_handle);
    gpio_task_handle = NULL;
  }
  rtsp_events_unregister(on_rtsp_event);

  // Ensure mute GPIO is active (muted) during shutdown for safety
  gpio_set_level(BOARD_MUTE_GPIO, BOARD_MUTE_GPIO_LEVEL);

  dac_enable_speaker(false);
  dac_set_power_mode(DAC_POWER_OFF);
  dac_deinit();

  // Tear down I2C buses (after DAC is deinitialized)
  // Free display bus first — only if it is not shared with the DAC bus
  if (s_i2c_disp_bus_handle != NULL &&
      s_i2c_disp_bus_handle != s_i2c_dac_bus_handle) {
    i2c_del_master_bus(s_i2c_disp_bus_handle);
  }
  s_i2c_disp_bus_handle = NULL;
  if (s_i2c_dac_bus_handle != NULL) {
    i2c_del_master_bus(s_i2c_dac_bus_handle);
    s_i2c_dac_bus_handle = NULL;
  }

  s_board_initialized = false;
  return ESP_OK;
}

static esp_err_t init_mute_gpio(void) {
  gpio_config_t mute_gpio_cfg = {
      .pin_bit_mask = (1ULL << BOARD_MUTE_GPIO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  esp_err_t err = gpio_config(&mute_gpio_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure mute GPIO");

  // Initialize to unmuted state (active low, so set high to unmute)
  gpio_set_level(BOARD_MUTE_GPIO, !BOARD_MUTE_GPIO_LEVEL);

  ESP_LOGI(TAG, "Mute GPIO initialized on GPIO %d (active %s)", BOARD_MUTE_GPIO,
           BOARD_MUTE_GPIO_LEVEL ? "high" : "low");
  return ESP_OK;
}

static esp_err_t init_gpio_isr_task(void) {
  esp_err_t err = board_gpio_isr_init();
  if (err != ESP_OK) {
    return err;
  }

  BaseType_t ret =
      xTaskCreate(spkfault_task, "gpio_events", ISR_HANDLER_TASK_STACK_SIZE,
                  NULL, ISR_HANDLER_TASK_PRIORITY, &gpio_task_handle);
  if (ret != pdPASS) {
    ESP_LOGE(TAG, "Failed to create GPIO events task");
    return ESP_ERR_NO_MEM;
  }

  return ESP_OK;
}

static esp_err_t init_spkfault_gpio(void) {
  gpio_config_t spkfault_cfg = {
      .pin_bit_mask = (1ULL << BOARD_SPKFAULT_GPIO),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_ENABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE, // Trigger on both fault and recovery
  };
  esp_err_t err = gpio_config(&spkfault_cfg);
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
}

static esp_err_t init_jack_gpio(void) {
  // Note: GPIO 34-39 on ESP32 are input-only and have no internal pull-up.
  // An external pull-up resistor is required on the jack detect pin.
  gpio_config_t jack_cfg = {
      .pin_bit_mask = (1ULL << BOARD_JACK_GPIO),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE, // GPIO 34 has no internal pull-up
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE, // Trigger on both insert and remove
  };
  esp_err_t err = gpio_config(&jack_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure jack GPIO");

  err = gpio_isr_handler_add(BOARD_JACK_GPIO, jack_isr_handler, NULL);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to add jack ISR handler");

  // Check initial state in case headphone is already inserted
  if (gpio_get_level(BOARD_JACK_GPIO) == 0) {
    xTaskNotify(gpio_task_handle, JACK_NOTIFY_CHANGED, eSetBits);
  }

  ESP_LOGI(TAG, "Headphone jack detection enabled on GPIO %d", BOARD_JACK_GPIO);
  return ESP_OK;
}

// Override the abort() function to mute GPIO during system panics
// This is called by ESP-IDF during panic/abort situations
void IRAM_ATTR __wrap_abort(void) {
  // Immediately mute the amplifier using direct register access
  // This must be fast and not rely on any complex systems
  if (BOARD_MUTE_GPIO_LEVEL) {
    // Active high - set bit
    GPIO.out_w1ts = (1ULL << BOARD_MUTE_GPIO);
  } else {
    // Active low - clear bit
    GPIO.out_w1tc = (1ULL << BOARD_MUTE_GPIO);
  }

  // Call the original abort function
  extern void __real_abort(void) __attribute__((noreturn));
  __real_abort();
}
