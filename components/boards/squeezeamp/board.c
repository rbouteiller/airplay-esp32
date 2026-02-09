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

#include "dac_tas57xx.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rtsp_events.h"
#include "led.h"
#include "soc/gpio_struct.h"

#define ISR_HANDLER_TASK_STACK_SIZE 2048
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

static esp_err_t init_mute_gpio(void);
static esp_err_t init_spkfault_gpio(void);
static esp_err_t init_jack_gpio(void);
static esp_err_t ensure_gpio_task_exists(void);
static void on_rtsp_event(rtsp_event_t event, void *user_data);

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
          tas57xx_enable_speaker(false);
          led_set_error(true);
        }
      }

      if (notification & SPKFAULT_NOTIFY_CLEAR) {
        if (speaker_fault_active) {
          speaker_fault_active = false;
          ESP_LOGI(TAG, "Speaker fault cleared");
          // Only re-enable speaker if no headphone inserted
          if (!headphone_inserted) {
            tas57xx_enable_speaker(true);
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
          tas57xx_enable_speaker(false);
        } else if (!jack_inserted && headphone_inserted) {
          headphone_inserted = false;
          // Only re-enable speaker if no fault active
          if (!speaker_fault_active) {
            tas57xx_enable_speaker(true);
          }
        }
      }
    }
  }
}

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
    tas57xx_set_power_mode(TAS57XX_AMP_OFF);
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
  (void)id;
  // No dynamic resource handles on SqueezeAMP
  return NULL;
}

esp_err_t iot_board_init(void) {
  esp_err_t err = ESP_OK;

  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

  // Initialize I2C for DAC control
  err = tas57xx_init(BOARD_I2C_PORT, BOARD_I2C_SDA_GPIO, BOARD_I2C_SCL_GPIO);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize TAS57xx: %s", esp_err_to_name(err));
    return err;
  }

  // Configure mute GPIO
  err = init_mute_gpio();
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Mute GPIO not available");
  }

  // Configure speaker fault detection
  err = init_spkfault_gpio();
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Speaker fault detection not available");
  }

  // Configure headphone jack detection
  err = init_jack_gpio();
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Headphone jack detection not available");
  }

  // Register for RTSP events to control DAC power
  rtsp_events_register(on_rtsp_event, NULL);

  // Start in standby
  tas57xx_set_power_mode(TAS57XX_AMP_OFF);

  s_board_initialized = true;
  ESP_LOGI(TAG, "SqueezeAMP DAC initialized");
  return ESP_OK;
}

esp_err_t iot_board_deinit(void) {
  if (!s_board_initialized) {
    return ESP_OK;
  }

#if BOARD_JACK_GPIO >= 0
  gpio_isr_handler_remove(BOARD_JACK_GPIO);
#endif
#if BOARD_SPKFAULT_GPIO >= 0
  gpio_isr_handler_remove(BOARD_SPKFAULT_GPIO);
#endif
  if (gpio_task_handle != NULL) {
    vTaskDelete(gpio_task_handle);
    gpio_task_handle = NULL;
  }
  rtsp_events_unregister(on_rtsp_event);

  // Ensure mute GPIO is active (muted) during shutdown for safety
#if BOARD_MUTE_GPIO >= 0
  gpio_set_level(BOARD_MUTE_GPIO, BOARD_MUTE_GPIO_LEVEL);
#endif

  tas57xx_enable_speaker(false);
  tas57xx_set_power_mode(TAS57XX_AMP_OFF);

  s_board_initialized = false;
  return ESP_OK;
}

static esp_err_t init_mute_gpio(void) {
#if BOARD_MUTE_GPIO >= 0
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

  ESP_LOGI(TAG, "Mute GPIO initialized on GPIO %d (active %s)",
           BOARD_MUTE_GPIO, BOARD_MUTE_GPIO_LEVEL ? "high" : "low");
  return ESP_OK;
#endif
  return ESP_ERR_NOT_FOUND;
}

static esp_err_t ensure_gpio_task_exists(void) {
  if (gpio_task_handle == NULL) {

    // Install ISR service - this is for all GPIOs,
    esp_err_t err = gpio_install_isr_service(0);
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
      ESP_LOGE(TAG, "Failed to install GPIO ISR service: %s",
               esp_err_to_name(err));
      return err;
    }

    BaseType_t ret =
        xTaskCreate(spkfault_task, "gpio_events", ISR_HANDLER_TASK_STACK_SIZE,
                    NULL, ISR_HANDLER_TASK_PRIORITY, &gpio_task_handle);
    if (ret != pdPASS) {
      ESP_LOGE(TAG, "Failed to create GPIO events task");
      return ESP_ERR_NO_MEM;
    }
  }

  return ESP_OK;
}

static esp_err_t init_spkfault_gpio(void) {
#if BOARD_SPKFAULT_GPIO >= 0
  // Ensure the handler task exists
  esp_err_t err = ensure_gpio_task_exists();
  if (err != ESP_OK) {
    return err;
  }

  gpio_config_t spkfault_cfg = {
      .pin_bit_mask = (1ULL << BOARD_SPKFAULT_GPIO),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_ENABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE, // Trigger on both fault and recovery
  };
  err = gpio_config(&spkfault_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure speaker fault GPIO");

  // Add handler for speaker fault interrupt
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
#endif
  return ESP_ERR_NOT_FOUND;
}

static esp_err_t init_jack_gpio(void) {
#if BOARD_JACK_GPIO >= 0
  // Ensure the handler task exists
  esp_err_t err = ensure_gpio_task_exists();
  if (err != ESP_OK) {
    return err;
  }

  // Note: GPIO 34-39 on ESP32 are input-only and have no internal pull-up.
  // An external pull-up resistor is required on the jack detect pin.
  gpio_config_t jack_cfg = {
      .pin_bit_mask = (1ULL << BOARD_JACK_GPIO),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE, // GPIO 34 has no internal pull-up
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE, // Trigger on both insert and remove
  };
  err = gpio_config(&jack_cfg);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to configure jack GPIO");

  // Add handler for jack interrupt
  err = gpio_isr_handler_add(BOARD_JACK_GPIO, jack_isr_handler, NULL);
  ESP_RETURN_ON_ERROR(err, TAG, "Failed to add jack ISR handler");

  // Check initial state in case headphone is already inserted
  if (gpio_get_level(BOARD_JACK_GPIO) == 0) {
    ESP_LOGI(TAG, "Headphone already inserted at startup");
    xTaskNotify(gpio_task_handle, JACK_NOTIFY_CHANGED, eSetBits);
  }

  ESP_LOGI(TAG, "Headphone jack detection enabled on GPIO %d",
           BOARD_JACK_GPIO);
  return ESP_OK;
#endif
  return ESP_ERR_NOT_FOUND;
}

// Override the abort() function to mute GPIO during system panics
// This is called by ESP-IDF during panic/abort situations
void IRAM_ATTR __wrap_abort(void) {
#if BOARD_MUTE_GPIO >= 0
  // Immediately mute the amplifier using direct register access
  // This must be fast and not rely on any complex systems
  if (BOARD_MUTE_GPIO_LEVEL) {
    // Active high - set bit
    GPIO.out_w1ts = (1ULL << BOARD_MUTE_GPIO);
  } else {
    // Active low - clear bit
    GPIO.out_w1tc = (1ULL << BOARD_MUTE_GPIO);
  }
#endif

  // Call the original abort function
  extern void __real_abort(void) __attribute__((noreturn));
  __real_abort();
}
