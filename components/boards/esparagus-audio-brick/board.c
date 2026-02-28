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
#include "driver/gpio.h"
#include "esp_attr.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led.h"
#include "rtsp_events.h"
#include "settings.h"

#define ISR_HANDLER_TASK_STACK_SIZE 2048
#define ISR_HANDLER_TASK_PRIORITY   5

// Notification bits for speaker fault task
#define SPKFAULT_NOTIFY_FAULT (1 << 0)
#define SPKFAULT_NOTIFY_CLEAR (1 << 1)

static const char TAG[] = "EsparagusBrick";

static bool s_board_initialized = false;
static TaskHandle_t gpio_task_handle = NULL;
static volatile bool speaker_fault_active = false;

static void on_rtsp_event(rtsp_event_t event, const rtsp_event_data_t *data,
                          void *user_data);
static esp_err_t init_spkfault_gpio(void);

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
  esp_err_t err = dac_init();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC: %s", esp_err_to_name(err));
    return err;
  }

  // Register for RTSP events to control DAC power
  rtsp_events_register(on_rtsp_event, NULL);

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

  dac_enable_speaker(false);
  dac_set_power_mode(DAC_POWER_OFF);

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
  // Install ISR service (shared across all GPIOs)
  esp_err_t err = gpio_install_isr_service(0);
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
    ESP_LOGE(TAG, "Failed to install GPIO ISR service: %s",
             esp_err_to_name(err));
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