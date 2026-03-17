/**
 * Hardware button driver — interrupt-driven with timer-based debounce.
 *
 * Each button GPIO triggers an ISR on any edge. The ISR resets a
 * FreeRTOS software timer (the debounce window). When the timer
 * expires — meaning the signal has been stable for DEBOUNCE_MS —
 * the callback reads the GPIO and acts on the new state.
 *
 * Volume buttons support auto-repeat: after REPEAT_DELAY_MS held,
 * the action repeats every REPEAT_INTERVAL_MS.
 *
 * Button actions are dispatched to a dedicated task via a queue so that
 * playback_control functions (which may do mDNS + HTTP) never block
 * the FreeRTOS timer daemon.
 */

#include "buttons.h"
#include "playback_control.h"
#include "spiram_task.h"

#include "board_common.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/timers.h"

static const char *TAG = "buttons";

#define DEBOUNCE_MS        50  // Stable period before accepting state change
#define REPEAT_DELAY_MS    500 // Hold duration before auto-repeat starts
#define REPEAT_INTERVAL_MS 200 // Auto-repeat interval for volume buttons
#define ACTION_QUEUE_LEN   8

typedef enum {
  BTN_PLAY_PAUSE,
  BTN_VOLUME_UP,
  BTN_VOLUME_DOWN,
  BTN_NEXT,
  BTN_PREV,
  BTN_COUNT
} button_id_t;

typedef struct {
  int gpio;
  bool pressed;    // Debounced state
  bool repeatable; // Supports auto-repeat (volume buttons)
  TimerHandle_t debounce_timer;
  TimerHandle_t repeat_timer; // Only created for repeatable buttons
} button_state_t;

static button_state_t buttons[BTN_COUNT];
static QueueHandle_t s_action_queue;

// Post a button action to the dedicated task (safe from timer callbacks)
static void post_button_action(button_id_t id) {
  int action = (int)id;
  // Non-blocking: drop if queue is full (better than blocking the timer task)
  xQueueSend(s_action_queue, &action, 0);
}

// Dedicated task that processes button actions — has enough stack for
// mDNS discovery + HTTP requests that DACP requires.
static void button_action_task(void *pvParameters) {
  (void)pvParameters;
  int action;
  while (1) {
    if (xQueueReceive(s_action_queue, &action, portMAX_DELAY) == pdTRUE) {
      switch ((button_id_t)action) {
      case BTN_PLAY_PAUSE:
        playback_control_play_pause();
        break;
      case BTN_VOLUME_UP:
        playback_control_volume_up();
        break;
      case BTN_VOLUME_DOWN:
        playback_control_volume_down();
        break;
      case BTN_NEXT:
        playback_control_next();
        break;
      case BTN_PREV:
        playback_control_prev();
        break;
      default:
        break;
      }
    }
  }
}

// Called when repeat timer fires (runs in timer daemon task)
static void repeat_timer_cb(TimerHandle_t timer) {
  int id = (int)(intptr_t)pvTimerGetTimerID(timer);
  button_state_t *btn = &buttons[id];

  if (!btn->pressed) {
    return;
  }

  post_button_action((button_id_t)id);
  // After the initial REPEAT_DELAY_MS, switch to the faster interval
  xTimerChangePeriod(btn->repeat_timer, pdMS_TO_TICKS(REPEAT_INTERVAL_MS), 0);
}

// Called when debounce timer expires (runs in timer daemon task)
static void debounce_timer_cb(TimerHandle_t timer) {
  int id = (int)(intptr_t)pvTimerGetTimerID(timer);
  button_state_t *btn = &buttons[id];

  // Read settled GPIO state (active low)
  bool now_pressed = (gpio_get_level(btn->gpio) == 0);

  if (now_pressed == btn->pressed) {
    return; // No actual state change after debounce
  }

  btn->pressed = now_pressed;

  if (now_pressed) {
    // Button just pressed — fire action via dedicated task
    post_button_action((button_id_t)id);

    // Start repeat timer for volume buttons (initial delay)
    if (btn->repeatable && btn->repeat_timer) {
      xTimerChangePeriod(btn->repeat_timer, pdMS_TO_TICKS(REPEAT_DELAY_MS), 0);
    }
  } else {
    // Button just released — stop repeat
    if (btn->repeat_timer) {
      xTimerStop(btn->repeat_timer, 0);
    }
  }
}

// GPIO ISR — just resets the debounce timer. Each new edge restarts the
// debounce window so the callback only fires once bouncing stops.
static void IRAM_ATTR gpio_isr_handler(void *arg) {
  int id = (int)(intptr_t)arg;
  BaseType_t woken = pdFALSE;
  xTimerResetFromISR(buttons[id].debounce_timer, &woken);
  if (woken) {
    portYIELD_FROM_ISR();
  }
}

static void configure_button(button_id_t id, int gpio, bool repeatable) {
  buttons[id].gpio = gpio;
  buttons[id].repeatable = repeatable;
  buttons[id].pressed = false;
  buttons[id].debounce_timer = NULL;
  buttons[id].repeat_timer = NULL;

  if (gpio < 0) {
    return;
  }

  // Create one-shot debounce timer
  buttons[id].debounce_timer =
      xTimerCreate("btn_db", pdMS_TO_TICKS(DEBOUNCE_MS), pdFALSE, // one-shot
                   (void *)(intptr_t)id, debounce_timer_cb);

  // Create one-shot repeat timer for volume buttons (manually restarted)
  if (repeatable) {
    buttons[id].repeat_timer = xTimerCreate(
        "btn_rpt", pdMS_TO_TICKS(REPEAT_DELAY_MS), pdFALSE, // one-shot
        (void *)(intptr_t)id, repeat_timer_cb);
  }

  // GPIOs 34-39 on ESP32 are input-only and lack internal pull-ups.
  // An external pull-up resistor is required for those pins.
  bool has_internal_pullup = (gpio < 34);
  gpio_config_t io_conf = {
      .pin_bit_mask = (1ULL << gpio),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en =
          has_internal_pullup ? GPIO_PULLUP_ENABLE : GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE,
  };
  gpio_config(&io_conf);

  gpio_isr_handler_add(gpio, gpio_isr_handler, (void *)(intptr_t)id);

  if (!has_internal_pullup) {
    ESP_LOGW(TAG, "Button %d on GPIO %d: no internal pull-up, needs external",
             id, gpio);
  }
  ESP_LOGI(TAG, "Button %d on GPIO %d (interrupt)", id, gpio);
}

esp_err_t buttons_init(void) {
  // Ensure the shared GPIO ISR service is installed (idempotent)
  esp_err_t err = board_gpio_isr_init();
  if (err != ESP_OK) {
    return err;
  }

  // Configure each button from Kconfig (adds ISR handlers)
  configure_button(BTN_PLAY_PAUSE, CONFIG_BTN_PLAY_PAUSE_GPIO, false);
  configure_button(BTN_VOLUME_UP, CONFIG_BTN_VOLUME_UP_GPIO, true);
  configure_button(BTN_VOLUME_DOWN, CONFIG_BTN_VOLUME_DOWN_GPIO, true);
  configure_button(BTN_NEXT, CONFIG_BTN_NEXT_GPIO, false);
  configure_button(BTN_PREV, CONFIG_BTN_PREV_GPIO, false);

  bool any_configured = false;
  for (int i = 0; i < BTN_COUNT; i++) {
    if (buttons[i].gpio >= 0) {
      any_configured = true;
      break;
    }
  }

  if (!any_configured) {
    ESP_LOGI(TAG, "No buttons configured");
    return ESP_OK;
  }

  // Queue + task for dispatching actions off the timer daemon task.
  // Stack 4096 is enough for mDNS + HTTP operations in DACP.
  s_action_queue = xQueueCreate(ACTION_QUEUE_LEN, sizeof(int));
  task_create_spiram(button_action_task, "btn_act", 4096, NULL, 5, NULL, NULL);

  ESP_LOGI(TAG, "Buttons initialized (interrupt-driven)");
  return ESP_OK;
}
