// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "bt_coex.h"

#include "a2dp_sink.h"
#include "spiram_task.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char *TAG = "bt_coex";

// Idle delay after AirPlay disconnects before the BT radio is resumed, so a
// quick reconnect / track change does not flap the radio.
#define BT_COEX_RESUME_IDLE_MS 15000
// Backoff before retrying a suspend/resume that failed with a transient error.
#define BT_COEX_RETRY_MS 2000

#define BT_COEX_QUEUE_LEN  8
#define BT_COEX_TASK_STACK 4096
#define BT_COEX_TASK_PRIO  5

// Radio state owned exclusively by the coexistence task.
//
//   ACTIVE ──PLAYING──▶ SUSPENDED ──DISCONNECTED──▶ RESUME_WAIT ──(idle)──▶
//   ACTIVE
//     ▲                    │  ▲                          │
//     └── BT_CONNECTED ────┘  └── CONNECTED/PAUSED ──────┘   (cancel resume)
//
// SUSPEND_RETRY / RESUME_WAIT also re-arm a short timer to retry a failed op.
typedef enum {
  COEX_ACTIVE = 0,    // radio up; no pending action
  COEX_SUSPENDED,     // radio suspended; no pending action
  COEX_SUSPEND_RETRY, // want suspended; last attempt failed, retry on timeout
  COEX_RESUME_WAIT,   // suspended; resume scheduled (idle delay or retry)
} coex_state_t;

static QueueHandle_t s_queue = NULL;
static TaskHandle_t s_task = NULL;

// Attempt to suspend the radio; returns the resulting state and, for a
// transient failure, arms the retry deadline.
static coex_state_t coex_do_suspend(TickType_t *wake_at) {
  esp_err_t err = bt_a2dp_sink_suspend();
  if (err == ESP_OK) {
    return COEX_SUSPENDED;
  }
  if (err == ESP_ERR_INVALID_STATE) {
    // A Bluetooth device is connected, so the radio must stay up.  The
    // BT_CONNECTED event settles us in COEX_ACTIVE; nothing to retry.
    return COEX_ACTIVE;
  }
  ESP_LOGW(TAG, "suspend failed (%s), retrying", esp_err_to_name(err));
  *wake_at = xTaskGetTickCount() + pdMS_TO_TICKS(BT_COEX_RETRY_MS);
  return COEX_SUSPEND_RETRY;
}

// Attempt to resume the radio; returns the resulting state and, on failure,
// arms the retry deadline.
static coex_state_t coex_do_resume(TickType_t *wake_at) {
  esp_err_t err = bt_a2dp_sink_resume();
  if (err == ESP_OK) {
    return COEX_ACTIVE;
  }
  ESP_LOGW(TAG, "resume failed (%s), retrying", esp_err_to_name(err));
  *wake_at = xTaskGetTickCount() + pdMS_TO_TICKS(BT_COEX_RETRY_MS);
  return COEX_RESUME_WAIT;
}

// Transition on an incoming event.
static coex_state_t coex_on_event(coex_state_t state, bt_coex_event_t evt,
                                  TickType_t *wake_at) {
  switch (evt) {
  case BT_COEX_EVT_AIRPLAY_PLAYING:
    // Streaming — free the radio for WiFi now (idempotent if already down).
    if (state == COEX_SUSPENDED) {
      return COEX_SUSPENDED;
    }
    return coex_do_suspend(wake_at);

  case BT_COEX_EVT_AIRPLAY_CONNECTED:
  case BT_COEX_EVT_AIRPLAY_PAUSED:
    // Session active/starting: cancel a scheduled resume so the radio stays
    // suspended, but do not newly suspend (only PLAYING suspends).
    if (state == COEX_RESUME_WAIT) {
      return COEX_SUSPENDED;
    }
    return state;

  case BT_COEX_EVT_AIRPLAY_DISCONNECTED:
    // Session ended: schedule a resume after the idle delay, but only if the
    // radio is actually suspended.  In ACTIVE and SUSPEND_RETRY the radio is
    // up (a transient suspend failure rolls back to active), so just settle in
    // ACTIVE and abandon any suspend attempt.
    if (state == COEX_SUSPENDED || state == COEX_RESUME_WAIT) {
      *wake_at = xTaskGetTickCount() + pdMS_TO_TICKS(BT_COEX_RESUME_IDLE_MS);
      return COEX_RESUME_WAIT;
    }
    return COEX_ACTIVE;

  case BT_COEX_EVT_BT_CONNECTED:
  case BT_COEX_EVT_BT_DISCONNECTED:
    // Bluetooth owns the radio and needs it up.  Normally the radio is already
    // active here.  But if a suspend raced with the connection (suspend passed
    // its s_connected check, then the connection completed before the disable),
    // the radio can actually be suspended while our tracked state says
    // otherwise — reconcile with the hardware by resuming, so the state never
    // desyncs and leaves Bluetooth off until reboot.
    if (bt_a2dp_sink_is_suspended()) {
      return coex_do_resume(wake_at);
    }
    return COEX_ACTIVE;
  }
  return state;
}

// Transition when the state's timer expires.
static coex_state_t coex_on_timeout(coex_state_t state, TickType_t *wake_at) {
  switch (state) {
  case COEX_SUSPEND_RETRY:
    return coex_do_suspend(wake_at);
  case COEX_RESUME_WAIT:
    return coex_do_resume(wake_at);
  default:
    return state; // no timer runs in this state
  }
}

static void bt_coex_task(void *arg) {
  (void)arg;
  coex_state_t state = COEX_ACTIVE;
  TickType_t wake_at = 0;

  for (;;) {
    // Block on the event queue, but only until the pending timed action (retry
    // or resume-after-idle) is due.  A negative remaining means it is already
    // due, so poll with a zero timeout.
    TickType_t timeout = portMAX_DELAY;
    if (state == COEX_SUSPEND_RETRY || state == COEX_RESUME_WAIT) {
      int32_t remaining = (int32_t)(wake_at - xTaskGetTickCount());
      timeout = (remaining > 0) ? (TickType_t)remaining : 0;
    }

    bt_coex_event_t evt;
    if (xQueueReceive(s_queue, &evt, timeout) == pdTRUE) {
      state = coex_on_event(state, evt, &wake_at);
    } else {
      state = coex_on_timeout(state, &wake_at);
    }
  }
}

esp_err_t bt_coex_start(void) {
  if (s_task) {
    return ESP_OK;
  }
  s_queue = xQueueCreate(BT_COEX_QUEUE_LEN, sizeof(bt_coex_event_t));
  if (!s_queue) {
    return ESP_ERR_NO_MEM;
  }
  BaseType_t ok =
      task_create_spiram(bt_coex_task, "bt_coex", BT_COEX_TASK_STACK, NULL,
                         BT_COEX_TASK_PRIO, &s_task, NULL);
  if (ok != pdPASS) {
    vQueueDelete(s_queue);
    s_queue = NULL;
    return ESP_ERR_NO_MEM;
  }
  return ESP_OK;
}

void bt_coex_post(bt_coex_event_t event) {
  if (!s_queue) {
    return;
  }
  if (xQueueSend(s_queue, &event, 0) != pdTRUE) {
    ESP_LOGW(TAG, "coex queue full, dropped event %d", (int)event);
  }
}
