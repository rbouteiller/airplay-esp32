/**
 * USB HID consumer control.
 *
 * The device already presents a UAC speaker to the host; this adds the return
 * path. Consumer-control usages (play/pause, next, prev, volume, mute) are
 * consumed natively by Windows, macOS and Linux, so pressing a button on the
 * speaker drives whatever media app the host has focused without any host-side
 * agent.
 */

#include "usb_hid_control.h"

#include "usb_desc_itf.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "tusb.h"

static const char *TAG = "usb_hid";

// A press with no gap before the release is sometimes coalesced by the host.
#define PRESS_HOLD_MS 20
#define EP_WAIT_MS    50
#define EP_POLL_STEPS 10

static SemaphoreHandle_t s_lock;

static uint16_t key_to_usage(usb_hid_key_t key) {
  switch (key) {
  case USB_HID_KEY_PLAY_PAUSE:
    return HID_USAGE_CONSUMER_PLAY_PAUSE;
  case USB_HID_KEY_NEXT:
    return HID_USAGE_CONSUMER_SCAN_NEXT_TRACK;
  case USB_HID_KEY_PREV:
    return HID_USAGE_CONSUMER_SCAN_PREVIOUS_TRACK;
  case USB_HID_KEY_VOLUME_UP:
    return HID_USAGE_CONSUMER_VOLUME_INCREMENT;
  case USB_HID_KEY_VOLUME_DOWN:
    return HID_USAGE_CONSUMER_VOLUME_DECREMENT;
  case USB_HID_KEY_MUTE:
    return HID_USAGE_CONSUMER_MUTE;
  }
  return 0;
}

static bool send_usage(uint16_t usage) {
  for (int i = 0; i < EP_POLL_STEPS && !tud_hid_ready(); i++) {
    vTaskDelay(pdMS_TO_TICKS(EP_WAIT_MS / EP_POLL_STEPS));
  }
  if (!tud_hid_ready()) {
    return false;
  }
  return tud_hid_report(HID_REPORT_ID_CONSUMER, &usage, sizeof(usage));
}

bool usb_hid_control_ready(void) {
  return tud_mounted() && tud_hid_ready();
}

esp_err_t usb_hid_control_send(usb_hid_key_t key) {
  if (!tud_mounted()) {
    ESP_LOGD(TAG, "Host not connected, dropping key %d", key);
    return ESP_ERR_INVALID_STATE;
  }

  if (s_lock == NULL) {
    static StaticSemaphore_t lock_buf;
    s_lock = xSemaphoreCreateMutexStatic(&lock_buf);
  }
  if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) != pdTRUE) {
    return ESP_ERR_TIMEOUT;
  }

  esp_err_t err = ESP_OK;
  if (send_usage(key_to_usage(key))) {
    vTaskDelay(pdMS_TO_TICKS(PRESS_HOLD_MS));
    send_usage(0); // release
    ESP_LOGI(TAG, "Sent media key %d to host", key);
  } else {
    ESP_LOGW(TAG, "HID endpoint not ready, dropped key %d", key);
    err = ESP_ERR_TIMEOUT;
  }

  xSemaphoreGive(s_lock);
  return err;
}
