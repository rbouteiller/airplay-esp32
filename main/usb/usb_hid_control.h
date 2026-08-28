#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * USB HID consumer control — lets the speaker drive transport keys on the
 * host it is acting as a sound card for. UAC carries no transport controls,
 * but HID consumer-control usages are handled natively by every desktop OS,
 * so no host-side software is needed.
 */

typedef enum {
  USB_HID_KEY_PLAY_PAUSE,
  USB_HID_KEY_NEXT,
  USB_HID_KEY_PREV,
  USB_HID_KEY_VOLUME_UP,
  USB_HID_KEY_VOLUME_DOWN,
  USB_HID_KEY_MUTE,
} usb_hid_key_t;

/** True once the host has enumerated and enabled the HID interface. */
bool usb_hid_control_ready(void);

/**
 * Send a press/release pair for the given key. Blocks for a few milliseconds
 * waiting for the HID endpoint, so call it from a task, not an ISR.
 */
esp_err_t usb_hid_control_send(usb_hid_key_t key);
