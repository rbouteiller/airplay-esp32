/*
 * Composite USB descriptors: UAC speaker (from espressif__usb_device_uac) plus
 * an HID consumer-control interface so the device can drive transport keys on
 * the host. Built in place of the component's own descriptors, which are
 * withheld when CONFIG_USB_DEVICE_UAC_AS_PART is set.
 *
 * SPDX-FileCopyrightText: 2019 Ha Thach (tinyusb.org)
 * SPDX-License-Identifier: MIT
 */

#include "tusb.h"
#include "uac_descriptors.h"
#include "usb_desc_itf.h"

#include "esp_log.h"

#include <string.h>

static const char *TAG = "usb_desc";

//--------------------------------------------------------------------+
// Device Descriptor
//--------------------------------------------------------------------+
static tusb_desc_device_t const desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,

    // IAD groups the audio control + streaming interfaces into one function.
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,

    .idVendor = CONFIG_USB_AUDIO_SINK_VID,
    .idProduct = CONFIG_USB_AUDIO_SINK_PID,
    // Bumped from 0x0100: Windows caches strings per VID/PID/revision and
    // would keep showing the old interface name otherwise.
    .bcdDevice = 0x0200,

    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,

    .bNumConfigurations = 0x01};

uint8_t const *tud_descriptor_device_cb(void) {
  return (uint8_t const *)&desc_device;
}

//--------------------------------------------------------------------+
// HID Report Descriptor
//--------------------------------------------------------------------+
static uint8_t const desc_hid_report[] = {
    TUD_HID_REPORT_DESC_CONSUMER(HID_REPORT_ID(HID_REPORT_ID_CONSUMER))};

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
  (void)instance;
  return desc_hid_report;
}

//--------------------------------------------------------------------+
// Configuration Descriptor
//--------------------------------------------------------------------+
#define CONFIG_TOTAL_LEN \
  (TUD_CONFIG_DESC_LEN + TUD_AUDIO_DEVICE_DESC_LEN + TUD_HID_DESC_LEN)

#define EPNUM_AUDIO_OUT 0x01
#define EPNUM_AUDIO_FB  0x81
#define EPNUM_AUDIO_IN  0x82
#define EPNUM_HID_IN    0x83

static uint8_t const desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN, 0x00, 100),
    TUD_AUDIO_DESCRIPTOR(ITF_NUM_AUDIO_CONTROL, 4, EPNUM_AUDIO_OUT,
                         EPNUM_AUDIO_IN, EPNUM_AUDIO_FB),
    // Poll every 10 ms — transport keys are user-paced, not latency critical.
    TUD_HID_DESCRIPTOR(ITF_NUM_HID, 6, HID_ITF_PROTOCOL_NONE,
                       sizeof(desc_hid_report), EPNUM_HID_IN,
                       CFG_TUD_HID_EP_BUFSIZE, 10),
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  return desc_configuration;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+
static char const *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, // 0: supported language English (0x0409)
    CONFIG_USB_AUDIO_SINK_MANUFACTURER, // 1
    CONFIG_USB_AUDIO_SINK_PRODUCT,      // 2
    CONFIG_USB_AUDIO_SINK_SERIAL,       // 3
    // Windows names a composite function from its interface string, not
    // iProduct, so Device Manager shows this one rather than index 2.
    CONFIG_USB_AUDIO_SINK_PRODUCT, // 4: UAC control interface
    "speaker",                     // 5: UAC streaming interface
    "media keys",                  // 6: HID interface
};

static uint16_t _desc_str[32];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;

  uint8_t chr_count;

  if (index == 0) {
    memcpy(&_desc_str[1], string_desc_arr[0], 2);
    chr_count = 1;
  } else {
    if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) {
      return NULL;
    }

    const char *str = string_desc_arr[index];

    chr_count = (uint8_t)strlen(str);
    if (chr_count > 31) {
      chr_count = 31;
    }

    for (uint8_t i = 0; i < chr_count; i++) {
      _desc_str[1 + i] = str[i];
    }
  }

  _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));

  return _desc_str;
}

//--------------------------------------------------------------------+
// HID callbacks — the host never reads from or writes to us.
//--------------------------------------------------------------------+
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
  (void)instance;
  (void)report_id;
  (void)report_type;
  (void)buffer;
  (void)reqlen;
  return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type, uint8_t const *buffer,
                           uint16_t bufsize) {
  (void)instance;
  (void)report_id;
  (void)report_type;
  (void)buffer;
  (void)bufsize;
}

//--------------------------------------------------------------------+
// Bus state. usb_device_uac only logs these when it owns the descriptors.
//--------------------------------------------------------------------+
void tud_mount_cb(void) {
  ESP_LOGI(TAG, "USB mounted");
}

void tud_umount_cb(void) {
  ESP_LOGI(TAG, "USB unmounted");
}
