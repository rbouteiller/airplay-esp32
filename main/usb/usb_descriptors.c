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
#include "usb_descriptors.h"

#include "esp_log.h"
#include "esp_mac.h"

#include <stdio.h>
#include <string.h>

static const char *TAG = "usb_desc";

//--------------------------------------------------------------------+
// Host OS guess
//--------------------------------------------------------------------+
// The speaker tells the host how fast to send through a feedback endpoint.
// At full speed the USB spec makes that value 10.14 in 3 bytes, the only form
// macOS accepts, while Windows' UAC2 driver accepts only 16.16 in 4 bytes;
// Linux takes either. TinyUSB converts to 10.14 when
// tud_audio_feedback_format_correction_cb() asks it to, and it asks each time
// the host opens the stream, so the choice can wait for enumeration to end.
//
// After the device descriptor, macOS reads the strings first and Windows and
// Linux the configuration (TinyUSB's uac2_speaker_fb example tells hosts
// apart the same way). The guess is kept until the next device descriptor
// request, so a later string read on its own cannot change it.
static bool s_after_device_desc;
static bool s_host_is_macos;

static void guess_host(bool strings_first) {
  if (s_after_device_desc) {
    s_after_device_desc = false;
    s_host_is_macos = strings_first;
  }
}

// Called by TinyUSB when the host opens the stream, full speed only.
// CONFIG_UAC_SUPPORT_MACOS still forces 10.14 for every host.
bool tud_audio_feedback_format_correction_cb(uint8_t func_id) {
  (void)func_id;
  return CFG_TUD_AUDIO_ENABLE_FEEDBACK_FORMAT_CORRECTION || s_host_is_macos;
}

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
    // Bumped from 0x0100, then 0x0200 when the strings took the device name:
    // Windows caches strings per VID/PID/revision and would keep showing the
    // old interface name otherwise.
    .bcdDevice = 0x0300,

    .iManufacturer = 0x01,
    .iProduct = 0x02,
    .iSerialNumber = 0x03,

    .bNumConfigurations = 0x01};

uint8_t const *tud_descriptor_device_cb(void) {
  s_after_device_desc = true;
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
  guess_host(false);
  return desc_configuration;
}

//--------------------------------------------------------------------+
// String Descriptors
//--------------------------------------------------------------------+
// The speaker's name, which the host shows in its sound settings.
static char s_name[4 * USB_DESC_NAME_MAX + 1] = CONFIG_USB_AUDIO_SINK_PRODUCT;

void usb_descriptors_set_name(const char *name) {
  if (name && name[0]) {
    strlcpy(s_name, name, sizeof(s_name));
  }
}

// The serial number is the chip's base MAC, written the way the ROM's
// USB-Serial-JTAG writes it, so each board is its own device to the host and
// keeps one identity across names. Filled in at the first request.
static char s_serial[18];

static const char *serial(void) {
  if (!s_serial[0]) {
    uint8_t mac[6];
    if (esp_efuse_mac_get_default(mac) == ESP_OK) {
      snprintf(s_serial, sizeof(s_serial), "%02X:%02X:%02X:%02X:%02X:%02X",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
      strlcpy(s_serial, "0", sizeof(s_serial));
    }
  }
  return s_serial;
}

#define STR_NAME NULL // stands for s_name in the table below

static char const *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, // 0: supported language English (0x0409)
    CONFIG_USB_AUDIO_SINK_MANUFACTURER, // 1
    STR_NAME,                           // 2: iProduct
    s_serial,                           // 3: see serial()
    // Windows names a composite function from its interface string, not
    // iProduct, and macOS names the output from the streaming interface's,
    // so all three carry the name.
    STR_NAME,     // 4: UAC control interface
    STR_NAME,     // 5: UAC streaming interface
    "media keys", // 6: HID interface
};

static uint16_t _desc_str[1 + USB_DESC_NAME_MAX];

// Decode UTF-8 into UTF-16 code units, up to max of them. A malformed
// sequence becomes U+FFFD, and a character that would not fit whole is
// dropped with everything after it.
static uint8_t utf8_to_utf16(const char *str, uint16_t *out, uint8_t max) {
  const uint8_t *s = (const uint8_t *)str;
  uint8_t n = 0;
  while (*s) {
    uint32_t cp;
    int extra;
    if (*s < 0x80) {
      cp = *s;
      extra = 0;
    } else if ((*s & 0xE0) == 0xC0) {
      cp = *s & 0x1F;
      extra = 1;
    } else if ((*s & 0xF0) == 0xE0) {
      cp = *s & 0x0F;
      extra = 2;
    } else if ((*s & 0xF8) == 0xF0) {
      cp = *s & 0x07;
      extra = 3;
    } else {
      cp = 0xFFFD;
      extra = 0;
    }
    s++;
    for (int i = 0; i < extra; i++, s++) {
      if ((*s & 0xC0) != 0x80) {
        cp = 0xFFFD;
        break;
      }
      cp = (cp << 6) | (*s & 0x3F);
    }
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
      cp = 0xFFFD;
    }
    if (cp >= 0x10000) {
      if (n + 2 > max) {
        break;
      }
      cp -= 0x10000;
      out[n++] = (uint16_t)(0xD800 | (cp >> 10));
      out[n++] = (uint16_t)(0xDC00 | (cp & 0x3FF));
    } else {
      if (n + 1 > max) {
        break;
      }
      out[n++] = (uint16_t)cp;
    }
  }
  return n;
}

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;
  guess_host(true);

  uint8_t chr_count;

  if (index == 0) {
    memcpy(&_desc_str[1], string_desc_arr[0], 2);
    chr_count = 1;
  } else {
    if (index >= sizeof(string_desc_arr) / sizeof(string_desc_arr[0])) {
      return NULL;
    }

    const char *str = string_desc_arr[index];
    if (str == STR_NAME) {
      str = s_name;
    } else if (str == s_serial) {
      str = serial();
    }

    chr_count = utf8_to_utf16(str, &_desc_str[1], USB_DESC_NAME_MAX);
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
  ESP_LOGI(TAG, "USB mounted (host looks like %s)",
           s_host_is_macos ? "macOS" : "Windows or Linux");
}

void tud_umount_cb(void) {
  ESP_LOGI(TAG, "USB unmounted");
}
