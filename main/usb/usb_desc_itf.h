#pragma once

/**
 * Interface numbering for the composite UAC + HID device. The UAC descriptor
 * macro consumes ITF_NUM_AUDIO_CONTROL and the following interface, so HID has
 * to sit after both. Shared with usb_hid_control.c, which passes the streaming
 * interface number to uac_device_init().
 */
enum {
  ITF_NUM_AUDIO_CONTROL = 0,
  ITF_NUM_AUDIO_STREAMING_SPK,
  ITF_NUM_HID,
  ITF_NUM_TOTAL,
};

// Report ID for the consumer-control (media key) report.
#define HID_REPORT_ID_CONSUMER 1
