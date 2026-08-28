/*
 * TinyUSB configuration for the composite UAC speaker + HID consumer-control
 * device. Replaces the copy shipped by espressif__usb_device_uac, which is
 * withheld when CONFIG_USB_DEVICE_UAC_AS_PART is set.
 *
 * SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

// clang-format off
// CFG_TUSB_OS_INC_PATH is pasted straight into an #include by TinyUSB, so
// clang-format must not put spaces around its trailing slash.

#ifdef __cplusplus
extern "C" {
#endif

#include "sdkconfig.h"
#include "tusb_config_uac.h"
#include "uac_config.h"
#include "uac_descriptors.h"

//--------------------------------------------------------------------+
// Board Specific Configuration
//--------------------------------------------------------------------+

#ifdef CONFIG_TINYUSB_RHPORT_HS
#if CONFIG_IDF_TARGET_ESP32P4
#define CFG_TUSB_RHPORT1_MODE OPT_MODE_DEVICE | OPT_MODE_HIGH_SPEED
#else
#define CFG_TUSB_RHPORT0_MODE OPT_MODE_DEVICE | OPT_MODE_HIGH_SPEED
#endif
#define CONFIG_USB_HS 1
#else
#define CFG_TUSB_RHPORT0_MODE OPT_MODE_DEVICE | OPT_MODE_FULL_SPEED
#define CONFIG_USB_HS         0
#endif

//--------------------------------------------------------------------
// Common Configuration
//--------------------------------------------------------------------

#ifndef CFG_TUSB_MCU
#error CFG_TUSB_MCU must be defined
#endif

#ifndef CFG_TUSB_OS
#define CFG_TUSB_OS OPT_OS_FREERTOS
#endif

#ifndef ESP_PLATFORM
#define ESP_PLATFORM 1
#endif

#ifndef CFG_TUSB_DEBUG
#define CFG_TUSB_DEBUG 0
#endif

#if TU_CHECK_MCU(OPT_MCU_ESP32S2, OPT_MCU_ESP32S3, OPT_MCU_ESP32P4, \
                 OPT_MCU_ESP32S31, OPT_MCU_ESP32H4)
#define CFG_TUSB_OS_INC_PATH freertos/
#endif

#define CFG_TUD_ENABLED 1

#ifndef CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_SECTION
#endif

#ifndef CFG_TUSB_MEM_ALIGN
#define CFG_TUSB_MEM_ALIGN __attribute__((aligned(4)))
#endif

//--------------------------------------------------------------------
// DEVICE CONFIGURATION
//--------------------------------------------------------------------

#ifndef CFG_TUD_ENDPOINT0_SIZE
#define CFG_TUD_ENDPOINT0_SIZE 64
#endif

// HID consumer control: lets the speaker drive transport keys on the host.
#define CFG_TUD_HID            1
#define CFG_TUD_HID_EP_BUFSIZE 8

#ifdef __cplusplus
}
#endif
// clang-format on
