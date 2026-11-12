// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * Name the host shows for the speaker: the product string and both audio
 * interface strings, which are what macOS's and Windows' sound settings
 * display. UTF-8; anything past USB_DESC_NAME_MAX UTF-16 units is cut.
 * Until set it is CONFIG_USB_AUDIO_SINK_PRODUCT. Call before TinyUSB starts:
 * hosts read the strings once, at enumeration.
 */
void usb_descriptors_set_name(const char *name);

/** Longest name, in UTF-16 code units, a string descriptor carries. */
#define USB_DESC_NAME_MAX 64
