#pragma once

#include "sdkconfig.h"

/**
 * OLED display module - Shows track metadata, playback position &
 * progress bar. Registers as an RTSP event observer to receive metadata
 * updates automatically.
 *
 * When CONFIG_DISPLAY_ENABLED is not set, display_init() is an inline no-op
 * and no display code is compiled or linked.
 */

#ifdef CONFIG_DISPLAY_ENABLED

/**
 * Initialize the OLED display and register for RTSP events.
 */
void display_init(void);

#else

static inline void display_init(void) {
}

#endif
