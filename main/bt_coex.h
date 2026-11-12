// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * WiFi/BT coexistence coordinator.
 *
 * On ESP32 the single radio is shared between WiFi and Classic Bluetooth; the
 * coexistence arbiter throttles WiFi RX whenever the BT controller is enabled,
 * even when idle.  To give AirPlay full WiFi bandwidth this module suspends the
 * BT radio while AirPlay is actively streaming and resumes it after AirPlay has
 * been idle for a short settling delay.
 *
 * All BT radio suspend/resume operations are performed by a single owner task,
 * driven by an ordered event queue.  Callers only post events (from any task
 * context); the task serialises every transition, which removes the flag races
 * that plagued the earlier ad-hoc implementation.
 */
typedef enum {
  BT_COEX_EVT_AIRPLAY_CONNECTED,    // AirPlay client attached (not yet playing)
  BT_COEX_EVT_AIRPLAY_PLAYING,      // AirPlay audio actively streaming
  BT_COEX_EVT_AIRPLAY_PAUSED,       // AirPlay paused (session still active)
  BT_COEX_EVT_AIRPLAY_DISCONNECTED, // AirPlay session ended
  BT_COEX_EVT_BT_CONNECTED,         // A Bluetooth device connected
  BT_COEX_EVT_BT_DISCONNECTED,      // The Bluetooth device disconnected
} bt_coex_event_t;

/**
 * Start the coexistence state machine (creates its event queue and owner task).
 * Idempotent — a second call is a no-op.
 */
esp_err_t bt_coex_start(void);

/**
 * Post an event to the coexistence state machine.  Safe to call from any task
 * context (RTSP callback, Bluetooth app task).  Never blocks the caller; if the
 * queue is somehow full the event is dropped with a warning.
 */
void bt_coex_post(bt_coex_event_t event);

#ifdef __cplusplus
}
#endif
