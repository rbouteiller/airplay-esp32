#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * Bluetooth A2DP Sink - receive audio from phones/tablets via Bluetooth.
 *
 * Supports SBC codec (built-in Bluedroid decoder).
 * Only available on ESP32 (original) which supports Classic Bluetooth.
 *
 * When a Bluetooth device connects, AirPlay services are disabled.
 * When it disconnects, AirPlay services are re-enabled.
 */

/**
 * Callback invoked when A2DP connection state changes.
 * @param connected true on connect, false on disconnect
 */
typedef void (*bt_a2dp_state_cb_t)(bool connected);

/**
 * Initialize and start the Bluetooth A2DP Sink.
 *
 * Sets up BT controller, Bluedroid, GAP (discoverable/connectable),
 * A2DP sink profile with SBC decoder, and AVRCP controller + target.
 *
 * @param device_name Bluetooth device name visible to phones
 * @param state_cb    Callback for connection state changes (may be NULL)
 * @return ESP_OK on success
 */
esp_err_t bt_a2dp_sink_init(const char *device_name,
                            bt_a2dp_state_cb_t state_cb);

/**
 * Check if a Bluetooth A2DP audio session is active.
 */
bool bt_a2dp_sink_is_connected(void);

/**
 * Enable or disable Bluetooth discoverability/connectability.
 * Saves the desired state — applied immediately if BT is running,
 * or deferred until the next bt_a2dp_sink_start().
 *
 * @param discoverable true to allow new BT connections, false to block them
 */
void bt_a2dp_sink_set_discoverable(bool discoverable);

/**
 * AVRCP passthrough commands for hardware button control.
 * These send commands to the connected BT source device.
 */
void bt_a2dp_send_playpause(void);
void bt_a2dp_send_next(void);
void bt_a2dp_send_prev(void);
void bt_a2dp_send_volume_up(void);
void bt_a2dp_send_volume_down(void);
