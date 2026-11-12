// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * DACP (Digital Audio Control Protocol) client.
 *
 * Sends commands back to the AirPlay source device (iPhone/Mac) so its
 * UI reflects changes made via hardware buttons on the receiver.
 *
 * Only works with AirPlay 1 connections — modern iOS AirPlay 2 does not
 * send DACP-ID/Active-Remote headers and uses the Media Remote Protocol
 * (MRP) instead, which we do not implement.  When DACP headers are
 * present we discover the client's DACP port via mDNS (_dacp._tcp) and
 * authenticate our HTTP requests with the Active-Remote token.
 *
 * Commands are HTTP GET requests to the client:
 *   GET /ctrl-int/1/playpause
 *   GET /ctrl-int/1/nextitem
 *   GET /ctrl-int/1/previtem
 *   GET /ctrl-int/1/volumeup
 *   GET /ctrl-int/1/volumedown
 *   GET /ctrl-int/1/setproperty?dmcp.volume=<0-100>
 */

/**
 * Initialize the DACP client. Must be called once at startup.
 */
void dacp_init(void);

/**
 * Store the DACP session identifiers from the RTSP handshake.
 * Called when DACP-ID and Active-Remote headers are parsed.
 *
 * @param dacp_id       Client's DACP-ID (hex string, e.g. "A1B2C3D4E5F6")
 * @param active_remote Client's Active-Remote token
 * @param client_ip     Client's IPv4 address (network byte order)
 */
void dacp_set_session(const char *dacp_id, const char *active_remote,
                      uint32_t client_ip);

/**
 * Clear the DACP session (on client disconnect).
 */
void dacp_clear_session(void);

/**
 * Send play/pause toggle command to the AirPlay client.
 */
void dacp_send_playpause(void);

/**
 * Send next track command to the AirPlay client.
 */
void dacp_send_next(void);

/**
 * Send previous track command to the AirPlay client.
 */
void dacp_send_prev(void);

/**
 * Send volume up step command to the AirPlay client.
 */
void dacp_send_volume_up(void);

/**
 * Send volume down step command to the AirPlay client.
 */
void dacp_send_volume_down(void);

/**
 * Send absolute volume change to the AirPlay client.
 * @param volume_percent Volume 0-100 (DACP linear scale)
 */
void dacp_send_volume(float volume_percent);

/**
 * Check whether a DACP session is currently active.
 * @return true if DACP-ID and Active-Remote are set
 */
bool dacp_is_active(void);

/**
 * Probe mDNS to check if the client's DACP service is still advertised.
 * Used in AirPlay v1 mode to differentiate pause from genuine disconnect.
 * @return true if the _dacp._tcp service matching the current session is found
 */
bool dacp_probe_service(void);
