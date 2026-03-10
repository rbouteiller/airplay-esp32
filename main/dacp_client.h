#pragma once

#include <stdint.h>

/**
 * DACP (Digital Audio Control Protocol) client.
 *
 * Sends commands back to the AirPlay source device (iPhone/Mac) so its
 * UI reflects changes made via hardware buttons on the receiver.
 *
 * The AirPlay client advertises a DACP service via mDNS (_dacp._tcp)
 * and sends DACP-ID / Active-Remote headers during the RTSP session.
 * We use these to discover the client's DACP port and authenticate
 * our HTTP requests.
 *
 * Commands are HTTP GET requests to the client:
 *   GET /ctrl-int/1/playpause
 *   GET /ctrl-int/1/nextitem
 *   GET /ctrl-int/1/previtem
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
 * Send volume change to the AirPlay client.
 * @param volume_percent Volume 0-100 (DACP linear scale)
 */
void dacp_send_volume(float volume_percent);
