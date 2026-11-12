// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>

#include "esp_err.h"
#include "esp_http_server.h"

/**
 * @file sendspin.h
 * @brief Sendspin player-role client (experimental, first milestone).
 *
 * Sendspin is a multi-room audio protocol in which the *server* discovers and
 * connects to speakers.  A speaker advertises _sendspin._tcp with the
 * WebSocket path to use, the server opens that socket, and the two exchange
 * JSON control messages plus binary audio chunks timestamped in the server's
 * monotonic clock.
 *
 * This build implements enough of it to prove the timing path:
 *
 *   - the WebSocket endpoint and its framing, including reassembly;
 *   - the Noise KKpsk2 handshake, keyed with a long-term PSK once a server has
 *     paired and with the published Sentinel PSK until then, and the encrypted
 *     transport that follows it;
 *   - pairing by static PIN (CPace) or by pairing PSK;
 *   - the init/hello/activate handshake, the client/time clock exchange and
 *     client/state reporting;
 *   - PCM, FLAC and -- where the SoC can keep up -- Opus stream playout
 *     through audio_engine_v2.
 *
 * It does NOT implement the dynamic pairing code.  Keying with the
 * Sentinel leaves the session *unpaired*: encrypted and replay-protected, but
 * with neither peer's identity proven, so a server may only use it for
 * playback once its operator has approved the device.
 *
 * Only one audio source can drive the output at a time.  Sendspin announces
 * itself unavailable while AirPlay, Bluetooth or USB owns it, which is the
 * protocol's own answer to an external source taking the speaker.
 */

/** Called when Sendspin takes or releases the audio output. */
typedef void (*sendspin_activity_cb_t)(bool active);

/**
 * Allocate the receive buffer, playout timeline and persistent identity.
 * Call once at boot, before sendspin_register().
 */
esp_err_t sendspin_init(sendspin_activity_cb_t callback);

/**
 * Attach the WebSocket endpoint to the running web server and start the
 * housekeeping task (clock sync, state reporting, mDNS advertisement).
 */
esp_err_t sendspin_register(httpd_handle_t server);

/** True while a Sendspin stream is driving the output. */
bool sendspin_is_streaming(void);

/**
 * Report whether the audio output is ours to use.
 *
 * Passing false ends any running stream and makes the client advertise
 * `available: false`, which the protocol defines as "my output is in use by
 * an external system": the server moves us to a solo group and stops sending
 * audio.  It will not resume on its own when we become available again.
 */
void sendspin_set_output_available(bool available);

/** Transport commands the board's buttons can send as a controller. */
typedef enum {
  SENDSPIN_CMD_PLAY,
  SENDSPIN_CMD_PAUSE,
  SENDSPIN_CMD_NEXT,
  SENDSPIN_CMD_PREVIOUS,
} sendspin_command_t;

/**
 * Queue a controller command for the server.
 *
 * Safe to call from any task: the command is handed to the Sendspin task,
 * which owns the socket, and goes out on its next tick.  Returns false if the
 * server has not activated the controller role or does not accept the
 * command, which is the caller's cue to fall back to a local action.
 */
bool sendspin_send_command(sendspin_command_t cmd);

/**
 * True when the server's metadata says the group is playing, as opposed to
 * paused.  A controller has to pick between 'play' and 'pause'; there is no
 * toggle in the protocol.
 */
bool sendspin_is_playing(void);

/**
 * The version-0 pairing token for this device: "SP:0" followed by 103 base32
 * characters carrying the client key and the pairing PSK.  Handing it to a
 * server is what authorises that server to adopt the device, so treat it as a
 * secret.
 */
const char *sendspin_pairing_token(void);

/**
 * The device's static pairing PIN: 8 decimal digits.  This is what an
 * operator types into a server that offers a pairing prompt, and it is also a
 * secret -- anyone who learns it can pair.
 */
const char *sendspin_pairing_pin(void);

/** How many servers this device is currently paired with. */
unsigned sendspin_paired_count(void);

/** True while a server holds the WebSocket session. */
bool sendspin_server_connected(void);

/**
 * Forget every pairing record.  The device keeps its identity, its pairing
 * token and its PIN, so a server can pair again; until one does, sessions
 * fall back to the Sentinel.  Any session already running is left alone --
 * the records only decide what the next handshake can resolve.
 *
 * There are only four slots and a fifth pairing evicts the oldest, so this is
 * how an operator clears out servers that are no longer around.
 *
 * Forgetting one side of a pairing strands the other: the server goes on
 * offering a PSK this device can no longer resolve, and the handshake then
 * fails in a way neither end reports.  Unpairing from the server is the
 * route that prunes both, so prefer it whenever the server is reachable.
 */
esp_err_t sendspin_forget_pairings(void);

/**
 * Generate a fresh client identity, and forget every pairing record with it.
 * The next handshake presents an unrecognised client_id, so a server that
 * still holds a stale record for this device stops offering a PSK we cannot
 * resolve and treats us as a device it has never seen -- which is the only
 * way out of that deadlock without editing the server's own store.
 *
 * The pairing token changes with the identity; the PIN does not.  The server
 * is left holding an orphan record for the old identity.
 */
esp_err_t sendspin_reset_identity(void);
