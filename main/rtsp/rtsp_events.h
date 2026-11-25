// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// AirPlay 2 remote control over the event channel.
//
// iOS sends no DACP id in AirPlay 2 mode, so play/pause, next/previous and the
// volume slider cannot be reached over DACP. Shairport Sync (remote/remote.c,
// ap2_event_receiver.c) sends MediaRemote commands instead: the sender opens a
// TCP connection to the eventPort from the initial SETUP, and the receiver
// writes "POST /command RTSP/1.0" requests with a binary plist on it,
// encrypted like the RTSP channel (ChaCha20-Poly1305, 2-byte length as AAD),
// and reads the sender's RTSP response.
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "hap.h"

// MediaRemote command numbers (modernMediaRemoteCommand)
#define RTSP_EVENTS_CMD_PLAY       0
#define RTSP_EVENTS_CMD_PAUSE      1
#define RTSP_EVENTS_CMD_PLAY_PAUSE 2
#define RTSP_EVENTS_CMD_STOP       3
#define RTSP_EVENTS_CMD_NEXT       4
#define RTSP_EVENTS_CMD_PREVIOUS   5

// Initial SETUP (AirPlay 2): event keys of the session and the group UUID
// (destination of the commands). group_uuid may be NULL or empty.
void rtsp_events_setup(const hap_session_t *session, const char *group_uuid);

// Event client accepted (called with the event socket lock held): new
// connection, so both nonces start at 0 again.
void rtsp_events_on_client(void);

// Event port task ends (called with the event socket lock held): wipe the keys
// of the session. The next SETUP brings new ones.
void rtsp_events_clear(void);

// Keys, group UUID and an event connection are there
bool rtsp_events_ready(void);

// Send and wait for the sender's answer (at most ~1 s). true: 2xx response.
// Blocking; calls from several tasks are serialised by the event socket lock.
bool rtsp_events_send_command(unsigned int command);
bool rtsp_events_send_volume(double unit_volume); // 0.0-1.0
