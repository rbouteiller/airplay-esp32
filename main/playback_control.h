#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * Source-agnostic playback controller.
 *
 * Routes hardware button actions to the correct backend (AirPlay or
 * Bluetooth) and notifies the remote client of changes.
 *
 * For AirPlay: applies volume/pause locally, then sends DACP commands
 * to the iOS/macOS client so its UI stays in sync.
 *
 * For Bluetooth: sends AVRCP passthrough commands to the source device,
 * which controls playback and sends volume back via absolute volume.
 */

typedef enum {
  PLAYBACK_SOURCE_NONE,
  PLAYBACK_SOURCE_AIRPLAY,
  PLAYBACK_SOURCE_BLUETOOTH,
} playback_source_t;

/**
 * Initialize playback control module.
 */
esp_err_t playback_control_init(void);

/**
 * Set the current audio source. Called by main.c when AirPlay or
 * Bluetooth connects/disconnects.
 */
void playback_control_set_source(playback_source_t source);

/**
 * Get the current audio source.
 */
playback_source_t playback_control_get_source(void);

/**
 * Toggle play/pause.
 */
void playback_control_play_pause(void);

/**
 * Increase volume by one step (~3 dB).
 */
void playback_control_volume_up(void);

/**
 * Decrease volume by one step (~3 dB).
 */
void playback_control_volume_down(void);

/**
 * Skip to next track.
 */
void playback_control_next(void);

/**
 * Skip to previous track.
 */
void playback_control_prev(void);
