#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Playback state fan-out, aggregated across every input.
 *
 * This started as an RTSP-only observer list, which was fine while exactly one
 * input could be running: whatever AirPlay said was the truth, and Bluetooth
 * and the USB sink borrowed its event types to say the same kind of thing.
 * Once two inputs can play at once that breaks down — the first one to stop
 * would tell the LED, the display and the board's amplifier power hook that
 * playback had finished while the other was still feeding I2S.
 *
 * So inputs no longer speak to listeners directly. Each one reports its own
 * state through playback_events_emit(), and the aggregate below is what
 * listeners see: connected while any input is connected, playing while any
 * input is playing. Listeners are unchanged in shape and still receive one
 * transition at a time; they just no longer need to know how many inputs
 * exist.
 */

typedef enum {
  PLAYBACK_SOURCE_NONE = 0,
  PLAYBACK_SOURCE_AIRPLAY,
  PLAYBACK_SOURCE_BLUETOOTH,
  PLAYBACK_SOURCE_USB,
  PLAYBACK_SOURCE_SENDSPIN,
  PLAYBACK_SOURCE_COUNT,
} playback_source_t;

typedef enum {
  PLAYBACK_EVENT_CONNECTED,
  PLAYBACK_EVENT_PLAYING,
  PLAYBACK_EVENT_PAUSED,
  PLAYBACK_EVENT_DISCONNECTED,
  PLAYBACK_EVENT_METADATA,
} playback_event_t;

// ============================================================================
// Metadata Event Data
// ============================================================================

#define METADATA_STRING_MAX 64

typedef struct {
  char title[METADATA_STRING_MAX];  // Track title (DMAP minm / bplist itemName)
  char artist[METADATA_STRING_MAX]; // Artist name (DMAP asar / bplist
                                    // artistName)
  char album[METADATA_STRING_MAX];  // Album name (DMAP asal / bplist albumName)
  char genre[METADATA_STRING_MAX];  // Genre (DMAP asgn)
  uint32_t duration_secs;           // Total track duration in seconds
  uint32_t position_secs;           // Current playback position in seconds
  bool has_artwork;                 // Whether artwork is available
} playback_metadata_t;

// ============================================================================
// Event Data Union
// ============================================================================

typedef union {
  playback_metadata_t metadata; // Valid when event == PLAYBACK_EVENT_METADATA
} playback_event_data_t;

/**
 * Event callback function type.
 * @param source The input that caused the transition
 * @param event The aggregate transition that occurred
 * @param data  Event-specific data (NULL for events with no data)
 * @param user_data Pointer registered with playback_events_register()
 */
typedef void (*playback_event_callback_t)(playback_source_t source,
                                          playback_event_t event,
                                          const playback_event_data_t *data,
                                          void *user_data);

/**
 * Register a listener for aggregate playback events.
 * @param callback Function to call when the aggregate state changes
 * @param user_data Pointer passed to callback (can be NULL)
 * @return 0 on success, -1 if max listeners reached
 */
int playback_events_register(playback_event_callback_t callback,
                             void *user_data);

/**
 * Unregister a previously registered listener.
 * @param callback The callback to remove
 */
void playback_events_unregister(playback_event_callback_t callback);

/**
 * Report a state change for one input.
 *
 * Listeners are only called when this changes the aggregate: the second input
 * to start playing is not another PLAYBACK_EVENT_PLAYING, and the first of two
 * to stop is not a PLAYBACK_EVENT_PAUSED. Metadata is forwarded only from the
 * input currently holding the display (see playback_events_active_source()),
 * so two concurrent streams do not overwrite each other's now-playing.
 *
 * @param source The input reporting the change
 * @param event  What that input is now doing
 * @param data   Event-specific data (NULL for events with no data)
 */
void playback_events_emit(playback_source_t source, playback_event_t event,
                          const playback_event_data_t *data);

/**
 * Drop an input's state without emitting on its behalf. Used when an input is
 * torn down from the outside and cannot report its own disconnect; the
 * resulting aggregate transition is still emitted.
 */
void playback_events_clear(playback_source_t source);

/** True while any input is connected, playing or paused. */
bool playback_events_any_connected(void);

/** True while any input is playing. */
bool playback_events_any_playing(void);

/**
 * The input that owns the display and the transport controls: the one that
 * most recently started playing, or failing that most recently connected.
 * PLAYBACK_SOURCE_NONE when everything is idle.
 */
playback_source_t playback_events_active_source(void);

/** True if that specific input is connected, playing or paused. */
bool playback_events_source_active(playback_source_t source);

/**
 * Format seconds as mm:ss string.
 * @param seconds Time in seconds
 * @param out Output buffer (at least 8 bytes for "999:59\0")
 * @param out_size Size of the output buffer
 */
void playback_format_time_mmss(uint32_t seconds, char *out, size_t out_size);
