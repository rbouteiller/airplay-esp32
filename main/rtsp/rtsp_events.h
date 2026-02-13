#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * RTSP event system - Observer pattern for playback state changes.
 * Allows multiple listeners to react to RTSP events without coupling.
 */

typedef enum {
  RTSP_EVENT_CLIENT_CONNECTED,
  RTSP_EVENT_PLAYING,
  RTSP_EVENT_PAUSED,
  RTSP_EVENT_DISCONNECTED,
  RTSP_EVENT_METADATA,
} rtsp_event_t;

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
} rtsp_metadata_t;

// ============================================================================
// Event Data Union
// ============================================================================

typedef union {
  rtsp_metadata_t metadata; // Valid when event == RTSP_EVENT_METADATA
} rtsp_event_data_t;

/**
 * Event callback function type.
 * @param event The event that occurred
 * @param data  Event-specific data (NULL for events with no data)
 * @param user_data Pointer registered with rtsp_events_register()
 */
typedef void (*rtsp_event_callback_t)(rtsp_event_t event,
                                      const rtsp_event_data_t *data,
                                      void *user_data);

/**
 * Register a listener for RTSP events.
 * @param callback Function to call when an event occurs
 * @param user_data Pointer passed to callback (can be NULL)
 * @return 0 on success, -1 if max listeners reached
 */
int rtsp_events_register(rtsp_event_callback_t callback, void *user_data);

/**
 * Unregister a previously registered listener.
 * @param callback The callback to remove
 */
void rtsp_events_unregister(rtsp_event_callback_t callback);

/**
 * Emit an event to all registered listeners.
 * Called internally by RTSP handlers.
 * @param event The event to emit
 * @param data  Event-specific data (NULL for events with no data)
 */
void rtsp_events_emit(rtsp_event_t event, const rtsp_event_data_t *data);

/**
 * Format seconds as mm:ss string.
 * @param seconds Time in seconds
 * @param out Output buffer (at least 8 bytes for "999:59\0")
 * @param out_size Size of output buffer
 */
void rtsp_format_time_mmss(uint32_t seconds, char *out, size_t out_size);
