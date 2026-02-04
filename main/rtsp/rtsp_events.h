#pragma once

/**
 * RTSP event system - Observer pattern for playback state changes.
 * Allows multiple listeners to react to RTSP events without coupling.
 */

typedef enum {
  RTSP_EVENT_CLIENT_CONNECTED,
  RTSP_EVENT_PLAYING,
  RTSP_EVENT_PAUSED,
  RTSP_EVENT_DISCONNECTED,
} rtsp_event_t;

typedef void (*rtsp_event_callback_t)(rtsp_event_t event, void *user_data);

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
 */
void rtsp_events_emit(rtsp_event_t event);
