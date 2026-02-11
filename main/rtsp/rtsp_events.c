#include "rtsp_events.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define MAX_LISTENERS 4

typedef struct {
  rtsp_event_callback_t callback;
  void *user_data;
} listener_t;

static listener_t listeners[MAX_LISTENERS];
static int listener_count = 0;

int rtsp_events_register(rtsp_event_callback_t callback, void *user_data) {
  if (callback == NULL || listener_count >= MAX_LISTENERS) {
    return -1;
  }

  // Check if already registered
  for (int i = 0; i < listener_count; i++) {
    if (listeners[i].callback == callback) {
      return 0;
    }
  }

  listeners[listener_count].callback = callback;
  listeners[listener_count].user_data = user_data;
  listener_count++;
  return 0;
}

void rtsp_events_unregister(rtsp_event_callback_t callback) {
  for (int i = 0; i < listener_count; i++) {
    if (listeners[i].callback == callback) {
      // Shift remaining listeners
      for (int j = i; j < listener_count - 1; j++) {
        listeners[j] = listeners[j + 1];
      }
      listener_count--;
      return;
    }
  }
}

void rtsp_events_emit(rtsp_event_t event, const rtsp_event_data_t *data) {
  for (int i = 0; i < listener_count; i++) {
    listeners[i].callback(event, data, listeners[i].user_data);
  }
}

void rtsp_format_time_mmss(uint32_t seconds, char *out, size_t out_size) {
  uint32_t mins = seconds / 60;
  uint32_t secs = seconds % 60;
  snprintf(out, out_size, "%" PRIu32 ":%02" PRIu32, mins, secs);
}
