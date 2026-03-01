#include "eq_events.h"

#include <stddef.h>

typedef struct {
  eq_event_callback_t callback;
  void *user_data;
} eq_listener_t;

static eq_listener_t s_listeners[EQ_MAX_LISTENERS];
static int s_listener_count = 0;

int eq_events_register(eq_event_callback_t callback, void *user_data) {
  if (callback == NULL || s_listener_count >= EQ_MAX_LISTENERS) {
    return -1;
  }

  /* Prevent duplicate registration */
  for (int i = 0; i < s_listener_count; i++) {
    if (s_listeners[i].callback == callback) {
      return 0;
    }
  }

  s_listeners[s_listener_count].callback = callback;
  s_listeners[s_listener_count].user_data = user_data;
  s_listener_count++;
  return 0;
}

void eq_events_unregister(eq_event_callback_t callback) {
  for (int i = 0; i < s_listener_count; i++) {
    if (s_listeners[i].callback == callback) {
      for (int j = i; j < s_listener_count - 1; j++) {
        s_listeners[j] = s_listeners[j + 1];
      }
      s_listener_count--;
      return;
    }
  }
}

void eq_events_emit(eq_event_t event, const eq_event_data_t *data) {
  for (int i = 0; i < s_listener_count; i++) {
    s_listeners[i].callback(event, data, s_listeners[i].user_data);
  }
}
