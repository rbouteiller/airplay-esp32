#include "playback_events.h"

#include "freertos/FreeRTOS.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

#define MAX_LISTENERS 4

typedef struct {
  playback_event_callback_t callback;
  void *user_data;
} listener_t;

// What one input is doing. The aggregate is derived from the whole array
// rather than counted incrementally, because inputs repeat themselves: RTSP
// emits PAUSED on both the pause handler and the teardown path, and a counter
// would drift every time one of those arrived twice.
typedef enum {
  SRC_IDLE = 0,
  SRC_CONNECTED,
  SRC_PLAYING,
  SRC_PAUSED,
} src_state_t;

static listener_t listeners[MAX_LISTENERS];
static int listener_count = 0;

static src_state_t s_state[PLAYBACK_SOURCE_COUNT];
static playback_source_t s_active = PLAYBACK_SOURCE_NONE;

// A spinlock, not a mutex: these calls arrive from the RTSP task, the httpd
// task, the Bluetooth callback context and the USB writer, and the first of
// them can land before any init function has run. The critical sections are a
// handful of array reads.
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

int playback_events_register(playback_event_callback_t callback,
                             void *user_data) {
  if (callback == NULL) {
    return -1;
  }

  int rc = 0;
  taskENTER_CRITICAL(&s_mux);
  bool found = false;
  for (int i = 0; i < listener_count; i++) {
    if (listeners[i].callback == callback) {
      found = true;
      break;
    }
  }
  if (!found) {
    if (listener_count >= MAX_LISTENERS) {
      rc = -1;
    } else {
      listeners[listener_count].callback = callback;
      listeners[listener_count].user_data = user_data;
      listener_count++;
    }
  }
  taskEXIT_CRITICAL(&s_mux);
  return rc;
}

void playback_events_unregister(playback_event_callback_t callback) {
  taskENTER_CRITICAL(&s_mux);
  for (int i = 0; i < listener_count; i++) {
    if (listeners[i].callback == callback) {
      for (int j = i; j < listener_count - 1; j++) {
        listeners[j] = listeners[j + 1];
      }
      listener_count--;
      break;
    }
  }
  taskEXIT_CRITICAL(&s_mux);
}

// Fan out on a snapshot: a listener is free to take its own locks, and the
// board hooks touch I2C, so none of them may run with interrupts disabled.
static void notify(playback_source_t source, playback_event_t event,
                   const playback_event_data_t *data) {
  listener_t snapshot[MAX_LISTENERS];
  int count;

  taskENTER_CRITICAL(&s_mux);
  count = listener_count;
  for (int i = 0; i < count; i++) {
    snapshot[i] = listeners[i];
  }
  taskEXIT_CRITICAL(&s_mux);

  for (int i = 0; i < count; i++) {
    snapshot[i].callback(source, event, data, snapshot[i].user_data);
  }
}

static void aggregate(bool *connected, bool *playing) {
  *connected = false;
  *playing = false;
  for (int i = PLAYBACK_SOURCE_NONE + 1; i < PLAYBACK_SOURCE_COUNT; i++) {
    if (s_state[i] != SRC_IDLE) {
      *connected = true;
    }
    if (s_state[i] == SRC_PLAYING) {
      *playing = true;
    }
  }
}

// Applies one input's new state and reports which aggregate transitions that
// caused, at most two: an input that starts playing from a fully idle device
// produces CONNECTED then PLAYING. Runs under s_mux.
static size_t transition(playback_source_t source, src_state_t next,
                         playback_event_t *out) {
  bool was_connected, was_playing;
  aggregate(&was_connected, &was_playing);

  s_state[source] = next;

  if (next == SRC_PLAYING) {
    s_active = source;
  } else if (s_active == source && next == SRC_IDLE) {
    s_active = PLAYBACK_SOURCE_NONE;
  } else if (s_active == PLAYBACK_SOURCE_NONE && next != SRC_IDLE) {
    s_active = source;
  }

  bool now_connected, now_playing;
  aggregate(&now_connected, &now_playing);

  // The input holding the display just left, but another is still up: hand
  // the display over rather than leaving it frozen on a finished track.
  if (s_active == PLAYBACK_SOURCE_NONE && now_connected) {
    for (int i = PLAYBACK_SOURCE_NONE + 1; i < PLAYBACK_SOURCE_COUNT; i++) {
      if (s_state[i] == SRC_PLAYING) {
        s_active = (playback_source_t)i;
        break;
      }
      if (s_state[i] != SRC_IDLE && s_active == PLAYBACK_SOURCE_NONE) {
        s_active = (playback_source_t)i;
      }
    }
  }

  size_t n = 0;
  if (!was_connected && now_connected) {
    out[n++] = PLAYBACK_EVENT_CONNECTED;
  }
  if (!was_playing && now_playing) {
    out[n++] = PLAYBACK_EVENT_PLAYING;
  } else if (was_playing && !now_playing && now_connected) {
    out[n++] = PLAYBACK_EVENT_PAUSED;
  }
  if (was_connected && !now_connected) {
    out[n++] = PLAYBACK_EVENT_DISCONNECTED;
  }
  return n;
}

void playback_events_emit(playback_source_t source, playback_event_t event,
                          const playback_event_data_t *data) {
  if (source <= PLAYBACK_SOURCE_NONE || source >= PLAYBACK_SOURCE_COUNT) {
    return;
  }

  if (event == PLAYBACK_EVENT_METADATA) {
    // Whoever holds the display gets to describe what is playing. Without
    // this the two streams alternate now-playing lines every few seconds.
    taskENTER_CRITICAL(&s_mux);
    const bool mine = (s_active == source || s_active == PLAYBACK_SOURCE_NONE);
    taskEXIT_CRITICAL(&s_mux);
    if (mine) {
      notify(source, PLAYBACK_EVENT_METADATA, data);
    }
    return;
  }

  src_state_t next;
  switch (event) {
  case PLAYBACK_EVENT_CONNECTED:
    next = SRC_CONNECTED;
    break;
  case PLAYBACK_EVENT_PLAYING:
    next = SRC_PLAYING;
    break;
  case PLAYBACK_EVENT_PAUSED:
    next = SRC_PAUSED;
    break;
  case PLAYBACK_EVENT_DISCONNECTED:
    next = SRC_IDLE;
    break;
  default:
    return;
  }

  playback_event_t out[2];
  size_t n;

  taskENTER_CRITICAL(&s_mux);
  // A session announcing itself again mid-stream must not demote the input
  // and fake a pause; only an explicit PAUSED or DISCONNECTED does that.
  if (next == SRC_CONNECTED && s_state[source] != SRC_IDLE) {
    taskEXIT_CRITICAL(&s_mux);
    return;
  }
  if (s_state[source] == next) {
    taskEXIT_CRITICAL(&s_mux);
    return;
  }
  n = transition(source, next, out);
  taskEXIT_CRITICAL(&s_mux);

  for (size_t i = 0; i < n; i++) {
    notify(source, out[i], NULL);
  }
}

void playback_events_clear(playback_source_t source) {
  playback_events_emit(source, PLAYBACK_EVENT_DISCONNECTED, NULL);
}

bool playback_events_any_connected(void) {
  bool connected, playing;
  taskENTER_CRITICAL(&s_mux);
  aggregate(&connected, &playing);
  taskEXIT_CRITICAL(&s_mux);
  return connected;
}

bool playback_events_any_playing(void) {
  bool connected, playing;
  taskENTER_CRITICAL(&s_mux);
  aggregate(&connected, &playing);
  taskEXIT_CRITICAL(&s_mux);
  return playing;
}

playback_source_t playback_events_active_source(void) {
  taskENTER_CRITICAL(&s_mux);
  const playback_source_t active = s_active;
  taskEXIT_CRITICAL(&s_mux);
  return active;
}

bool playback_events_source_active(playback_source_t source) {
  if (source <= PLAYBACK_SOURCE_NONE || source >= PLAYBACK_SOURCE_COUNT) {
    return false;
  }
  taskENTER_CRITICAL(&s_mux);
  const bool active = (s_state[source] != SRC_IDLE);
  taskEXIT_CRITICAL(&s_mux);
  return active;
}

void playback_format_time_mmss(uint32_t seconds, char *out, size_t out_size) {
  uint32_t mins = seconds / 60;
  uint32_t secs = seconds % 60;
  snprintf(out, out_size, "%" PRIu32 ":%02" PRIu32, mins, secs);
}
