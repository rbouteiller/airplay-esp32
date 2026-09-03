/**
 * Source-agnostic playback controller.
 *
 * For AirPlay:
 *   - Play/Pause: mute/unmute the DAC locally.  If the source sent
 *     DACP headers (AirPlay 1), we also forward the command via DACP
 *     so the source UI updates.  Modern iOS AirPlay 2 does not send
 *     DACP headers, so local mute is the only option.
 *   - Next/Prev: forwarded via DACP when available (AirPlay 1 only).
 *   - Volume: adjusted locally (DAC + NVS persistence) and mirrored
 *     to the source via DACP when available.
 *
 * For Bluetooth:
 *   - All commands sent as AVRCP passthrough to source device
 *   - Source device controls playback and sends volume back
 */

#include "playback_control.h"

#include "dac.h"
#include "dacp_client.h"
#include "playback_events.h"
#include "rtsp_server.h"
#include "settings.h"

#include "esp_log.h"

#ifdef CONFIG_BT_A2DP_ENABLE
#include "a2dp_sink.h"
#endif

#ifdef CONFIG_USB_AUDIO_SINK
#include "usb_hid_control.h"
#endif

#ifdef CONFIG_SENDSPIN_ENABLE
#include "sendspin.h"
#endif

static const char *TAG = "playback_ctrl";

#define VOLUME_STEP_DB 3.0f
#define VOLUME_MIN_DB  (-30.0f)
#define VOLUME_MAX_DB  0.0f

static playback_source_t s_source = PLAYBACK_SOURCE_NONE;
static bool s_muted = false;
static float s_pre_mute_db = -15.0f;

esp_err_t playback_control_init(void) {
  dacp_init();
  ESP_LOGI(TAG, "Playback control initialized");
  return ESP_OK;
}

void playback_control_set_source(playback_source_t source) {
  if (s_muted) {
    // The muting source is on its way out, so clearing the flag alone would
    // leave the DAC parked at the mute floor for whoever takes the output
    // next. Restore the level here rather than emitting a playing event.
    s_muted = false;
    settings_set_volume(s_pre_mute_db);
    dac_set_volume(s_pre_mute_db);
  }
  // After the restore, so a level changed while muted is what gets written.
  settings_persist_volume();
  s_source = source;
  ESP_LOGI(TAG, "Source set to %d", source);
}

playback_source_t playback_control_get_source(void) {
  return s_source;
}

// ============================================================================
// AirPlay local volume helpers
// ============================================================================

static float clamp_volume(float db) {
  if (db < VOLUME_MIN_DB) {
    return VOLUME_MIN_DB;
  }
  if (db > VOLUME_MAX_DB) {
    return VOLUME_MAX_DB;
  }
  return db;
}

// Convert AirPlay dB (-30..0) to DACP percent (0..100)
static float db_to_dacp_percent(float db) {
  if (db <= VOLUME_MIN_DB) {
    return 0.0f;
  }
  if (db >= VOLUME_MAX_DB) {
    return 100.0f;
  }
  return ((db - VOLUME_MIN_DB) / (VOLUME_MAX_DB - VOLUME_MIN_DB)) * 100.0f;
}

static float dacp_percent_to_db(float percent) {
  if (percent <= 0.0f) {
    return VOLUME_MIN_DB;
  }
  if (percent >= 100.0f) {
    return VOLUME_MAX_DB;
  }
  return VOLUME_MIN_DB + (percent / 100.0f) * (VOLUME_MAX_DB - VOLUME_MIN_DB);
}

// Apply a level to the DAC without disturbing mute, and keep the cached
// setting in step so the web UI and the level getter agree.
static void apply_level(float db) {
  if (s_muted) {
    s_pre_mute_db = db;
  } else {
    settings_set_volume(db);
  }
}

static void local_adjust_volume(float step_db) {
  float current_db;
  (void)settings_get_volume(&current_db);
  if (s_muted) {
    current_db = s_pre_mute_db;
  }

  float new_db = clamp_volume(current_db + step_db);
  apply_level(new_db);

  ESP_LOGI(TAG, "Volume: %.1f -> %.1f dB%s", current_db, new_db,
           s_muted ? " (muted)" : "");

  if (s_source == PLAYBACK_SOURCE_AIRPLAY) {
    airplay_set_volume(new_db);
    // Notify AirPlay client via DACP (best-effort, don't block local action)
    dacp_send_volume(db_to_dacp_percent(new_db));
  }
}

// ============================================================================
// Public API
// ============================================================================

void playback_control_play_pause(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY: {
    if (dacp_is_active()) {
      // Tell the source to toggle playback — it will FLUSH the stream
      // on pause and RECORD on resume, so we don't need local muting.
      // Signal the v1 grace period loop (if active) so it sends the
      // DACP command at the right time and keeps waiting for reconnect.
      // If not in a grace period, the flag is harmless.
      rtsp_server_request_resume();
      dacp_send_playpause();
      ESP_LOGI(TAG, "AirPlay play/pause sent via DACP");
    } else {
      // Fallback: mute/unmute the DAC locally when no DACP session
      playback_control_set_muted(!s_muted);
    }
    break;
  }
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_playpause();
    break;
#endif
#ifdef CONFIG_USB_AUDIO_SINK
  case PLAYBACK_SOURCE_USB:
    usb_hid_control_send(USB_HID_KEY_PLAY_PAUSE);
    break;
#endif
#ifdef CONFIG_SENDSPIN_ENABLE
  case PLAYBACK_SOURCE_SENDSPIN:
    // The protocol has no toggle, so pick the command from what the server
    // last said the group was doing.
    if (!sendspin_send_command(sendspin_is_playing() ? SENDSPIN_CMD_PAUSE
                                                     : SENDSPIN_CMD_PLAY)) {
      playback_control_set_muted(!s_muted);
    }
    break;
#endif
  default:
    ESP_LOGI(TAG, "Play/pause: no active source (source=%d)", s_source);
    break;
  }
}

void playback_control_volume_up(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
  case PLAYBACK_SOURCE_SENDSPIN:
    local_adjust_volume(VOLUME_STEP_DB);
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_volume_up();
    break;
#endif
#ifdef CONFIG_USB_AUDIO_SINK
  case PLAYBACK_SOURCE_USB:
    usb_hid_control_send(USB_HID_KEY_VOLUME_UP);
    break;
#endif
  default:
    break;
  }
}

void playback_control_volume_down(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
  case PLAYBACK_SOURCE_SENDSPIN:
    local_adjust_volume(-VOLUME_STEP_DB);
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_volume_down();
    break;
#endif
#ifdef CONFIG_USB_AUDIO_SINK
  case PLAYBACK_SOURCE_USB:
    usb_hid_control_send(USB_HID_KEY_VOLUME_DOWN);
    break;
#endif
  default:
    break;
  }
}

void playback_control_next(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
    dacp_send_next();
    ESP_LOGI(TAG, "AirPlay next track via DACP");
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_next();
    break;
#endif
#ifdef CONFIG_USB_AUDIO_SINK
  case PLAYBACK_SOURCE_USB:
    usb_hid_control_send(USB_HID_KEY_NEXT);
    break;
#endif
#ifdef CONFIG_SENDSPIN_ENABLE
  case PLAYBACK_SOURCE_SENDSPIN:
    sendspin_send_command(SENDSPIN_CMD_NEXT);
    break;
#endif
  default:
    break;
  }
}

void playback_control_prev(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
    dacp_send_prev();
    ESP_LOGI(TAG, "AirPlay prev track via DACP");
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_prev();
    break;
#endif
#ifdef CONFIG_USB_AUDIO_SINK
  case PLAYBACK_SOURCE_USB:
    usb_hid_control_send(USB_HID_KEY_PREV);
    break;
#endif
#ifdef CONFIG_SENDSPIN_ENABLE
  case PLAYBACK_SOURCE_SENDSPIN:
    sendspin_send_command(SENDSPIN_CMD_PREVIOUS);
    break;
#endif
  default:
    break;
  }
}

void playback_control_set_muted(bool muted) {
  if (muted == s_muted) {
    return;
  }
  if (muted) {
    (void)settings_get_volume(&s_pre_mute_db);
    dac_set_volume(VOLUME_MIN_DB);
    s_muted = true;
    playback_events_emit(s_source, PLAYBACK_EVENT_PAUSED, NULL);
    ESP_LOGI(TAG, "Muted locally (was %.1f dB)", s_pre_mute_db);
  } else {
    s_muted = false;
    // Muting left the cached level alone, so settings_set_volume() may see no
    // change and skip the DAC. Drive it directly to leave the mute floor.
    settings_set_volume(s_pre_mute_db);
    dac_set_volume(s_pre_mute_db);
    playback_events_emit(s_source, PLAYBACK_EVENT_PLAYING, NULL);
    ESP_LOGI(TAG, "Unmuted locally (%.1f dB)", s_pre_mute_db);
  }
}

void playback_control_set_volume_percent(int percent) {
  const float db = clamp_volume(dacp_percent_to_db((float)percent));
  apply_level(db);
  // Not persisted here: a server dragging a slider sends a command per step.
  // The level is committed at the next pause or when the session ends.
  ESP_LOGI(TAG, "Volume set to %d%% (%.1f dB)%s", percent, db,
           s_muted ? " (muted)" : "");
}

void playback_control_toggle_mute(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
  case PLAYBACK_SOURCE_SENDSPIN:
    playback_control_set_muted(!s_muted);
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    // Bluetooth uses AVRCP absolute volume — no dedicated mute. Log.
    ESP_LOGI(TAG, "Bluetooth: mute toggle not supported (use source device)");
    break;
#endif
#ifdef CONFIG_USB_AUDIO_SINK
  case PLAYBACK_SOURCE_USB:
    usb_hid_control_send(USB_HID_KEY_MUTE);
    break;
#endif
  default:
    ESP_LOGI(TAG, "Toggle mute: no active source (source=%d)", s_source);
    break;
  }
}

bool playback_control_is_muted(void) {
  return s_muted;
}

int playback_control_get_volume_percent(void) {
  if (s_muted) {
    return 0;
  }
  return playback_control_get_level_percent();
}

int playback_control_get_level_percent(void) {
  float db;
  if (s_muted) {
    db = s_pre_mute_db;
  } else {
    (void)settings_get_volume(&db);
  }
  return (int)(db_to_dacp_percent(clamp_volume(db)) + 0.5f);
}
