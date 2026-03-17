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
#include "rtsp_events.h"
#include "rtsp_server.h"
#include "settings.h"

#include "esp_log.h"

#ifdef CONFIG_BT_A2DP_ENABLE
#include "a2dp_sink.h"
#endif

static const char *TAG = "playback_ctrl";

#define VOLUME_STEP_DB 3.0f
#define VOLUME_MIN_DB  (-30.0f)
#define VOLUME_MAX_DB  0.0f

static playback_source_t s_source = PLAYBACK_SOURCE_NONE;
static bool s_muted = false;
static float s_pre_mute_db = 0.0f;

esp_err_t playback_control_init(void) {
  dacp_init();
  ESP_LOGI(TAG, "Playback control initialized");
  return ESP_OK;
}

void playback_control_set_source(playback_source_t source) {
  s_muted = false;
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

static void airplay_adjust_volume(float step_db) {
  float current_db;
  if (settings_get_volume(&current_db) != ESP_OK) {
    current_db = -15.0f; // default 50 %
  }

  float new_db = clamp_volume(current_db + step_db);
  airplay_set_volume(new_db);

  if (s_muted) {
    // Update saved level so unmute restores the new volume
    s_pre_mute_db = new_db;
  } else {
    dac_set_volume(new_db);
  }

  // Notify AirPlay client via DACP
  dacp_send_volume(db_to_dacp_percent(new_db));

  ESP_LOGI(TAG, "AirPlay volume: %.1f -> %.1f dB%s", current_db, new_db,
           s_muted ? " (muted)" : "");
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
      dacp_send_playpause();
      ESP_LOGI(TAG, "AirPlay play/pause sent via DACP");
    } else {
      // Fallback: mute/unmute the DAC locally when no DACP session
      if (!s_muted) {
        if (settings_get_volume(&s_pre_mute_db) != ESP_OK) {
          s_pre_mute_db = -15.0f; // default 50 %
        }
        dac_set_volume(VOLUME_MIN_DB);
        s_muted = true;
        rtsp_events_emit(RTSP_EVENT_PAUSED, NULL);
        ESP_LOGI(TAG, "AirPlay muted locally (was %.1f dB)", s_pre_mute_db);
      } else {
        dac_set_volume(s_pre_mute_db);
        s_muted = false;
        rtsp_events_emit(RTSP_EVENT_PLAYING, NULL);
        ESP_LOGI(TAG, "AirPlay unmuted locally (%.1f dB)", s_pre_mute_db);
      }
    }
    break;
  }
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_playpause();
    break;
#endif
  default:
    ESP_LOGD(TAG, "Play/pause: no active source");
    break;
  }
}

void playback_control_volume_up(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
    airplay_adjust_volume(VOLUME_STEP_DB);
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_volume_up();
    break;
#endif
  default:
    break;
  }
}

void playback_control_volume_down(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY:
    airplay_adjust_volume(-VOLUME_STEP_DB);
    break;
#ifdef CONFIG_BT_A2DP_ENABLE
  case PLAYBACK_SOURCE_BLUETOOTH:
    bt_a2dp_send_volume_down();
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
  default:
    break;
  }
}
