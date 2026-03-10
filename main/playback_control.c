/**
 * Source-agnostic playback controller.
 *
 * For AirPlay 2:
 *   - Volume: adjust locally (DAC + NVS persistence)
 *   - Play/Pause: control audio_receiver locally (TCP back-pressure
 *     throttles the source). The phone UI won't reflect the pause.
 *   - Next/Prev: not possible without the MediaRemote protocol.
 *   DACP calls are kept as best-effort for AirPlay 1 connections.
 *
 * For Bluetooth:
 *   - All commands sent as AVRCP passthrough to source device
 *   - Source device controls playback and sends volume back
 */

#include "playback_control.h"

#include "audio_receiver.h"
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
#define VOLUME_MIN_DB  -30.0f
#define VOLUME_MAX_DB  0.0f

static playback_source_t s_source = PLAYBACK_SOURCE_NONE;

esp_err_t playback_control_init(void) {
  dacp_init();
  ESP_LOGI(TAG, "Playback control initialized");
  return ESP_OK;
}

void playback_control_set_source(playback_source_t source) {
  s_source = source;
  ESP_LOGI(TAG, "Source set to %d", source);
}

playback_source_t playback_control_get_source(void) { return s_source; }

// ============================================================================
// AirPlay local volume helpers
// ============================================================================

static float clamp_volume(float db) {
  if (db < VOLUME_MIN_DB)
    return VOLUME_MIN_DB;
  if (db > VOLUME_MAX_DB)
    return VOLUME_MAX_DB;
  return db;
}

// Convert AirPlay dB (-30..0) to DACP percent (0..100)
static float db_to_dacp_percent(float db) {
  if (db <= VOLUME_MIN_DB)
    return 0.0f;
  if (db >= VOLUME_MAX_DB)
    return 100.0f;
  return ((db - VOLUME_MIN_DB) / (VOLUME_MAX_DB - VOLUME_MIN_DB)) * 100.0f;
}

static void airplay_adjust_volume(float step_db) {
  // Read current volume from the RTSP server's connection
  // We use airplay_set_volume which handles Q15 conversion + NVS persistence
  float current_db;
  if (settings_get_volume(&current_db) != ESP_OK) {
    current_db = 0.0f;
  }

  float new_db = clamp_volume(current_db + step_db);
  airplay_set_volume(new_db);
  dac_set_volume(new_db);

  // Notify AirPlay client via DACP
  dacp_send_volume(db_to_dacp_percent(new_db));

  ESP_LOGI(TAG, "AirPlay volume: %.1f -> %.1f dB", current_db, new_db);
}

// ============================================================================
// Public API
// ============================================================================

void playback_control_play_pause(void) {
  switch (s_source) {
  case PLAYBACK_SOURCE_AIRPLAY: {
    bool playing = audio_receiver_is_playing();
    if (playing) {
      audio_receiver_pause();
      rtsp_events_emit(RTSP_EVENT_PAUSED, NULL);
    } else {
      audio_receiver_set_playing(true);
      rtsp_events_emit(RTSP_EVENT_PLAYING, NULL);
    }
    dacp_send_playpause();
    ESP_LOGI(TAG, "AirPlay %s", playing ? "paused" : "resumed");
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
    dacp_send_next(); // Best-effort, AirPlay 1 only
    ESP_LOGD(TAG, "AirPlay next track (DACP best-effort)");
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
    dacp_send_prev(); // Best-effort, AirPlay 1 only
    ESP_LOGD(TAG, "AirPlay prev track (DACP best-effort)");
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
