/**
 * Bluetooth A2DP Sink implementation for ESP32.
 *
 * Uses the ESP-IDF Bluedroid stack to receive A2DP audio (SBC codec,
 * decoded internally to PCM) and play it through the shared I2S output.
 *
 * Architecture:
 *   BT stack → data callback → ringbuffer → I2S writer task → I2S DMA
 *
 * Integration with AirPlay:
 *   - On BT connect:    notify main → stop AirPlay services
 *   - On BT disconnect: notify main → restart AirPlay services
 *   - LED/display updates via rtsp_events (reuses the same event types)
 *   - AVRCP metadata → RTSP_EVENT_METADATA for display
 */

#include "a2dp_sink.h"

#include "audio_output.h"
#include "dac.h"
#include "led.h"
#include "rtsp_events.h"
#include "settings.h"

#include "esp_a2dp_api.h"
#include "esp_avrc_api.h"
#include "esp_bt.h"
#include "esp_bt_device.h"
#include "esp_bt_main.h"
#include "esp_gap_bt_api.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include <inttypes.h>
#include <string.h>

static const char *TAG = "bt_a2dp";

/* ========================================================================== */
/* Configuration                                                              */
/* ========================================================================== */

#define RINGBUF_SIZE     (16 * 1024)
#define RINGBUF_PREFETCH (RINGBUF_SIZE * 6 / 10)

#define BT_TASK_STACK 4096
#define BT_TASK_PRIO  (configMAX_PRIORITIES - 3)
#define BT_TASK_QLEN  10

#define I2S_TASK_STACK 2560
#define I2S_TASK_PRIO  7

#if CONFIG_FREERTOS_UNICORE
#define I2S_TASK_CORE 0
#else
#define I2S_TASK_CORE 1
#endif

/* ========================================================================== */
/* BT App Task Types                                                          */
/* ========================================================================== */

typedef void (*bt_app_cb_t)(uint16_t event, void *param);

typedef struct {
  uint16_t sig;
  uint16_t event;
  bt_app_cb_t cb;
  void *param;
} bt_app_msg_t;

enum { BT_APP_SIG_WORK_DISPATCH = 0 };
enum { BT_APP_EVT_STACK_UP = 0 };

/* ========================================================================== */
/* Ringbuffer mode                                                            */
/* ========================================================================== */

typedef enum {
  RINGBUF_MODE_PREFETCHING,
  RINGBUF_MODE_PROCESSING,
  RINGBUF_MODE_DROPPING,
} ringbuf_mode_t;

/* ========================================================================== */
/* State                                                                      */
/* ========================================================================== */

static bt_a2dp_state_cb_t s_state_cb = NULL;
static volatile bool s_connected = false;
static volatile bool s_audio_started = false;
static volatile bool s_i2s_task_running = false;
static bool s_bt_discoverable = true;
static uint8_t s_avrc_volume = 127; /* 0-127, AVRCP absolute volume */

static RingbufHandle_t s_ringbuf = NULL;
static SemaphoreHandle_t s_i2s_sem = NULL;
static ringbuf_mode_t s_ringbuf_mode = RINGBUF_MODE_PREFETCHING;

static TaskHandle_t s_bt_task_handle = NULL;
static TaskHandle_t s_i2s_task_handle = NULL;
static QueueHandle_t s_bt_task_queue = NULL;

static uint32_t s_sample_rate = 44100;

/* ========================================================================== */
/* BT App Task — context-switch from BT stack to app task                     */
/* ========================================================================== */

static bool bt_app_send_msg(bt_app_msg_t *msg) {
  if (s_bt_task_queue == NULL) {
    return false;
  }
  return xQueueSend(s_bt_task_queue, msg, pdMS_TO_TICKS(10)) == pdTRUE;
}

static bool bt_app_work_dispatch(bt_app_cb_t cb, uint16_t event, void *param,
                                 int param_len) {
  bt_app_msg_t msg = {
      .sig = BT_APP_SIG_WORK_DISPATCH,
      .event = event,
      .cb = cb,
      .param = NULL,
  };
  if (param_len > 0 && param != NULL) {
    msg.param = malloc((size_t)param_len);
    if (!msg.param) {
      return false;
    }
    memcpy(msg.param, param, (size_t)param_len);
  }
  if (!bt_app_send_msg(&msg)) {
    free(msg.param);
    return false;
  }
  return true;
}

static void bt_app_task(void *arg) {
  bt_app_msg_t msg;
  while (true) {
    if (xQueueReceive(s_bt_task_queue, &msg, portMAX_DELAY) == pdTRUE) {
      if (msg.sig == BT_APP_SIG_WORK_DISPATCH && msg.cb) {
        msg.cb(msg.event, msg.param);
      }
      free(msg.param);
    }
  }
}

/* ========================================================================== */
/* I2S Writer Task — reads ringbuffer, writes to I2S                          */
/* ========================================================================== */

static void bt_i2s_writer_task(void *arg) {
  // Wait for ringbuffer to reach prefetch level
  xSemaphoreTake(s_i2s_sem, portMAX_DELAY);

  int16_t silence[256] = {0};

  while (s_i2s_task_running) {
    size_t item_size = 0;
    void *data =
        xRingbufferReceiveUpTo(s_ringbuf, &item_size, pdMS_TO_TICKS(20), 512);
    if (data != NULL && item_size > 0) {
      audio_output_write(data, item_size, portMAX_DELAY);
      vRingbufferReturnItem(s_ringbuf, data);
    } else {
      // Buffer underrun — write silence to keep I2S fed
      audio_output_write(silence, sizeof(silence), pdMS_TO_TICKS(10));
    }
  }

  s_i2s_task_handle = NULL;
  vTaskDelete(NULL);
}

static void i2s_task_start(void) {
  s_ringbuf_mode = RINGBUF_MODE_PREFETCHING;

  if (s_ringbuf == NULL) {
    s_ringbuf = xRingbufferCreate(RINGBUF_SIZE, RINGBUF_TYPE_BYTEBUF);
  }
  if (s_i2s_sem == NULL) {
    s_i2s_sem = xSemaphoreCreateBinary();
  }

  s_i2s_task_running = true;
  xTaskCreatePinnedToCore(bt_i2s_writer_task, "bt_i2s", I2S_TASK_STACK, NULL,
                          I2S_TASK_PRIO, &s_i2s_task_handle, I2S_TASK_CORE);
}

static void i2s_task_stop(void) {
  s_i2s_task_running = false;

  // Unblock the writer if it's waiting on the semaphore
  if (s_i2s_sem) {
    xSemaphoreGive(s_i2s_sem);
  }

  // Wait for the task to exit
  int timeout = 20;
  while (s_i2s_task_handle != NULL && timeout-- > 0) {
    vTaskDelay(pdMS_TO_TICKS(50));
  }

  // Flush and free the ringbuffer so heap is returned before AirPlay restarts
  if (s_ringbuf) {
    void *data;
    size_t size;
    while ((data = xRingbufferReceive(s_ringbuf, &size, 0)) != NULL) {
      vRingbufferReturnItem(s_ringbuf, data);
    }
    vRingbufferDelete(s_ringbuf);
    s_ringbuf = NULL;
  }

  if (s_i2s_sem) {
    vSemaphoreDelete(s_i2s_sem);
    s_i2s_sem = NULL;
  }

  // Reset sample rate to AirPlay default
  audio_output_set_sample_rate(44100);
  audio_output_flush();
}

/* ========================================================================== */
/* A2DP data callback — BT stack context → ringbuffer                         */
/* ========================================================================== */

static void bt_a2dp_data_cb(const uint8_t *data, uint32_t len) {
  if (s_ringbuf == NULL || len == 0) {
    return;
  }

  // Feed LED VU meter from the decoded PCM
  led_audio_feed((const int16_t *)data, len / 4);

  size_t free_size = xRingbufferGetCurFreeSize(s_ringbuf);

  switch (s_ringbuf_mode) {
  case RINGBUF_MODE_PREFETCHING:
    xRingbufferSend(s_ringbuf, data, len, 0);
    if ((RINGBUF_SIZE - free_size + len) >= RINGBUF_PREFETCH) {
      s_ringbuf_mode = RINGBUF_MODE_PROCESSING;
      xSemaphoreGive(s_i2s_sem);
    }
    break;

  case RINGBUF_MODE_PROCESSING:
    if (free_size < (size_t)len) {
      s_ringbuf_mode = RINGBUF_MODE_DROPPING;
      ESP_LOGW(TAG, "Ringbuf full, dropping");
    } else {
      xRingbufferSend(s_ringbuf, data, len, 0);
    }
    break;

  case RINGBUF_MODE_DROPPING:
    if (free_size > RINGBUF_PREFETCH) {
      s_ringbuf_mode = RINGBUF_MODE_PROCESSING;
      xRingbufferSend(s_ringbuf, data, len, 0);
    }
    break;
  }
}

/* ========================================================================== */
/* A2DP event handler (runs in app task context) */
/* ========================================================================== */

static void bt_a2dp_evt_handler(uint16_t event, void *param) {
  esp_a2d_cb_param_t *a2d = (esp_a2d_cb_param_t *)param;

  switch (event) {
  case ESP_A2D_CONNECTION_STATE_EVT: {
    esp_a2d_connection_state_t state = a2d->conn_stat.state;

    if (state == ESP_A2D_CONNECTION_STATE_CONNECTING) {
      ESP_LOGI(TAG, "A2DP connecting...");
    } else if (state == ESP_A2D_CONNECTION_STATE_CONNECTED) {
      ESP_LOGI(TAG, "A2DP connected");
      s_connected = true;

      // Notify main app to disable AirPlay (stops playback task + RTSP)
      if (s_state_cb) {
        s_state_cb(true);
      }

      // Start BT playback
      i2s_task_start();

      // LED/display: show connected state
      rtsp_events_emit(RTSP_EVENT_CLIENT_CONNECTED, NULL);

      // Don't accept more connections while connected
      esp_bt_gap_set_scan_mode(ESP_BT_NON_CONNECTABLE, ESP_BT_NON_DISCOVERABLE);

    } else if (state == ESP_A2D_CONNECTION_STATE_DISCONNECTING) {
      ESP_LOGI(TAG, "A2DP disconnecting...");
    } else if (state == ESP_A2D_CONNECTION_STATE_DISCONNECTED) {
      ESP_LOGI(TAG, "A2DP disconnected");
      s_connected = false;
      s_audio_started = false;

      // Stop BT playback
      i2s_task_stop();

      // LED/display: show disconnected state
      rtsp_events_emit(RTSP_EVENT_DISCONNECTED, NULL);

      // Notify main app to re-enable AirPlay (restarts playback + RTSP)
      if (s_state_cb) {
        s_state_cb(false);
      }

      // Discoverable state is managed by main via set_discoverable()

      // Persist the last-used volume so it is restored on next connect
      settings_set_bt_volume(s_avrc_volume);
    }
    break;
  }

  case ESP_A2D_AUDIO_STATE_EVT: {
    esp_a2d_audio_state_t state = a2d->audio_stat.state;
    if (state == ESP_A2D_AUDIO_STATE_STARTED) {
      ESP_LOGI(TAG, "Audio stream started");
      s_audio_started = true;
      rtsp_events_emit(RTSP_EVENT_PLAYING, NULL);
    } else {
      ESP_LOGI(TAG, "Audio stream stopped/suspended");
      s_audio_started = false;
      rtsp_events_emit(RTSP_EVENT_PAUSED, NULL);
    }
    break;
  }

  case ESP_A2D_AUDIO_CFG_EVT: {
    ESP_LOGI(TAG, "Audio codec configured, type=%d", a2d->audio_cfg.mcc.type);
    if (a2d->audio_cfg.mcc.type == ESP_A2D_MCT_SBC) {
      // Use the new struct-based CIE accessors
      uint8_t sf = a2d->audio_cfg.mcc.cie.sbc_info.samp_freq;
      if (sf & ESP_A2D_SBC_CIE_SF_48K) {
        s_sample_rate = 48000;
      } else if (sf & ESP_A2D_SBC_CIE_SF_44K) {
        s_sample_rate = 44100;
      } else if (sf & ESP_A2D_SBC_CIE_SF_32K) {
        s_sample_rate = 32000;
      } else if (sf & ESP_A2D_SBC_CIE_SF_16K) {
        s_sample_rate = 16000;
      }
      ESP_LOGI(TAG, "SBC sample rate: %" PRIu32 " Hz", s_sample_rate);
      audio_output_set_sample_rate(s_sample_rate);
    }
    break;
  }

  case ESP_A2D_PROF_STATE_EVT:
    ESP_LOGI(TAG, "A2DP profile %s",
             a2d->a2d_prof_stat.init_state == ESP_A2D_INIT_SUCCESS
                 ? "inited"
                 : "deinited");
    break;

  default:
    break;
  }
}

/* A2DP callback (BT stack context) → dispatch to app task */
static void bt_a2dp_cb(esp_a2d_cb_event_t event, esp_a2d_cb_param_t *param) {
  bt_app_work_dispatch(bt_a2dp_evt_handler, (uint16_t)event, param,
                       sizeof(esp_a2d_cb_param_t));
}

/* ========================================================================== */
/* AVRCP Controller — get metadata from source device                         */
/* ========================================================================== */

static void bt_avrc_ct_evt_handler(uint16_t event, void *param) {
  esp_avrc_ct_cb_param_t *rc = (esp_avrc_ct_cb_param_t *)param;
  static rtsp_event_data_t meta_data;

  switch (event) {
  case ESP_AVRC_CT_CONNECTION_STATE_EVT:
    ESP_LOGI(TAG, "AVRC CT %s",
             rc->conn_stat.connected ? "connected" : "disconnected");
    if (rc->conn_stat.connected) {
      // Request track metadata
      esp_avrc_ct_send_metadata_cmd(
          0, ESP_AVRC_MD_ATTR_TITLE | ESP_AVRC_MD_ATTR_ARTIST |
                 ESP_AVRC_MD_ATTR_ALBUM | ESP_AVRC_MD_ATTR_GENRE);
      // Register for track change notification
      esp_avrc_ct_send_register_notification_cmd(1, ESP_AVRC_RN_TRACK_CHANGE,
                                                 0);
    }
    break;

  case ESP_AVRC_CT_METADATA_RSP_EVT: {
    // Metadata response — one attribute per event
    uint8_t attr_id = rc->meta_rsp.attr_id;
    uint8_t *text = rc->meta_rsp.attr_text;
    int len = rc->meta_rsp.attr_length;

    if (text == NULL || len == 0) {
      break;
    }

    // Build metadata event for display
    char *dst = NULL;
    size_t dst_size = 0;

    switch (attr_id) {
    case ESP_AVRC_MD_ATTR_TITLE:
      dst = meta_data.metadata.title;
      dst_size = sizeof(meta_data.metadata.title);
      break;
    case ESP_AVRC_MD_ATTR_ARTIST:
      dst = meta_data.metadata.artist;
      dst_size = sizeof(meta_data.metadata.artist);
      break;
    case ESP_AVRC_MD_ATTR_ALBUM:
      dst = meta_data.metadata.album;
      dst_size = sizeof(meta_data.metadata.album);
      break;
    case ESP_AVRC_MD_ATTR_GENRE:
      dst = meta_data.metadata.genre;
      dst_size = sizeof(meta_data.metadata.genre);
      break;
    default:
      break;
    }

    if (dst) {
      size_t copy_len = (size_t)len < dst_size - 1 ? (size_t)len : dst_size - 1;
      memcpy(dst, text, copy_len);
      dst[copy_len] = '\0';
      ESP_LOGI(TAG, "Metadata attr %d: %s", attr_id, dst);

      // Emit metadata event after each attribute update
      rtsp_events_emit(RTSP_EVENT_METADATA, &meta_data);
    }
    break;
  }

  case ESP_AVRC_CT_CHANGE_NOTIFY_EVT:
    if (rc->change_ntf.event_id == ESP_AVRC_RN_TRACK_CHANGE) {
      ESP_LOGI(TAG, "Track changed");
      // Clear old metadata so stale fields don't persist
      memset(&meta_data, 0, sizeof(meta_data));

      // Request new metadata
      esp_avrc_ct_send_metadata_cmd(
          0, ESP_AVRC_MD_ATTR_TITLE | ESP_AVRC_MD_ATTR_ARTIST |
                 ESP_AVRC_MD_ATTR_ALBUM | ESP_AVRC_MD_ATTR_GENRE);
      // Re-register for track change
      esp_avrc_ct_send_register_notification_cmd(1, ESP_AVRC_RN_TRACK_CHANGE,
                                                 0);
    }
    break;

  default:
    break;
  }
}

static void bt_avrc_ct_cb(esp_avrc_ct_cb_event_t event,
                          esp_avrc_ct_cb_param_t *param) {
  bt_app_work_dispatch(bt_avrc_ct_evt_handler, (uint16_t)event, param,
                       sizeof(esp_avrc_ct_cb_param_t));
}

/* ========================================================================== */
/* AVRCP Target — handle volume commands from source device                   */
/* ========================================================================== */

static void bt_avrc_tg_evt_handler(uint16_t event, void *param) {
  esp_avrc_tg_cb_param_t *tg = (esp_avrc_tg_cb_param_t *)param;

  switch (event) {
  case ESP_AVRC_TG_CONNECTION_STATE_EVT:
    ESP_LOGI(TAG, "AVRC TG %s",
             tg->conn_stat.connected ? "connected" : "disconnected");
    break;

  case ESP_AVRC_TG_SET_ABSOLUTE_VOLUME_CMD_EVT: {
    uint8_t volume = tg->set_abs_vol.volume; // 0-127
    s_avrc_volume = volume;
    ESP_LOGD(TAG, "Set absolute volume: %d/127", volume);

    // Map 0-127 → -30..0 dB and apply to DAC
    // dac_set_volume does I2C — safe here because bt_app_task dispatches
    // sequentially, but keep it lightweight
    float volume_db = ((float)volume / 127.0f) * 30.0f - 30.0f;
    dac_set_volume(volume_db);
    break;
  }

  case ESP_AVRC_TG_REGISTER_NOTIFICATION_EVT:
    if (tg->reg_ntf.event_id == ESP_AVRC_RN_VOLUME_CHANGE) {
      // Respond with current volume (interim response)
      esp_avrc_rn_param_t rn_param;
      rn_param.volume = s_avrc_volume;
      esp_avrc_tg_send_rn_rsp(ESP_AVRC_RN_VOLUME_CHANGE,
                              ESP_AVRC_RN_RSP_INTERIM, &rn_param);
    }
    break;

  default:
    break;
  }
}

static void bt_avrc_tg_cb(esp_avrc_tg_cb_event_t event,
                          esp_avrc_tg_cb_param_t *param) {
  bt_app_work_dispatch(bt_avrc_tg_evt_handler, (uint16_t)event, param,
                       sizeof(esp_avrc_tg_cb_param_t));
}

/* ========================================================================== */
/* GAP callback                                                               */
/* ========================================================================== */

static void bt_gap_cb(esp_bt_gap_cb_event_t event,
                      esp_bt_gap_cb_param_t *param) {
  switch (event) {
  case ESP_BT_GAP_AUTH_CMPL_EVT:
    if (param->auth_cmpl.stat == ESP_BT_STATUS_SUCCESS) {
      ESP_LOGI(TAG, "Auth success: %s", param->auth_cmpl.device_name);
    } else {
      ESP_LOGW(TAG, "Auth failed: status=%d", param->auth_cmpl.stat);
    }
    break;

  case ESP_BT_GAP_CFM_REQ_EVT:
    ESP_LOGI(TAG, "SSP confirm request (num=%" PRIu32 "), auto-accepting",
             param->cfm_req.num_val);
    esp_bt_gap_ssp_confirm_reply(param->cfm_req.bda, true);
    break;

  case ESP_BT_GAP_PIN_REQ_EVT:
    ESP_LOGI(TAG, "Legacy PIN request");
    break;

  case ESP_BT_GAP_KEY_NOTIF_EVT:
    ESP_LOGI(TAG, "SSP passkey notify: %" PRIu32, param->key_notif.passkey);
    break;

  case ESP_BT_GAP_KEY_REQ_EVT:
    ESP_LOGI(TAG, "SSP passkey request");
    break;

  case ESP_BT_GAP_MODE_CHG_EVT:
    ESP_LOGD(TAG, "GAP mode changed to %d", param->mode_chg.mode);
    break;

  default:
    break;
  }
}

/* ========================================================================== */
/* Stack-up handler — called when Bluedroid is (re-)enabled                   */
/* ========================================================================== */

static void bt_stack_evt_handler(uint16_t event, void *param) {
  (void)param;

  if (event != BT_APP_EVT_STACK_UP) {
    return;
  }

  ESP_LOGI(TAG, "BT stack up, initializing profiles");

  // GAP
  esp_bt_gap_register_callback(bt_gap_cb);

#ifdef CONFIG_BT_SSP_ENABLED
  // Secure Simple Pairing — numeric comparison for BT 2.1+ devices
  esp_bt_sp_param_t param_type = ESP_BT_SP_IOCAP_MODE;
  esp_bt_io_cap_t iocap = ESP_BT_IO_CAP_IO;
  esp_bt_gap_set_security_param(param_type, &iocap, sizeof(uint8_t));
#endif

  // Legacy Pairing — fixed PIN from Kconfig
  esp_bt_pin_type_t pin_type = ESP_BT_PIN_TYPE_FIXED;
  esp_bt_pin_code_t pin_code;
  const char *pin_str = CONFIG_BT_PIN_CODE;
  uint8_t pin_len = strlen(pin_str);
  if (pin_len > ESP_BT_PIN_CODE_LEN) {
    pin_len = ESP_BT_PIN_CODE_LEN;
  }
  memcpy(pin_code, pin_str, pin_len);
  esp_bt_gap_set_pin(pin_type, pin_len, pin_code);
  ESP_LOGI(TAG, "BT PIN set (%d digits)", pin_len);

  // AVRC Controller (to get metadata from source)
  esp_avrc_ct_register_callback(bt_avrc_ct_cb);
  esp_avrc_ct_init();

  // AVRC Target (to receive volume commands)
  esp_avrc_tg_register_callback(bt_avrc_tg_cb);
  esp_avrc_tg_init();
  esp_avrc_rn_evt_cap_mask_t evt_set = {0};
  evt_set.bits = (1 << ESP_AVRC_RN_VOLUME_CHANGE);
  esp_avrc_tg_set_rn_evt_cap(&evt_set);

  // A2DP Sink
  esp_a2d_register_callback(bt_a2dp_cb);
  esp_a2d_sink_register_data_callback(bt_a2dp_data_cb);
  esp_a2d_sink_init();

  // Apply saved discoverable state
  if (s_bt_discoverable) {
    esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE, ESP_BT_GENERAL_DISCOVERABLE);
  } else {
    esp_bt_gap_set_scan_mode(ESP_BT_NON_CONNECTABLE, ESP_BT_NON_DISCOVERABLE);
  }

  // Restore saved BT volume (falls back to 127 / 0 dB if none stored)
  {
    uint8_t saved_vol;
    if (settings_get_bt_volume(&saved_vol) == ESP_OK) {
      s_avrc_volume = saved_vol;
    }
    float volume_db = ((float)s_avrc_volume / 127.0f) * 30.0f - 30.0f;
    dac_set_volume(volume_db);
    ESP_LOGI(TAG, "BT volume restored: %d/127 (%.1f dB)", s_avrc_volume,
             volume_db);
  }

  ESP_LOGI(TAG, "BT A2DP sink ready, waiting for connections");
}

/* ========================================================================== */
/* Public API                                                                 */
/* ========================================================================== */

esp_err_t bt_a2dp_sink_init(const char *device_name,
                            bt_a2dp_state_cb_t state_cb) {
  s_state_cb = state_cb;

  ESP_LOGI(TAG, "Initializing Bluetooth A2DP Sink: %s", device_name);

  // Release BLE memory — we only need Classic BT
  ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_BLE));

  // Initialize BT controller
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_err_t err = esp_bt_controller_init(&bt_cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "BT controller init failed: %s", esp_err_to_name(err));
    return err;
  }

  err = esp_bt_controller_enable(ESP_BT_MODE_CLASSIC_BT);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "BT controller enable failed: %s", esp_err_to_name(err));
    return err;
  }

  // Initialize Bluedroid
  esp_bluedroid_config_t bluedroid_cfg = BT_BLUEDROID_INIT_CONFIG_DEFAULT();
#ifndef CONFIG_BT_SSP_ENABLED
  bluedroid_cfg.ssp_en = false; // Disable SSP to force legacy PIN pairing
#endif
  err = esp_bluedroid_init_with_cfg(&bluedroid_cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Bluedroid init failed: %s", esp_err_to_name(err));
    return err;
  }

  err = esp_bluedroid_enable();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Bluedroid enable failed: %s", esp_err_to_name(err));
    return err;
  }

  // Set device name
  esp_bt_gap_set_device_name(device_name);

  // Create the BT app task and event queue
  s_bt_task_queue = xQueueCreate(BT_TASK_QLEN, sizeof(bt_app_msg_t));
  if (s_bt_task_queue == NULL) {
    ESP_LOGE(TAG, "Failed to create BT task queue");
    return ESP_ERR_NO_MEM;
  }

  BaseType_t ret = xTaskCreate(bt_app_task, "bt_app", BT_TASK_STACK, NULL,
                               BT_TASK_PRIO, &s_bt_task_handle);
  if (ret != pdPASS) {
    ESP_LOGE(TAG, "Failed to create BT app task");
    return ESP_ERR_NO_MEM;
  }

  // Dispatch stack-up event to app task
  bt_app_work_dispatch(bt_stack_evt_handler, BT_APP_EVT_STACK_UP, NULL, 0);

  return ESP_OK;
}

bool bt_a2dp_sink_is_connected(void) {
  return s_connected;
}

void bt_a2dp_sink_set_discoverable(bool discoverable) {
  s_bt_discoverable = discoverable;
  if (s_connected) {
    return;
  }
  if (discoverable) {
    ESP_LOGI(TAG, "BT discoverable enabled");
    esp_bt_gap_set_scan_mode(ESP_BT_CONNECTABLE, ESP_BT_GENERAL_DISCOVERABLE);
  } else {
    ESP_LOGI(TAG, "BT discoverable disabled");
    esp_bt_gap_set_scan_mode(ESP_BT_NON_CONNECTABLE, ESP_BT_NON_DISCOVERABLE);
  }
}
