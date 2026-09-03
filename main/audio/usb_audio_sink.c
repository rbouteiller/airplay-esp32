/**
 * USB Audio Class (UAC) sink — ESP32 as a USB speaker.
 *
 * The board enumerates on the attached computer as a stereo USB audio
 * output device.  PCM arriving from the host is buffered and written to
 * the same I2S path AirPlay uses, so both sources share the DAC, its DSP
 * and its volume control.
 *
 * Only one source may drive I2S at a time: the state callback lets the
 * application suspend AirPlay while the host is streaming and resume it
 * once the stream has been idle for CONFIG_USB_AUDIO_SINK_IDLE_MS.
 *
 * Note this is the opposite direction to audio_output_usb.c, which
 * presents the board as a USB *microphone* fed by AirPlay.  The two are
 * mutually exclusive.
 */

#include "usb_audio_sink.h"

#include "audio_output.h"
#include "dac.h"
#include "led.h"
#include "playback_events.h"
#include "settings.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/task.h"
#include "usb_device_uac.h"

#if CONFIG_USB_DEVICE_UAC_AS_PART
#include "usb_desc_itf.h"
#endif

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "usb_sink";

#if CONFIG_UAC_SAMPLE_RATE != CONFIG_OUTPUT_SAMPLE_RATE_HZ
#error \
    "CONFIG_UAC_SAMPLE_RATE must match CONFIG_OUTPUT_SAMPLE_RATE_HZ — the UAC descriptor advertises one fixed rate and the sink does not resample"
#endif

#if CONFIG_UAC_SPEAKER_CHANNEL_NUM != 2
#error "CONFIG_USB_AUDIO_SINK requires CONFIG_UAC_SPEAKER_CHANNEL_NUM=2"
#endif

#if !defined(CONFIG_UAC_BIT_RESOLUTION_16)
#error "CONFIG_USB_AUDIO_SINK requires CONFIG_UAC_BIT_RESOLUTION_16"
#endif

#define BYTES_PER_FRAME 4 // 16-bit stereo

// ~100 ms of slack between the USB stack and I2S, primed with ~20 ms so
// the first writes don't immediately underrun.
#define RINGBUF_SIZE \
  ((size_t)(CONFIG_OUTPUT_SAMPLE_RATE_HZ / 10) * BYTES_PER_FRAME)
#define RINGBUF_PREFETCH \
  ((size_t)(CONFIG_OUTPUT_SAMPLE_RATE_HZ / 50) * BYTES_PER_FRAME)

#define IDLE_TIMEOUT_US ((int64_t)CONFIG_USB_AUDIO_SINK_IDLE_MS * 1000)

#define SINK_TASK_STACK 4096
#define SINK_TASK_PRIO  AUDIO_PLAYBACK_TASK_PRIORITY
#if CONFIG_FREERTOS_UNICORE
#define SINK_TASK_CORE 0
#else
#define SINK_TASK_CORE 1
#endif

#define VOLUME_MIN_DB (-30.0f)
#define VOLUME_MAX_DB 0.0f

static RingbufHandle_t s_ringbuf;
static TaskHandle_t s_task;
static usb_audio_sink_state_cb_t s_state_cb;

static volatile bool s_streaming;
static volatile int64_t s_last_rx_us;
static uint32_t s_dropped;
static uint32_t s_underruns;
static _Atomic uint32_t s_rx_bytes;
static int64_t s_stats_us;

#define STATS_INTERVAL_US 2000000

// Host feature-unit updates are handled on the TinyUSB task during a
// control transfer; defer the (I2C) DAC writes to the sink task so USB
// never stalls behind the bus.  -1 means "nothing pending".
static _Atomic int32_t s_pending_volume = -1;
static _Atomic int32_t s_pending_mute = -1;
static float s_unmuted_db = -15.0f;
// Latched mute state, owned by the sink task.
static bool s_muted;

// ============================================================================
// UAC callbacks
// ============================================================================

// Host -> device PCM.  Runs on the component's usb_spk_task (priority
// CONFIG_UAC_SPK_TASK_PRIORITY), not in interrupt context.
static esp_err_t uac_output_cb(uint8_t *buf, size_t len, void *cb_ctx) {
  (void)cb_ctx;

  // Snapshot the handle: usb_audio_sink_init() may still be tearing down.
  RingbufHandle_t ringbuf = s_ringbuf;
  if (ringbuf == NULL || len == 0) {
    return ESP_OK;
  }

  s_last_rx_us = esp_timer_get_time();
  atomic_fetch_add(&s_rx_bytes, (uint32_t)len);
  led_audio_feed((const int16_t *)buf, len / BYTES_PER_FRAME);

  if (xRingbufferSend(ringbuf, buf, len, 0) != pdTRUE) {
    // Either the sink task is still handing I2S over from AirPlay, or the
    // host is running ahead of our clock.  Dropping is preferable to
    // blocking the USB stack.
    s_dropped++;
  }

  if (!s_streaming && s_task != NULL) {
    xTaskNotifyGive(s_task);
  }
  return ESP_OK;
}

static void uac_set_mute_cb(uint32_t mute, void *cb_ctx) {
  (void)cb_ctx;
  atomic_store(&s_pending_mute, mute ? 1 : 0);
}

// The component hands us 0..100 (mapped from the host's -50..0 dB).
static void uac_set_volume_cb(uint32_t volume, void *cb_ctx) {
  (void)cb_ctx;
  if (volume > 100) {
    volume = 100;
  }
  atomic_store(&s_pending_volume, (int32_t)volume);
}

static void apply_host_controls(void) {
  int32_t mute = atomic_exchange(&s_pending_mute, -1);
  if (mute >= 0) {
    s_muted = (mute == 1);
    ESP_LOGI(TAG, "Host %s", s_muted ? "muted" : "unmuted");
  }

  int32_t volume = atomic_exchange(&s_pending_volume, -1);
  if (volume >= 0) {
    s_unmuted_db = VOLUME_MIN_DB +
                   ((float)volume / 100.0f) * (VOLUME_MAX_DB - VOLUME_MIN_DB);
    ESP_LOGI(TAG, "Host volume %" PRId32 " %% -> %.1f dB", volume,
             s_unmuted_db);
  }

  // Mute is a latched state, not an event: a volume change while muted must
  // update s_unmuted_db without lifting the mute.
  if (mute >= 0 || volume >= 0) {
    dac_set_volume(s_muted ? VOLUME_MIN_DB : s_unmuted_db);
  }
}

// ============================================================================
// Writer task
// ============================================================================

static size_t ringbuf_filled(void) {
  return RINGBUF_SIZE - xRingbufferGetCurFreeSize(s_ringbuf);
}

static void ringbuf_drain(void) {
  size_t item_size = 0;
  void *data;
  while ((data = xRingbufferReceiveUpTo(s_ringbuf, &item_size, 0,
                                        RINGBUF_SIZE)) != NULL) {
    vRingbufferReturnItem(s_ringbuf, data);
  }
}

// Diagnostic: the host's delivered frame rate should equal the I2S rate.  A
// standing difference means the two clocks are not locked and the ring buffer
// is absorbing the error until it runs dry or overflows.
static void log_stats(void) {
  int64_t now = esp_timer_get_time();
  int64_t elapsed = now - s_stats_us;
  if (elapsed < STATS_INTERVAL_US) {
    return;
  }
  s_stats_us = now;
  uint32_t bytes = atomic_exchange(&s_rx_bytes, 0);
  uint32_t fps = (uint32_t)((uint64_t)(bytes / BYTES_PER_FRAME) * 1000000U /
                            (uint64_t)elapsed);
  ESP_LOGD(TAG,
           "host %" PRIu32 " fps (i2s %d) ring %u/%u dropped %" PRIu32
           " underruns %" PRIu32,
           fps, CONFIG_OUTPUT_SAMPLE_RATE_HZ, (unsigned)ringbuf_filled(),
           (unsigned)RINGBUF_SIZE, s_dropped, s_underruns);
}

static void usb_sink_task(void *arg) {
  (void)arg;
  static const int16_t silence[256] = {0};

  for (;;) {
    if (!s_streaming) {
      // Idle: wait for the host to start pushing frames, then let a small
      // prefetch accumulate before taking the output over from AirPlay.
      ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
      if (ringbuf_filled() < RINGBUF_PREFETCH) {
        continue;
      }
      ESP_LOGI(TAG, "Host stream started");
      s_streaming = true;
      // An AirPlay session may have left the clock at its own rate, and this
      // path writes to I2S directly without resampling.
      audio_output_set_sample_rate(CONFIG_UAC_SAMPLE_RATE);
      if (s_state_cb != NULL) {
        s_state_cb(true);
      }
      // The board keeps the amplifier in DAC_POWER_OFF until it sees these,
      // so without them the USB stream is written to a sleeping DAC.
      // CLIENT_CONNECTED also clears whatever the display was last showing.
      playback_events_emit(PLAYBACK_SOURCE_USB, PLAYBACK_EVENT_CONNECTED, NULL);
      playback_events_emit(PLAYBACK_SOURCE_USB, PLAYBACK_EVENT_PLAYING, NULL);
      // UAC carries no track info, so label the source instead.
      playback_event_data_t meta = {0};
      snprintf(meta.metadata.title, METADATA_STRING_MAX, "USB Audio");
      playback_events_emit(PLAYBACK_SOURCE_USB, PLAYBACK_EVENT_METADATA, &meta);
      s_dropped = 0;
      s_underruns = 0;
      atomic_store(&s_rx_bytes, 0);
      s_stats_us = esp_timer_get_time();
      continue;
    }

    apply_host_controls();
    log_stats();

    size_t item_size = 0;
    void *data =
        xRingbufferReceiveUpTo(s_ringbuf, &item_size, pdMS_TO_TICKS(20), 512);
    if (data != NULL) {
      audio_output_write(data, item_size, portMAX_DELAY);
      vRingbufferReturnItem(s_ringbuf, data);
      continue;
    }

    if (esp_timer_get_time() - s_last_rx_us > IDLE_TIMEOUT_US) {
      ESP_LOGI(TAG, "Host stream idle, releasing output (%" PRIu32 " dropped)",
               s_dropped);
      s_streaming = false;
      ringbuf_drain();
      audio_output_flush();
      playback_events_emit(PLAYBACK_SOURCE_USB, PLAYBACK_EVENT_DISCONNECTED,
                           NULL);
      if (s_state_cb != NULL) {
        s_state_cb(false);
      }
      continue;
    }

    // Short gap between USB packets — keep I2S fed rather than underrun.
    s_underruns++;
    audio_output_write(silence, sizeof(silence), pdMS_TO_TICKS(10));
  }
}

// ============================================================================
// Public API
// ============================================================================

esp_err_t usb_audio_sink_init(usb_audio_sink_state_cb_t state_cb) {
  if (s_task != NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  (void)settings_get_volume(&s_unmuted_db);

  s_state_cb = state_cb;
  s_last_rx_us = esp_timer_get_time();

  s_ringbuf = xRingbufferCreate(RINGBUF_SIZE, RINGBUF_TYPE_BYTEBUF);
  if (s_ringbuf == NULL) {
    ESP_LOGE(TAG, "Failed to allocate %u byte ring buffer",
             (unsigned)RINGBUF_SIZE);
    return ESP_ERR_NO_MEM;
  }

  if (xTaskCreatePinnedToCore(usb_sink_task, "usb_sink", SINK_TASK_STACK, NULL,
                              SINK_TASK_PRIO, &s_task,
                              SINK_TASK_CORE) != pdPASS) {
    ESP_LOGE(TAG, "Failed to create writer task");
    vRingbufferDelete(s_ringbuf);
    s_ringbuf = NULL;
    return ESP_ERR_NO_MEM;
  }

  uac_device_config_t cfg = {
      .skip_tinyusb_init = false,
      .output_cb = uac_output_cb,
      .input_cb = NULL,
      .set_mute_cb = uac_set_mute_cb,
      .set_volume_cb = uac_set_volume_cb,
      .cb_ctx = NULL,
#if CONFIG_USB_DEVICE_UAC_AS_PART
      // We own the descriptors, so the driver cannot infer this itself.
      .spk_itf_num = ITF_NUM_AUDIO_STREAMING_SPK,
      .mic_itf_num = 0,
#endif
  };

  esp_err_t err = uac_device_init(&cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "uac_device_init failed: %s", esp_err_to_name(err));
    vTaskDelete(s_task);
    s_task = NULL;
    vRingbufferDelete(s_ringbuf);
    s_ringbuf = NULL;
    return err;
  }

  ESP_LOGI(TAG, "USB audio sink ready (%d Hz stereo, %u ms buffer)",
           CONFIG_UAC_SAMPLE_RATE,
           (unsigned)(RINGBUF_SIZE / BYTES_PER_FRAME * 1000 /
                      CONFIG_OUTPUT_SAMPLE_RATE_HZ));
  return ESP_OK;
}

bool usb_audio_sink_is_streaming(void) {
  return s_streaming;
}
