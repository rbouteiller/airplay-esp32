/**
 * USB Audio Class (UAC) output — ESP32 as a USB audio source
 *
 * The ESP32 enumerates as a USB microphone (audio input device) on the
 * connected host.  Decoded AirPlay audio is fed to the host via the UAC
 * input callback.  This allows direct connection to USB-input amplifiers
 * or recording on a PC with software like Audacity.
 *
 * Uses the espressif/usb_device_uac managed component which handles all
 * USB descriptor, endpoint, and class-level protocol details.
 */

#include "audio_output.h"

#include "audio_receiver.h"
#include "audio_resample.h"
#include "led.h"
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/task.h"
#include "rtsp_server.h"
#include "usb_device_uac.h"
#include <stdlib.h>
#include <string.h>

#define TAG           "audio_usb"
#define OUTPUT_RATE   CONFIG_OUTPUT_SAMPLE_RATE_HZ
#define FRAME_SAMPLES 352

#if CONFIG_OUTPUT_SAMPLE_RATE_HZ != CONFIG_UAC_SAMPLE_RATE
#error \
    "USB audio output requires CONFIG_OUTPUT_SAMPLE_RATE_HZ to match CONFIG_UAC_SAMPLE_RATE"
#endif

/* Max output frames after resampling one input frame */
#define MAX_RESAMPLE_FRAMES \
  ((size_t)((FRAME_SAMPLES + 2) * ((double)OUTPUT_RATE / 44100) + 16))

#if CONFIG_FREERTOS_UNICORE
#define PLAYBACK_CORE 0
#else
#define PLAYBACK_CORE 1
#endif

/* Ring buffer bridging the playback task (producer) and the USB input
 * callback (consumer).  Sized for ~50 ms of stereo 16-bit audio.       */
#define USB_RINGBUF_BYTES \
  ((size_t)(OUTPUT_RATE) / 10 * 4) /* ~100 ms stereo 16-bit */

static RingbufHandle_t s_ringbuf;
static volatile bool flush_requested = false;
static volatile int source_rate = 44100;
static volatile bool resample_reinit_needed = false;

/* ── USB UAC input callback (pull model) ──────────────────────────────
 * Called by the UAC stack when the host requests audio data.
 * We fill buf from the ring buffer; on underrun we send silence.       */

static esp_err_t usb_input_cb(uint8_t *buf, size_t len, size_t *bytes_read,
                              void *cb_ctx) {
  size_t item_size = 0;
  void *data = xRingbufferReceiveUpTo(s_ringbuf, &item_size, 0, len);
  if (data && item_size > 0) {
    memcpy(buf, data, item_size);
    vRingbufferReturnItem(s_ringbuf, data);
    *bytes_read = item_size;
  } else {
    memset(buf, 0, len);
    *bytes_read = len;
  }
  return ESP_OK;
}

/* ── Volume ────────────────────────────────────────────────────────── */

static void apply_volume(int16_t *buf, size_t n) {
#ifndef CONFIG_DAC_CONTROLS_VOLUME
  int32_t vol = airplay_get_volume_q15();
  for (size_t i = 0; i < n; i++) {
    buf[i] = (int16_t)(((int32_t)buf[i] * vol) >> 15);
  }
#endif
}

/* ── Playback task ─────────────────────────────────────────────────── */

static void playback_task(void *arg) {
  int16_t *pcm = malloc((size_t)(FRAME_SAMPLES + 1) * 2 * sizeof(int16_t));
  int16_t *silence = calloc((size_t)FRAME_SAMPLES * 2, sizeof(int16_t));
  int16_t *resample_buf = malloc(MAX_RESAMPLE_FRAMES * 2 * sizeof(int16_t));
  if (!pcm || !silence || !resample_buf) {
    ESP_LOGE(TAG, "Failed to allocate buffers");
    free(pcm);
    free(silence);
    free(resample_buf);
    vTaskDelete(NULL);
    return;
  }

  while (true) {
    if (resample_reinit_needed) {
      resample_reinit_needed = false;
      audio_resample_init((uint32_t)source_rate, OUTPUT_RATE, 2);
    }
    if (flush_requested) {
      flush_requested = false;
      audio_resample_reset();
      /* Drain the ring buffer */
      size_t item_size;
      void *item;
      while ((item = xRingbufferReceive(s_ringbuf, &item_size, 0)) != NULL) {
        vRingbufferReturnItem(s_ringbuf, item);
      }
    }

    size_t samples = audio_receiver_read(pcm, FRAME_SAMPLES + 1);
    if (samples > 0) {
      int16_t *play_buf = pcm;
      size_t play_samples = samples;
      if (audio_resample_is_active()) {
        play_samples = audio_resample_process(pcm, samples, resample_buf,
                                              MAX_RESAMPLE_FRAMES);
        play_buf = resample_buf;
      }
      apply_volume(play_buf, play_samples * 2);
      led_audio_feed(play_buf, play_samples);

      size_t bytes = play_samples * 4; /* stereo 16-bit */
      xRingbufferSend(s_ringbuf, play_buf, bytes, portMAX_DELAY);
      taskYIELD();
    } else {
      led_audio_feed(silence, FRAME_SAMPLES);
      /* Feed silence to keep the USB stream flowing */
      xRingbufferSend(s_ringbuf, silence, (size_t)FRAME_SAMPLES * 4,
                      pdMS_TO_TICKS(10));
      vTaskDelay(1);
    }
  }
}

/* ── Public API ────────────────────────────────────────────────────── */

esp_err_t audio_output_init(void) {
  ESP_LOGI(TAG, "Initialising USB UAC audio output (rate=%d)", OUTPUT_RATE);

  s_ringbuf = xRingbufferCreate(USB_RINGBUF_BYTES, RINGBUF_TYPE_BYTEBUF);
  if (!s_ringbuf) {
    ESP_LOGE(TAG, "Failed to create ring buffer");
    return ESP_ERR_NO_MEM;
  }

  uac_device_config_t uac_cfg = {
      .skip_tinyusb_init = false,
      .output_cb = NULL,        /* not a speaker — no host-to-device audio */
      .input_cb = usb_input_cb, /* device-to-host: AirPlay audio out */
      .set_mute_cb = NULL,
      .set_volume_cb = NULL,
      .cb_ctx = NULL,
  };

  esp_err_t err = uac_device_init(&uac_cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "UAC device init failed: %s", esp_err_to_name(err));
    vRingbufferDelete(s_ringbuf);
    s_ringbuf = NULL;
    return err;
  }

  audio_resample_init(44100, OUTPUT_RATE, 2);
  ESP_LOGI(TAG, "USB UAC output ready");
  return ESP_OK;
}

void audio_output_start(void) {
  xTaskCreatePinnedToCore(playback_task, "usb_play", 4096, NULL, 7, NULL,
                          PLAYBACK_CORE);
}

void audio_output_flush(void) {
  flush_requested = true;
}

void audio_output_set_source_rate(int rate) {
  if (rate > 0 && rate != source_rate) {
    source_rate = rate;
    resample_reinit_needed = true;
  }
}
