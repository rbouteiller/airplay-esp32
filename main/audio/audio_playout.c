#include "audio_playout.h"
#include "sdkconfig.h"

#include <stddef.h>
#include <inttypes.h>
#include <string.h>

#include "driver/i2s_std.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"

#define TAG "audio_playout"

#define I2S_DMA_DESC_NUM  2U
#define I2S_DMA_FRAME_NUM AUDIO_PLAYOUT_FRAMES
#define I2S_RATE_HZ       44100U
#define TX_TAG_Q_CAP      8U
#define TX_DONE_Q_CAP     8U

typedef struct {
  uint32_t rtp;
  uint32_t generation;
  uint32_t frames;
} tx_tag_t;

static i2s_chan_handle_t s_tx;
static bool s_enabled;
static uint32_t s_nominal_mclk_hz;
static int32_t s_tune_ppm;

/* SPSC queues: playout task -> TX ISR for tags; TX ISR -> playout task for
 * completions. Capacity is intentionally larger than the two DMA descriptors
 * so the producer can publish the next tag before a blocking write wakes on
 * the previous descriptor's EOF. */
static tx_tag_t s_tag_q[TX_TAG_Q_CAP];
static uint32_t s_tag_head;
static uint32_t s_tag_tail;
static audio_playout_completion_t s_done_q[TX_DONE_Q_CAP];
static uint32_t s_done_head;
static uint32_t s_done_tail;

static uint64_t s_submitted_frames;
static uint64_t s_completed_frames;
static uint64_t s_tagged_completions;
static uint64_t s_untagged_completions;
static uint64_t s_completion_overflows;
static uint64_t s_write_calls;
static uint64_t s_write_total_us;
static uint32_t s_write_last_us;
static uint32_t s_write_max_us;

static inline void queues_reset(void) {
  __atomic_store_n(&s_tag_head, 0U, __ATOMIC_RELEASE);
  __atomic_store_n(&s_tag_tail, 0U, __ATOMIC_RELEASE);
  __atomic_store_n(&s_done_head, 0U, __ATOMIC_RELEASE);
  __atomic_store_n(&s_done_tail, 0U, __ATOMIC_RELEASE);
}

static bool tag_push(uint32_t rtp, uint32_t generation, uint32_t frames) {
  const uint32_t head = __atomic_load_n(&s_tag_head, __ATOMIC_RELAXED);
  const uint32_t tail = __atomic_load_n(&s_tag_tail, __ATOMIC_ACQUIRE);
  const uint32_t next = (head + 1U) % TX_TAG_Q_CAP;
  if (next == tail) {
    return false;
  }
  s_tag_q[head].rtp = rtp;
  s_tag_q[head].generation = generation;
  s_tag_q[head].frames = frames;
  __atomic_store_n(&s_tag_head, next, __ATOMIC_RELEASE);
  return true;
}

static bool IRAM_ATTR tag_pop_isr(tx_tag_t *out) {
  const uint32_t tail = __atomic_load_n(&s_tag_tail, __ATOMIC_RELAXED);
  const uint32_t head = __atomic_load_n(&s_tag_head, __ATOMIC_ACQUIRE);
  if (tail == head) {
    return false;
  }
  *out = s_tag_q[tail];
  __atomic_store_n(&s_tag_tail, (tail + 1U) % TX_TAG_Q_CAP,
                   __ATOMIC_RELEASE);
  return true;
}

static bool IRAM_ATTR done_push_isr(const tx_tag_t *tag, int64_t local_us) {
  const uint32_t head = __atomic_load_n(&s_done_head, __ATOMIC_RELAXED);
  const uint32_t tail = __atomic_load_n(&s_done_tail, __ATOMIC_ACQUIRE);
  const uint32_t next = (head + 1U) % TX_DONE_Q_CAP;
  if (next == tail) {
    return false;
  }
  s_done_q[head].rtp = tag->rtp;
  s_done_q[head].generation = tag->generation;
  s_done_q[head].frames = tag->frames;
  s_done_q[head].done_local_us = local_us;
  __atomic_store_n(&s_done_head, next, __ATOMIC_RELEASE);
  return true;
}

static bool IRAM_ATTR on_sent(i2s_chan_handle_t handle,
                              i2s_event_data_t *event,
                              void *user_ctx) {
  (void)handle;
  (void)event;
  (void)user_ctx;

  tx_tag_t tag;
  if (!tag_pop_isr(&tag)) {
    __atomic_add_fetch(&s_untagged_completions, 1ULL, __ATOMIC_RELAXED);
    return false;
  }

  /* esp_timer_get_time() is lock-free and documented for ISR use. Timestamp
   * the DMA EOF itself; conversion to PTP is done later in task context. */
  const int64_t done_local_us = esp_timer_get_time();
  __atomic_add_fetch(&s_completed_frames, tag.frames, __ATOMIC_RELAXED);
  __atomic_add_fetch(&s_tagged_completions, 1ULL, __ATOMIC_RELAXED);
  if (!done_push_isr(&tag, done_local_us)) {
    __atomic_add_fetch(&s_completion_overflows, 1ULL, __ATOMIC_RELAXED);
  }
  return false;
}

static void diag_reset(void) {
  __atomic_store_n(&s_submitted_frames, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_completed_frames, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_tagged_completions, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_untagged_completions, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_completion_overflows, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_write_calls, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_write_total_us, 0ULL, __ATOMIC_RELAXED);
  __atomic_store_n(&s_write_last_us, 0U, __ATOMIC_RELAXED);
  __atomic_store_n(&s_write_max_us, 0U, __ATOMIC_RELAXED);
}

esp_err_t audio_playout_init(void) {
  if (s_tx) {
    return ESP_OK;
  }

  i2s_chan_config_t chan_cfg =
      I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
  chan_cfg.dma_desc_num = I2S_DMA_DESC_NUM;
  chan_cfg.dma_frame_num = I2S_DMA_FRAME_NUM;
  chan_cfg.auto_clear = true;

  esp_err_t err = i2s_new_channel(&chan_cfg, &s_tx, NULL);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "i2s_new_channel failed: %s", esp_err_to_name(err));
    return err;
  }

  i2s_std_config_t cfg = {
      .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(I2S_RATE_HZ),
      .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT,
                                                      I2S_SLOT_MODE_STEREO),
      .gpio_cfg = {
          .mclk = CONFIG_I2S_SCK_IO,
          .bclk = CONFIG_I2S_BCK_IO,
          .ws = CONFIG_I2S_WS_IO,
          .dout = CONFIG_I2S_DO_IO,
          .din = I2S_GPIO_UNUSED,
      },
  };

  err = i2s_channel_init_std_mode(s_tx, &cfg);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "i2s_channel_init_std_mode failed: %s", esp_err_to_name(err));
    return err;
  }

  const i2s_event_callbacks_t callbacks = {
      .on_recv = NULL,
      .on_recv_q_ovf = NULL,
      .on_sent = on_sent,
      .on_send_q_ovf = NULL,
  };
  err = i2s_channel_register_event_callback(s_tx, &callbacks, NULL);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "i2s callback registration failed: %s", esp_err_to_name(err));
    return err;
  }

  queues_reset();
  diag_reset();
  s_enabled = false;
  s_tune_ppm = 0;

  /* The channel is READY here, which is the state required by
   * i2s_channel_tune_rate(). Capture the actual nominal MCLK so ppm
   * corrections are relative to the hardware clock chosen by IDF. */
  i2s_tuning_info_t initial_tune = {0};
  err = i2s_channel_tune_rate(s_tx, NULL, &initial_tune);
  if (err == ESP_OK) {
    s_nominal_mclk_hz = initial_tune.curr_mclk_hz;
  } else {
    s_nominal_mclk_hz = I2S_RATE_HZ * 256U;
    ESP_LOGW(TAG, "initial tune query failed: %s; assuming MCLK=%" PRIu32,
             esp_err_to_name(err), s_nominal_mclk_hz);
  }

  /* Keep the channel READY/disabled. V22 preloads both DMA descriptors before
   * the exact PTP start edge, then enables the channel. This removes the
   * zero-descriptor ambiguity that made earlier EOF counting unreliable. */
  ESP_LOGI(TAG,
           "I2S V22: 44100Hz stereo 16-bit, DMA=%ux%u, MCLK=%" PRIu32
           "Hz, pins %d/%d/%d/%d",
           (unsigned)I2S_DMA_DESC_NUM, (unsigned)I2S_DMA_FRAME_NUM,
           s_nominal_mclk_hz, CONFIG_I2S_SCK_IO, CONFIG_I2S_BCK_IO,
           CONFIG_I2S_WS_IO, CONFIG_I2S_DO_IO);
  return ESP_OK;
}

void audio_playout_flush(void) {
  if (!s_tx) {
    return;
  }
  if (s_enabled) {
    (void)i2s_channel_disable(s_tx);
    s_enabled = false;
  }
  queues_reset();
  diag_reset();
}

esp_err_t audio_playout_preload_tagged(const int16_t *stereo, uint32_t frames,
                                       uint32_t rtp, uint32_t generation) {
  if (!s_tx || !stereo || frames == 0U || s_enabled) {
    return ESP_ERR_INVALID_STATE;
  }
  size_t loaded = 0;
  const size_t bytes = (size_t)frames * 2U * sizeof(int16_t);
  esp_err_t err = i2s_channel_preload_data(s_tx, stereo, bytes, &loaded);
  if (err != ESP_OK || loaded != bytes) {
    return err == ESP_OK ? ESP_ERR_NO_MEM : err;
  }
  if (!tag_push(rtp, generation, frames)) {
    return ESP_ERR_NO_MEM;
  }
  __atomic_add_fetch(&s_submitted_frames, frames, __ATOMIC_RELAXED);
  return ESP_OK;
}

esp_err_t audio_playout_enable(void) {
  if (!s_tx) {
    return ESP_ERR_INVALID_STATE;
  }
  if (s_enabled) {
    return ESP_OK;
  }
  esp_err_t err = i2s_channel_enable(s_tx);
  if (err == ESP_OK) {
    s_enabled = true;
  }
  return err;
}

esp_err_t audio_playout_write_tagged(const int16_t *stereo, uint32_t frames,
                                     uint32_t rtp, uint32_t generation) {
  if (!s_tx || !s_enabled || !stereo || frames == 0U) {
    return ESP_ERR_INVALID_STATE;
  }

  /* Publish the tag before entering the blocking write. With two descriptors
   * there are already outstanding tagged blocks while running, so an EOF that
   * wakes this write always consumes the oldest earlier tag, never this one. */
  if (!tag_push(rtp, generation, frames)) {
    return ESP_ERR_NO_MEM;
  }

  size_t written = 0;
  const size_t bytes = (size_t)frames * 2U * sizeof(int16_t);
  const int64_t t0 = esp_timer_get_time();
  esp_err_t err = i2s_channel_write(s_tx, stereo, bytes, &written,
                                    portMAX_DELAY);
  const uint32_t elapsed_us = (uint32_t)(esp_timer_get_time() - t0);
  __atomic_store_n(&s_write_last_us, elapsed_us, __ATOMIC_RELAXED);
  __atomic_add_fetch(&s_write_calls, 1ULL, __ATOMIC_RELAXED);
  __atomic_add_fetch(&s_write_total_us, elapsed_us, __ATOMIC_RELAXED);
  uint32_t old_max = __atomic_load_n(&s_write_max_us, __ATOMIC_RELAXED);
  while (elapsed_us > old_max &&
         !__atomic_compare_exchange_n(&s_write_max_us, &old_max, elapsed_us,
                                      false, __ATOMIC_RELAXED,
                                      __ATOMIC_RELAXED)) {
  }

  if (err == ESP_OK && written == bytes) {
    __atomic_add_fetch(&s_submitted_frames, frames, __ATOMIC_RELAXED);
    return ESP_OK;
  }

  /* A failed write invalidates the FIFO relationship between application tags
   * and DMA descriptors. Caller will flush/re-prime the channel. */
  return err == ESP_OK ? ESP_FAIL : err;
}

bool audio_playout_poll_completion(audio_playout_completion_t *out) {
  if (!out) {
    return false;
  }
  const uint32_t tail = __atomic_load_n(&s_done_tail, __ATOMIC_RELAXED);
  const uint32_t head = __atomic_load_n(&s_done_head, __ATOMIC_ACQUIRE);
  if (tail == head) {
    return false;
  }
  *out = s_done_q[tail];
  __atomic_store_n(&s_done_tail, (tail + 1U) % TX_DONE_Q_CAP,
                   __ATOMIC_RELEASE);
  return true;
}

bool audio_playout_is_enabled(void) {
  return s_enabled;
}

void audio_playout_get_diag(audio_playout_diag_t *out) {
  if (!out) {
    return;
  }
  out->submitted_frames = __atomic_load_n(&s_submitted_frames, __ATOMIC_RELAXED);
  out->completed_frames = __atomic_load_n(&s_completed_frames, __ATOMIC_RELAXED);
  out->tagged_completions = __atomic_load_n(&s_tagged_completions, __ATOMIC_RELAXED);
  out->untagged_completions = __atomic_load_n(&s_untagged_completions, __ATOMIC_RELAXED);
  out->completion_overflows = __atomic_load_n(&s_completion_overflows, __ATOMIC_RELAXED);
  out->write_calls = __atomic_load_n(&s_write_calls, __ATOMIC_RELAXED);
  out->write_total_us = __atomic_load_n(&s_write_total_us, __ATOMIC_RELAXED);
  out->write_last_us = __atomic_load_n(&s_write_last_us, __ATOMIC_RELAXED);
  out->write_max_us = __atomic_load_n(&s_write_max_us, __ATOMIC_RELAXED);
}

int32_t audio_playout_get_tune_ppm(void) {
  return s_tune_ppm;
}

uint32_t audio_playout_get_nominal_mclk_hz(void) {
  return s_nominal_mclk_hz;
}

esp_err_t audio_playout_tune_ppm(int32_t target_ppm,
                                 audio_playout_tune_info_t *out) {
  if (!s_tx || !s_enabled || s_nominal_mclk_hz == 0U) {
    return ESP_ERR_INVALID_STATE;
  }
  if (target_ppm > 160) target_ppm = 160;
  if (target_ppm < -160) target_ppm = -160;
  if (target_ppm == s_tune_ppm) {
    if (out) {
      out->requested_ppm = s_tune_ppm;
      out->curr_mclk_hz = (uint32_t)((int64_t)s_nominal_mclk_hz +
          ((int64_t)s_nominal_mclk_hz * s_tune_ppm) / 1000000LL);
      out->actual_delta_mclk_hz = (int32_t)out->curr_mclk_hz -
                                   (int32_t)s_nominal_mclk_hz;
    }
    return ESP_OK;
  }

  /* ADDSUB is relative to the CURRENT clock, so apply only the requested
   * ppm step. The max/min bounds remain relative to the initial MCLK. */
  const int32_t step_ppm = target_ppm - s_tune_ppm;
  const int32_t step_delta_hz = (int32_t)(
      ((int64_t)s_nominal_mclk_hz * step_ppm) / 1000000LL);
  const int32_t limit_hz = (int32_t)(
      ((int64_t)s_nominal_mclk_hz * 160LL) / 1000000LL) + 4;
  i2s_tuning_config_t cfg = {
      .tune_mode = I2S_TUNING_MODE_ADDSUB,
      .tune_mclk_val = step_delta_hz,
      .max_delta_mclk = limit_hz,
      .min_delta_mclk = -limit_hz,
  };
  i2s_tuning_info_t info = {0};

  /* IDF 5.5 requires READY for rate tuning. This is intentionally executed
   * only between application writes on the playout task. Espressif's own
   * dynamic-tuning example uses this same disable/tune/enable sequence. */
  esp_err_t err = i2s_channel_disable(s_tx);
  if (err != ESP_OK) return err;
  s_enabled = false;
  err = i2s_channel_tune_rate(s_tx, &cfg, &info);
  if (err == ESP_OK) {
    s_tune_ppm = target_ppm;
  }
  esp_err_t en_err = i2s_channel_enable(s_tx);
  if (en_err == ESP_OK) s_enabled = true;
  if (err == ESP_OK && en_err != ESP_OK) err = en_err;

  if (out) {
    out->requested_ppm = s_tune_ppm;
    out->curr_mclk_hz = info.curr_mclk_hz;
    out->actual_delta_mclk_hz = info.delta_mclk_hz;
  }
  return err;
}

uint32_t audio_playout_hardware_latency_us(void) {
  return (uint32_t)(((uint64_t)I2S_DMA_DESC_NUM * I2S_DMA_FRAME_NUM *
                     1000000ULL) / I2S_RATE_HZ);
}
