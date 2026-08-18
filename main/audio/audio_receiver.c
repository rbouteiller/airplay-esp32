#include "audio_receiver.h"

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "aac_decoder.h"
#include "audio_crypto.h"
#include "aac_rtp_ring.h"
#include "pcm_rtp_ring.h"
#include "audio_playout.h"
#include "esp_heap_caps.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "network/ptp_clock.h"
#include "network/socket_utils.h"

#define AP2_PACKET_MAX             8192U
#define AP2_RX_STACK               6144U
#define AP2_DECODE_STACK           7168U
#define AP2_STATS_STACK            4096U
#define AP2_PLAYOUT_STACK          4096U
#define AP2_NETWORK_CORE           0
#define AP2_DECODE_CORE            1
#define AP2_RX_PRIORITY            7
#define AP2_DECODE_PRIORITY        6
#define AP2_PLAYOUT_PRIORITY       8
#define AP2_STATS_PRIORITY         2
#define AP2_PCM_CAPACITY_FRAMES    4096U
#define AP2_STATS_PERIOD_MS        2000U
#define AP2_FIRST_DECODE_LOGS      3U

#define AP2_PID_CALC_PERIOD_US    1000000LL  /* PID math at 1 Hz */
#define AP2_PID_TUNE_PERIOD_US    5000000LL  /* physical I2S retune <= 0.2 Hz */
#define AP2_PID_DEADBAND_US          1000    /* +/-1 ms is already good */
#define AP2_PID_SOFTBAND_US          2000    /* 1..2 ms => gentler P action */
#define AP2_PID_MAX_PPM               160
#define AP2_PID_MIN_TUNE_PPM            5
#define AP2_PID_MAX_JUMP_PPM            80

/* V22 continuous-start alignment.  A new generation enables I2S only once.
 * Two silent DMA blocks establish the actual running sample-clock phase.  The
 * first tagged EOF gives a precise PTP observation; while the second silent
 * block is still playing, the first real block is queued from the RTP sample
 * that belongs at the next physical DMA boundary.  I2S is never disabled
 * between phase measurement and real audio, removing V21's non-repeatable
 * second-enable latency. */
#define AP2_START_SILENCE_FUTURE_BLOCKS    4U
#define AP2_START_ALIGN_TIMEOUT_US      30000LL
#define AP2_START_PRIME_GUARD_BLOCKS        8U

/* V22 true PID around tagged DMA-EOF phase.
 * P reacts to phase error, I learns the steady crystal/rate bias, D damps
 * motion through zero.  The derivative is low-pass filtered because the PTP
 * timestamp itself has some jitter.  PID is evaluated more often than the
 * physical tune operation so control knowledge can evolve without repeatedly
 * disable/tune/enable cycling I2S. */
#define AP2_PID_KP_PPM_PER_MS          22.0
#define AP2_PID_KI_PPM_PER_MS_S         0.55
#define AP2_PID_KD_PPM_PER_MS_PER_S    55.0
#define AP2_PID_D_ALPHA                  0.20
#define AP2_PID_I_TERM_LIMIT_PPM       110.0
#define AP2_PCM_TARGET_MS           4000U
#define AP2_PLAYOUT_PRIME_MS         250U
#define AP2_TIMELINE_PAST_MS          1000U
#define AP2_TIMELINE_FUTURE_MS       45000U
#define AP2_DECODE_IDLE_TICKS       1U

static const char *TAG = "audio_v22";

/* Updated by RTSP control on Core0, consumed by playout on Core1. */
static volatile int32_t s_volume_target_q15 = 32768;
/* Number of output-volume target updates since the last compact STAT line.
 * Kept atomic so RTSP/Core0 never needs to log or lock on the control path. */
static volatile uint32_t s_volume_cmd_count = 0;

typedef struct {
  bool anchor_valid;
  bool playing;
  uint64_t anchor_ptp_ns;
  uint32_t anchor_rtp;
  uint32_t generation;
  audio_format_t format;
  uint32_t format_generation;
  bool deferred_flush_valid;
  uint32_t deferred_flush_rtp;
  bool timeline_reset_pending;
} timing_snapshot_t;

typedef struct {
  uint64_t rx;
  uint64_t decoded;
  uint64_t stale_predecrypt;
  uint64_t stale_predecode;
  uint64_t timeline_drop;
  uint64_t aac_store_drop;
  uint64_t pcm_write_error;
  uint64_t decrypt_error;
  uint64_t decode_error;
  uint64_t empty_payload;
  uint64_t generation_drop;
  uint64_t seq_gap;
  uint64_t rtp_gap;
  uint32_t last_seq;
  uint32_t last_rtp;
  uint32_t last_rtp_generation;
  uint32_t last_decoded_end_rtp;
  uint64_t playout_blocks;
  uint64_t playout_underruns;
  uint64_t playout_resyncs;
  uint64_t playout_flushes;
  uint64_t playout_prime_waits;
  uint64_t playout_starts;
  uint32_t playout_state; /* 0=STOPPED, 1=PRIMING, 2=RUNNING */
  uint32_t last_playout_rtp;
  int32_t tx_start_err_us;
  int32_t tx_end_err_us;
  int32_t tx_end_err_ema_us;
  uint32_t tx_fetch_us;
  /* V18 scheduler phase probe. Positive means the block RTP cursor is ahead
   * of the RTP wanted by PTP at that observation point. */
  int32_t sched_err_frames;
  int32_t write_start_err_frames;
  int32_t write_end_err_frames;
  int32_t desired_cursor_err_frames;
  /* V22: tagged TX DMA EOF phase. + means physical DMA completion was early
   * versus the AirPlay PTP target, - means late. */
  int32_t output_sync_frames;
  int32_t output_sync_us;      /* EMA used by compact log */
  int32_t output_sync_raw_us;  /* most recent tagged completion */
  uint32_t output_sync_generation;
  bool output_sync_valid;
  uint64_t dma_tagged_completions;
  uint32_t dma_pipeline_blocks;
  uint32_t pcm_peak_in;
  uint32_t pcm_peak_out;
  uint64_t pcm_rail_in;
  uint64_t pcm_clip_out;
  int32_t volume_q15;
  int32_t servo_ppm;
  int32_t servo_target_ppm;
  int32_t servo_slope_us_per_s;
  uint32_t servo_mclk_hz;
  uint64_t servo_updates;
  uint64_t servo_errors;
} diag_stats_t;

typedef struct {
  audio_format_t format;
  audio_encrypt_t encrypt;
  audio_stats_t public_stats;
  audio_stream_type_t stream_type;

  int listen_sock;
  int client_sock;
  uint16_t port;
  volatile bool engine_running;
  volatile bool rx_running;

  TaskHandle_t rx_task;
  TaskHandle_t decode_task;
  TaskHandle_t playout_task;
  TaskHandle_t stats_task;
  uint8_t *packet;
  uint8_t *decrypt_buf;
  uint8_t *decode_aac;
  int16_t *decode_pcm;
  aac_rtp_ring_t *aac_ring;
  pcm_rtp_ring_t *pcm_ring;

  portMUX_TYPE state_mux;
  bool playing;
  bool anchor_valid;
  uint64_t anchor_clock_id;
  uint64_t anchor_ptp_ns;
  uint32_t anchor_rtp;
  uint32_t generation;
  uint32_t format_generation;
  bool deferred_flush_valid;
  uint32_t deferred_flush_rtp;
  bool timeline_reset_pending;
  volatile bool i2s_flush_requested;

  diag_stats_t diag;
} ap2_state_t;

static ap2_state_t s = {
    .listen_sock = -1,
    .client_sock = -1,
    .stream_type = AUDIO_STREAM_NONE,
    .generation = 1,
    .format_generation = 1,
    .timeline_reset_pending = true,
    .state_mux = portMUX_INITIALIZER_UNLOCKED,
};

static void snapshot_state(timing_snapshot_t *out) {
  taskENTER_CRITICAL(&s.state_mux);
  out->anchor_valid = s.anchor_valid;
  out->playing = s.playing;
  out->anchor_ptp_ns = s.anchor_ptp_ns;
  out->anchor_rtp = s.anchor_rtp;
  out->generation = s.generation;
  out->format = s.format;
  out->format_generation = s.format_generation;
  out->deferred_flush_valid = s.deferred_flush_valid;
  out->deferred_flush_rtp = s.deferred_flush_rtp;
  out->timeline_reset_pending = s.timeline_reset_pending;
  taskEXIT_CRITICAL(&s.state_mux);
}

static uint32_t next_generation(uint32_t generation) {
  generation++;
  return generation ? generation : 1U;
}

/* Immediate FLUSH/pause ends the current timeline now, but V8 deliberately
 * does not publish a new generation yet. TCP may keep arriving while the
 * anchor is invalid; those packets are provisional and will be made
 * unreachable atomically when the next valid anchor commits a new epoch. */
static void mark_timeline_discontinuity(void) {
  taskENTER_CRITICAL(&s.state_mux);
  s.anchor_valid = false;
  s.deferred_flush_valid = false;
  s.timeline_reset_pending = true;
  taskEXIT_CRITICAL(&s.state_mux);
  s.diag.last_decoded_end_rtp = 0;
  s.i2s_flush_requested = true;
}

static uint32_t commit_anchor_epoch_locked(void) {
  uint32_t gen = s.generation;
  if (s.timeline_reset_pending) {
    gen = next_generation(gen);
    /* Publish the backing stores first. Any task holding the previous state
     * snapshot can only fail a generation check during this tiny window. */
    if (s.aac_ring) {
      aac_rtp_ring_set_generation(s.aac_ring, gen);
    }
    if (s.pcm_ring) {
      pcm_rtp_ring_set_generation(s.pcm_ring, gen);
    }
    s.generation = gen;
    s.timeline_reset_pending = false;
    s.deferred_flush_valid = false;
    s.diag.last_decoded_end_rtp = 0;
  }
  return gen;
}

static inline int32_t rtp_delta(uint32_t a, uint32_t b) {
  return (int32_t)(a - b);
}

static bool wanted_rtp_now(const timing_snapshot_t *snap, uint32_t *out) {
  if (!snap || !out || !snap->playing || !snap->anchor_valid ||
      snap->timeline_reset_pending || !ptp_clock_is_locked()) {
    return false;
  }
  int sr = snap->format.sample_rate > 0 ? snap->format.sample_rate : 44100;
  int64_t now_ns = (int64_t)ptp_clock_get_time_ns();
  int64_t dt_ns = now_ns - (int64_t)snap->anchor_ptp_ns;
  int64_t ds = (dt_ns * (int64_t)sr) / 1000000000LL;
  *out = snap->anchor_rtp + (uint32_t)ds;
  return true;
}

static bool wanted_rtp_at_ptp(const timing_snapshot_t *snap, uint64_t ptp_ns,
                               uint32_t *out) {
  if (!snap || !out || !snap->playing || !snap->anchor_valid ||
      snap->timeline_reset_pending || !ptp_clock_is_locked()) {
    return false;
  }
  int sr = snap->format.sample_rate > 0 ? snap->format.sample_rate : 44100;
  int64_t dt_ns = (int64_t)ptp_ns - (int64_t)snap->anchor_ptp_ns;
  int64_t ds = (dt_ns * (int64_t)sr) / 1000000000LL;
  *out = snap->anchor_rtp + (uint32_t)ds;
  return true;
}

static bool rtp_to_ptp_ns(const timing_snapshot_t *snap, uint32_t rtp,
                           uint64_t *out_ptp_ns) {
  if (!snap || !out_ptp_ns || !snap->anchor_valid ||
      snap->timeline_reset_pending) {
    return false;
  }
  const int sr = snap->format.sample_rate > 0 ? snap->format.sample_rate : 44100;
  const int32_t ds = rtp_delta(rtp, snap->anchor_rtp);
  const int64_t dt_ns = ((int64_t)ds * 1000000000LL) / (int64_t)sr;
  const int64_t ptp = (int64_t)snap->anchor_ptp_ns + dt_ns;
  if (ptp < 0) {
    return false;
  }
  *out_ptp_ns = (uint64_t)ptp;
  return true;
}

/* V22: pace DMA submission from the AirPlay PTP/RTP timeline instead of
 * letting an empty DMA ring decide how far the software cursor runs ahead.
 * Long waits yield to FreeRTOS; only the final sub-millisecond interval uses
 * short ROM delays. */
static void wait_until_ptp_ns(uint64_t target_ptp_ns) {
  while (s.engine_running) {
    const uint64_t now = ptp_clock_get_time_ns();
    if (now >= target_ptp_ns) {
      return;
    }
    const uint64_t remain_us = (target_ptp_ns - now) / 1000ULL;
    if (remain_us > 2000ULL) {
      vTaskDelay(1);
    } else if (remain_us > 250ULL) {
      esp_rom_delay_us(100);
    } else if (remain_us > 40ULL) {
      esp_rom_delay_us(20);
    } else {
      esp_rom_delay_us(2);
    }
  }
}

/* RTP admission filter for the currently committed timeline. */
static bool rtp_in_admission_window(uint32_t rtp,
                                    const timing_snapshot_t *snap,
                                    int32_t *delta_samples_out) {
  uint32_t wanted = 0;
  if (!wanted_rtp_now(snap, &wanted)) {
    if (delta_samples_out) {
      *delta_samples_out = 0;
    }
    return true;
  }

  const int sr = snap->format.sample_rate > 0 ? snap->format.sample_rate : 44100;
  const int32_t past_limit =
      -(int32_t)(((int64_t)sr * AP2_TIMELINE_PAST_MS) / 1000LL);
  const int32_t future_limit =
      (int32_t)(((int64_t)sr * AP2_TIMELINE_FUTURE_MS) / 1000LL);
  const int32_t delta = rtp_delta(rtp, wanted);

  if (delta_samples_out) {
    *delta_samples_out = delta;
  }
  return delta >= past_limit && delta <= future_limit;
}

static bool frame_is_fully_stale(uint32_t rtp, const timing_snapshot_t *snap,
                                 int64_t *end_delta_us) {
  uint32_t wanted;
  if (!wanted_rtp_now(snap, &wanted)) {
    return false;
  }
  uint32_t frame_samples = snap->format.frame_size > 0
                               ? (uint32_t)snap->format.frame_size
                               : 1024U;
  uint32_t end_rtp = rtp + frame_samples;
  int32_t remaining = rtp_delta(end_rtp, wanted);
  if (end_delta_us) {
    int sr = snap->format.sample_rate > 0 ? snap->format.sample_rate : 44100;
    *end_delta_us = ((int64_t)remaining * 1000000LL) / sr;
  }
  return remaining <= 0;
}

static ssize_t read_exact(int sock, uint8_t *buf, size_t len) {
  size_t total = 0;
  while (total < len && s.rx_running) {
    ssize_t n = recv(sock, buf + total, len - total, 0);
    if (n > 0) {
      total += (size_t)n;
      continue;
    }
    if (n == 0) {
      return 0;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      continue;
    }
    return -1;
  }
  return s.rx_running ? (ssize_t)total : -1;
}

static void update_continuity(uint32_t seq, uint32_t rtp,
                              const timing_snapshot_t *snap,
                              uint32_t *last_generation, bool *have_previous) {
  if (*last_generation != snap->generation) {
    *last_generation = snap->generation;
    *have_previous = false;
  }

  if (*have_previous) {
    uint32_t expected_seq = (s.diag.last_seq + 1U) & 0x00ffffffU;
    if ((seq & 0x00ffffffU) != expected_seq) {
      s.diag.seq_gap++;
    }
    uint32_t step = snap->format.frame_size > 0
                        ? (uint32_t)snap->format.frame_size
                        : 1024U;
    if ((uint32_t)(rtp - s.diag.last_rtp) != step) {
      s.diag.rtp_gap++;
    }
  }
  s.diag.last_seq = seq & 0x00ffffffU;
  s.diag.last_rtp = rtp;
  s.diag.last_rtp_generation = snap->generation;
  *have_previous = true;
}

static void ap2_rx_task(void *arg) {
  (void)arg;
  uint32_t last_generation = 0;
  bool have_previous = false;

  ESP_LOGI(TAG, "RX task started on core %d", xPortGetCoreID());
  while (s.rx_running) {
    struct sockaddr_in client_addr = {0};
    socklen_t alen = sizeof(client_addr);
    int c = accept(s.listen_sock, (struct sockaddr *)&client_addr, &alen);
    if (c < 0) {
      if (s.rx_running && errno != EAGAIN && errno != EWOULDBLOCK) {
        ESP_LOGW(TAG, "accept errno=%d", errno);
      }
      vTaskDelay(pdMS_TO_TICKS(20));
      continue;
    }

    s.client_sock = c;
    struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ESP_LOGI(TAG, "AirPlay 2 buffered TCP connected (core=%d)", xPortGetCoreID());

    while (s.rx_running) {
      uint8_t lb[2];
      if (read_exact(c, lb, sizeof(lb)) != 2) {
        break;
      }
      uint16_t data_len = (uint16_t)(((uint16_t)lb[0] << 8) | lb[1]);
      if (data_len < 2 || data_len > AP2_PACKET_MAX) {
        ESP_LOGW(TAG, "invalid framed length=%u", (unsigned)data_len);
        break;
      }
      size_t packet_len = (size_t)data_len - 2U;
      if (read_exact(c, s.packet, packet_len) != (ssize_t)packet_len) {
        break;
      }
      if (packet_len < 8U) {
        continue;
      }

      uint32_t seq = ((uint32_t)s.packet[1] << 16) |
                     ((uint32_t)s.packet[2] << 8) | s.packet[3];
      uint32_t rtp = ((uint32_t)s.packet[4] << 24) |
                     ((uint32_t)s.packet[5] << 16) |
                     ((uint32_t)s.packet[6] << 8) | s.packet[7];

      timing_snapshot_t snap;
      snapshot_state(&snap);
      s.diag.rx++;
      s.public_stats.packets_received++;
      s.public_stats.last_seq = (uint16_t)(seq & 0xffffU);
      s.public_stats.last_timestamp = rtp;

      /* A packet far outside the current PTP/RTP timeline is a transition
       * leftover, not useful AAC for this committed generation. */
      if (!rtp_in_admission_window(rtp, &snap, NULL)) {
        s.diag.timeline_drop++;
        s.public_stats.packets_dropped++;
        continue;
      }

      update_continuity(seq, rtp, &snap, &last_generation, &have_previous);

      if (frame_is_fully_stale(rtp, &snap, NULL)) {
        s.diag.stale_predecrypt++;
        s.public_stats.late_frames++;
        s.public_stats.packets_dropped++;
        continue; // Important: old packet is discarded before decrypt/decode.
      }

      int dec_len = audio_crypto_decrypt_buffered(&s.encrypt, s.packet,
                                                   packet_len, s.decrypt_buf,
                                                   AP2_PACKET_MAX);
      if (dec_len < 0) {
        s.diag.decrypt_error++;
        s.public_stats.decrypt_errors++;
        continue;
      }
      if (dec_len == 0) {
        s.diag.empty_payload++;
        continue;
      }

      /* Decrypt itself takes time, so validate the timeline once more
       * before publishing the AU into the direct RTP ring. */
      snapshot_state(&snap);
      if (!rtp_in_admission_window(rtp, &snap, NULL)) {
        s.diag.timeline_drop++;
        s.public_stats.packets_dropped++;
        continue;
      }
      if (frame_is_fully_stale(rtp, &snap, NULL)) {
        s.diag.stale_predecode++;
        s.public_stats.late_frames++;
        s.public_stats.packets_dropped++;
        continue;
      }

      uint32_t wanted = 0;
      bool wanted_valid = wanted_rtp_now(&snap, &wanted);
      if (!aac_rtp_ring_store(s.aac_ring, seq, rtp, snap.generation,
                              snap.format_generation, s.decrypt_buf,
                              (size_t)dec_len, wanted, wanted_valid)) {
        /* Never block TCP. Capacity/oversize/slot conflicts are visible in
         * AAC-ring stats; only this incoming AU is discarded. */
        s.diag.aac_store_drop++;
        s.public_stats.buffer_overruns++;
        s.public_stats.packets_dropped++;
      }
    }

    close(c);
    s.client_sock = -1;
    ESP_LOGI(TAG, "AirPlay 2 buffered TCP disconnected");
  }

  s.rx_task = NULL;
  vTaskDelete(NULL);
}

static void ap2_decode_task(void *arg) {
  (void)arg;
  aac_decoder_t *decoder = NULL;
  uint32_t decoder_format_generation = 0;
  uint32_t first_logs = 0;
  uint32_t decode_generation = 0;
  uint32_t next_decode_rtp = 0;
  bool next_decode_valid = false;
  uint32_t decode_yield_counter = 0;

  ESP_LOGI(TAG, "AAC decode task started on core %d", xPortGetCoreID());
  while (s.engine_running) {
    timing_snapshot_t snap;
    snapshot_state(&snap);

    if (decode_generation != snap.generation) {
      decode_generation = snap.generation;
      next_decode_valid = false;
      decoder_format_generation = 0;
    }

    /* Compressed AAC may accumulate before the anchor. Decode only when a
     * real PTP/RTP playback cursor exists; this keeps PCM near the cursor. */
    uint32_t wanted = 0;
    if (!wanted_rtp_now(&snap, &wanted)) {
      vTaskDelay(AP2_DECODE_IDLE_TICKS);
      continue;
    }

    int sr = snap.format.sample_rate > 0 ? snap.format.sample_rate : 44100;
    uint32_t target_samples =
        (uint32_t)(((uint64_t)sr * AP2_PCM_TARGET_MS) / 1000ULL);
    if (s.diag.last_decoded_end_rtp != 0 &&
        rtp_delta(s.diag.last_decoded_end_rtp, wanted) >=
            (int32_t)target_samples) {
      vTaskDelay(AP2_DECODE_IDLE_TICKS);
      continue;
    }

    aac_rtp_item_t item = {0};
    bool got = false;
    if (!next_decode_valid) {
      got = aac_rtp_ring_take_at_or_after(
          s.aac_ring, wanted, snap.generation, s.decode_aac,
          AAC_RTP_SLOT_BYTES, &item);
    } else {
      /* If a missing AU has already passed the cursor, skip its RTP position
       * rather than waiting forever for data that can no longer be useful. */
      if (rtp_delta(next_decode_rtp + AAC_RTP_FRAME_SAMPLES, wanted) <= 0) {
        next_decode_rtp += AAC_RTP_FRAME_SAMPLES;
        s.diag.stale_predecode++;
        s.public_stats.late_frames++;
        if ((++decode_yield_counter & 0x07U) == 0U) {
          vTaskDelay(1);
        }
        continue;
      }
      got = aac_rtp_ring_take_exact(
          s.aac_ring, next_decode_rtp, snap.generation, s.decode_aac,
          AAC_RTP_SLOT_BYTES, &item);
    }

    if (!got) {
      vTaskDelay(AP2_DECODE_IDLE_TICKS);
      continue;
    }

    /* Slot is already FREE here. Core0 may reuse its storage while this task
     * decodes the private scratch copy. */
    next_decode_rtp = item.rtp + AAC_RTP_FRAME_SAMPLES;
    next_decode_valid = true;

    snapshot_state(&snap);
    if (item.generation != snap.generation) {
      s.diag.generation_drop++;
      s.public_stats.packets_dropped++;
      next_decode_valid = false;
      if ((++decode_yield_counter & 0x07U) == 0U) {
        vTaskDelay(1);
      }
      continue;
    }
    if (frame_is_fully_stale(item.rtp, &snap, NULL)) {
      s.diag.stale_predecode++;
      s.public_stats.late_frames++;
      s.public_stats.packets_dropped++;
      if ((++decode_yield_counter & 0x07U) == 0U) {
        vTaskDelay(1);
      }
      continue;
    }

    if (!decoder || decoder_format_generation != item.format_generation) {
      aac_decoder_destroy(decoder);
      decoder = NULL;
      aac_decoder_config_t cfg = {
          .sample_rate = snap.format.sample_rate,
          .channels = snap.format.channels,
          .bits_per_sample = snap.format.bits_per_sample,
      };
      decoder = aac_decoder_create(&cfg);
      decoder_format_generation = item.format_generation;
      if (!decoder) {
        s.diag.decode_error++;
        s.public_stats.packets_dropped++;
        vTaskDelay(1);
        continue;
      }
      ESP_LOGI(TAG, "AAC decoder ready: %d Hz, %d ch, frame=%d (core=%d)",
               snap.format.sample_rate, snap.format.channels,
               snap.format.frame_size, xPortGetCoreID());
    }

    snapshot_state(&snap);
    if (item.generation != snap.generation ||
        frame_is_fully_stale(item.rtp, &snap, NULL)) {
      s.diag.stale_predecode++;
      s.public_stats.late_frames++;
      s.public_stats.packets_dropped++;
      if ((++decode_yield_counter & 0x07U) == 0U) {
        vTaskDelay(1);
      }
      continue;
    }

    aac_decode_info_t info = {0};
    int frames = aac_decoder_decode(decoder, s.decode_aac, item.len,
                                    s.decode_pcm, AP2_PCM_CAPACITY_FRAMES,
                                    &info);
    if (frames < 0) {
      s.diag.decode_error++;
      s.public_stats.packets_dropped++;
    } else {
      snapshot_state(&snap);
      if (item.generation != snap.generation) {
        s.diag.generation_drop++;
        s.public_stats.packets_dropped++;
        next_decode_valid = false;
      } else {
        uint32_t current_wanted = 0;
        bool current_wanted_valid = wanted_rtp_now(&snap, &current_wanted);
        bool stored = pcm_rtp_ring_write(
            s.pcm_ring, item.rtp, s.decode_pcm, (size_t)frames, info.channels,
            item.generation, current_wanted, current_wanted_valid);
        if (!stored) {
          s.diag.pcm_write_error++;
          s.public_stats.packets_dropped++;
        } else {
          s.diag.decoded++;
          s.diag.last_decoded_end_rtp = item.rtp + (uint32_t)frames;
          s.public_stats.packets_decoded++;
          if (first_logs < AP2_FIRST_DECODE_LOGS) {
            ++first_logs;
            ESP_LOGI(TAG,
                     "DECODE+RING OK #%u: seq=%" PRIu32 " rtp=%" PRIu32
                     " pcm_frames=%d ch=%d core=%d",
                     (unsigned)first_logs, item.seq, item.rtp, frames,
                     info.channels, xPortGetCoreID());
          }
        }
      }
    }

    if ((++decode_yield_counter & 0x07U) == 0U) {
      vTaskDelay(1);
    }
  }

  aac_decoder_destroy(decoder);
  s.decode_task = NULL;
  vTaskDelete(NULL);
}

static bool completion_sync_us(const timing_snapshot_t *snap,
                               const audio_playout_completion_t *done,
                               int32_t *sync_us_out) {
  if (!snap || !done || !sync_us_out || done->generation != snap->generation ||
      !snap->anchor_valid || snap->timeline_reset_pending) {
    return false;
  }

  uint64_t target_end_ptp = 0;
  if (!rtp_to_ptp_ns(snap, done->rtp + done->frames, &target_end_ptp)) {
    return false;
  }

  /* ISR timestamps DMA EOF in the local esp_timer domain.  Convert the
   * captured edge to PTP with the current filtered offset. */
  const int64_t ptp_offset_ns = ptp_clock_get_offset_ns();
  const int64_t done_ptp_ns = done->done_local_us * 1000LL + ptp_offset_ns;
  *sync_us_out = (int32_t)(((int64_t)target_end_ptp - done_ptp_ns) / 1000LL);
  return true;
}

static void process_i2s_completions(const timing_snapshot_t *snap) {
  audio_playout_completion_t done;
  while (audio_playout_poll_completion(&done)) {
    int32_t sync_us = 0;
    if (!completion_sync_us(snap, &done, &sync_us)) {
      continue;
    }

    s.diag.output_sync_raw_us = sync_us;
    if (!s.diag.output_sync_valid ||
        s.diag.output_sync_generation != done.generation) {
      s.diag.output_sync_us = sync_us;
      s.diag.output_sync_generation = done.generation;
      s.diag.output_sync_valid = true;
      ESP_LOGI(TAG,
               "SYNC START=%+.2f ms (%s) | DMA EOF vs AirPlay PTP",
               (double)sync_us / 1000.0,
               sync_us > 0 ? "ESP early" : (sync_us < 0 ? "ESP late" : "aligned"));
    } else {
      /* Small EMA removes ISR/PTP timestamp jitter from the human-readable
       * status without hiding a persistent offset. */
      s.diag.output_sync_us += (sync_us - s.diag.output_sync_us) / 8;
    }

    const int sr = snap->format.sample_rate > 0 ? snap->format.sample_rate : 44100;
    s.diag.output_sync_frames =
        (int32_t)(((int64_t)s.diag.output_sync_us * sr) / 1000000LL);
    s.diag.dma_tagged_completions++;
  }
}

static inline uint32_t abs_i16_u32(int16_t v) {
  return v == INT16_MIN ? 32768U : (uint32_t)(v < 0 ? -v : v);
}

/* No normalization/AGC is applied. AAC PCM is already signed 16-bit full
 * scale. We only attenuate it according to AirPlay volume, with a short ramp
 * to avoid clicks when volume changes. */
static void apply_output_volume(int16_t *pcm, uint32_t frames,
                                int32_t *current_q15) {
  if (!pcm || !current_q15 || frames == 0U) return;
  int32_t target = __atomic_load_n(&s_volume_target_q15, __ATOMIC_ACQUIRE);
  if (target < 0) target = 0;
  if (target > 32768) target = 32768;
  const int32_t start = *current_q15;
  uint32_t peak_in = 0, peak_out = 0;
  uint64_t rail_in = 0, clip_out = 0;
  const int64_t dg = (int64_t)target - (int64_t)start;
  for (uint32_t f = 0; f < frames; ++f) {
    const int32_t gain = start + (int32_t)((dg * (int64_t)(f + 1U)) / (int64_t)frames);
    for (uint32_t ch = 0; ch < 2U; ++ch) {
      const uint32_t i = f * 2U + ch;
      const int16_t in = pcm[i];
      const uint32_t ai = abs_i16_u32(in);
      if (ai > peak_in) peak_in = ai;
      if (in == INT16_MAX || in == INT16_MIN) rail_in++;
      int64_t y = (int64_t)in * (int64_t)gain;
      y += y >= 0 ? 16384 : -16384;
      y >>= 15;
      if (y > INT16_MAX) { y = INT16_MAX; clip_out++; }
      else if (y < INT16_MIN) { y = INT16_MIN; clip_out++; }
      pcm[i] = (int16_t)y;
      const uint32_t ao = abs_i16_u32(pcm[i]);
      if (ao > peak_out) peak_out = ao;
    }
  }
  *current_q15 = target;
  uint32_t old_peak = __atomic_load_n(&s.diag.pcm_peak_in, __ATOMIC_RELAXED);
  while (peak_in > old_peak &&
         !__atomic_compare_exchange_n(&s.diag.pcm_peak_in, &old_peak, peak_in,
                                      false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
  old_peak = __atomic_load_n(&s.diag.pcm_peak_out, __ATOMIC_RELAXED);
  while (peak_out > old_peak &&
         !__atomic_compare_exchange_n(&s.diag.pcm_peak_out, &old_peak, peak_out,
                                      false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
  __atomic_add_fetch(&s.diag.pcm_rail_in, rail_in, __ATOMIC_RELAXED);
  __atomic_add_fetch(&s.diag.pcm_clip_out, clip_out, __ATOMIC_RELAXED);
  __atomic_store_n(&s.diag.volume_q15, target, __ATOMIC_RELAXED);
}

static void ap2_playout_task(void *arg) {
  (void)arg;
  int16_t *block = heap_caps_malloc(
      AUDIO_PLAYOUT_FRAMES * 2U * sizeof(int16_t),
      MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!block) {
    block = malloc(AUDIO_PLAYOUT_FRAMES * 2U * sizeof(int16_t));
  }
  if (!block) {
    ESP_LOGE(TAG, "playout block allocation failed");
    s.playout_task = NULL;
    vTaskDelete(NULL);
    return;
  }

  typedef enum {
    PLAYOUT_STOPPED = 0,
    PLAYOUT_PRIMING = 1,
    PLAYOUT_RUNNING = 2,
  } playout_state_t;

  uint32_t cursor_rtp = 0; /* next block to submit after two preloaded blocks */
  uint32_t cursor_generation = 0;
  bool cursor_valid = false;
  uint32_t log_underrun_div = 0;
  int32_t volume_current_q15 = __atomic_load_n(&s_volume_target_q15, __ATOMIC_ACQUIRE);
  playout_state_t state = PLAYOUT_STOPPED;
  int32_t servo_ppm = 0;
  int32_t servo_target_ppm = 0;
  int64_t pid_last_calc_us = 0;
  int64_t pid_last_tune_us = 0;
  uint32_t servo_generation = 0;
  double pid_integral_ms_s = 0.0;
  double pid_prev_error_ms = 0.0;
  double pid_d_filtered_ms_s = 0.0;
  bool pid_prev_valid = false;
  s.diag.playout_state = PLAYOUT_STOPPED;

  ESP_LOGI(TAG,
           "PTP/RTP playout task started core=%d prio=%u block=%u prime=%ums",
           xPortGetCoreID(), (unsigned)AP2_PLAYOUT_PRIORITY,
           (unsigned)AUDIO_PLAYOUT_FRAMES, (unsigned)AP2_PLAYOUT_PRIME_MS);

  while (s.engine_running) {
    if (s.i2s_flush_requested) {
      s.i2s_flush_requested = false;
      audio_playout_flush();
      cursor_valid = false;
      s.diag.dma_pipeline_blocks = 0;
      s.diag.output_sync_valid = false;
      state = PLAYOUT_STOPPED;
      s.diag.playout_state = state;
      s.diag.playout_flushes++;
    }

    timing_snapshot_t snap;
    snapshot_state(&snap);
    process_i2s_completions(&snap);

    if (cursor_valid && state == PLAYOUT_RUNNING &&
        snap.deferred_flush_valid &&
        rtp_delta(cursor_rtp, snap.deferred_flush_rtp) >= 0) {
      ESP_LOGI(TAG, "deferred flush boundary reached at rtp=%" PRIu32,
               cursor_rtp);
      mark_timeline_discontinuity();
      cursor_valid = false;
      state = PLAYOUT_STOPPED;
      s.diag.playout_state = state;
      continue;
    }

    uint32_t desired_rtp = 0;
    bool timeline_ok = false;
    if (snap.playing && snap.anchor_valid && !snap.timeline_reset_pending &&
        ptp_clock_is_locked()) {
      timeline_ok = wanted_rtp_now(&snap, &desired_rtp);
    }

    if (!timeline_ok) {
      cursor_valid = false;
      s.diag.dma_pipeline_blocks = 0;
      state = PLAYOUT_STOPPED;
      s.diag.playout_state = state;
      vTaskDelay(1);
      continue;
    }

    if (cursor_generation != snap.generation || state == PLAYOUT_STOPPED) {
      cursor_generation = snap.generation;
      servo_generation = snap.generation;
      pid_last_calc_us = esp_timer_get_time();
      pid_last_tune_us = pid_last_calc_us;
      /* Keep the learned I/frequency bias across track changes, but reset D.
       * A new anchor can have a different startup phase and must not look like
       * a huge instantaneous phase velocity. */
      pid_prev_valid = false;
      pid_d_filtered_ms_s = 0.0;
      servo_target_ppm = servo_ppm;
      s.diag.servo_target_ppm = servo_ppm;
      s.diag.servo_slope_us_per_s = 0;
      cursor_valid = false;
      s.diag.dma_pipeline_blocks = 0;
      s.diag.output_sync_valid = false;
      state = PLAYOUT_PRIMING;
      s.diag.playout_state = state;
      s.diag.playout_resyncs++;
      audio_playout_flush(); /* READY/disabled for deterministic preload */
    }

    if (state == PLAYOUT_PRIMING) {
      const int sr = snap.format.sample_rate > 0 ? snap.format.sample_rate : 44100;
      const uint32_t prime_frames =
          (uint32_t)(((uint64_t)sr * AP2_PLAYOUT_PRIME_MS) / 1000ULL);

      /* Wait until enough real PCM exists before starting the silent phase
       * probe.  Once I2S is enabled we intentionally never stop it between
       * measurement and the first real block, so the real block must already
       * be available for an immediate queue operation. */
      const uint32_t guard_start = desired_rtp;
      const uint32_t guard_frames =
          prime_frames + AP2_START_PRIME_GUARD_BLOCKS * AUDIO_PLAYOUT_FRAMES;
      if (!pcm_rtp_ring_has_range(s.pcm_ring, guard_start, guard_frames,
                                  snap.generation)) {
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      static int16_t silence[AUDIO_PLAYOUT_FRAMES * 2U];
      memset(silence, 0, sizeof(silence));

      /* The silence tags use generation 0 on purpose: their EOFs are only a
       * phase probe and must not become the generation's public SYNC START.
       * The first real block carries the real generation and therefore becomes
       * the first normal sync observation. */
      const uint32_t silence_rtp =
          desired_rtp + AP2_START_SILENCE_FUTURE_BLOCKS * AUDIO_PLAYOUT_FRAMES;
      uint64_t silence_start_ptp = 0;
      if (!rtp_to_ptp_ns(&snap, silence_rtp, &silence_start_ptp)) {
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      if (audio_playout_preload_tagged(silence, AUDIO_PLAYOUT_FRAMES,
                                       silence_rtp, 0U) != ESP_OK ||
          audio_playout_preload_tagged(silence, AUDIO_PLAYOUT_FRAMES,
                                       silence_rtp + AUDIO_PLAYOUT_FRAMES,
                                       0U) != ESP_OK) {
        audio_playout_flush();
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      wait_until_ptp_ns(silence_start_ptp);

      timing_snapshot_t after_wait;
      snapshot_state(&after_wait);
      if (!after_wait.playing || !after_wait.anchor_valid ||
          after_wait.timeline_reset_pending ||
          after_wait.generation != snap.generation || s.i2s_flush_requested ||
          !ptp_clock_is_locked()) {
        audio_playout_flush();
        cursor_valid = false;
        state = PLAYOUT_STOPPED;
        s.diag.playout_state = state;
        continue;
      }

      /* This is the only enable for the whole startup epoch. */
      if (audio_playout_enable() != ESP_OK) {
        audio_playout_flush();
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      /* Wait for EOF of the first silent block.  The second silent descriptor
       * is already running, leaving one full block (~5.8 ms) to calculate the
       * exact RTP sample for descriptor #3 and queue it without stopping I2S. */
      const int64_t align_deadline = esp_timer_get_time() + AP2_START_ALIGN_TIMEOUT_US;
      audio_playout_completion_t probe_done;
      bool have_probe = false;
      while (esp_timer_get_time() < align_deadline) {
        if (audio_playout_poll_completion(&probe_done)) {
          if (probe_done.generation == 0U && probe_done.rtp == silence_rtp) {
            have_probe = true;
            break;
          }
          /* No real-generation completion can exist yet. Ignore any stale
           * diagnostic item left over from a prior disabled epoch. */
        } else {
          vTaskDelay(1);
        }
      }
      if (!have_probe) {
        audio_playout_flush();
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      /* Convert the measured EOF edge into PTP.  Descriptor #3 starts exactly
       * one 256-frame interval after descriptor #1 EOF because descriptor #2
       * is already in flight.  Over one block, even the maximum +/-160 ppm
       * servo correction changes the estimate by <1 us. */
      const int64_t ptp_offset_ns = ptp_clock_get_offset_ns();
      const int64_t probe_done_ptp_ns =
          probe_done.done_local_us * 1000LL + ptp_offset_ns;
      int64_t rate_scale_ppm = 1000000LL + (int64_t)servo_ppm;
      if (rate_scale_ppm < 900000LL) rate_scale_ppm = 900000LL;
      const uint64_t block_den = (uint64_t)sr * (uint64_t)rate_scale_ppm;
      const uint64_t block_ns =
          ((uint64_t)AUDIO_PLAYOUT_FRAMES * 1000000000ULL * 1000000ULL +
           block_den / 2ULL) / block_den;
      uint64_t real_boundary_ptp =
          probe_done_ptp_ns > 0 ? (uint64_t)probe_done_ptp_ns + block_ns
                                : silence_start_ptp + 2ULL * block_ns;

      /* Positive test offset means intentionally play content earlier.  At a
       * fixed physical boundary that is equivalent to selecting the RTP sample
       * whose nominal presentation time lies test_offset in the future. */
      int64_t mapped_ptp = (int64_t)real_boundary_ptp +
                           (int64_t)CONFIG_AP2_PLAYOUT_TEST_OFFSET_US * 1000LL;
      if (mapped_ptp < 0) mapped_ptp = 0;

      /* Round to the nearest RTP sample instead of truncating.  This makes the
       * startup alignment resolution one sample (22.68 us at 44.1 kHz). */
      const uint64_t half_sample_ns = 500000000ULL / (uint64_t)sr;
      uint32_t real_start_rtp = 0;
      if (!wanted_rtp_at_ptp(&snap, (uint64_t)mapped_ptp + half_sample_ns,
                             &real_start_rtp)) {
        audio_playout_flush();
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      /* Revalidate the timeline after waiting for the probe EOF. */
      timing_snapshot_t align_snap;
      snapshot_state(&align_snap);
      if (!align_snap.playing || !align_snap.anchor_valid ||
          align_snap.timeline_reset_pending ||
          align_snap.generation != snap.generation || s.i2s_flush_requested ||
          !ptp_clock_is_locked()) {
        audio_playout_flush();
        cursor_valid = false;
        state = PLAYOUT_STOPPED;
        s.diag.playout_state = state;
        continue;
      }

      bool ok = pcm_rtp_ring_read_256(s.pcm_ring, real_start_rtp,
                                      snap.generation, block);
      if (!ok) {
        /* Do not allow the already-running silent probe to leak into audible
         * timing indefinitely. A miss restarts the one-enable alignment epoch
         * after more PCM has arrived. */
        audio_playout_flush();
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }
      apply_output_volume(block, AUDIO_PLAYOUT_FRAMES, &volume_current_q15);
      if (audio_playout_write_tagged(block, AUDIO_PLAYOUT_FRAMES,
                                     real_start_rtp,
                                     snap.generation) != ESP_OK) {
        audio_playout_flush();
        s.diag.playout_prime_waits++;
        vTaskDelay(1);
        continue;
      }

      /* Report the raw one-enable startup phase only as a diagnostic.  It is
       * NOT used as a second-enable compensation as in V21. */
      uint64_t probe_target_end_ptp = 0;
      int32_t probe_sync_us = 0;
      if (rtp_to_ptp_ns(&snap, silence_rtp + AUDIO_PLAYOUT_FRAMES,
                        &probe_target_end_ptp)) {
        probe_sync_us = (int32_t)(((int64_t)probe_target_end_ptp -
                                   probe_done_ptp_ns) / 1000LL);
      }
      const int32_t align_samples =
          rtp_delta(real_start_rtp,
                    silence_rtp + 2U * AUDIO_PLAYOUT_FRAMES);

      cursor_rtp = real_start_rtp + AUDIO_PLAYOUT_FRAMES;
      cursor_valid = true;
      s.diag.dma_pipeline_blocks = 2U; /* silent #2 + first real block */
      state = PLAYOUT_RUNNING;
      s.diag.playout_state = state;
      s.diag.playout_starts++;
      ESP_LOGI(TAG,
               "ALIGN gen=%" PRIu32 " probe=%+.2fms shift=%" PRId32
               " samples (%+.3fms) real_rtp=%" PRIu32 " | I2S continuous",
               snap.generation, (double)probe_sync_us / 1000.0,
               align_samples, (double)align_samples * 1000.0 / (double)sr,
               real_start_rtp);
      continue;
    }

    /* In RUNNING, cursor_rtp is the next future block to queue. The two DMA
     * descriptors are paced by their EOF interrupts. No guessed current+1
     * subtraction is used for sync any more; the ISR completion tags are the
     * source of truth. */
    s.diag.desired_cursor_err_frames = rtp_delta(cursor_rtp, desired_rtp);

    const uint64_t fetch_begin_ptp = ptp_clock_get_time_ns();
    bool have_pcm = pcm_rtp_ring_read_256(
        s.pcm_ring, cursor_rtp, snap.generation, block);
    const uint64_t fetch_end_ptp = ptp_clock_get_time_ns();
    if (!have_pcm) {
      memset(block, 0, AUDIO_PLAYOUT_FRAMES * 2U * sizeof(int16_t));
      s.diag.playout_underruns++;
      if ((++log_underrun_div & 0x7fU) == 1U) {
        ESP_LOGW(TAG, "PCM underrun rtp=%" PRIu32 " gen=%" PRIu32,
                 cursor_rtp, snap.generation);
      }
    }
    s.diag.tx_fetch_us =
        (uint32_t)((fetch_end_ptp - fetch_begin_ptp) / 1000ULL);
    apply_output_volume(block, AUDIO_PLAYOUT_FRAMES, &volume_current_q15);

    const esp_err_t write_err = audio_playout_write_tagged(
        block, AUDIO_PLAYOUT_FRAMES, cursor_rtp, snap.generation);
    process_i2s_completions(&snap);

    /* V22 true PID clock servo.
     *
     * Sign convention from tagged DMA EOF:
     *   SYNC < 0 : ESP is late  -> positive ppm (speed I2S up)
     *   SYNC > 0 : ESP is early -> negative pressure on ppm
     *
     * The PID math runs every 1 s, but i2s_channel_tune_rate() is allowed at
     * most every 5 s and only for a useful >=5 ppm change.  This separation
     * matters because IDF tuning needs disable->tune->enable, which can itself
     * perturb phase.  +/-1 ms is deliberately treated as GOOD: once there and
     * phase velocity is modest, the clock is held instead of chasing 0.000 ms.
     */
    const int64_t pid_now_us = esp_timer_get_time();
    if (write_err == ESP_OK && s.diag.output_sync_valid &&
        s.diag.output_sync_generation == snap.generation &&
        servo_generation == snap.generation &&
        pid_now_us - pid_last_calc_us >= AP2_PID_CALC_PERIOD_US) {
      const double dt_s = (double)(pid_now_us - pid_last_calc_us) / 1000000.0;
      pid_last_calc_us = pid_now_us;

      /* Controller error is opposite to SYNC: negative SYNC (late) must
       * request positive ppm. */
      const double sync_ms = (double)s.diag.output_sync_us / 1000.0;
      const double error_ms = -sync_ms;

      double d_raw_ms_s = 0.0;
      if (pid_prev_valid && dt_s > 0.001) {
        d_raw_ms_s = (error_ms - pid_prev_error_ms) / dt_s;
        pid_d_filtered_ms_s += AP2_PID_D_ALPHA *
            (d_raw_ms_s - pid_d_filtered_ms_s);
      } else {
        pid_d_filtered_ms_s = 0.0;
      }
      pid_prev_error_ms = error_ms;
      pid_prev_valid = true;
      /* Keep log sign intuitive: positive d means SYNC is moving upward. */
      s.diag.servo_slope_us_per_s =
          (int32_t)(-pid_d_filtered_ms_s * 1000.0);

      const int32_t abs_sync_us = s.diag.output_sync_us < 0
          ? -s.diag.output_sync_us : s.diag.output_sync_us;
      const bool in_deadband = abs_sync_us <= AP2_PID_DEADBAND_US;

      /* In the 1..2 ms soft band reduce proportional aggression.  Outside
       * 2 ms use full P.  This prevents unnecessary hunting once we are already
       * close enough for multiroom use. */
      double p_error_ms = error_ms;
      if (abs_sync_us > AP2_PID_DEADBAND_US &&
          abs_sync_us <= AP2_PID_SOFTBAND_US) {
        p_error_ms *= 0.45;
      }

      const double p_term = AP2_PID_KP_PPM_PER_MS * p_error_ms;
      const double d_term = AP2_PID_KD_PPM_PER_MS_PER_S * pid_d_filtered_ms_s;

      /* Candidate integral update with anti-windup.  We integrate outside the
       * +/-1 ms good zone.  If P+I+D is already saturated in the same direction
       * as the error, freeze I; if the error would pull us out of saturation,
       * allow it to unwind. */
      double i_term = AP2_PID_KI_PPM_PER_MS_S * pid_integral_ms_s;
      double unsat = p_term + i_term + d_term;
      bool allow_i = !in_deadband;
      if (allow_i) {
        if ((unsat >= AP2_PID_MAX_PPM && error_ms > 0.0) ||
            (unsat <= -AP2_PID_MAX_PPM && error_ms < 0.0)) {
          allow_i = false;
        }
      }
      if (allow_i) {
        pid_integral_ms_s += error_ms * dt_s;
        const double i_limit_state = AP2_PID_I_TERM_LIMIT_PPM /
                                     AP2_PID_KI_PPM_PER_MS_S;
        if (pid_integral_ms_s > i_limit_state) pid_integral_ms_s = i_limit_state;
        if (pid_integral_ms_s < -i_limit_state) pid_integral_ms_s = -i_limit_state;
        i_term = AP2_PID_KI_PPM_PER_MS_S * pid_integral_ms_s;
      }

      double command = p_term + i_term + d_term;
      if (command > AP2_PID_MAX_PPM) command = AP2_PID_MAX_PPM;
      if (command < -AP2_PID_MAX_PPM) command = -AP2_PID_MAX_PPM;
      int32_t next_target = (int32_t)(command >= 0.0 ? command + 0.5 : command - 0.5);

      /* GOOD zone: if phase is not racing through it, keep the learned clock.
       * D still remains alive, so a clear passage through the band will be seen
       * on the next calculation rather than being hidden forever. */
      const double sync_slope_ms_s = -pid_d_filtered_ms_s;
      if (in_deadband && sync_slope_ms_s > -0.080 && sync_slope_ms_s < 0.080) {
        next_target = servo_ppm;
      }
      servo_target_ppm = next_target;
      s.diag.servo_target_ppm = servo_target_ppm;
    }

    if (write_err == ESP_OK && s.diag.output_sync_valid &&
        s.diag.output_sync_generation == snap.generation &&
        servo_generation == snap.generation &&
        pid_now_us - pid_last_tune_us >= AP2_PID_TUNE_PERIOD_US) {
      int32_t delta = servo_target_ppm - servo_ppm;
      int32_t abs_delta = delta < 0 ? -delta : delta;
      if (abs_delta >= AP2_PID_MIN_TUNE_PPM) {
        if (delta > AP2_PID_MAX_JUMP_PPM) delta = AP2_PID_MAX_JUMP_PPM;
        if (delta < -AP2_PID_MAX_JUMP_PPM) delta = -AP2_PID_MAX_JUMP_PPM;
        const int32_t next_ppm = servo_ppm + delta;

        audio_playout_tune_info_t ti = {0};
        esp_err_t te = audio_playout_tune_ppm(next_ppm, &ti);
        pid_last_tune_us = pid_now_us;
        if (te == ESP_OK) {
          servo_ppm = next_ppm;
          s.diag.servo_ppm = servo_ppm;
          s.diag.servo_mclk_hz = ti.curr_mclk_hz;
          s.diag.servo_updates++;
        } else {
          s.diag.servo_errors++;
        }
      }
    }

    if (write_err == ESP_OK) {
      s.diag.playout_blocks++;
      s.diag.last_playout_rtp = cursor_rtp;
      cursor_rtp += AUDIO_PLAYOUT_FRAMES;
      s.diag.dma_pipeline_blocks = 2U;
    } else {
      /* A failed write breaks the exact tag<->descriptor FIFO relationship.
       * Flush and re-prime rather than pretending the software cursor moved. */
      audio_playout_flush();
      cursor_valid = false;
      s.diag.dma_pipeline_blocks = 0;
      s.diag.output_sync_valid = false;
      state = PLAYOUT_PRIMING;
      s.diag.playout_state = state;
      s.diag.playout_resyncs++;
      vTaskDelay(1);
    }
  }

  audio_playout_flush();
  free(block);
  s.playout_task = NULL;
  vTaskDelete(NULL);
}

static void ap2_stats_task(void *arg) {
  (void)arg;
  diag_stats_t prev = {0};
  pcm_rtp_ring_stats_t pcm_prev = {0};
  aac_rtp_ring_stats_t aac_prev = {0};
  unsigned idle_periods = 0;
  ESP_LOGI(TAG, "stats task started on core %d", xPortGetCoreID());

  while (s.engine_running) {
    vTaskDelay(pdMS_TO_TICKS(AP2_STATS_PERIOD_MS));
    timing_snapshot_t snap;
    snapshot_state(&snap);
    diag_stats_t now = s.diag;
    now.pcm_peak_in = __atomic_exchange_n(&s.diag.pcm_peak_in, 0U, __ATOMIC_RELAXED);
    now.pcm_peak_out = __atomic_exchange_n(&s.diag.pcm_peak_out, 0U, __ATOMIC_RELAXED);
    pcm_rtp_ring_stats_t pcm = {0};
    aac_rtp_ring_stats_t aac = {0};
    pcm_rtp_ring_get_stats(s.pcm_ring, &pcm);
    aac_rtp_ring_get_stats(s.aac_ring, &aac);

    bool active = now.rx != prev.rx || now.decoded != prev.decoded ||
                  now.stale_predecrypt != prev.stale_predecrypt ||
                  now.stale_predecode != prev.stale_predecode ||
                  now.decode_error != prev.decode_error ||
                  now.aac_store_drop != prev.aac_store_drop ||
                  now.pcm_write_error != prev.pcm_write_error ||
                  aac.collisions != aac_prev.collisions ||
                  aac.stale_replaced != aac_prev.stale_replaced ||
                  aac.oversized != aac_prev.oversized ||
                  pcm.future_collisions != pcm_prev.future_collisions ||
                  now.playout_blocks != prev.playout_blocks ||
                  now.playout_underruns != prev.playout_underruns ||
                  now.playout_resyncs != prev.playout_resyncs ||
                  now.playout_starts != prev.playout_starts;
    if (!active && ++idle_periods < 5U) {
      continue;
    }
    idle_periods = 0;

    int pcm_ahead_ms = -1;
    int rx_ahead_ms = -1;
    uint32_t wanted = 0;
    if (wanted_rtp_now(&snap, &wanted)) {
      int sr = snap.format.sample_rate > 0 ? snap.format.sample_rate : 44100;
      if (now.last_decoded_end_rtp != 0) {
        pcm_ahead_ms = (int)(((int64_t)rtp_delta(
            now.last_decoded_end_rtp, wanted) * 1000LL) / sr);
      }
      if (now.last_rtp != 0 && now.last_rtp_generation == snap.generation) {
        int32_t d = rtp_delta(now.last_rtp, wanted);
        /* RTP signed deltas are meaningful only inside one committed epoch. */
        const int32_t sane = (int32_t)(AAC_RTP_SLOT_COUNT * AAC_RTP_FRAME_SAMPLES);
        if (d > -sane && d < sane) {
          rx_ahead_ms = (int)(((int64_t)d * 1000LL) / sr);
        }
      }
    }
    audio_playout_diag_t pdiag = {0};
    audio_playout_get_diag(&pdiag);

    int aac_buffer_ms = (int)(((uint64_t)aac.ready_slots *
                               AAC_RTP_FRAME_SAMPLES * 1000ULL) / 44100ULL);

    /* V22 compact archive log. SYNC comes from the EOF ISR for an RTP-tagged
     * DMA block, not from a guessed queue depth. Keep only timing/buffer/error
     * diagnostics here; volume/level telemetry is intentionally omitted. */
    const double sync_ms = now.output_sync_valid
        ? (double)now.output_sync_us / 1000.0 : 0.0;
    const uint64_t drops =
        (now.timeline_drop - prev.timeline_drop) +
        (now.aac_store_drop - prev.aac_store_drop);
    const uint64_t collisions =
        (aac.collisions - aac_prev.collisions) +
        (pcm.future_collisions - pcm_prev.future_collisions);
    const uint64_t dma_diag_err =
        pdiag.untagged_completions + pdiag.completion_overflows;
    /* Drain the command counter so it cannot grow indefinitely; it is no
     * longer printed in the archive log. */
    (void)__atomic_exchange_n(&s_volume_cmd_count, 0, __ATOMIC_ACQ_REL);

    if (now.playout_state == 2 && now.output_sync_valid) {
      ESP_LOGI(TAG,
               "SYNC=%+.2fms S=%+d/%+dppm d=%+.3fms/s | PCM=%dms AAC=%dms"
               " | U=%" PRIu64 " R=%" PRIu64 " DROP=%" PRIu64
               " COLL=%" PRIu64 " DEC=%" PRIu64 " DMA=%" PRIu64,
               sync_ms, now.servo_ppm, now.servo_target_ppm,
               (double)now.servo_slope_us_per_s / 1000.0,
               pcm_ahead_ms, aac_buffer_ms,
               now.playout_underruns - prev.playout_underruns,
               now.playout_resyncs - prev.playout_resyncs, drops, collisions,
               now.decode_error - prev.decode_error, dma_diag_err);
    } else {
      ESP_LOGI(TAG,
               "SYNC=-- | PCM=%dms AAC=%dms | U=%" PRIu64 " R=%" PRIu64
               " DROP=%" PRIu64 " COLL=%" PRIu64 " DEC=%" PRIu64
               " DMA=%" PRIu64 " | %s",
               pcm_ahead_ms, aac_buffer_ms,
               now.playout_underruns - prev.playout_underruns,
               now.playout_resyncs - prev.playout_resyncs, drops, collisions,
               now.decode_error - prev.decode_error, dma_diag_err,
               now.playout_state == 1 ? "PRIME" : "STOP");
    }
    prev = now;
    pcm_prev = pcm;
    aac_prev = aac;
  }

  s.stats_task = NULL;
  vTaskDelete(NULL);
}

esp_err_t audio_receiver_init(void) {
  s.diag.volume_q15 = __atomic_load_n(&s_volume_target_q15, __ATOMIC_ACQUIRE);
  if (!s.packet) {
    s.packet = heap_caps_malloc(AP2_PACKET_MAX,
                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s.packet) {
      s.packet = malloc(AP2_PACKET_MAX);
    }
  }
  if (!s.decrypt_buf) {
    s.decrypt_buf = heap_caps_malloc(AP2_PACKET_MAX,
                                     MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s.decrypt_buf) {
      s.decrypt_buf = malloc(AP2_PACKET_MAX);
    }
  }
  if (!s.decode_aac) {
    s.decode_aac = heap_caps_malloc(AAC_RTP_SLOT_BYTES,
                                    MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!s.decode_aac) {
      s.decode_aac = malloc(AAC_RTP_SLOT_BYTES);
    }
  }
  if (!s.decode_pcm) {
    s.decode_pcm = heap_caps_malloc(AP2_PCM_CAPACITY_FRAMES * 2U * sizeof(int16_t),
                                    MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!s.decode_pcm) {
      s.decode_pcm = malloc(AP2_PCM_CAPACITY_FRAMES * 2U * sizeof(int16_t));
    }
  }
  if (!s.aac_ring && aac_rtp_ring_create(&s.aac_ring) != ESP_OK) {
    return ESP_ERR_NO_MEM;
  }
  if (!s.pcm_ring && pcm_rtp_ring_create(&s.pcm_ring) != ESP_OK) {
    return ESP_ERR_NO_MEM;
  }
  if (!s.packet || !s.decrypt_buf || !s.decode_aac || !s.decode_pcm ||
      !s.aac_ring || !s.pcm_ring) {
    return ESP_ERR_NO_MEM;
  }

  aac_rtp_ring_set_generation(s.aac_ring, s.generation);
  pcm_rtp_ring_set_generation(s.pcm_ring, s.generation);

  ESP_RETURN_ON_ERROR(audio_playout_init(), TAG, "I2S playout init failed");
  s.engine_running = true;
  if (xTaskCreatePinnedToCore(ap2_playout_task, "ap2_playout",
                              AP2_PLAYOUT_STACK, NULL, AP2_PLAYOUT_PRIORITY,
                              &s.playout_task, AP2_DECODE_CORE) != pdPASS) {
    return ESP_FAIL;
  }
  if (xTaskCreatePinnedToCore(ap2_decode_task, "ap2_decode", AP2_DECODE_STACK,
                              NULL, AP2_DECODE_PRIORITY, &s.decode_task,
                              AP2_DECODE_CORE) != pdPASS) {
    return ESP_FAIL;
  }
  if (xTaskCreatePinnedToCore(ap2_stats_task, "ap2_stats", AP2_STATS_STACK,
                              NULL, AP2_STATS_PRIORITY, &s.stats_task,
                              AP2_NETWORK_CORE) != pdPASS) {
    return ESP_FAIL;
  }

  ESP_LOGI(TAG,
           "V22: Core0 TCP RX never intentionally waits -> RTP admission [-1s,+45s] -> stale drop -> decrypt -> direct RTP AAC ring");
  ESP_LOGI(TAG,
           "V22: AAC ring 2048 x 2048 bytes (~47.5 s address span); consumed slots become FREE before decode");
  ESP_LOGI(TAG,
           "V22: Core1 decode target ~4 s + 250 ms primed high-priority PTP/RTP I2S playout");
  ESP_LOGI(TAG,
           "V22 START: one I2S enable -> 2 silent tagged blocks -> sample-aligned real RTP boundary; test offset=%d us",
           (int)CONFIG_AP2_PLAYOUT_TEST_OFFSET_US);
  ESP_LOGI(TAG,
           "V22 LOG: ALIGN + true PID; +/-1ms GOOD; S=actual/target ppm; d=SYNC slope");
  return ESP_OK;
}

void audio_receiver_set_format(const audio_format_t *f) {
  if (!f) {
    return;
  }
  taskENTER_CRITICAL(&s.state_mux);
  s.format = *f;
  s.format_generation++;
  if (s.format_generation == 0) {
    s.format_generation = 1;
  }
  taskEXIT_CRITICAL(&s.state_mux);
  ESP_LOGI(TAG, "FORMAT codec=%s sr=%d ch=%d bits=%d frame=%d",
           f->codec, f->sample_rate, f->channels, f->bits_per_sample,
           f->frame_size);
}

void audio_receiver_set_encryption(const audio_encrypt_t *e) {
  if (e) {
    s.encrypt = *e;
  } else {
    memset(&s.encrypt, 0, sizeof(s.encrypt));
  }
  ESP_LOGI(TAG, "ENCRYPT type=%d key_len=%u", (int)s.encrypt.type,
           (unsigned)s.encrypt.key_len);
}

void audio_receiver_set_stream_type(audio_stream_type_t t) { s.stream_type = t; }

esp_err_t audio_receiver_start_buffered(uint16_t port) {
  if (s.listen_sock >= 0) {
    return ESP_OK;
  }
  // A previous session may have just closed its listener. Do not create a
  // second RX task until the old one has observed rx_running=false and exited.
  for (int i = 0; s.rx_task != NULL && i < 50; ++i) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  if (s.rx_task != NULL) {
    ESP_LOGE(TAG, "previous AP2 RX task did not stop");
    return ESP_ERR_INVALID_STATE;
  }
  uint16_t bound = port;
  s.listen_sock = socket_utils_bind_tcp_listener(port, 1, true, &bound);
  if (s.listen_sock < 0) {
    return ESP_FAIL;
  }
  s.port = bound;
  s.rx_running = true;
  if (xTaskCreatePinnedToCore(ap2_rx_task, "ap2_rx", AP2_RX_STACK, NULL,
                              AP2_RX_PRIORITY, &s.rx_task,
                              AP2_NETWORK_CORE) != pdPASS) {
    s.rx_running = false;
    close(s.listen_sock);
    s.listen_sock = -1;
    return ESP_FAIL;
  }
  ESP_LOGI(TAG, "AP2 buffered listener port=%u (RX core=%d)",
           (unsigned)s.port, AP2_NETWORK_CORE);
  return ESP_OK;
}

esp_err_t audio_receiver_start_stream(uint16_t data_port, uint16_t control_port,
                                      uint16_t tcp_port) {
  (void)data_port;
  (void)control_port;
  if (s.stream_type != AUDIO_STREAM_BUFFERED) {
    ESP_LOGW(TAG, "Ignoring non-buffered stream type=%d", (int)s.stream_type);
    return ESP_ERR_NOT_SUPPORTED;
  }
  return audio_receiver_start_buffered(tcp_port);
}

esp_err_t audio_receiver_start(uint16_t data_port, uint16_t control_port) {
  (void)data_port;
  (void)control_port;
  return ESP_ERR_NOT_SUPPORTED;
}

void audio_receiver_stop(void) {
  s.rx_running = false;
  taskENTER_CRITICAL(&s.state_mux);
  s.playing = false;
  taskEXIT_CRITICAL(&s.state_mux);
  mark_timeline_discontinuity();

  if (s.client_sock >= 0) {
    shutdown(s.client_sock, SHUT_RDWR);
    close(s.client_sock);
    s.client_sock = -1;
  }
  if (s.listen_sock >= 0) {
    shutdown(s.listen_sock, SHUT_RDWR);
    close(s.listen_sock);
    s.listen_sock = -1;
  }
  s.port = 0;
}

void audio_receiver_stop_buffered_only(void) { audio_receiver_stop(); }
uint16_t audio_receiver_get_buffered_port(void) { return s.port; }
uint16_t audio_receiver_get_stream_port(void) { return s.port; }
void audio_receiver_set_volume_q15(int32_t volume_q15) {
  if (volume_q15 < 0) volume_q15 = 0;
  if (volume_q15 > 32768) volume_q15 = 32768;
  __atomic_store_n(&s_volume_target_q15, volume_q15, __ATOMIC_RELEASE);
  __atomic_add_fetch(&s_volume_cmd_count, 1, __ATOMIC_RELAXED);
}

int32_t audio_receiver_get_volume_q15(void) {
  return __atomic_load_n(&s_volume_target_q15, __ATOMIC_ACQUIRE);
}

void audio_receiver_get_stats(audio_stats_t *out) { if (out) *out = s.public_stats; }
size_t audio_receiver_read(int16_t *b, size_t n) { (void)b; (void)n; return 0; }
bool audio_receiver_has_data(void) { return false; }

void audio_receiver_flush(void) { mark_timeline_discontinuity(); }
void audio_receiver_seek_flush(void) { mark_timeline_discontinuity(); }
void audio_receiver_set_deferred_flush(uint32_t ts) {
  taskENTER_CRITICAL(&s.state_mux);
  s.deferred_flush_rtp = ts;
  s.deferred_flush_valid = true;
  taskEXIT_CRITICAL(&s.state_mux);
  ESP_LOGI(TAG, "deferred flush armed for RTP=%" PRIu32, ts);
}

void audio_receiver_pause(void) {
  taskENTER_CRITICAL(&s.state_mux);
  s.playing = false;
  taskEXIT_CRITICAL(&s.state_mux);
  mark_timeline_discontinuity();
}

void audio_receiver_set_playout_latency_samples(uint32_t v) { (void)v; }
void audio_receiver_set_output_latency_us(uint32_t v) { (void)v; }
uint32_t audio_receiver_get_output_latency_us(void) { return 0; }
uint32_t audio_receiver_get_hardware_latency_us(void) { return audio_playout_hardware_latency_us(); }
uint32_t audio_receiver_get_advertised_latency_us(void) { return 0; }

void audio_receiver_set_playing(bool p) {
  taskENTER_CRITICAL(&s.state_mux);
  s.playing = p;
  taskEXIT_CRITICAL(&s.state_mux);
  if (!p) {
    mark_timeline_discontinuity();
  }
}

bool audio_receiver_is_playing(void) {
  bool playing;
  taskENTER_CRITICAL(&s.state_mux);
  playing = s.playing;
  taskEXIT_CRITICAL(&s.state_mux);
  return playing;
}

void audio_receiver_reset_timing(void) {
  mark_timeline_discontinuity();
  ptp_clock_clear();
}

void audio_receiver_set_client_control(uint32_t ip, uint16_t port) {
  (void)ip;
  (void)port;
}

void audio_receiver_set_anchor_time(uint64_t clock_id, uint64_t ptp_ns,
                                    uint32_t rtp) {
  if (clock_id) {
    ptp_clock_set_master_clock_id(clock_id);
  }
  uint32_t gen;
  bool committed;
  taskENTER_CRITICAL(&s.state_mux);
  committed = s.timeline_reset_pending;
  gen = commit_anchor_epoch_locked();
  s.anchor_clock_id = clock_id;
  s.anchor_ptp_ns = ptp_ns;
  s.anchor_rtp = rtp;
  s.anchor_valid = true;
  taskEXIT_CRITICAL(&s.state_mux);

  ESP_LOGI(TAG, "ANCHOR clock=%016" PRIx64 " ptp=%" PRIu64
                " rtp=%" PRIu32 " gen=%" PRIu32 "%s",
           clock_id, ptp_ns, rtp, gen,
           committed ? " (new timeline committed; waiting for PTP lock if needed)"
                     : " (anchor update; waiting for PTP lock if needed)");
}
