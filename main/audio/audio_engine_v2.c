#include "audio_engine_v2.h"

#include <inttypes.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "audio_v2";

/* Longest single blocking slice used while waiting for timeline space.  A
 * shorter slice keeps the decode task responsive to epoch changes even if the
 * consumer never signals. */
#define AUDIO_V2_PUSH_WAIT_SLICE_MS 50U

esp_err_t audio_engine_v2_init(audio_engine_v2_t *engine,
                               const audio_format_t *format,
                               uint32_t frame_samples, uint16_t capacity) {
  if (!engine || !format || format->sample_rate <= 0 || format->channels <= 0 ||
      format->channels > AUDIO_V2_MAX_CHANNELS) {
    return ESP_ERR_INVALID_ARG;
  }

  memset(engine, 0, sizeof(*engine));
  engine->publish_lock = (portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;
  audio_epoch_init(&engine->epoch);
  audio_clock_map_reset(&engine->clock_map);
  esp_err_t err =
      audio_timeline_init(&engine->timeline, capacity, frame_samples);
  if (err != ESP_OK) {
    return err;
  }

  engine->format = *format;
  uint32_t preroll_samples =
      (uint32_t)((uint64_t)format->sample_rate * 180U / 1000U);
  audio_scheduler_init(&engine->scheduler, preroll_samples, 1000000LL);
  engine->playing = false;
  engine->initialized = true;
  audio_scheduler_begin_epoch(&engine->scheduler,
                              audio_epoch_get(&engine->epoch), 0);
  ESP_LOGI(TAG,
           "initialized: %d Hz, %d ch, frame=%" PRIu32
           " blocks=%u preroll=%" PRIu32,
           format->sample_rate, format->channels, frame_samples,
           (unsigned)capacity, preroll_samples);
  return ESP_OK;
}

void audio_engine_v2_deinit(audio_engine_v2_t *engine) {
  if (!engine) {
    return;
  }
  audio_timeline_deinit(&engine->timeline);
  memset(engine, 0, sizeof(*engine));
}

uint32_t audio_engine_v2_begin_epoch(audio_engine_v2_t *engine,
                                     int64_t now_us) {
  if (!engine || !engine->initialized) {
    return 0;
  }
  portENTER_CRITICAL(&engine->publish_lock);
  uint32_t next = audio_epoch_advance(&engine->epoch);
  audio_timeline_clear_slots(&engine->timeline);
  portEXIT_CRITICAL(&engine->publish_lock);
  /* Outside the critical section: waking a producer blocked on a full
   * timeline has to happen with interrupts enabled. */
  audio_timeline_signal_space(&engine->timeline);
  audio_clock_map_reset(&engine->clock_map);
  audio_scheduler_begin_epoch(&engine->scheduler, next, now_us);
  engine->concealed_samples = 0;
  engine->blocks_inserted = 0;
  engine->blocks_rejected = 0;
  engine->last_status_log_us = 0;
  engine->conceal_events = 0;
  engine->conceal_events_logged = 0;
  // audio_scheduler_begin_epoch() zeroed the live trim count, so the snapshot
  // has to follow it: otherwise the next status line subtracts the old total
  // from zero and reports the per-second rate as a wrapped uint32.
  engine->drift_servo_trims_logged = 0;
  engine->last_conceal_gap_rtp = 0;
  __atomic_store_n(&engine->diag_rx_packets, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_gate_drops, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_enqueue_ok, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_enqueue_retries, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_queue_drops, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_dequeued, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_epoch_drops, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_decode_ok, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_decode_fail, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&engine->diag_pcm_inserted, 0, __ATOMIC_RELAXED);
  engine->start_watchdog_armed = false;
  engine->start_watchdog_anchor_us = 0;
  engine->start_watchdog_epoch = next;
  engine->start_watchdog_anchor_rtp = 0;
  ESP_LOGI(TAG, "new epoch=%" PRIu32, next);
  return next;
}

void audio_engine_v2_set_format(audio_engine_v2_t *engine,
                                const audio_format_t *format) {
  if (!engine || !format || format->sample_rate <= 0 || format->channels <= 0 ||
      format->channels > AUDIO_V2_MAX_CHANNELS) {
    return;
  }
  engine->format = *format;
  engine->scheduler.preroll_samples =
      (uint32_t)((uint64_t)format->sample_rate * 180U / 1000U);
}

bool audio_engine_v2_set_frame_samples(audio_engine_v2_t *engine,
                                       uint32_t frame_samples) {
  if (!engine || !engine->initialized) {
    return false;
  }
  if (engine->timeline.frame_samples == frame_samples) {
    return true;
  }
  if (!audio_timeline_set_frame_samples(&engine->timeline, frame_samples)) {
    ESP_LOGE(TAG, "frame=%" PRIu32 " does not fit the slot stride",
             frame_samples);
    return false;
  }
  ESP_LOGI(TAG, "frame=%" PRIu32 " (%u blocks)", frame_samples,
           (unsigned)engine->timeline.capacity);
  return true;
}

bool audio_engine_v2_set_anchor(audio_engine_v2_t *engine, uint32_t anchor_rtp,
                                uint64_t anchor_network_ns,
                                int64_t playout_offset_ns) {
  if (!engine || !engine->initialized) {
    return false;
  }
  bool ok = audio_clock_map_set(
      &engine->clock_map, (uint32_t)engine->format.sample_rate, anchor_rtp,
      anchor_network_ns, playout_offset_ns);
  if (ok) {
    if (engine->scheduler.state == AUDIO_SCHED_WAIT_ANCHOR) {
      engine->scheduler.state = AUDIO_SCHED_PREROLL;
      engine->scheduler.wait_reason = AUDIO_SCHED_WAIT_PREROLL;
    }
    engine->start_watchdog_armed = true;
    engine->start_watchdog_anchor_us = esp_timer_get_time();
    engine->start_watchdog_epoch = engine->scheduler.epoch;
    engine->start_watchdog_anchor_rtp = anchor_rtp;
  }
  return ok;
}

void audio_engine_v2_wait_for_anchor(audio_engine_v2_t *engine,
                                     int64_t now_us) {
  if (!engine || !engine->initialized) {
    return;
  }

  audio_clock_map_reset(&engine->clock_map);
  engine->scheduler.state =
      engine->playing ? AUDIO_SCHED_WAIT_ANCHOR : AUDIO_SCHED_PAUSED;
  engine->scheduler.cursor_rtp = 0;
  engine->scheduler.wanted_rtp = 0;
  engine->scheduler.raw_playout_error_samples = 0;
  engine->scheduler.playout_error_samples = 0;
  engine->scheduler.filtered_playout_error_q16 = 0;
  engine->scheduler.max_abs_playout_error_samples = 0;
  engine->scheduler.estimated_drift_ppm = 0;
  engine->scheduler.drift_reference_error_q16 = 0;
  engine->scheduler.drift_reference_network_ns = 0;
  engine->scheduler.error_filter_valid = false;
  engine->scheduler.drift_servo_accum = 0;
  engine->scheduler.drift_servo_phase = 0;
  engine->scheduler.drift_servo_warmup = 0;
  engine->scheduler.preroll_started_us = now_us;
}

void audio_engine_v2_set_playing(audio_engine_v2_t *engine, bool playing) {
  if (!engine || !engine->initialized) {
    return;
  }

  /* RTSP may repeat RECORD/rate=1 while a new epoch is already waiting for
   * its anchor or preroll.  The public playing flag and the scheduler state
   * are related, but they are not the same state machine: returning only
   * because playing was already true can leave a PAUSED/IDLE scheduler
   * stranded, while blindly calling set_paused(false) can kick a running
   * scheduler back to PREROLL. */
  engine->playing = playing;

  if (!playing) {
    engine->start_watchdog_armed = false;
    if (engine->scheduler.state != AUDIO_SCHED_PAUSED) {
      audio_scheduler_set_paused(&engine->scheduler, true);
    }
    return;
  }

  switch (engine->scheduler.state) {
  case AUDIO_SCHED_PLAYING:
  case AUDIO_SCHED_WAIT_ANCHOR:
  case AUDIO_SCHED_PREROLL:
  case AUDIO_SCHED_RECOVERING:
    /* Already active for this epoch.  Do not disturb cursor/preroll. */
    return;

  case AUDIO_SCHED_PAUSED:
  case AUDIO_SCHED_IDLE:
  default:
    /* A repeated playing=true must be able to revive a scheduler which
     * was paused by the probe/teardown sequence.  Choose the next state
     * from the actual clock-map validity instead of forcing PREROLL. */
    engine->scheduler.state =
        engine->clock_map.valid ? AUDIO_SCHED_PREROLL : AUDIO_SCHED_WAIT_ANCHOR;
    engine->scheduler.wait_reason = engine->clock_map.valid
                                        ? AUDIO_SCHED_WAIT_PREROLL
                                        : AUDIO_SCHED_WAIT_CLOCK_MAP;
    engine->scheduler.preroll_started_us = esp_timer_get_time();
    return;
  }
}

bool audio_engine_v2_is_nearly_full(audio_engine_v2_t *engine) {
  return engine && engine->initialized &&
         audio_timeline_is_nearly_full(&engine->timeline);
}

size_t audio_engine_v2_deferred_flush(audio_engine_v2_t *engine, uint32_t epoch,
                                      uint32_t flush_rtp) {
  if (!engine || !engine->initialized) {
    return 0U;
  }

  /* Deliberately not an epoch change.  A track transition keeps a continuous
   * RTP timeline and the sender sends no fresh SETRATEANCHORTIME, so resetting
   * the clock map here would leave the scheduler in WAIT_ANCHOR forever. */
  const size_t dropped =
      audio_timeline_discard_from(&engine->timeline, epoch, flush_rtp);
  ESP_LOGI(TAG, "deferred flush at rtp=%" PRIu32 " dropped=%u remaining=%u",
           flush_rtp, (unsigned)dropped,
           (unsigned)audio_timeline_count(&engine->timeline));
  return dropped;
}

bool audio_engine_v2_push_pcm(audio_engine_v2_t *engine, uint32_t epoch,
                              uint32_t first_rtp, const int16_t *pcm,
                              size_t samples, uint8_t channels) {
  if (!engine || !engine->initialized || !pcm || samples == 0U ||
      samples > engine->timeline.frame_samples || channels == 0U ||
      channels > AUDIO_V2_MAX_CHANNELS) {
    return false;
  }

  audio_timeline_reservation_t reservation = {0};
  int16_t *timeline_pcm = NULL;

  /* Phase 1: validate the current stream identity and reserve a private
   * timeline slot.  Keep publish_lock only for the short control-state
   * transaction; the potentially slow PSRAM copy happens after unlock. */
  portENTER_CRITICAL(&engine->publish_lock);

  if (!audio_epoch_matches(&engine->epoch, epoch)) {
    engine->blocks_rejected++;
    portEXIT_CRITICAL(&engine->publish_lock);
    return false;
  }

  if (!audio_timeline_reserve(&engine->timeline, epoch, first_rtp, &reservation,
                              &timeline_pcm)) {
    engine->blocks_rejected++;
    portEXIT_CRITICAL(&engine->publish_lock);
    return false;
  }

  /* A retransmitted/duplicate block that is already READY needs no second
   * payload copy.  Treat it exactly like the previous insert() no-op path. */
  if (reservation.duplicate) {
    engine->blocks_inserted++;
    (void)__atomic_add_fetch(&engine->diag_pcm_inserted, 1U, __ATOMIC_RELAXED);
    portEXIT_CRITICAL(&engine->publish_lock);
    return true;
  }

  portEXIT_CRITICAL(&engine->publish_lock);

  /* Stage 2 optimization: copy decoded PCM with no engine publish lock and no
   * timeline metadata lock held.  The reservation is private/WRITING, so
   * playback cannot observe a partially copied block. */
  memcpy(timeline_pcm, pcm, samples * channels * sizeof(int16_t));
  /* A short trailing packet still starts on a frame boundary, so keep the slot
   * a whole block and silence the tail rather than replaying the last epoch. */
  if (samples < engine->timeline.frame_samples) {
    memset(&timeline_pcm[samples * channels], 0,
           (engine->timeline.frame_samples - samples) * channels *
               sizeof(int16_t));
  }

  /* Phase 2: before publishing, revalidate stream identity. A FLUSH/seek can
   * advance epoch while PCM is copied outside the locks. */
  portENTER_CRITICAL(&engine->publish_lock);

  if (!audio_epoch_matches(&engine->epoch, epoch)) {
    audio_timeline_cancel(&engine->timeline, &reservation);
    engine->blocks_rejected++;
    portEXIT_CRITICAL(&engine->publish_lock);
    return false;
  }

  if (!audio_timeline_commit(&engine->timeline, &reservation)) {
    /* commit() consumes/cancels a valid reservation on every terminal path. */
    engine->blocks_rejected++;
    portEXIT_CRITICAL(&engine->publish_lock);
    return false;
  }

  engine->blocks_inserted++;
  (void)__atomic_add_fetch(&engine->diag_pcm_inserted, 1U, __ATOMIC_RELAXED);

  portEXIT_CRITICAL(&engine->publish_lock);
  return true;
}

bool audio_engine_v2_push_pcm_wait(audio_engine_v2_t *engine, uint32_t epoch,
                                   uint32_t first_rtp, const int16_t *pcm,
                                   size_t samples, uint8_t channels,
                                   uint32_t timeout_ms) {
  if (!engine || !engine->initialized) {
    return false;
  }

  const int64_t deadline_us =
      esp_timer_get_time() + (int64_t)timeout_ms * 1000LL;

  while (audio_epoch_matches(&engine->epoch, epoch)) {
    if (!audio_timeline_phase_blocked(&engine->timeline, epoch, first_rtp) &&
        audio_timeline_free_slots(&engine->timeline) > 0U) {
      return audio_engine_v2_push_pcm(engine, epoch, first_rtp, pcm, samples,
                                      channels);
    }

    const int64_t remaining_us = deadline_us - esp_timer_get_time();
    if (remaining_us <= 0) {
      return false;
    }

    /* Block on the consumer instead of polling.  The timeline gives this
     * semaphore whenever it retires a slot or is flushed, so the wake-up is
     * immediate and the decode task stays off the run queue while the sender
     * is being back-pressured.  The cap bounds the wait so teardown is never
     * blocked behind a paused scheduler holding a full timeline. */
    uint32_t wait_ms = (uint32_t)(remaining_us / 1000LL);
    if (wait_ms > AUDIO_V2_PUSH_WAIT_SLICE_MS) {
      wait_ms = AUDIO_V2_PUSH_WAIT_SLICE_MS;
    }
    (void)audio_timeline_wait_for_space(&engine->timeline, wait_ms + 1U);
  }
  return false;
}

size_t audio_engine_v2_render(audio_engine_v2_t *engine,
                              int64_t output_network_ns, int16_t *out,
                              size_t samples) {
  if (!engine || !engine->initialized || !out || samples == 0U) {
    return 0;
  }
  if (!engine->playing) {
    memset(out, 0, samples * engine->format.channels * sizeof(int16_t));
    return samples;
  }

  const audio_scheduler_state_t state_before = engine->scheduler.state;
  const uint32_t cursor_before = engine->scheduler.cursor_rtp;
  size_t concealed = 0;
  size_t produced = audio_scheduler_render(
      &engine->scheduler, &engine->timeline, &engine->clock_map,
      output_network_ns, out, samples, (uint8_t)engine->format.channels,
      &concealed);
  if (engine->scheduler.state == AUDIO_SCHED_PLAYING) {
    engine->start_watchdog_armed = false;
  }

  if (state_before != AUDIO_SCHED_PLAYING &&
      engine->scheduler.state == AUDIO_SCHED_PLAYING) {
    ESP_LOGI(
        TAG,
        "start decision: epoch=%" PRIu32 " wanted=%" PRIu32 " start=%" PRIu32
        " delta=%" PRId32 " blocks=%u attempts=%" PRIu64 " fallback=%" PRIu64,
        engine->scheduler.epoch, engine->scheduler.wanted_rtp,
        engine->scheduler.cursor_rtp,
        (int32_t)(engine->scheduler.cursor_rtp - engine->scheduler.wanted_rtp),
        (unsigned)audio_timeline_count(&engine->timeline),
        engine->scheduler.start_attempts, engine->scheduler.fallback_attempts);
  }

  if (engine->start_watchdog_armed &&
      engine->start_watchdog_epoch == engine->scheduler.epoch) {
    int64_t watchdog_now_us = esp_timer_get_time();
    if (engine->start_watchdog_anchor_us > 0 &&
        watchdog_now_us - engine->start_watchdog_anchor_us >= 3000000LL) {
      audio_timeline_diag_t diag;
      memset(&diag, 0, sizeof(diag));
      (void)audio_timeline_get_diag(&engine->timeline, engine->scheduler.epoch,
                                    engine->scheduler.wanted_rtp, &diag);
      ESP_LOGE(
          TAG,
          "START STALL: epoch=%" PRIu32 " anchor=%" PRIu32
          " playing=%d state=%s reason=%s clock=%d wanted=%" PRIu32
          " blocks=%u oldest=%s%" PRIu32 " newest_end=%s%" PRIu32
          " covered=%d next=%s%" PRIu32 " contiguous=%" PRIu32 "/%" PRIu32
          " attempts=%" PRIu64 " fallback=%" PRIu64 " silent=%" PRIu64
          " inserted=%" PRIu64 " rejected=%" PRIu64,
          engine->scheduler.epoch, engine->start_watchdog_anchor_rtp,
          engine->playing ? 1 : 0,
          audio_scheduler_state_name(engine->scheduler.state),
          audio_scheduler_wait_reason_name(engine->scheduler.wait_reason),
          engine->clock_map.valid ? 1 : 0, engine->scheduler.wanted_rtp,
          (unsigned)diag.count, diag.has_oldest ? "" : "n/a:", diag.oldest_rtp,
          diag.has_newest ? "" : "n/a:", diag.newest_end_rtp,
          diag.target_covered ? 1 : 0,
          diag.has_next ? "" : "n/a:", diag.next_rtp, diag.contiguous_samples,
          engine->scheduler.preroll_samples, engine->scheduler.start_attempts,
          engine->scheduler.fallback_attempts,
          engine->scheduler.silent_render_calls, engine->blocks_inserted,
          engine->blocks_rejected);
      ESP_LOGE(TAG,
               "PIPELINE: rx=%" PRIu64 " gate_drop=%" PRIu64 " enq=%" PRIu64
               " enq_retry=%" PRIu64 " queue_drop=%" PRIu64 " deq=%" PRIu64
               " epoch_drop=%" PRIu64 " decode_ok=%" PRIu64
               " decode_fail=%" PRIu64 " pcm_insert=%" PRIu64,
               __atomic_load_n(&engine->diag_rx_packets, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_gate_drops, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_enqueue_ok, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_enqueue_retries, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_queue_drops, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_dequeued, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_epoch_drops, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_decode_ok, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_decode_fail, __ATOMIC_RELAXED),
               __atomic_load_n(&engine->diag_pcm_inserted, __ATOMIC_RELAXED));
      engine->start_watchdog_armed = false;
    }
  }

  if (concealed > 0U) {
    /* Concealment is recorded, never logged from here.  This runs on the I2S
     * playback task: a formatted ESP_LOGW plus a timeline dump can block for
     * milliseconds on the UART mutex, and a burst of holes would then starve
     * the very task that has to drain them.  The 1 Hz status line below
     * reports the accumulated counters instead. */
    engine->conceal_events++;
    engine->last_conceal_gap_rtp = cursor_before;
  }
  engine->concealed_samples += concealed;

  int64_t now_us = esp_timer_get_time();
  if (engine->scheduler.state == AUDIO_SCHED_PLAYING &&
      now_us - engine->last_status_log_us >= 1000000LL) {
    engine->last_status_log_us = now_us;
    int32_t filtered_samples = engine->scheduler.playout_error_samples;
    int32_t raw_samples = engine->scheduler.raw_playout_error_samples;
    int32_t span_samples = engine->scheduler.raw_error_span_valid
                               ? engine->scheduler.raw_error_max_samples -
                                     engine->scheduler.raw_error_min_samples
                               : 0;
    engine->scheduler.raw_error_span_valid = false;
    int32_t filtered_us = 0;
    int32_t raw_us = 0;
    int32_t span_us = 0;
    if (engine->format.sample_rate > 0) {
      filtered_us = (int32_t)(((int64_t)filtered_samples * 1000000LL) /
                              engine->format.sample_rate);
      raw_us = (int32_t)(((int64_t)raw_samples * 1000000LL) /
                         engine->format.sample_rate);
      span_us = (int32_t)(((int64_t)span_samples * 1000000LL) /
                          engine->format.sample_rate);
    }
    uint32_t raw_abs_us =
        (uint32_t)(raw_us < 0 ? -(int64_t)raw_us : (int64_t)raw_us);
    uint32_t filtered_abs_us =
        (uint32_t)(filtered_us < 0 ? -(int64_t)filtered_us
                                   : (int64_t)filtered_us);
    const uint64_t new_conceals =
        engine->conceal_events - engine->conceal_events_logged;
    engine->conceal_events_logged = engine->conceal_events;
    const uint32_t new_trims =
        engine->scheduler.drift_servo_trims - engine->drift_servo_trims_logged;
    engine->drift_servo_trims_logged = engine->scheduler.drift_servo_trims;
    ESP_LOGI(TAG,
             "playout: raw=%s%" PRIu32 ".%03" PRIu32 " ms span=%" PRId32
             " us filt=%s%" PRIu32 ".%03" PRIu32 " ms (%" PRId32
             " smp) drift=%" PRId32 " ppm trims=%" PRIu32 "/s (%" PRIu32
             ") buffered=%u concealed=%" PRIu64 " holes=%" PRIu64 " (+%" PRIu64
             ")",
             raw_us < 0 ? "-" : "", raw_abs_us / 1000U, raw_abs_us % 1000U,
             span_us, filtered_us < 0 ? "-" : "", filtered_abs_us / 1000U,
             filtered_abs_us % 1000U, filtered_samples,
             engine->scheduler.estimated_drift_ppm, new_trims,
             engine->scheduler.drift_servo_trims,
             (unsigned)audio_timeline_count(&engine->timeline),
             engine->concealed_samples, engine->conceal_events, new_conceals);
  }
  return produced;
}
