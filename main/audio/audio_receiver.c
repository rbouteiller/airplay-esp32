#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "audio_receiver.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "audio_buffer.h"
#include "audio_decoder.h"
#include "audio_output.h"
#include "audio_receiver_internal.h"
#include "audio_stream.h"
#include "audio_timing.h"
#include "ntp_clock.h"
#include "ptp_clock.h"

#define DEFAULT_SAMPLE_RATE     44100
#define DEFAULT_CHANNELS        2
#define DEFAULT_BITS_PER_SAMPLE 16
#define DEFAULT_FRAME_SIZE      352
#define DECRYPT_BUFFER_SIZE     8192

static const char *TAG = "audio_recv";

static audio_receiver_state_t receiver = {0};

static void audio_receiver_reset_stats(void) {
  memset(&receiver.stats, 0, sizeof(receiver.stats));
}

static void audio_receiver_reset_resend_state(void) {
  receiver.rtp_sequence_valid = false;
  receiver.resend_window_first = 0;
  receiver.resend_missing_mask = 0;
  receiver.resend_last_request_time_us = 0;
  receiver.last_resend_error_time_us = 0;
}

static void audio_receiver_reset_blocks(void) {
  receiver.blocks_read = 0;
  receiver.blocks_read_in_sequence = 0;
}

static void audio_receiver_copy_stream_state(audio_stream_t *dst,
                                             const audio_stream_t *src) {
  if (!dst || !src) {
    return;
  }

  dst->format = src->format;
  dst->encrypt = src->encrypt;
}

// True when the PCM timeline owns playback.  Both stream types use it; they
// never run at the same time, and the engine is re-pointed at the right codec
// frame length when each one starts.
static inline bool engine_v2_active(void) {
  return receiver.engine_v2_ready && receiver.stream;
}

// AAC frames are always 1024 samples.  ALAC packet length comes from the SDP
// (`a=fmtp` frame length), 352 on every sender seen so far.
static uint32_t engine_v2_frame_samples(audio_stream_type_t type,
                                        const audio_stream_t *stream) {
  if (type == AUDIO_STREAM_BUFFERED) {
    return AUDIO_TIMELINE_FRAME_SAMPLES;
  }
  return stream->format.frame_size > 0 ? (uint32_t)stream->format.frame_size
                                       : AUDIO_TIMELINE_RT_FRAME_SAMPLES;
}

static void audio_receiver_reset_engine_v2(void);

// Create the engine on first use.  It costs ~790 KB of PSRAM, and it is never
// torn down afterwards: the playback task calls audio_engine_v2_render() on
// every I2S refill and freeing the timeline underneath it would race.  The
// slot pool is therefore sized once for the longest frame either codec uses,
// and switching streams only re-points the addressing quantum -- 192 slots
// hold ~4.5 s of AAC or ~1.5 s of ALAC.
static esp_err_t audio_receiver_ensure_engine_v2(audio_stream_type_t type) {
  audio_stream_t *stream = type == AUDIO_STREAM_BUFFERED
                               ? receiver.buffered_stream
                               : receiver.realtime_stream;
  if (!stream) {
    return ESP_ERR_INVALID_STATE;
  }

  if (!receiver.decoder_mutex) {
    receiver.decoder_mutex = xSemaphoreCreateMutex();
    if (!receiver.decoder_mutex) {
      ESP_LOGE(TAG, "Failed to create decoder mutex");
      return ESP_ERR_NO_MEM;
    }
  }

  if (!receiver.engine_v2_ready) {
    esp_err_t err = audio_engine_v2_init(&receiver.engine_v2, &stream->format,
                                         AUDIO_TIMELINE_FRAME_SAMPLES,
                                         AUDIO_V2_TIMELINE_BLOCKS);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Engine init failed: %s", esp_err_to_name(err));
      return err;
    }
    receiver.engine_v2_ready = true;
  }

  const uint32_t frame_samples = engine_v2_frame_samples(type, stream);

  if (receiver.engine_v2.timeline.frame_samples != frame_samples) {
    // Bump the epoch and drop queued work *before* the pool is re-cut.  The
    // re-cut moves every slot address, and a decode worker or the playback
    // task can still be copying through a pointer it took under the old
    // stride.  A stale epoch makes new pushes fail immediately, which lets
    // the re-cut wait the stragglers out instead of racing them.  The
    // outgoing stream's clock map and cursor describe nothing the timeline
    // still holds either.
    audio_receiver_reset_engine_v2();
  }

  if (!audio_engine_v2_set_frame_samples(&receiver.engine_v2, frame_samples)) {
    return ESP_ERR_INVALID_ARG;
  }

  // Realtime decodes inline on the rx task; only buffered offloads.
  if (type == AUDIO_STREAM_BUFFERED && !receiver.decode_worker) {
    // The worker is torn down by audio_receiver_stop() together with the
    // decoder it uses, so it is recreated on every buffered SETUP.
    esp_err_t err =
        audio_decode_worker_create(&receiver, &receiver.decode_worker);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Decode worker create failed: %s", esp_err_to_name(err));
      return err;
    }
  }

  return ESP_OK;
}

// Discard everything buffered for the buffered path and wait for a fresh
// anchor.  Advancing the epoch invalidates in-flight decode jobs and the whole
// timeline in one step, so no stale PCM can reach the new segment.
static void audio_receiver_reset_engine_v2(void) {
  if (!receiver.engine_v2_ready) {
    return;
  }
  audio_decode_worker_discard_pending(receiver.decode_worker);
  (void)audio_engine_v2_begin_epoch(&receiver.engine_v2, esp_timer_get_time());
  receiver.aac_diag_rtp_valid = false;
  receiver.engine_v2_anchor_pending = false;
}

// Local -> sender clock offset, and whether that clock is actually locked.
//
// The sender's anchor timestamps are PTP for AirPlay 2 (control packet 0x57)
// and NTP for AirPlay 1 (0x54), so the engine cannot assume PTP the way it did
// while only the buffered path used it.  Which one applies is decided by the
// anchor itself, not by whichever clock happens to be locked: a PTP lock left
// over from a previous session (or kept alive by another sender on the
// network) would otherwise map an AirPlay 1 anchor into the PTP timeline, and
// vice versa, putting every block decades from its real playout time.  Like
// compute_early_us() in audio_timing.c this must be re-read on every render:
// before a lock the offset is 0, and freezing that value places the anchor
// days from local time and wraps the int32 RTP delta.
static int64_t audio_receiver_network_offset_ns(bool *locked) {
  const bool have_lock = receiver.engine_v2_anchor_uses_ptp
                             ? ptp_clock_is_locked()
                             : ntp_clock_is_locked();
  if (locked) {
    *locked = have_lock;
  }
  if (!have_lock) {
    return 0;
  }
  return receiver.engine_v2_anchor_uses_ptp ? ptp_clock_get_offset_ns()
                                            : ntp_clock_get_offset_ns();
}

// Publish the pending anchor once a network clock is usable.  Before the first
// lock the offset is 0, which would place the anchor days away from local time
// and wrap the int32 RTP delta into a meaningless position.
// Retried from the playback task; re-arming with identical values is a no-op.
static void audio_receiver_arm_engine_v2_anchor(void) {
  bool locked = false;
  (void)audio_receiver_network_offset_ns(&locked);
  if (!receiver.engine_v2_anchor_pending || !locked) {
    return;
  }
  if (audio_engine_v2_set_anchor(&receiver.engine_v2,
                                 receiver.engine_v2_anchor_rtp,
                                 receiver.engine_v2_anchor_network_ns,
                                 receiver.engine_v2_playout_offset_ns)) {
    receiver.engine_v2_anchor_pending = false;
  }
}

esp_err_t audio_receiver_init(void) {
  if (receiver.buffer.decode_buffer) {
    return ESP_OK;
  }

  receiver.realtime_stream = audio_stream_create_realtime();
  if (receiver.realtime_stream) {
    receiver.realtime_stream->ctx = &receiver;
  }
  receiver.buffered_stream = audio_stream_create_buffered();
  if (receiver.buffered_stream) {
    receiver.buffered_stream->ctx = &receiver;
  }
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    ESP_LOGE(TAG, "Failed to allocate audio streams");
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return ESP_ERR_NO_MEM;
  }

  receiver.stream = receiver.realtime_stream;

  audio_format_t default_format = {0};
  strcpy(default_format.codec, "AppleLossless");
  default_format.sample_rate = DEFAULT_SAMPLE_RATE;
  default_format.channels = DEFAULT_CHANNELS;
  default_format.bits_per_sample = DEFAULT_BITS_PER_SAMPLE;
  default_format.frame_size = DEFAULT_FRAME_SIZE;

  receiver.realtime_stream->format = default_format;
  receiver.buffered_stream->format = default_format;

  esp_err_t err = audio_buffer_init(&receiver.buffer);
  if (err != ESP_OK) {
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return err;
  }

  receiver.decrypt_buffer_size = DECRYPT_BUFFER_SIZE;
#ifdef CONFIG_SPIRAM
  receiver.decrypt_buffer = heap_caps_malloc(
      receiver.decrypt_buffer_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
  if (!receiver.decrypt_buffer) {
    receiver.decrypt_buffer = malloc(receiver.decrypt_buffer_size);
  }
  if (!receiver.decrypt_buffer) {
    ESP_LOGE(TAG, "Failed to allocate decrypt buffer");
    audio_buffer_deinit(&receiver.buffer);
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return ESP_ERR_NO_MEM;
  }

  audio_timing_init(&receiver.timing);

  receiver.buffered_listen_socket = -1;
  receiver.buffered_client_socket = -1;

  audio_receiver_reset_blocks();

  return ESP_OK;
}

void audio_receiver_set_format(const audio_format_t *format) {
  if (!format) {
    return;
  }
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    return;
  }

  receiver.realtime_stream->format = *format;
  receiver.buffered_stream->format = *format;

  // The decode worker task may be inside audio_decoder_decode() right now.
  if (receiver.decoder_mutex) {
    xSemaphoreTake(receiver.decoder_mutex, portMAX_DELAY);
  }
  audio_decoder_destroy(receiver.decoder);
  receiver.decoder = NULL;

  audio_decoder_config_t cfg = {.format = *format};
  receiver.decoder = audio_decoder_create(&cfg);
  if (receiver.decoder_mutex) {
    xSemaphoreGive(receiver.decoder_mutex);
  }
  if (!receiver.decoder) {
    ESP_LOGW(TAG, "Decoder not initialized for codec: %s", format->codec);
  }

  if (receiver.engine_v2_ready) {
    audio_engine_v2_set_format(&receiver.engine_v2, format);
  }
  audio_output_set_source_rate(format->sample_rate);
}

void audio_receiver_set_encryption(const audio_encrypt_t *encrypt) {
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    return;
  }
  if (encrypt) {
    receiver.realtime_stream->encrypt = *encrypt;
    receiver.buffered_stream->encrypt = *encrypt;
  } else {
    memset(&receiver.realtime_stream->encrypt, 0,
           sizeof(receiver.realtime_stream->encrypt));
    memset(&receiver.buffered_stream->encrypt, 0,
           sizeof(receiver.buffered_stream->encrypt));
  }
}

void audio_receiver_set_playout_latency_samples(uint32_t latency_samples) {
  audio_timing_set_playout_latency(&receiver.timing, latency_samples);
}

void audio_receiver_set_output_latency_us(uint32_t latency_us) {
  audio_timing_set_output_latency(&receiver.timing, latency_us);
}

uint32_t audio_receiver_get_output_latency_us(void) {
  return audio_timing_get_output_latency(&receiver.timing);
}

uint32_t audio_receiver_get_hardware_latency_us(void) {
  return audio_timing_get_hardware_latency();
}

uint32_t audio_receiver_get_advertised_latency_us(void) {
  return audio_timing_get_advertised_latency(&receiver.timing);
}

void audio_receiver_set_anchor_time(uint64_t clock_id, uint64_t network_time_ns,
                                    uint32_t rtp_time) {
  if (!receiver.stream) {
    return;
  }

  int sample_rate = receiver.stream->format.sample_rate;
  if (sample_rate <= 0) {
    sample_rate = 44100;
  }
  // Window size for the upper RTP gate: 10 s of samples.  Large enough that
  // a normal 2-4 s pre-buffer passes, but small enough to reject stale frames
  // left in the TCP socket buffer after a backward seek.
  const uint32_t gate_window = (uint32_t)(10 * sample_rate);
  const int32_t seek_threshold = 5 * sample_rate;

  // --- Phase 1: Arm RTP gates BEFORE opening the blanket gate -----------
  //
  // The blanket gate (discard_all_until_anchor) blocks ALL frames from the
  // TCP task.  The per-RTP gates filter by timestamp range.  On single-core
  // ESP32-S2, ESP_LOGI can yield to the scheduler, so any gap between
  // clearing the blanket and arming the per-RTP gates lets the TCP task
  // queue stale frames.  Arm first, then open.
  bool gates_armed = false;

  // Path A: seek_flush set arm_gate_on_next_anchor because the buffer was
  // already empty when the flush happened (forward-seek).
  if (receiver.arm_gate_on_next_anchor) {
    receiver.arm_gate_on_next_anchor = false;
    receiver.discard_before_rtp = rtp_time;
    receiver.discard_before_rtp_valid = true;
    receiver.discard_above_rtp = rtp_time + gate_window;
    receiver.discard_above_rtp_valid = true;
    gates_armed = true;
    ESP_LOGI(TAG,
             "RTP gates armed on anchor: discard_before=%lu discard_above=%lu",
             (unsigned long)rtp_time, (unsigned long)(rtp_time + gate_window));
  }

  // Path B: Anchor-change detection — the phone changed track with a
  // PAUSE → RESUME cycle but no FLUSHBUFFERED.
  //
  // Compare the new anchor against the EXPECTED current playback position
  // (old_anchor_rtp + elapsed_time × sample_rate), NOT against the raw old
  // anchor.  The raw old anchor was set at the start of the previous play
  // segment; comparing against it gives a delta equal to (elapsed_play_time +
  // new_anchor_lead_time), which easily exceeds the 5-second threshold on a
  // normal pause/resume within the same track — causing a false flush that
  // empties valid pre-buffered frames and produces 6+ seconds of silence.
  // Using the expected position instead, normal resume gives a delta of only
  // the anchor's lead-time offset (< 2 s), while a real track-change or seek
  // gives a huge delta (many minutes).
  if (!gates_armed && receiver.timing.anchor_valid) {
    // Choose reference point for the seek-detection comparison:
    //   - If we have a pause snapshot, use it. The snapshot was taken at the
    //     exact moment the sender said PAUSE, so it reflects the true pause
    //     position rather than a wall-clock estimate that keeps running during
    //     the pause and overshoots by (pause_duration x sample_rate).
    //   - Otherwise fall back to the elapsed-time estimate (covers the edge
    //     case where a track changes without a prior PAUSE signal).
    uint32_t reference_rtp;
    if (receiver.paused_rtp_valid) {
      reference_rtp = receiver.paused_rtp;
      receiver.paused_rtp_valid = false; // one-shot: consume after use
      // Compute the pause duration from the RTP snapshot so we can notify
      // the PTP clock without tracking a separate wall-clock timestamp.
      // anchor_local_time_ns/1000 is the µs when the anchor was set;
      // adding the played-sample offset gives the µs when play paused.
      int32_t played =
          (int32_t)(reference_rtp - receiver.timing.anchor_rtp_time);
      int64_t pause_time_us = receiver.timing.anchor_local_time_ns / 1000LL +
                              (int64_t)played * 1000000LL / sample_rate;
      int64_t pause_us = esp_timer_get_time() - pause_time_us;
      ptp_clock_notify_resume((pause_us > 0) ? (uint32_t)(pause_us / 1000LL)
                                             : 0);
      ESP_LOGD(TAG, "Path B: pause snapshot rtp=%lu pause=%.1f s",
               (unsigned long)reference_rtp, (float)pause_us / 1e6f);
    } else {
      int64_t elapsed_us = esp_timer_get_time() -
                           (receiver.timing.anchor_local_time_ns / 1000LL);
      if (elapsed_us < 0) {
        elapsed_us = 0;
      }
      // Cap elapsed to prevent int64 overflow on very long pauses.
      if (elapsed_us > 600000000LL) {
        elapsed_us = 600000000LL;
      }
      int32_t elapsed_samples =
          (int32_t)((elapsed_us * (int64_t)sample_rate) / 1000000LL);
      reference_rtp =
          receiver.timing.anchor_rtp_time + (uint32_t)elapsed_samples;
    }
    int32_t delta = (int32_t)(rtp_time - reference_rtp);
    int32_t abs_delta = delta < 0 ? -delta : delta;
    if (abs_delta > seek_threshold) {
      ESP_LOGI(TAG,
               "Anchor change detected: ref_rtp=%lu new_rtp=%lu "
               "delta=%ld samples (%.1f s) - flushing & arming gates",
               (unsigned long)reference_rtp, (unsigned long)rtp_time,
               (long)delta, (float)delta / sample_rate);
      audio_receiver_reset_engine_v2();
      receiver.timing.deferred_flush_pending = false;
      receiver.blocks_read_in_sequence = 0;
      receiver.discard_before_rtp = rtp_time;
      receiver.discard_before_rtp_valid = true;
      receiver.discard_above_rtp = rtp_time + gate_window;
      receiver.discard_above_rtp_valid = true;
    } else {
      ESP_LOGD(TAG,
               "Anchor resume OK: ref_rtp=%lu new_rtp=%lu "
               "delta=%ld samples (%.2f s) - same track, no flush",
               (unsigned long)reference_rtp, (unsigned long)rtp_time,
               (long)delta, (float)delta / (float)sample_rate);
    }
  }

  // NOW safe to clear the blanket gate — per-RTP gates are active.
  receiver.discard_all_until_anchor = false;

  // A second pass used to re-check the sorted buffer's oldest frame here,
  // because a frame queued before seek_flush could still be sitting below the
  // new anchor.  The timeline needs no such sweep: blocks are addressed by
  // RTP, so anything stranded below the cursor is never scheduled.

  // Pin the PTP clock to the master announced by the anchor packet's
  // clock_id field.  Without this, ptp_clock can lock to any PTP master
  // on the LAN (HomePods, AppleTVs, NTP-PTP gateways) and produce offsets
  // that have nothing to do with the AirPlay sender's clock domain.
  // clock_id == 0 happens on the AirPlay 1 NTP path; in that case leave
  // the filter as-is (set or cleared by a prior 0xD7 anchor / TEARDOWN).
  if (clock_id != 0) {
    ptp_clock_set_master_clock_id(clock_id);
  }

  audio_timing_set_anchor(&receiver.timing, &receiver.stream->format, clock_id,
                          network_time_ns, rtp_time);

  if (engine_v2_active()) {
    // Keep the clock map in the sender's clock domain and let
    // audio_receiver_read() convert local time into it with the live offset,
    // exactly as audio_timing.c's compute_early_us() re-reads the offset on
    // every frame.  Baking the offset into the anchor here instead strands the
    // stream whenever the anchor lands before a lock: SETPEERS zeroes the
    // offset, so the anchor would sit days in the future and never be reached.
    receiver.engine_v2_anchor_rtp = rtp_time;
    receiver.engine_v2_anchor_network_ns = network_time_ns;
    // A timeline ID is only present on the AirPlay 2 (PTP) anchors; the
    // AirPlay 1 sync packet path passes 0.
    receiver.engine_v2_anchor_uses_ptp = (clock_id != 0);
    receiver.engine_v2_playout_offset_ns =
        ((int64_t)receiver.timing.playout_latency_samples * 1000000000LL) /
        sample_rate;
    receiver.engine_v2_anchor_pending = true;
    audio_receiver_arm_engine_v2_anchor();
    if (receiver.engine_v2_anchor_pending) {
      // No usable clock yet.  Keep the buffered PCM and wait rather than
      // discarding a full pre-buffer.
      audio_engine_v2_wait_for_anchor(&receiver.engine_v2,
                                      esp_timer_get_time());
    }
  }
}

void audio_receiver_set_playing(bool playing) {
  audio_timing_set_playing(&receiver.timing, playing);
  if (receiver.engine_v2_ready) {
    audio_engine_v2_set_playing(&receiver.engine_v2, playing);
  }
  if (!playing) {
    receiver.blocks_read_in_sequence = 0;
    // Snapshot the expected RTP position at the moment of pause so that
    // Path B in audio_receiver_set_anchor_time() can compare the next
    // resume anchor against the actual pause position.
    //
    // Without this, Path B uses (anchor_rtp + wall_clock_elapsed), which
    // overshoots by the pause duration and fires a false seek flush on any
    // pause >= seek_threshold (5 s) — causing up to 7+ s of silence when
    // pre-buffered frames end up far ahead of the unwanted new anchor.
    if (receiver.timing.anchor_valid && receiver.stream) {
      int sample_rate = receiver.stream->format.sample_rate;
      if (sample_rate <= 0) {
        sample_rate = 44100;
      }
      int64_t elapsed_us = esp_timer_get_time() -
                           (receiver.timing.anchor_local_time_ns / 1000LL);
      if (elapsed_us < 0) {
        elapsed_us = 0;
      }
      if (elapsed_us > 600000000LL) {
        elapsed_us = 600000000LL;
      }
      int32_t elapsed_samples =
          (int32_t)((elapsed_us * (int64_t)sample_rate) / 1000000LL);
      receiver.paused_rtp =
          receiver.timing.anchor_rtp_time + (uint32_t)elapsed_samples;
      receiver.paused_rtp_valid = true;
      ESP_LOGD(TAG, "Pause: RTP snapshot=%lu (elapsed=%.2f s)",
               (unsigned long)receiver.paused_rtp, (float)elapsed_us / 1e6f);
    }
  }
}

void audio_receiver_reset_timing(void) {
  audio_timing_reset(&receiver.timing);
}

bool audio_receiver_is_playing(void) {
  return receiver.timing.playing;
}

void audio_receiver_set_stream_type(audio_stream_type_t type) {
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    return;
  }
  audio_stream_t *target = receiver.realtime_stream;
  if (type == AUDIO_STREAM_BUFFERED) {
    target = receiver.buffered_stream;
  }

  if (!target) {
    return;
  }

  if (receiver.stream != target) {
    if (receiver.stream) {
      audio_receiver_copy_stream_state(target, receiver.stream);
      if (receiver.stream->running && receiver.stream->ops &&
          receiver.stream->ops->stop) {
        receiver.stream->ops->stop(receiver.stream);
      }
    }
    receiver.stream = target;
  }

  receiver.stream->type = type;
}

esp_err_t audio_receiver_start(uint16_t data_port, uint16_t control_port) {
  esp_err_t engine_err = audio_receiver_ensure_engine_v2(AUDIO_STREAM_REALTIME);
  if (engine_err != ESP_OK) {
    return engine_err;
  }

  audio_receiver_set_stream_type(AUDIO_STREAM_REALTIME);

  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->start) {
    return ESP_FAIL;
  }

  // Always stop and restart fresh
  if (receiver.stream->running) {
    receiver.stream->ops->stop(receiver.stream);
  }

  receiver.data_port = data_port;
  receiver.control_port = control_port;

  // Starting a stream resets all timing state (including pause tracking)
  audio_receiver_reset_stats();
  audio_receiver_reset_engine_v2();
  audio_timing_reset(&receiver.timing);
  // audio_timing defaults to playing; mirror that onto the engine, which
  // starts paused, so a sender that never sends an explicit rate=1 still
  // produces audio.
  audio_engine_v2_set_playing(&receiver.engine_v2, receiver.timing.playing);
  audio_receiver_reset_resend_state();

  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  return receiver.stream->ops->start(receiver.stream, data_port);
}

esp_err_t audio_receiver_start_buffered(uint16_t tcp_port) {
  esp_err_t engine_err = audio_receiver_ensure_engine_v2(AUDIO_STREAM_BUFFERED);
  if (engine_err != ESP_OK) {
    return engine_err;
  }

  audio_receiver_set_stream_type(AUDIO_STREAM_BUFFERED);

  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->start) {
    return ESP_FAIL;
  }

  // Buffered streams use a fixed port, no need to restart if running
  if (receiver.stream->running) {
    return ESP_OK;
  }

  // Starting a stream resets all timing state (including pause tracking)
  audio_receiver_reset_stats();
  audio_receiver_reset_engine_v2();
  audio_timing_reset(&receiver.timing);
  // audio_timing defaults to playing; mirror that onto the engine, which
  // starts paused, so a sender that never sends an explicit rate=1 still
  // produces audio.
  audio_engine_v2_set_playing(&receiver.engine_v2, receiver.timing.playing);
  audio_receiver_reset_resend_state();

  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  return receiver.stream->ops->start(receiver.stream, tcp_port);
}

esp_err_t audio_receiver_start_stream(uint16_t data_port, uint16_t control_port,
                                      uint16_t tcp_port) {
  if (!receiver.stream) {
    return ESP_FAIL;
  }
  if (receiver.stream->type == AUDIO_STREAM_BUFFERED) {
    return audio_receiver_start_buffered(tcp_port);
  }

  return audio_receiver_start(data_port, control_port);
}

uint16_t audio_receiver_get_stream_port(void) {
  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->get_port) {
    return 0;
  }

  return receiver.stream->ops->get_port(receiver.stream);
}

void audio_receiver_set_client_control(uint32_t client_ip,
                                       uint16_t client_control_port) {
  if (client_ip == 0 || client_control_port == 0) {
    receiver.retransmit_enabled = false;
    audio_receiver_reset_resend_state();
    return;
  }
  memset(&receiver.client_control_addr, 0,
         sizeof(receiver.client_control_addr));
  receiver.client_control_addr.sin_family = AF_INET;
  receiver.client_control_addr.sin_addr.s_addr = client_ip;
  receiver.client_control_addr.sin_port = htons(client_control_port);
  receiver.retransmit_enabled = true;
  audio_receiver_reset_resend_state();
  ESP_LOGI(TAG, "NACK retransmission enabled, client control port %u",
           client_control_port);
}

void audio_receiver_stop(void) {
  if (receiver.realtime_stream && receiver.realtime_stream->ops &&
      receiver.realtime_stream->ops->stop) {
    receiver.realtime_stream->ops->stop(receiver.realtime_stream);
  }

  if (receiver.buffered_stream && receiver.buffered_stream->ops &&
      receiver.buffered_stream->ops->stop) {
    receiver.buffered_stream->ops->stop(receiver.buffered_stream);
  }

  // Stop the decode worker before the decoder it uses goes away.  The engine
  // itself is kept: the playback task renders from it on every I2S refill.
  audio_decode_worker_destroy(receiver.decode_worker);
  receiver.decode_worker = NULL;

  if (receiver.decoder_mutex) {
    xSemaphoreTake(receiver.decoder_mutex, portMAX_DELAY);
  }
  audio_decoder_destroy(receiver.decoder);
  receiver.decoder = NULL;
  if (receiver.decoder_mutex) {
    xSemaphoreGive(receiver.decoder_mutex);
  }

  if (receiver.realtime_stream) {
    memset(&receiver.realtime_stream->encrypt, 0,
           sizeof(receiver.realtime_stream->encrypt));
  }
  if (receiver.buffered_stream) {
    memset(&receiver.buffered_stream->encrypt, 0,
           sizeof(receiver.buffered_stream->encrypt));
  }

  receiver.retransmit_enabled = false;
  memset(&receiver.client_control_addr, 0,
         sizeof(receiver.client_control_addr));
  audio_receiver_reset_resend_state();

  audio_receiver_flush();
}

void audio_receiver_stop_buffered_only(void) {
  if (receiver.buffered_stream && receiver.buffered_stream->ops &&
      receiver.buffered_stream->ops->stop) {
    receiver.buffered_stream->ops->stop(receiver.buffered_stream);
  }
}

void audio_receiver_get_stats(audio_stats_t *stats) {
  if (!stats) {
    return;
  }
  memcpy(stats, &receiver.stats, sizeof(receiver.stats));
}

size_t audio_receiver_read(int16_t *buffer, size_t samples) {
  if (!buffer || samples == 0) {
    return 0;
  }

  if (engine_v2_active()) {
    audio_receiver_arm_engine_v2_anchor();
    // The scheduler works in the sender's clock domain: network = local +
    // offset.
    const int64_t playout_network_ns =
        audio_output_get_next_playout_time_ns(esp_timer_get_time()) +
        audio_receiver_network_offset_ns(NULL);
    return audio_engine_v2_render(&receiver.engine_v2, playout_network_ns,
                                  buffer, samples);
  }

  return 0;
}

bool audio_receiver_has_data(void) {
  return engine_v2_active() &&
         audio_timeline_count(&receiver.engine_v2.timeline) > 0;
}

void audio_receiver_flush(void) {
  // Flush is an explicit reset — clear all timing state including pause
  // tracking.  The sender will provide fresh anchor times after flush.
  // Also disarm any pending deferred flush so it does not fire on the
  // next track's frames.
  audio_receiver_reset_engine_v2();
  audio_timing_reset(&receiver.timing);
  audio_receiver_reset_resend_state();

  receiver.discard_before_rtp_valid = false;
  receiver.discard_above_rtp_valid = false;
  receiver.arm_gate_on_next_anchor = false;
  receiver.discard_all_until_anchor = false;
  receiver.paused_rtp_valid = false;
  receiver.blocks_read_in_sequence = 1;
}

void audio_receiver_seek_flush(void) {
  // Mid-stream seek flush (FLUSH / immediate FLUSHBUFFERED).  Same as
  // audio_receiver_flush(); the timeline re-prerolls from the new anchor by
  // itself.  Also disarms any pending deferred flush (audio_timing_reset
  // clears it).
  audio_receiver_flush();
  // Request that the RTP gate be armed as soon as the next anchor arrives.
  // This covers the forward-seek case where the buffer is already empty by
  // the time SETRATEANCHORTIME arrives, so the seek-detection heuristic
  // (which needs oldest_rtp from the buffer) would otherwise miss arming it.
  receiver.arm_gate_on_next_anchor = true;
  // Reject ALL incoming frames until the next anchor.  Prevents stale TCP
  // data from filling the buffer between FLUSHBUFFERED and SETRATEANCHORTIME,
  // which would cause a second flush and double the startup delay.
  receiver.discard_all_until_anchor = true;
}

void audio_receiver_set_deferred_flush(uint32_t flush_until_ts) {
  if (!receiver.stream) {
    return;
  }
  // Write flush_until_ts before arming the flag so no reader ever sees
  // deferred_flush_pending=true with a stale timestamp.
  receiver.timing.flush_until_ts = flush_until_ts;
  receiver.timing.deferred_flush_pending = true;
  ESP_LOGI(TAG, "Deferred flush armed: flush_until_ts=%" PRIu32,
           flush_until_ts);
}

void audio_receiver_pause(void) {
  // Stop the consumer.  The receiver tasks keep running so the audio buffer
  // continues to fill with pre-buffered audio — TCP back-pressure naturally
  // throttles the sender.  On resume the phone sends a fresh
  // SETRATEANCHORTIME anchor that re-aligns the buffered frames to the
  // correct wall-clock position; no flush or offset compensation is needed.
  audio_timing_set_playing(&receiver.timing, false);
  if (receiver.engine_v2_ready) {
    audio_engine_v2_set_playing(&receiver.engine_v2, false);
  }
  receiver.blocks_read_in_sequence = 0;
}

uint16_t audio_receiver_get_buffered_port(void) {
  return receiver.buffered_port;
}
