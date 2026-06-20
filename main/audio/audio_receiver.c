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

esp_err_t audio_receiver_init(void) {
  if (receiver.buffer.pool) {
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

  size_t pending_capacity =
      sizeof(audio_frame_header_t) +
      ((size_t)MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS * sizeof(int16_t));
  audio_timing_init(&receiver.timing, pending_capacity);
  audio_timing_set_format(&receiver.timing, &receiver.stream->format);

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

  audio_decoder_destroy(receiver.decoder);
  receiver.decoder = NULL;

  audio_decoder_config_t cfg = {.format = *format};
  receiver.decoder = audio_decoder_create(&cfg);
  if (!receiver.decoder) {
    ESP_LOGW(TAG, "Decoder not initialized for codec: %s", format->codec);
  }

  audio_timing_set_format(&receiver.timing, format);
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

void audio_receiver_set_output_latency_us(uint32_t latency_us) {
  if (!receiver.stream) {
    return;
  }
  audio_timing_set_output_latency(&receiver.timing, &receiver.stream->format,
                                  latency_us);
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
  // PAUSE → RESUME cycle but no FLUSHBUFFERED.  The buffer may already be
  // empty (consumed during playback), so the seek-detection heuristic
  // below (which needs oldest_rtp from the buffer) would miss it.
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
      audio_buffer_flush(&receiver.buffer);
      receiver.timing.playout_started = false;
      receiver.timing.pending_valid = false;
      receiver.timing.pending_frame_len = 0;
      receiver.timing.ready_time_us = 0;
      receiver.timing.deferred_flush_pending = false;
      receiver.blocks_read_in_sequence = 0;
      receiver.discard_before_rtp = rtp_time;
      receiver.discard_before_rtp_valid = true;
      receiver.discard_above_rtp = rtp_time + gate_window;
      receiver.discard_above_rtp_valid = true;
      receiver.timing.quick_start = true;
      gates_armed = true;
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

  // --- Phase 2: Seek detection from buffer content ----------------------
  //
  // If stale data managed to enter the buffer (e.g. queued before
  // seek_flush was called), detect it by comparing the oldest buffered
  // RTP timestamp against the new anchor.
  uint32_t oldest_rtp = 0;
  if (audio_buffer_oldest_timestamp(&receiver.buffer, &oldest_rtp)) {
    int32_t rtp_ahead = (int32_t)(oldest_rtp - rtp_time);
    int32_t abs_ahead = rtp_ahead < 0 ? -rtp_ahead : rtp_ahead;
    if (abs_ahead > seek_threshold) {
      ESP_LOGI(TAG,
               "Seek detected: oldest_rtp=%lu, new anchor rtp=%lu, "
               "delta=%ld samples (%.1f s) — flushing stale buffer",
               (unsigned long)oldest_rtp, (unsigned long)rtp_time,
               (long)rtp_ahead, (float)rtp_ahead / sample_rate);
      audio_buffer_flush(&receiver.buffer);
      receiver.timing.playout_started = false;
      receiver.timing.pending_valid = false;
      receiver.timing.pending_frame_len = 0;
      receiver.timing.ready_time_us = 0;
      receiver.timing.deferred_flush_pending = false;
      receiver.blocks_read_in_sequence = 0;
      receiver.timing.quick_start = true;
      if (!gates_armed) {
        receiver.discard_before_rtp = rtp_time;
        receiver.discard_before_rtp_valid = true;
        receiver.discard_above_rtp = rtp_time + gate_window;
        receiver.discard_above_rtp_valid = true;
      }
    }
  }

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
}

void audio_receiver_set_playing(bool playing) {
  audio_timing_set_playing(&receiver.timing, playing);
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
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);
  audio_receiver_reset_resend_state();

  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  return receiver.stream->ops->start(receiver.stream, data_port);
}

esp_err_t audio_receiver_start_buffered(uint16_t tcp_port) {
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
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);
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

  audio_decoder_destroy(receiver.decoder);
  receiver.decoder = NULL;

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
  if (!receiver.buffer.pool || !buffer || samples == 0) {
    return 0;
  }

  return audio_timing_read(&receiver.timing, &receiver.buffer, receiver.stream,
                           &receiver.stats, buffer, samples);
}

bool audio_receiver_has_data(void) {
  int buffered_frames = audio_buffer_get_frame_count(&receiver.buffer);
  return buffered_frames > 0 || receiver.timing.pending_valid;
}

void audio_receiver_flush(void) {
  // Flush is an explicit reset — clear all timing state including pause
  // tracking.  The sender will provide fresh anchor times after flush.
  // Also disarm any pending deferred flush so it does not fire on the
  // next track's frames.
  audio_buffer_flush(&receiver.buffer);
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
  // Mid-stream seek flush (FLUSH / immediate FLUSHBUFFERED).  Like
  // audio_receiver_flush() but sets timing.quick_start so audio_timing_read
  // starts as soon as 1 frame is available, with normal anchor-based timing.
  // Also disarms any pending deferred flush (audio_timing_reset clears it).
  audio_receiver_flush();
  receiver.timing.quick_start = true;
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
  // Write flush_until_ts before arming the flag so audio_timing_read never
  // sees deferred_flush_pending=true with a stale timestamp.
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
  receiver.blocks_read_in_sequence = 0;
}

uint16_t audio_receiver_get_buffered_port(void) {
  return receiver.buffered_port;
}
