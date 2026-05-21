#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "audio_timing.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "ntp_clock.h"
#include "ptp_clock.h"

#define DEFAULT_BUFFER_LATENCY_US  200000 // 200ms startup jitter buffer
#define HARDWARE_OUTPUT_LATENCY_US 46000  // ~46ms I2S DMA latency
// PIPELINE_PROCESSING_LATENCY_US: combined fixed delay between a frame
// landing on the wire at the phone and entering the sorted jitter buffer
// on our side.  Breakdown (approximate, measured on a quiet WiFi network):
//   ~10 ms  AAC decode (1024-sample frame, single-call)
//   ~ 1 ms  ChaCha20 decrypt
//   ~ 4 ms  WiFi+TCP receive jitter median
// Reported to the phone as part of outputLatencyMicros so its scheduler
// knows the actual end-to-end pipeline depth.  Kept independent of
// HARDWARE_OUTPUT_LATENCY_US (DMA-side) and DEFAULT_BUFFER_LATENCY_US
// (jitter-buffer target depth) so each can be tuned in isolation.
#define PIPELINE_PROCESSING_LATENCY_US 15000
#define MIN_STARTUP_FRAMES             4
#define DRIFT_ADJUST_THRESHOLD_FRAMES  2
#define TIMING_THRESHOLD_US            40000 // 40ms early/late threshold
// If a frame is late by more than this, flush the whole buffer at once
// instead of draining one frame per DMA callback (which would cause seconds
// of silence while thousands of stale frames are individually dropped).
// Kept independent of DEFAULT_BUFFER_LATENCY_US so reducing the startup
// buffer doesn't also reduce the late-detection threshold.
#define BULK_FLUSH_LATE_THRESHOLD_US 2000000 // 2 seconds
// If a frame is late by more than this, flush the whole buffer at once
// instead of draining one frame per DMA callback (which would cause seconds
// of silence while thousands of stale frames are individually dropped).
// Kept independent of DEFAULT_BUFFER_LATENCY_US so reducing the startup
// buffer doesn't also reduce the late-detection threshold.
#define BULK_FLUSH_LATE_THRESHOLD_US 2000000 // 2 seconds
// MAX_CONSECUTIVE_EARLY: number of consecutive early frames before we conclude
// the anchor is genuinely stuck/wrong.  At ~8 ms per frame this is ~6 seconds
// of silence, which is well beyond any normal pre-buffer depth.
#define MAX_CONSECUTIVE_EARLY 750
// MAX_CONSECUTIVE_LATE: number of consecutive individually-late frames before
// we conclude the whole buffer is stale and do a bulk flush.  At ~8 ms/frame
// this is ~24 ms — just enough to distinguish a genuine stale-buffer from a
// one-off WiFi jitter spike, without the 20-frame drain+log storm.
#define MAX_CONSECUTIVE_LATE 3
// MAX_CONSECUTIVE_LATE: number of consecutive individually-late frames before
// we conclude the whole buffer is stale and do a bulk flush.  At ~8 ms/frame
// this is ~24 ms — just enough to distinguish a genuine stale-buffer from a
// one-off WiFi jitter spike, without the 20-frame drain+log storm.
#define MAX_CONSECUTIVE_LATE 3

// POST_FLUSH_STALE_THRESHOLD_US: in post_flush mode the bypass plays frames
// unconditionally to avoid silence during the phone's pre-buffer window
// (typically 2–4 s).  Frames that are MORE than this many µs early are from
// the wrong seek position (old audio still draining through the TCP pipeline)
// and must be discarded rather than played.  10 s is well above the deepest
// observed AirPlay 2 pre-buffer depth and well below any real seek delta.
#define POST_FLUSH_STALE_THRESHOLD_US 10000000LL // 10 seconds
// POST_FLUSH_LATE_DROP_US: in post_flush, frames whose play time is more
// than this far in the past are dropped rather than played.  Set above the
// pre-buffer depth that normal post_flush handles (~200 ms early), but well
// below the multi-second lateness seen on AP2 group rejoin.
#define POST_FLUSH_LATE_DROP_US 300000LL // 300 ms
// POST_FLUSH_TIMEOUT_US: maximum duration of the post_flush bypass.  After a
// seek/flush the phone's pre-buffer window causes frames to appear hundreds of
// ms early.  We play them immediately for this duration so the user hears audio
// right away, then revert to normal timing so the anchor can enforce A/V sync.
#define POST_FLUSH_TIMEOUT_US 500000LL // 500 ms

// Closed-loop fill-depth controller.  Keeps the time-span of buffered audio
// (newest_play_time − oldest_play_time) close to timing->output_latency_us
// so the system retains equal jitter margin on both sides.  Without this,
// any small clock-rate mismatch between the source (phone) and our DAC
// causes the fill depth to drift monotonically until something catastrophic
// (underrun or bulk flush) resets it.
//
// FILL_DEPTH_DEADBAND_US: corrections only fire outside ±this band around
// the target.  Wide enough that normal TCP-batch jitter doesn't trigger.
//
// MIN_CORRECTION_INTERVAL_FRAMES: at most one correction per N played
// frames.  At ~23 ms per AAC frame and one frame's worth of skew per
// correction, N=200 caps effective sample-rate skew at ~0.5 % — well
// below the threshold of audibility.
#define FILL_DEPTH_DEADBAND_US         100000 // ±100 ms hysteresis
#define MIN_CORRECTION_INTERVAL_FRAMES 200

static const char *TAG = "audio_time";
// consecutive_early_frames is now a field in audio_timing_t so it resets
// automatically whenever a new anchor is set.

static uint32_t frame_samples_from_format(const audio_format_t *format) {
  if (format->frame_size > 0) {
    return (uint32_t)format->frame_size;
  }
  if (format->max_samples_per_frame > 0) {
    return format->max_samples_per_frame;
  }
  return AAC_FRAMES_PER_PACKET;
}

static void update_timing_targets(audio_timing_t *timing,
                                  const audio_format_t *format) {
  timing->nominal_frame_samples = frame_samples_from_format(format);

  if (format->sample_rate <= 0 || timing->nominal_frame_samples == 0) {
    timing->target_buffer_frames = MIN_STARTUP_FRAMES;
    return;
  }

  uint64_t latency_samples =
      ((uint64_t)timing->output_latency_us * (uint64_t)format->sample_rate) /
      1000000ULL;
  uint32_t target_frames =
      (uint32_t)((latency_samples + timing->nominal_frame_samples - 1) /
                 timing->nominal_frame_samples);
  if (target_frames < MIN_STARTUP_FRAMES) {
    target_frames = MIN_STARTUP_FRAMES;
  }
  timing->target_buffer_frames = target_frames;
}

typedef enum {
  SYNC_MODE_NONE, // No clock sync, use local anchor time
  SYNC_MODE_PTP,  // AirPlay 2 PTP sync
  SYNC_MODE_NTP,  // AirPlay 1 NTP sync
} sync_mode_t;

// Compute how early (positive) or late (negative) a frame is in microseconds
static bool compute_early_us(const audio_timing_t *timing,
                             const audio_format_t *format,
                             uint32_t rtp_timestamp, sync_mode_t sync_mode,
                             int64_t *early_us) {
  if (!timing->anchor_valid || format->sample_rate <= 0) {
    return false;
  }

  int32_t rtp_delta = (int32_t)(rtp_timestamp - timing->anchor_rtp_time);
  int64_t frame_offset_ns =
      ((int64_t)rtp_delta * 1000000000LL) / format->sample_rate;

  int64_t target_ns;
  switch (sync_mode) {
  case SYNC_MODE_PTP:
    // AirPlay 2: use network time with PTP offset for multi-room sync
    target_ns = (int64_t)timing->anchor_network_time_ns -
                ptp_clock_get_offset_ns() + frame_offset_ns;
    break;
  case SYNC_MODE_NTP:
    // AirPlay 1: use network time with NTP offset for multi-room sync
    // offset = remote_time - local_time, so local = remote - offset
    target_ns = (int64_t)timing->anchor_network_time_ns -
                ntp_clock_get_offset_ns() + frame_offset_ns;
    break;
  default:
    // Fallback: use local anchor time (no multi-room sync)
    target_ns = timing->anchor_local_time_ns + frame_offset_ns;
    break;
  }

  // Subtract hardware latency to account for I2S DMA delay
  target_ns -= (int64_t)HARDWARE_OUTPUT_LATENCY_US * 1000LL;

  int64_t now_ns = (int64_t)esp_timer_get_time() * 1000LL;
  *early_us = (target_ns - now_ns) / 1000LL;

  return true;
}

void audio_timing_init(audio_timing_t *timing, size_t pending_capacity) {
  if (!timing) {
    return;
  }

  memset(timing, 0, sizeof(*timing));
  timing->output_latency_us = DEFAULT_BUFFER_LATENCY_US;
  timing->playing = true;

  if (pending_capacity > 0) {
    timing->pending_frame = (uint8_t *)malloc(pending_capacity);
    if (timing->pending_frame) {
      timing->pending_frame_capacity = pending_capacity;
    }
  }
}

void audio_timing_reset(audio_timing_t *timing) {
  if (!timing) {
    return;
  }

  timing->playout_started = false;
  timing->anchor_valid = false;
  timing->pending_valid = false;
  timing->pending_frame_len = 0;
  timing->ready_time_us = 0;
  timing->consecutive_early_frames = 0;
  timing->consecutive_late_frames = 0;
  timing->post_flush = false;
  timing->post_flush_start_us = 0;
  timing->deferred_flush_pending = false;
  timing->flush_until_ts = 0;
  timing->frames_since_correction = 0;
}

void audio_timing_set_format(audio_timing_t *timing,
                             const audio_format_t *format) {
  if (!timing || !format) {
    return;
  }

  update_timing_targets(timing, format);
}

void audio_timing_set_output_latency(audio_timing_t *timing,
                                     const audio_format_t *format,
                                     uint32_t latency_us) {
  if (!timing || !format) {
    return;
  }

  timing->output_latency_us = latency_us;
  update_timing_targets(timing, format);
}

uint32_t audio_timing_get_output_latency(const audio_timing_t *timing) {
  if (!timing) {
    return 0;
  }

  return timing->output_latency_us;
}

uint32_t audio_timing_get_hardware_latency(void) {
  return HARDWARE_OUTPUT_LATENCY_US;
}

uint32_t audio_timing_get_advertised_latency(const audio_timing_t *timing) {
  // Total end-to-end latency between the phone scheduling a frame and the
  // DAC emitting it.  Reported to the phone in outputLatencyMicros so it
  // schedules sends to land in our sorted buffer at the right time.
  //
  //   output_latency_us         — controller target (jitter-buffer depth)
  // + HARDWARE_OUTPUT_LATENCY_US — I2S DMA delay (fixed)
  // + PIPELINE_PROCESSING_LATENCY_US — decrypt + decode + net jitter constant
  uint32_t base =
      timing ? timing->output_latency_us : DEFAULT_BUFFER_LATENCY_US;
  return base + HARDWARE_OUTPUT_LATENCY_US + PIPELINE_PROCESSING_LATENCY_US;
}

void audio_timing_set_anchor(audio_timing_t *timing,
                             const audio_format_t *format, uint64_t clock_id,
                             uint64_t network_time_ns, uint32_t rtp_time) {
  if (!timing || !format) {
    return;
  }

  (void)clock_id;

  int64_t now_ns = (int64_t)esp_timer_get_time() * 1000LL;

  timing->anchor_rtp_time = rtp_time;
  timing->anchor_network_time_ns = network_time_ns;
  timing->anchor_local_time_ns = now_ns;
  timing->ptp_locked = ptp_clock_is_locked();
  timing->anchor_valid = true;
  // Reset frame counters so pre-buffered audio after a pause/resume or
  // track skip does not accumulate into the new anchor's counts.
  timing->consecutive_early_frames = 0;
  timing->consecutive_late_frames = 0;
}

void audio_timing_set_playing(audio_timing_t *timing, bool playing) {
  if (!timing) {
    return;
  }

  ESP_LOGI(TAG, "set_playing: %s -> %s", timing->playing ? "playing" : "paused",
           playing ? "playing" : "paused");

  timing->playing = playing;
  if (!playing) {
    // Discard any partially-pending frame so resume starts cleanly from
    // the oldest frame in the sorted buffer.
    timing->pending_valid = false;
    timing->pending_frame_len = 0;
  }
}

size_t audio_timing_read(audio_timing_t *timing, audio_buffer_t *buffer,
                         const audio_stream_t *stream, audio_stats_t *stats,
                         int16_t *out, size_t samples) {
  if (!timing || !buffer || !stream || !out || samples == 0) {
    return 0;
  }

  if (!timing->playing) {
    return 0;
  }

  const audio_format_t *format = &stream->format;
  int buffered_frames = audio_buffer_get_frame_count(buffer);

  // Wait for enough buffer before starting
  if (!timing->playout_started && !timing->pending_valid) {
    if (buffered_frames < (int)timing->target_buffer_frames) {
      return 0;
    }
    // Wait for anchor before playing.
    // Normal startup: allow a 1-second fallback so a stream with no anchor
    // (e.g. AirPlay 1 without NTP) can still start.
    if (!timing->anchor_valid) {
      int64_t now_us = esp_timer_get_time();
      if (timing->ready_time_us == 0) {
        timing->ready_time_us = now_us;
      }
      if (now_us - timing->ready_time_us < 1000000) {
        return 0; // Still waiting for anchor
      }
      // Waited 1 second, no anchor - proceed without sync
    }
  }

  // Determine sync mode: PTP (AirPlay 2), NTP (AirPlay 1), or local fallback
  sync_mode_t sync_mode = SYNC_MODE_NONE;
  if (ptp_clock_is_locked()) {
    sync_mode = SYNC_MODE_PTP;
  } else if (ntp_clock_is_locked()) {
    sync_mode = SYNC_MODE_NTP;
  }

  // ---------- Fill-depth diagnostic (no correction) ----------
  //
  // Earlier revisions of this code dropped or padded frames here to keep the
  // buffer time-span near timing->output_latency_us.  That was misguided:
  // the buffer time-span reflects the phone's PUSH pattern (TCP bursts and
  // end-of-track pre-buffer routinely send 1–4 s ahead), not playout drift.
  // Frames have correct RTP-anchored play times; dropping them just causes
  // audible skips of legitimately-future audio.  PTP keeps us synced and
  // the per-frame early-pending / late-drop paths handle transients, so no
  // depth-based correction is needed.  Memory pressure is handled by the
  // overflow path in audio_buffer_queue_chunk.
  //
  // We still expose the depth as a diagnostic so anomalies (e.g. depth
  // staying above a couple of seconds for a long stretch, indicating a
  // sender bug) remain visible in logs without forcing corrective action.
  if (timing->anchor_valid && timing->playout_started &&
      format->sample_rate > 0 && timing->nominal_frame_samples > 0 &&
      buffered_frames >= 2 &&
      timing->frames_since_correction >= MIN_CORRECTION_INTERVAL_FRAMES) {
    int64_t depth_us = ((int64_t)buffered_frames *
                        (int64_t)timing->nominal_frame_samples * 1000000LL) /
                       (int64_t)format->sample_rate;
    int64_t target_us = (int64_t)timing->output_latency_us;
    int64_t excess = depth_us - target_us;
    if (excess < 0)
      excess = -excess;
    if (excess > FILL_DEPTH_DEADBAND_US) {
      ESP_LOGD(TAG, "fill_depth=%lldms (target=%lldms, frames=%d) — no action",
               depth_us / 1000LL, target_us / 1000LL, buffered_frames);
      timing->frames_since_correction = 0;
    }
  }
  // -----------------------------------------------------------

  // Drain up to MAX_DRAIN_ATTEMPTS late/invalid frames within a SINGLE
  // DMA callback.  The previous limit of 8 was the root cause of run-away
  // lateness: each call that returned silence (instead of playing a frame)
  // forfeited ~23 ms of RTP advancement while wall time kept moving, so
  // every late frame we dropped MADE us more late.  Draining many frames
  // in one pass advances RTP at zero wall-time cost and lets the buffer
  // skip past stale data without the DMA ever idling.
  enum { MAX_DRAIN_ATTEMPTS = 256 };
  for (int attempt = 0; attempt < MAX_DRAIN_ATTEMPTS; attempt++) {
    size_t item_size = 0;
    void *item = NULL;
    bool from_pending = false;

    // Get frame from pending or buffer
    if (timing->pending_valid) {
      item_size = timing->pending_frame_len;
      if (item_size < sizeof(audio_frame_header_t)) {
        timing->pending_valid = false;
        timing->pending_frame_len = 0;
        continue;
      }
      item = timing->pending_frame;
      from_pending = true;
    } else {
      if (!audio_buffer_take(buffer, &item, &item_size, 0)) {
        if (stats) {
          stats->buffer_underruns++;
        }
        return 0;
      }
      buffered_frames = audio_buffer_get_frame_count(buffer);

      if (item_size < sizeof(audio_frame_header_t)) {
        audio_buffer_return(buffer, item);
        continue;
      }
    }

    audio_frame_header_t *hdr = (audio_frame_header_t *)item;
    size_t frame_samples = hdr->samples_per_channel;
    size_t channels = hdr->channels ? hdr->channels : format->channels;
    int16_t *pcm = (int16_t *)(hdr + 1);

    // Validate frame
    if (frame_samples == 0 || channels == 0) {
      if (from_pending) {
        timing->pending_valid = false;
        timing->pending_frame_len = 0;
      } else {
        audio_buffer_return(buffer, item);
      }
      continue;
    }

    size_t expected_bytes =
        sizeof(*hdr) + frame_samples * channels * sizeof(int16_t);
    if (item_size < expected_bytes) {
      if (from_pending) {
        timing->pending_valid = false;
        timing->pending_frame_len = 0;
      } else {
        audio_buffer_return(buffer, item);
      }
      continue;
    }

    if (frame_samples > samples) {
      frame_samples = samples;
    }

    // Deferred flush check (AirPlay 2 FLUSHBUFFERED with flushFromSeq):
    // keep playing until the frame whose RTP timestamp reaches flush_until_ts,
    // then bulk-flush the remainder of the buffer and start fresh.
    // Signed 32-bit subtraction handles RTP wraparound correctly.
    if (timing->deferred_flush_pending) {
      if ((int32_t)(hdr->rtp_timestamp - timing->flush_until_ts) >= 0) {
        ESP_LOGI(TAG,
                 "Deferred flush triggered at ts=%" PRIu32 " (until_ts=%" PRIu32
                 ")",
                 hdr->rtp_timestamp, timing->flush_until_ts);
        if (from_pending) {
          timing->pending_valid = false;
          timing->pending_frame_len = 0;
        } else {
          audio_buffer_return(buffer, item);
        }
        audio_buffer_flush(buffer);
        timing->deferred_flush_pending = false;
        timing->playout_started = false;
        timing->ready_time_us = 0;
        timing->consecutive_early_frames = 0;
        timing->consecutive_late_frames = 0;
        // post_flush = true so the first frame of the next track plays
        // immediately rather than waiting out the phone's pre-buffer window.
        timing->post_flush = true;
        timing->post_flush_start_us = 0;
        return 0;
      }
    }

    // Handle early/late frames based on anchor timing.
    //
    // post_flush bypasses ALL timing checks (early and late) and plays every
    // frame unconditionally.  This mirrors shairport-sync's
    // first_packet_timestamp==0 path: after a seek or flush, the phone's anchor
    // may be stale by hundreds of ms (startup buffer fill delay + pre-buffer
    // depth), so frames appear early or late through no fault of the stream.
    // Enforcing timing here causes silence or cascading re-flushes.
    // post_flush clears only when a frame is genuinely on-time, at which point
    // the anchor has settled and normal timing can re-engage.
    if (timing->anchor_valid && format->sample_rate > 0) {
      int64_t early_us = 0;
      if (compute_early_us(timing, format, hdr->rtp_timestamp, sync_mode,
                           &early_us)) {
        if (timing->post_flush) {
          // Bypass: play regardless of early/late — the phone pre-buffers
          // several seconds ahead of the anchor's current position after a
          // seek, so frames appear early through no fault of the stream.
          //
          // Track the start time so we can exit post_flush after a timeout
          // rather than requiring early to reach ±TIMING_THRESHOLD_US (which
          // may never happen if the pre-buffer depth exceeds the threshold).
          if (timing->post_flush_start_us == 0) {
            timing->post_flush_start_us = esp_timer_get_time();
          }
          int64_t flush_elapsed =
              esp_timer_get_time() - timing->post_flush_start_us;
          // Exception: frames that are MORE than POST_FLUSH_STALE_THRESHOLD_US
          // early are old-position data still draining from the TCP kernel
          // buffer (e.g. frames from 2:30 after a seek back to 0:00).  Discard
          // those so the user never hears audio from the wrong position.
          if (early_us > POST_FLUSH_STALE_THRESHOLD_US) {
            // This frame is from the wrong seek position — still draining the
            // TCP kernel buffer from before the flush.  Bulk-flush the entire
            // ring buffer so all remaining stale (and any already-queued new)
            // frames are cleared in one shot.  Draining one-by-one takes
            // hundreds of DMA callbacks (8 frames/callback × hundreds of stale
            // frames) causing seconds of silent lag that compounds each seek.
            ESP_LOGW(
                TAG, "post_flush: bulk flush %d stale frames (%lld s early)",
                audio_buffer_get_frame_count(buffer), early_us / 1000000LL);
            if (from_pending) {
              timing->pending_valid = false;
              timing->pending_frame_len = 0;
            } else {
              audio_buffer_return(buffer, item);
            }
            audio_buffer_flush(buffer);
            timing->playout_started = false;
            timing->ready_time_us = 0;
            timing->consecutive_early_frames = 0;
            timing->consecutive_late_frames = 0;
            // Keep post_flush=true so new-position frames that refill the
            // buffer will play immediately rather than waiting out the anchor.
            return 0;
          }
          // Within pre-buffer depth — play and check if we should exit.
          // Exit post_flush when either:
          //  1. early is within ±TIMING_THRESHOLD_US (anchor is on-time), or
          //  2. POST_FLUSH_TIMEOUT_US has elapsed (pre-buffer depth exceeds
          //     threshold but anchor is stable — let normal timing take over
          //     so frames are held until their scheduled play point).
          //
          // Exception: a frame that is more than POST_FLUSH_LATE_DROP_US in
          // the past is from a previous play position (typical of an AP2
          // group-rejoin where the source replays the group's continuous
          // timeline into our buffer).  Playing it would emit audibly stale
          // audio; instead drop it and continue draining within post_flush
          // so we burn through the backlog and reach the live edge.
          if (early_us < -POST_FLUSH_LATE_DROP_US) {
            if (timing->consecutive_late_frames == 0) {
              ESP_LOGW(TAG, "post_flush: dropping stale frame %lld ms late",
                       -early_us / 1000LL);
            }
            timing->consecutive_late_frames++;
            if (stats) {
              stats->late_frames++;
            }
            if (from_pending) {
              timing->pending_valid = false;
              timing->pending_frame_len = 0;
            } else {
              audio_buffer_return(buffer, item);
            }
            continue;
          }
          if ((early_us >= -TIMING_THRESHOLD_US &&
               early_us <= TIMING_THRESHOLD_US) ||
              flush_elapsed >= POST_FLUSH_TIMEOUT_US) {
            ESP_LOGI(TAG, "post_flush done: early=%lld ms, elapsed=%lld ms",
                     early_us / 1000LL, flush_elapsed / 1000LL);
            timing->post_flush = false;
            timing->post_flush_start_us = 0;
          }
          timing->consecutive_early_frames = 0;
          timing->consecutive_late_frames = 0;
          // Fall through to play the frame.
        } else if (early_us > TIMING_THRESHOLD_US) {
          timing->consecutive_early_frames++;

          // If we have had an implausibly long run of early frames the anchor
          // is probably stuck or wrong — give up on it so playback can
          // continue.  This threshold is high enough (~6 s) that it never
          // fires during normal pre-buffered-audio scenarios.
          if (timing->consecutive_early_frames > MAX_CONSECUTIVE_EARLY) {
            ESP_LOGW(TAG,
                     "Invalidating stuck anchor: consecutive=%d, early=%lld ms",
                     timing->consecutive_early_frames, early_us / 1000LL);
            timing->anchor_valid = false;
            timing->consecutive_early_frames = 0;
            // Fall through to play the frame normally
          } else {
            // Frame is early — store it as pending and output silence.
            // The pending frame is re-checked on every subsequent call;
            // once wall-clock catches up it will be played on time.
            // This is the normal path for pre-buffered audio after a pause.
            static int early_count = 0;
            early_count++;
            if (early_count % 100 == 1) {
              ESP_LOGD(TAG,
                       "Frame too early #%d: %lld ms, buffered=%d, pending=%d",
                       early_count, early_us / 1000LL, buffered_frames,
                       timing->pending_valid ? 1 : 0);
            }
            if (!from_pending && timing->pending_frame &&
                item_size <= timing->pending_frame_capacity) {
              memcpy(timing->pending_frame, item, item_size);
              timing->pending_frame_len = item_size;
              timing->pending_valid = true;
              audio_buffer_return(buffer, item);
            }
            memset(out, 0, samples * channels * sizeof(int16_t));
            return samples;
          }
        } else if (early_us < -TIMING_THRESHOLD_US) {
          // Reset consecutive early counter on late/normal frames
          timing->consecutive_early_frames = 0;
          timing->consecutive_late_frames++;

          // Late frame — drop it and continue draining within the SAME call.
          // The 256-attempt drain loop chews through stale frames at zero
          // wall-time cost.  We used to bulk-flush the whole buffer on
          // >2 s late frames as a shortcut, but that path:
          //  - re-armed post_flush, which then played the very next stale
          //    frame unconditionally (producing audible jitter), and
          //  - returned silence to the DMA, burning ~23 ms of wall time
          //    while RTP didn't advance — each cycle made us more late and
          //    we could never catch up (observed in AirPlay 2 group rejoin,
          //    where the source's anchor is set in the past relative to
          //    current PTP time and frames pour in 1.5–2 s late).
          // Dropping & continuing lets the drain loop skip past arbitrarily
          // many stale frames in one call.
          if (timing->consecutive_late_frames == 1) {
            ESP_LOGW(TAG, "Dropping late frame(s): %lld ms",
                     -early_us / 1000LL);
          }
          if (stats) {
            stats->late_frames++;
          }
          if (from_pending) {
            timing->pending_valid = false;
            timing->pending_frame_len = 0;
          } else {
            audio_buffer_return(buffer, item);
          }
          continue;
        }
      }
    }

    // Frame is on time (or anchor-invalid) — reset counters.
    timing->consecutive_early_frames = 0;
    timing->consecutive_late_frames = 0;

    // Copy PCM data to output
    memcpy(out, pcm, frame_samples * channels * sizeof(int16_t));

    // Cleanup
    if (from_pending) {
      timing->pending_valid = false;
      timing->pending_frame_len = 0;
    } else {
      audio_buffer_return(buffer, item);
    }

    if (!timing->playout_started) {
      timing->playout_started = true;
    }

    // Tick the fill-depth controller's rate limiter once per played frame.
    if (timing->frames_since_correction < UINT32_MAX) {
      timing->frames_since_correction++;
    }

    return frame_samples;
  }

  return 0;
}
