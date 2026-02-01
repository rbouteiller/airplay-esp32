#include <stdlib.h>
#include <string.h>

#include "audio_timing.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "ntp_clock.h"
#include "ptp_clock.h"

#define DEFAULT_BUFFER_LATENCY_US     500000 // 500ms buffer for network jitter
#define HARDWARE_OUTPUT_LATENCY_US    46000  // ~46ms I2S DMA latency
#define MIN_STARTUP_FRAMES            4
#define DRIFT_ADJUST_THRESHOLD_FRAMES 2
#define TIMING_THRESHOLD_US           40000 // 40ms early/late threshold
#define MAX_EARLY_US                  500000 // 500ms max early - play anyway if older
#define MAX_CONSECUTIVE_EARLY \
  50 // Invalidate anchor after this many early frames

static const char *TAG = "audio_time";
static int consecutive_early_frames = 0;

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

  // Account for accumulated pause time - shift "now" backwards by pause
  // duration This effectively makes the buffered frames appear "on time" after
  // resume
  int64_t adjusted_now_ns = now_ns - timing->total_pause_duration_ns;

  *early_us = (target_ns - adjusted_now_ns) / 1000LL;

  // Debug: log when pause offset is significant
  static int log_count = 0;
  if (timing->total_pause_duration_ns > 0 && (log_count++ % 500 == 0)) {
    ESP_LOGD(TAG, "Timing: pause_offset=%lld ms, early=%lld ms",
             timing->total_pause_duration_ns / 1000000LL, *early_us / 1000LL);
  }

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
  timing->pause_start_time_ns = 0;
  timing->total_pause_duration_ns = 0;
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

void audio_timing_set_anchor(audio_timing_t *timing,
                             const audio_format_t *format, uint64_t clock_id,
                             uint64_t network_time_ns, uint32_t rtp_time) {
  if (!timing || !format) {
    return;
  }

  (void)clock_id;

  int64_t now_ns = (int64_t)esp_timer_get_time() * 1000LL;

  ESP_LOGI(TAG, "set_anchor: rtp=%lu, network_time=%llu ns",
           (unsigned long)rtp_time, (unsigned long long)network_time_ns);

  timing->anchor_rtp_time = rtp_time;
  timing->anchor_network_time_ns = network_time_ns;
  timing->anchor_local_time_ns = now_ns;
  timing->ptp_locked = ptp_clock_is_locked();
  timing->anchor_valid = true;

  // Reset pause tracking on new anchor - fresh timing baseline
  timing->total_pause_duration_ns = 0;
  timing->pause_start_time_ns = 0;
}

void audio_timing_set_playing(audio_timing_t *timing, bool playing) {
  if (!timing) {
    return;
  }

  int64_t now_ns = (int64_t)esp_timer_get_time() * 1000LL;

  ESP_LOGI(TAG, "set_playing: %s -> %s, pause_start=%lld, total_pause=%lld ms",
           timing->playing ? "playing" : "paused",
           playing ? "playing" : "paused", timing->pause_start_time_ns,
           timing->total_pause_duration_ns / 1000000LL);

  if (!playing && timing->playing) {
    // Transitioning to paused state - record pause start time
    timing->pause_start_time_ns = now_ns;
    ESP_LOGI(TAG, "Playback paused at %lld ns", now_ns);
  } else if (playing && !timing->playing) {
    // Transitioning to playing state - accumulate pause duration
    if (timing->pause_start_time_ns > 0) {
      int64_t pause_duration = now_ns - timing->pause_start_time_ns;
      timing->total_pause_duration_ns += pause_duration;
      ESP_LOGI(
          TAG,
          "Playback resumed after %lld ms pause, total pause offset: %lld ms",
          pause_duration / 1000000LL,
          timing->total_pause_duration_ns / 1000000LL);
    } else {
      ESP_LOGW(TAG, "Resume but pause_start_time_ns was 0!");
    }
    timing->pause_start_time_ns = 0;
  }

  timing->playing = playing;
  if (!playing) {
    // Keep anchor_valid and buffer intact - just stop consuming
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
    // Buffer is ready - wait up to 1 second for anchor to arrive
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

  for (int attempt = 0; attempt < 8; attempt++) {
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
      if (!audio_buffer_take(buffer, &item, &item_size, pdMS_TO_TICKS(10))) {
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

    // Handle early/late frames based on anchor timing
    if (timing->anchor_valid && format->sample_rate > 0) {
      int64_t early_us = 0;
      if (compute_early_us(timing, format, hdr->rtp_timestamp, sync_mode,
                           &early_us)) {
        if (early_us > TIMING_THRESHOLD_US) {
          consecutive_early_frames++;

          // If frame is way too early or we've had too many early frames,
          // the anchor is probably wrong - invalidate it and play normally
          if (early_us > MAX_EARLY_US ||
              consecutive_early_frames > MAX_CONSECUTIVE_EARLY) {
            ESP_LOGW(TAG, "Invalidating anchor: early_us=%lld, consecutive=%d",
                     early_us / 1000LL, consecutive_early_frames);
            timing->anchor_valid = false;
            consecutive_early_frames = 0;
            // Fall through to play the frame normally
          } else {
            // Frame is slightly early - output silence, keep frame for later
            static int early_count = 0;
            early_count++;
            if (early_count % 100 == 1) {
              ESP_LOGW(TAG,
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
          consecutive_early_frames = 0;
          // Too late: drop frame
          ESP_LOGW(TAG, "Dropping late frame: %lld ms", -early_us / 1000LL);
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

    // Frame is on time - reset early counter
    consecutive_early_frames = 0;

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

    return frame_samples;
  }

  return 0;
}
