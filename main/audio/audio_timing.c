#include <stdlib.h>
#include <string.h>

#include "audio_timing.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "ntp_clock.h"
#include "ptp_clock.h"

#define DEFAULT_BUFFER_LATENCY_US 500000 // 500ms buffer for network jitter
#define HARDWARE_OUTPUT_LATENCY_US 46000 // ~46ms I2S DMA latency
#define MIN_STARTUP_FRAMES 4
#define DRIFT_ADJUST_THRESHOLD_FRAMES 2
#define TIMING_THRESHOLD_US 40000 // 40ms early/late threshold

static const char *TAG = "audio_time";

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
  SYNC_MODE_NONE,  // No clock sync, use local anchor time
  SYNC_MODE_PTP,   // AirPlay 2 PTP sync
  SYNC_MODE_NTP,   // AirPlay 1 NTP sync
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
  timing->anchor_rtp_time = rtp_time;
  timing->anchor_network_time_ns = network_time_ns;
  timing->anchor_local_time_ns = (int64_t)esp_timer_get_time() * 1000LL;
  timing->ptp_locked = ptp_clock_is_locked();
  timing->anchor_valid = true;
}

void audio_timing_set_playing(audio_timing_t *timing, bool playing) {
  if (!timing) {
    return;
  }

  timing->playing = playing;
  if (!playing) {
    timing->playout_started = false;
    timing->anchor_valid = false;
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
          // Too early: output silence, keep frame for later
          if (!from_pending && timing->pending_frame &&
              item_size <= timing->pending_frame_capacity) {
            memcpy(timing->pending_frame, item, item_size);
            timing->pending_frame_len = item_size;
            timing->pending_valid = true;
            audio_buffer_return(buffer, item);
          }
          memset(out, 0, samples * channels * sizeof(int16_t));
          return samples;
        } else if (early_us < -TIMING_THRESHOLD_US) {
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
