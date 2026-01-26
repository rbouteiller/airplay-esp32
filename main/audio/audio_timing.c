#include <stdlib.h>
#include <string.h>

#include "audio_timing.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "ptp_clock.h"

#define DEFAULT_OUTPUT_LATENCY_US 500000
#define MIN_STARTUP_FRAMES 4
#define EARLY_SCHEDULE_THRESHOLD_US 2000
#define LATE_SCHEDULE_THRESHOLD_US 15000
#define DRIFT_ADJUST_THRESHOLD_FRAMES 2

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
      ((uint64_t)timing->output_latency_us *
       (uint64_t)format->sample_rate) /
      1000000ULL;
  uint32_t target_frames =
      (uint32_t)((latency_samples + timing->nominal_frame_samples - 1) /
                 timing->nominal_frame_samples);
  if (target_frames < MIN_STARTUP_FRAMES) {
    target_frames = MIN_STARTUP_FRAMES;
  }
  timing->target_buffer_frames = target_frames;
}

static int64_t frame_duration_us(const audio_timing_t *timing,
                                 const audio_format_t *format) {
  if (format->sample_rate <= 0 || timing->nominal_frame_samples == 0) {
    return 0;
  }

  return ((int64_t)timing->nominal_frame_samples * 1000000LL) /
         format->sample_rate;
}

static int64_t early_threshold_us(const audio_timing_t *timing,
                                  const audio_format_t *format) {
  int64_t frame_us = frame_duration_us(timing, format);
  if (frame_us <= 0) {
    return EARLY_SCHEDULE_THRESHOLD_US;
  }

  if (frame_us < EARLY_SCHEDULE_THRESHOLD_US) {
    return EARLY_SCHEDULE_THRESHOLD_US;
  }

  return frame_us;
}

static int64_t late_threshold_us(const audio_timing_t *timing,
                                 const audio_format_t *format) {
  int64_t frame_us = frame_duration_us(timing, format);
  if (frame_us <= 0) {
    return LATE_SCHEDULE_THRESHOLD_US;
  }

  int64_t threshold = frame_us * 2;
  if (threshold < LATE_SCHEDULE_THRESHOLD_US) {
    return LATE_SCHEDULE_THRESHOLD_US;
  }

  return threshold;
}

static bool compute_target_local_ns(const audio_timing_t *timing,
                                    const audio_format_t *format,
                                    uint32_t rtp_timestamp, bool use_offset,
                                    int64_t offset_ns,
                                    int64_t anchor_time_offset_ns,
                                    int64_t *target_local_ns) {
  if (!timing->anchor_valid || format->sample_rate <= 0) {
    return false;
  }

  int32_t rtp_delta =
      (int32_t)(rtp_timestamp - timing->anchor_rtp_time);
  int64_t frame_offset_ns =
      ((int64_t)rtp_delta * 1000000000LL) / format->sample_rate;

  int64_t anchor_local_ns = 0;
  if (use_offset) {
    anchor_local_ns = (int64_t)timing->anchor_network_time_ns +
                      anchor_time_offset_ns - offset_ns;
  } else if (timing->anchor_local_time_ns != 0) {
    anchor_local_ns = timing->anchor_local_time_ns;
  } else {
    return false;
  }

  *target_local_ns = anchor_local_ns + frame_offset_ns;
  return true;
}

static bool compute_early_us(const audio_timing_t *timing,
                             const audio_format_t *format,
                             uint32_t rtp_timestamp, bool use_offset,
                             int64_t offset_ns, int64_t anchor_time_offset_ns,
                             int64_t *early_us) {
  int64_t target_local_ns = 0;
  if (!compute_target_local_ns(timing, format, rtp_timestamp, use_offset,
                               offset_ns, anchor_time_offset_ns,
                               &target_local_ns)) {
    return false;
  }

  int64_t now_ns = (int64_t)esp_timer_get_time() * 1000LL;
  *early_us = (target_local_ns - now_ns) / 1000LL;
  return true;
}

void audio_timing_init(audio_timing_t *timing, size_t pending_capacity) {
  if (!timing) {
    return;
  }

  memset(timing, 0, sizeof(*timing));
  timing->output_latency_us = DEFAULT_OUTPUT_LATENCY_US;
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
  timing->last_played_valid = false;
  timing->ntp_anchor_valid = false;
  timing->ntp_anchor_offset_ns = 0;
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

  timing->anchor_clock_id = clock_id;
  timing->anchor_rtp_time = rtp_time;
  timing->anchor_network_time_ns = network_time_ns;

  bool ptp_locked = ptp_clock_is_locked();
  bool ntp_locked = ntp_clock_is_locked();
  if (ptp_locked) {
    int64_t offset_ns = ptp_clock_get_offset_ns();
    timing->anchor_local_time_ns =
        (int64_t)network_time_ns - offset_ns;
    timing->ntp_anchor_valid = false;
    timing->ntp_anchor_offset_ns = 0;
  } else if (ntp_locked) {
    int64_t ntp_time_ns = (int64_t)ntp_clock_get_time_ns();
    timing->ntp_anchor_offset_ns =
        ntp_time_ns - (int64_t)network_time_ns;
    timing->ntp_anchor_valid = true;
    timing->anchor_local_time_ns = (int64_t)network_time_ns +
                                   timing->ntp_anchor_offset_ns -
                                   ntp_clock_get_offset_ns();
  } else {
    timing->anchor_local_time_ns =
        (int64_t)esp_timer_get_time() * 1000LL;
    timing->ntp_anchor_valid = false;
    timing->ntp_anchor_offset_ns = 0;
  }

  if (!timing->anchor_valid) {
    ESP_LOGI(TAG,
             "Anchor set: rtp=%u, local_time=%lld ms, ptp_locked=%d, ntp=%d",
             rtp_time, timing->anchor_local_time_ns / 1000000LL, ptp_locked,
             ntp_locked);
  }

  timing->ptp_locked = ptp_locked;
  timing->ntp_locked = ntp_locked;
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
    timing->last_played_valid = false;
    timing->ntp_anchor_valid = false;
    timing->ntp_anchor_offset_ns = 0;
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

  bool ptp_locked = ptp_clock_is_locked();
  bool ntp_locked = ntp_clock_is_locked();
  if (timing->ptp_locked && !ptp_locked) {
    if (timing->anchor_valid && timing->last_played_valid) {
      int64_t early_us = 0;
      if (compute_early_us(timing, format, timing->last_played_rtp, true,
                           ptp_clock_get_offset_ns(), 0, &early_us)) {
        if (early_us >= 0) {
          ESP_LOGW(TAG, "PTP lock lost: early by %lld ms",
                   early_us / 1000LL);
        } else {
          ESP_LOGW(TAG, "PTP lock lost: late by %lld ms",
                   (-early_us) / 1000LL);
        }
      } else {
        ESP_LOGW(TAG, "PTP lock lost (no timing reference)");
      }
    } else {
      ESP_LOGW(TAG, "PTP lock lost (no timing reference)");
    }
  }
  if (timing->ntp_locked && !ntp_locked) {
    if (timing->anchor_valid && timing->last_played_valid &&
        timing->ntp_anchor_valid) {
      int64_t early_us = 0;
      if (compute_early_us(timing, format, timing->last_played_rtp, true,
                           ntp_clock_get_offset_ns(),
                           timing->ntp_anchor_offset_ns, &early_us)) {
        if (early_us >= 0) {
          ESP_LOGW(TAG, "NTP lock lost: early by %lld ms",
                   early_us / 1000LL);
        } else {
          ESP_LOGW(TAG, "NTP lock lost: late by %lld ms",
                   (-early_us) / 1000LL);
        }
      } else {
        ESP_LOGW(TAG, "NTP lock lost (no timing reference)");
      }
    } else {
      ESP_LOGW(TAG, "NTP lock lost (no timing reference)");
    }
  }
  timing->ptp_locked = ptp_locked;
  timing->ntp_locked = ntp_locked;

  bool use_offset = false;
  int64_t offset_ns = 0;
  int64_t anchor_time_offset_ns = 0;
  const char *sync_source = "none";
  if (ptp_locked) {
    use_offset = true;
    offset_ns = ptp_clock_get_offset_ns();
    anchor_time_offset_ns = 0;
    sync_source = "ptp";
  } else if (ntp_locked && timing->ntp_anchor_valid) {
    use_offset = true;
    offset_ns = ntp_clock_get_offset_ns();
    anchor_time_offset_ns = timing->ntp_anchor_offset_ns;
    sync_source = "ntp";
  }

  bool sync_mode =
      use_offset && timing->anchor_valid && format->sample_rate > 0 &&
      stream->type != AUDIO_STREAM_BUFFERED;

  int buffered_frames = audio_buffer_get_frame_count(buffer);

  if (!timing->playout_started && !timing->pending_valid) {
    if (!timing->anchor_valid) {
      return 0;
    }
    if (buffered_frames < (int)timing->target_buffer_frames) {
      return 0;
    }
  }

  static int wait_log = 0;
  static int timing_log_count = 0;
  int64_t early_limit_us = early_threshold_us(timing, format);
  int64_t late_limit_us = late_threshold_us(timing, format);

  for (int attempt = 0; attempt < 8; attempt++) {
    size_t item_size = 0;
    void *item = NULL;
    bool from_pending = false;

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

    if (sync_mode) {
      int64_t early_us = 0;
      if (compute_early_us(timing, format, hdr->rtp_timestamp, true, offset_ns,
                           anchor_time_offset_ns, &early_us)) {
        if (early_us > early_limit_us) {
          if (!from_pending) {
            if (timing->pending_frame &&
                item_size <= timing->pending_frame_capacity) {
              memcpy(timing->pending_frame, item, item_size);
              timing->pending_frame_len = item_size;
              timing->pending_valid = true;
            }
            audio_buffer_return(buffer, item);
          }

          if (!timing->playout_started && ++wait_log % 100 == 1) {
            ESP_LOGI(TAG, "Waiting for sync: early=%lld ms, buf=%d",
                     early_us / 1000LL, buffered_frames);
          }
          return 0;
        }

        if (early_us < -late_limit_us) {
          ESP_LOGD(TAG, "Playing late frame: %lld ms late, rtp=%u, buf=%d",
                   (-early_us) / 1000LL, hdr->rtp_timestamp, buffered_frames);
        }
      }
    }

    if (timing->anchor_valid && format->sample_rate > 0) {
      if (++timing_log_count >= 4000) {
        int64_t log_early_us = 0;
        if (compute_early_us(timing, format, hdr->rtp_timestamp, use_offset,
                             offset_ns, anchor_time_offset_ns, &log_early_us)) {
          ESP_LOGI(TAG, "Timing: drift=%lld ms, sync=%s, buf=%d",
                   log_early_us / 1000LL, sync_source, buffered_frames);
        }
        timing_log_count = 0;
      }
    }

    if (frame_samples > samples) {
      frame_samples = samples;
    }

    int adjust = 0;
    if (!sync_mode && timing->anchor_valid) {
      if (buffered_frames >
          (int)timing->target_buffer_frames + DRIFT_ADJUST_THRESHOLD_FRAMES) {
        adjust = -1;
      } else if (buffered_frames <
                 (int)timing->target_buffer_frames -
                     DRIFT_ADJUST_THRESHOLD_FRAMES) {
        adjust = 1;
      }
    }

    size_t out_samples = frame_samples;
    if (adjust < 0 && out_samples > 1) {
      out_samples--;
    } else if (adjust > 0 && out_samples + 1 <= samples) {
      out_samples++;
    }

    size_t copy_samples =
        (out_samples <= frame_samples) ? out_samples : frame_samples;
    memcpy(out, pcm, copy_samples * channels * sizeof(int16_t));

    if (out_samples > frame_samples) {
      size_t base = (frame_samples - 1) * channels;
      for (size_t ch = 0; ch < channels; ch++) {
        out[frame_samples * channels + ch] = out[base + ch];
      }
    }

    uint32_t played_rtp = hdr->rtp_timestamp;
    if (from_pending) {
      timing->pending_valid = false;
      timing->pending_frame_len = 0;
    } else {
      audio_buffer_return(buffer, item);
    }
    timing->last_played_rtp = played_rtp;
    timing->last_played_valid = true;
    if (!timing->playout_started) {
      timing->playout_started = true;
      ESP_LOGI(TAG, "Playout started: anchor_valid=%d, sync=%s, latency=%u us",
               timing->anchor_valid, sync_source,
               timing->output_latency_us);
    }
    return out_samples;
  }

  return 0;
}
