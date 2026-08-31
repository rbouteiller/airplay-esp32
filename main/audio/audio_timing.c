#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "audio_timing.h"

#include "audio_output.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "ntp_clock.h"
#include "ptp_clock.h"

#define DEFAULT_BUFFER_LATENCY_US 2000 // 2ms startup jitter buffer
// Additional pipeline latency to account for task scheduling, I2S write
// blocking, and resampler processing.  Without this, frames pass the
// timing check "on time" but actually exit the speaker several ms later.
#define PIPELINE_LATENCY_US 5000 // ~5ms scheduling + write delay

static const char *TAG = "audio_time";

void audio_timing_init(audio_timing_t *timing) {
  if (!timing) {
    return;
  }

  memset(timing, 0, sizeof(*timing));
  timing->output_latency_us = DEFAULT_BUFFER_LATENCY_US;
  timing->playing = true;
}

void audio_timing_reset(audio_timing_t *timing) {
  if (!timing) {
    return;
  }

  timing->anchor_valid = false;
  timing->deferred_flush_pending = false;
  timing->flush_until_ts = 0;
}

void audio_timing_set_output_latency(audio_timing_t *timing,
                                     uint32_t latency_us) {
  if (!timing) {
    return;
  }

  timing->output_latency_us = latency_us;
}

uint32_t audio_timing_get_output_latency(const audio_timing_t *timing) {
  if (!timing) {
    return 0;
  }

  return timing->output_latency_us;
}

uint32_t audio_timing_get_hardware_latency(void) {
  return audio_output_get_hardware_latency_us();
}

uint32_t audio_timing_get_advertised_latency(const audio_timing_t *timing) {
  // Total end-to-end latency between the phone scheduling a frame and the
  // DAC emitting it.  Reported to the phone in outputLatencyMicros so it
  // schedules sends to land in our sorted buffer at the right time.
  //
  //   output_latency_us         — controller target (jitter-buffer depth)
  // + audio_output_get_hardware_latency_us() — I2S DMA delay (dynamic)
  // + PIPELINE_LATENCY_US — scheduling + write delay constant
  uint32_t base =
      timing ? timing->output_latency_us : DEFAULT_BUFFER_LATENCY_US;
  return base + audio_output_get_hardware_latency_us() + PIPELINE_LATENCY_US;
}

void audio_timing_set_playout_latency(audio_timing_t *timing,
                                      uint32_t latency_samples) {
  if (!timing) {
    return;
  }
  timing->playout_latency_samples = latency_samples;
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

  // Compute lead time: how far in the future this anchor's network timestamp
  // is relative to now.  Negative means the anchor is already in the past
  // (normal: the phone pre-buffers and the anchor is 200–800 ms old by the
  // time we receive it).
  int64_t lead_ms = ((int64_t)network_time_ns -
                     (int64_t)(ptp_clock_get_offset_ns() + now_ns)) /
                    1000000LL;
  ESP_LOGI(TAG, "Anchor set: rtp=%" PRIu32 " lead=%lld ms ptp_locked=%d",
           rtp_time, (long long)lead_ms, timing->ptp_locked);
}

void audio_timing_set_playing(audio_timing_t *timing, bool playing) {
  if (!timing) {
    return;
  }

  ESP_LOGI(TAG, "set_playing: %s -> %s", timing->playing ? "playing" : "paused",
           playing ? "playing" : "paused");

  timing->playing = playing;
}

bool audio_timing_take_deferred_flush(audio_timing_t *timing,
                                      uint32_t timestamp,
                                      uint32_t *flush_until_ts) {
  if (!timing || !timing->deferred_flush_pending) {
    return false;
  }

  const uint32_t until = timing->flush_until_ts;
  // Signed 32-bit subtraction handles RTP wraparound correctly.
  if ((int32_t)(timestamp - until) < 0) {
    return false;
  }

  // Test-and-clear: the RTSP task can re-arm at any moment, and only the
  // caller that observes the transition may act on it.
  if (!__atomic_exchange_n(&timing->deferred_flush_pending, false,
                           __ATOMIC_SEQ_CST)) {
    return false;
  }

  if (flush_until_ts) {
    *flush_until_ts = until;
  }
  return true;
}
