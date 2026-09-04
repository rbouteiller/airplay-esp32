#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "audio_clock_map.h"
#include "audio_timeline.h"

typedef enum {
  AUDIO_SCHED_IDLE = 0,
  AUDIO_SCHED_WAIT_ANCHOR,
  AUDIO_SCHED_PREROLL,
  AUDIO_SCHED_PLAYING,
  AUDIO_SCHED_PAUSED,
  AUDIO_SCHED_RECOVERING,
} audio_scheduler_state_t;

typedef enum {
  AUDIO_SCHED_WAIT_NONE = 0,
  AUDIO_SCHED_WAIT_PAUSED,
  AUDIO_SCHED_WAIT_CLOCK_MAP,
  AUDIO_SCHED_WAIT_PTP_TO_RTP,
  AUDIO_SCHED_WAIT_PREROLL,
  AUDIO_SCHED_WAIT_FALLBACK_DATA,
} audio_scheduler_wait_reason_t;

typedef struct {
  audio_scheduler_state_t state;
  uint32_t epoch;
  uint32_t cursor_rtp;
  uint32_t wanted_rtp;
  uint32_t preroll_samples;
  int64_t preroll_started_us;
  int64_t fallback_after_us;
  /* Raw block-boundary error is useful for debugging but contains the
   * expected callback/DMA phase sawtooth. filtered_playout_error_q16 tracks
   * the same error at the rendered block midpoint with a 1/8 IIR filter. */
  int32_t raw_playout_error_samples;
  /* Peak-to-peak span of the raw error since the last status log, i.e. the
   * measurement noise floor the servo thresholds have to clear. */
  int32_t raw_error_min_samples;
  int32_t raw_error_max_samples;
  bool raw_error_span_valid;
  int32_t playout_error_samples;
  int64_t filtered_playout_error_q16;
  int32_t max_abs_playout_error_samples;
  int32_t estimated_drift_ppm;
  int64_t drift_reference_error_q16;
  int64_t drift_reference_network_ns;
  uint64_t rendered_samples;
  bool error_filter_valid;
  /* Drift servo: closes the loop between the output crystal and the sender's
   * clock by trimming one sample at a time.  See audio_scheduler.c. */
  int64_t drift_servo_accum;
  uint32_t drift_servo_phase;
  uint32_t drift_servo_trims;
  uint32_t drift_servo_warmup;
  audio_scheduler_wait_reason_t wait_reason;
  uint64_t render_calls;
  uint64_t silent_render_calls;
  uint64_t start_attempts;
  uint64_t fallback_attempts;
} audio_scheduler_t;

void audio_scheduler_init(audio_scheduler_t *scheduler,
                          uint32_t preroll_samples, int64_t fallback_after_us);
void audio_scheduler_begin_epoch(audio_scheduler_t *scheduler, uint32_t epoch,
                                 int64_t now_us);
void audio_scheduler_set_paused(audio_scheduler_t *scheduler, bool paused);

size_t audio_scheduler_render(audio_scheduler_t *scheduler,
                              audio_timeline_t *timeline,
                              const audio_clock_map_t *clock_map,
                              int64_t output_network_ns, int16_t *out,
                              size_t samples, uint8_t channels,
                              size_t *concealed_samples);

const char *audio_scheduler_state_name(audio_scheduler_state_t state);
const char *
audio_scheduler_wait_reason_name(audio_scheduler_wait_reason_t reason);
