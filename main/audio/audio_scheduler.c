// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "audio_scheduler.h"

#include <string.h>

#include "esp_timer.h"

const char *audio_scheduler_state_name(audio_scheduler_state_t state) {
  switch (state) {
  case AUDIO_SCHED_IDLE:
    return "IDLE";
  case AUDIO_SCHED_WAIT_ANCHOR:
    return "WAIT_ANCHOR";
  case AUDIO_SCHED_PREROLL:
    return "PREROLL";
  case AUDIO_SCHED_PLAYING:
    return "PLAYING";
  case AUDIO_SCHED_PAUSED:
    return "PAUSED";
  case AUDIO_SCHED_RECOVERING:
    return "RECOVERING";
  default:
    return "UNKNOWN";
  }
}

const char *
audio_scheduler_wait_reason_name(audio_scheduler_wait_reason_t reason) {
  switch (reason) {
  case AUDIO_SCHED_WAIT_NONE:
    return "NONE";
  case AUDIO_SCHED_WAIT_PAUSED:
    return "PAUSED";
  case AUDIO_SCHED_WAIT_CLOCK_MAP:
    return "CLOCK_MAP";
  case AUDIO_SCHED_WAIT_PTP_TO_RTP:
    return "PTP_TO_RTP";
  case AUDIO_SCHED_WAIT_PREROLL:
    return "PREROLL";
  case AUDIO_SCHED_WAIT_FALLBACK_DATA:
    return "FALLBACK_DATA";
  default:
    return "UNKNOWN";
  }
}

static void output_silence(int16_t *out, size_t samples, uint8_t channels) {
  memset(out, 0, samples * channels * sizeof(int16_t));
}

/* A servo trim moves the source one frame against the output.  Duplicating or
 * dropping a frame does that in one step, which shifts the phase of everything
 * playing at that instant -- 13 degrees at 1600 Hz -- and a sine tone carried
 * a pop at every trim, however quiet the frame chosen for it.  The move is
 * spread over the whole render block instead: output frame k reads the source
 * at k + trim_progress(k) for a shrink and k - trim_progress(k) for a stretch,
 * the progress rising smoothly from 0 to 1, and positions between frames are
 * read through a windowed-sinc interpolator.  For those 8 ms the playback rate
 * is off by at most 0.56 %, so a tone's phase turns gradually and nothing
 * lands outside its own critical band.
 *
 * The kernel reads TRIM_REACH frames either side of a position, so the ramp
 * starts and ends that far inside the block and the source that was read is
 * all it ever needs. */
#define TRIM_REACH 8
#define TRIM_TAPS  (2 * TRIM_REACH)
/* A block too short for a ramp at least as long as the kernel is not trimmed;
 * every playback task renders 353 frames. */
#define TRIM_MIN_FRAMES (4 * TRIM_REACH)
/* Output frames held back while the source behind them is still being read;
 * TRIM_REACH + 1 at most, rounded up to a power of two. */
#define TRIM_PENDING 16

/* How far through the trim output frame k of a block is, in Q16: 0 up to
 * TRIM_REACH frames in, 1 from TRIM_REACH frames before the end, and
 * 6t^5 - 15t^4 + 10t^3 between them, whose first two derivatives vanish at
 * both ends, so the rate leaves 1 and returns to it without a corner. */
static int32_t trim_progress(size_t k, size_t frames) {
  if (k <= TRIM_REACH) {
    return 0;
  }
  if (k >= frames - TRIM_REACH) {
    return 65536;
  }
  const uint64_t t =
      ((uint64_t)(k - TRIM_REACH) << 16) / (frames - 2U * TRIM_REACH);
  const uint64_t t3 = (((t * t) >> 16) * t) >> 16;
  /* 6t^2 - 15t + 10, which stays between 1 and 10 for t in [0, 1]. */
  const uint64_t poly = ((6U * t * t) >> 16) + (10ULL << 16) - 15U * t;
  return (int32_t)((t3 * poly) >> 16);
}

/* Weights, in Q20 and summing to exactly 1, for reading the source mu (Q16,
 * 0 < mu < 1) past the frame under tap TRIM_REACH - 1.  The kernel is a sinc
 * under the window (1 - (x/9)^2)^6, which keeps it within -78 dB of an ideal
 * fractional delay up to 12 kHz at 44.1 kHz.
 *
 * It needs no trigonometry, which matters because the ESP32-C5 has no FPU:
 * sinc(j - mu) = (-1)^(j+1) sin(pi mu) / (pi (j - mu)), and sin(pi mu) / pi is
 * the same for every tap, so it cancels when the weights are normalised.  What
 * is left is scaled by mu (1 - mu) to keep the two taps beside mu finite. */
static void trim_kernel(int32_t mu, int32_t weight[TRIM_TAPS]) {
  /* mu (1 - mu) in Q32, at most 2^30. */
  const int32_t scale = mu * (65536 - mu);
  int64_t raw[TRIM_TAPS];
  int64_t sum = 0;
  for (int t = 0; t < TRIM_TAPS; t++) {
    const int32_t j = t + 1 - TRIM_REACH;
    const int32_t x = j * 65536 - mu;
    /* The window in Q30. */
    const int64_t x9 = x / 9;
    const int64_t u = (1LL << 30) - ((x9 * x9) >> 2);
    const int64_t u2 = (u * u + (1LL << 29)) >> 30;
    const int64_t u4 = (u2 * u2 + (1LL << 29)) >> 30;
    const int64_t window = (u4 * u2 + (1LL << 29)) >> 30;
    /* The sinc in Q28, from two 32-bit divisions: a single Q16 quotient
     * would cost the kernel 5 dB. */
    int64_t sinc;
    if (j == 0) {
      sinc = (int64_t)(65536 - mu) << 12;
    } else if (j == 1) {
      sinc = (int64_t)mu << 12;
    } else {
      const int32_t num = j % 2 != 0 ? scale : -scale;
      const int32_t whole = num / x;
      sinc = (int64_t)whole * 4096 + (num - whole * x) * 4096 / x;
    }
    raw[t] = (sinc * window + (1LL << 33)) >> 34;
    sum += raw[t];
  }
  /* sum is 0.78 to 1 in Q24, so its Q16 reciprocal fits 32 bits. */
  const uint32_t inverse = UINT32_MAX / (uint32_t)(sum >> 8);
  int32_t total = 0;
  for (int t = 0; t < TRIM_TAPS; t++) {
    weight[t] = (int32_t)((raw[t] * inverse + (1LL << 19)) >> 20);
    total += weight[t];
  }
  /* The rounding goes in the heaviest tap, so the DC gain is exactly 1. */
  weight[mu < 32768 ? TRIM_REACH - 1 : TRIM_REACH] += (1 << 20) - total;
}

/* Source frame `index` of a block being trimmed; a shrink's spare frame
 * follows the block. */
static const int16_t *trim_source(const int16_t *out, size_t frames,
                                  uint8_t channels, const int16_t *spare,
                                  size_t index) {
  return index < frames ? &out[index * channels] : spare;
}

/* Rewrite a block of source frames in `out` as `frames` output frames that
 * slip one frame against them: a stretch (direction -1) holds frames - 1
 * source frames, a shrink (+1) holds `frames` and continues into `spare`.  The
 * block is rewritten in place, front to back.  No output from frame k onwards
 * reads the source before k - TRIM_REACH, so each output frame waits in
 * `pending` until the source under it is no longer needed. */
static void trim_resample(int16_t *out, size_t frames, uint8_t channels,
                          int direction, const int16_t *spare) {
  int16_t pending[TRIM_PENDING][AUDIO_V2_MAX_CHANNELS];
  const size_t frame_bytes = (size_t)channels * sizeof(int16_t);
  for (size_t k = 0; k < frames; k++) {
    /* Source position in Q16, never negative: the ramp starts after k = 0. */
    const int64_t pos =
        (int64_t)k * 65536 + (int64_t)direction * trim_progress(k, frames);
    const size_t base = (size_t)(pos >> 16);
    const int32_t mu = (int32_t)(pos & 0xFFFF);
    int16_t *frame = pending[k % TRIM_PENDING];
    if (mu == 0) {
      memcpy(frame, trim_source(out, frames, channels, spare, base),
             frame_bytes);
    } else {
      int32_t weight[TRIM_TAPS];
      const int16_t *tap[TRIM_TAPS];
      trim_kernel(mu, weight);
      for (size_t t = 0; t < TRIM_TAPS; t++) {
        tap[t] = trim_source(out, frames, channels, spare,
                             base + t + 1U - TRIM_REACH);
      }
      for (uint8_t ch = 0; ch < channels; ch++) {
        int64_t acc = 1 << 19;
        for (size_t t = 0; t < TRIM_TAPS; t++) {
          acc += (int64_t)weight[t] * tap[t][ch];
        }
        acc >>= 20;
        frame[ch] = (int16_t)(acc > INT16_MAX   ? INT16_MAX
                              : acc < INT16_MIN ? INT16_MIN
                                                : acc);
      }
    }
    if (k >= TRIM_REACH) {
      memcpy(&out[(k - TRIM_REACH) * channels],
             pending[(k - TRIM_REACH) % TRIM_PENDING], frame_bytes);
    }
  }
  for (size_t k = frames - TRIM_REACH; k < frames; k++) {
    memcpy(&out[k * channels], pending[k % TRIM_PENDING], frame_bytes);
  }
}

/* Drift servo.  The DAC and the sender run on independent crystals, so the RTP
 * cursor advances at the output's rate while the schedule advances at the
 * sender's.  Nothing else closes that loop -- cursor_rtp is monotonic and the
 * timeline read is exact -- so an uncorrected 10-40 ppm offset walks playout
 * 40-140 ms per hour away from the rest of the group.
 *
 * The rate is proportional to the error, not gated on a hysteresis band.  Each
 * render adds error*block_size to a running sum and a trim fires whenever that
 * sum crosses DRIFT_SERVO_TRIM_THRESHOLD, which makes the trim rate
 *   trims/s = |error| * sample_rate / THRESHOLD
 * independently of the render size.  The loop settles where that equals the
 * crystal drift, so the total trim count is set by the drift alone -- 21 ppm
 * is 0.93 samples/s, i.e. ~1 trim/s no matter how the servo is tuned.  A
 * hysteresis band cannot reduce that count, it only defers the same trims into
 * a burst: a 5 ms / 1.5 ms band sat idle for 154 s and then ran 31 trims/s for
 * 5 s, and a periodic 31 Hz disturbance is far more audible than one isolated
 * trim per second.  Spreading them out is therefore both tighter and quieter.
 *
 * At the measured 21 ppm the error parks near 5 samples (0.1 ms) instead of
 * sweeping the old 1.4-5.0 ms band, which is what keeps a stereo pair aligned.
 * The closed-loop time constant is THRESHOLD / sample_rate, ~5 s, far slower
 * than the ~1 sample of measurement noise, so the loop does not chase it; the
 * sum is signed, so symmetric noise cancels rather than accumulating.
 *
 * No innovation clamp is needed here, unlike the servo this mirrors on the
 * realtime path.  That one measured error at whatever moment the playback task
 * happened to run, against a MODELLED queue depth, so a starved task always
 * measured "late" and dragged the filter down.  playout_error_samples comes
 * from audio_output_get_next_playout_time_ns(), which reads the live queue, so
 * a late call measures a correspondingly later playout instant and the error
 * stays put.  The 1/8 IIR above has only callback phase jitter left to
 * remove. */
#define DRIFT_SERVO_TRIM_THRESHOLD 237000
/* Anti-windup: bound the queued correction so a transient unwinds in two trims
 * rather than overshooting by however long it lasted. */
#define DRIFT_SERVO_ACCUM_LIMIT (2 * DRIFT_SERVO_TRIM_THRESHOLD)
/* Rate limit, in renders between trims.  At the 352-sample render quantum one
 * sample per 4 renders is 710 ppm, a 0.07 % pitch deviation and comfortably
 * under the ~0.2 % JND.  It binds only above ~3.8 ms of error, so recovery
 * from a large transient is no slower than a pure bang-bang servo. */
#define DRIFT_SERVO_MIN_TRIM_INTERVAL 4
/* Renders to ignore after an epoch starts.  The DMA ring is still filling, so
 * audio_output_get_pipeline_us() under-reports and the computed playout instant
 * lands early -- which reads as several ms of positive error that resolves
 * itself once the ring reaches steady occupancy.  ~2 s at any block size. */
#define DRIFT_SERVO_WARMUP_RENDERS 250

void audio_scheduler_init(audio_scheduler_t *scheduler,
                          uint32_t preroll_samples, int64_t fallback_after_us) {
  if (!scheduler) {
    return;
  }
  *scheduler = (audio_scheduler_t){
      .state = AUDIO_SCHED_IDLE,
      .preroll_samples = preroll_samples,
      .fallback_after_us = fallback_after_us,
  };
}

void audio_scheduler_begin_epoch(audio_scheduler_t *scheduler, uint32_t epoch,
                                 int64_t now_us) {
  if (!scheduler) {
    return;
  }
  scheduler->state = AUDIO_SCHED_WAIT_ANCHOR;
  scheduler->epoch = epoch;
  scheduler->cursor_rtp = 0;
  scheduler->preroll_started_us = now_us;
  scheduler->wanted_rtp = 0;
  scheduler->raw_playout_error_samples = 0;
  scheduler->raw_error_span_valid = false;
  scheduler->playout_error_samples = 0;
  scheduler->filtered_playout_error_q16 = 0;
  scheduler->max_abs_playout_error_samples = 0;
  scheduler->estimated_drift_ppm = 0;
  scheduler->drift_reference_error_q16 = 0;
  scheduler->drift_reference_network_ns = 0;
  scheduler->rendered_samples = 0;
  scheduler->error_filter_valid = false;
  scheduler->drift_servo_accum = 0;
  scheduler->drift_servo_phase = 0;
  scheduler->drift_servo_warmup = 0;
  scheduler->drift_servo_trims = 0;
  scheduler->wait_reason = AUDIO_SCHED_WAIT_CLOCK_MAP;
  scheduler->render_calls = 0;
  scheduler->silent_render_calls = 0;
  scheduler->start_attempts = 0;
  scheduler->fallback_attempts = 0;
}

void audio_scheduler_set_paused(audio_scheduler_t *scheduler, bool paused) {
  if (!scheduler) {
    return;
  }
  scheduler->state = paused ? AUDIO_SCHED_PAUSED : AUDIO_SCHED_PREROLL;
  scheduler->wait_reason =
      paused ? AUDIO_SCHED_WAIT_PAUSED : AUDIO_SCHED_WAIT_PREROLL;
}

size_t audio_scheduler_render(audio_scheduler_t *scheduler,
                              audio_timeline_t *timeline,
                              const audio_clock_map_t *clock_map,
                              int64_t output_network_ns, int16_t *out,
                              size_t samples, uint8_t channels,
                              size_t *concealed_samples) {
  if (concealed_samples) {
    *concealed_samples = 0;
  }
  if (!scheduler || !timeline || !clock_map || !out || samples == 0U) {
    return 0;
  }
  scheduler->render_calls++;

  if (scheduler->state == AUDIO_SCHED_PAUSED ||
      scheduler->state == AUDIO_SCHED_IDLE) {
    scheduler->wait_reason = AUDIO_SCHED_WAIT_PAUSED;
    scheduler->silent_render_calls++;
    output_silence(out, samples, channels);
    return samples;
  }

  if (!clock_map->valid) {
    scheduler->state = AUDIO_SCHED_WAIT_ANCHOR;
    scheduler->wait_reason = AUDIO_SCHED_WAIT_CLOCK_MAP;
    scheduler->silent_render_calls++;
    output_silence(out, samples, channels);
    return samples;
  }

  uint32_t wanted_rtp = 0;
  if (!audio_clock_map_network_to_rtp(clock_map, output_network_ns,
                                      &wanted_rtp)) {
    scheduler->wait_reason = AUDIO_SCHED_WAIT_PTP_TO_RTP;
    scheduler->silent_render_calls++;
    output_silence(out, samples, channels);
    return samples;
  }

  scheduler->wanted_rtp = wanted_rtp;
  scheduler->wait_reason = AUDIO_SCHED_WAIT_NONE;
  /* +1 plays one source sample more than the block holds (playout speeds up),
   * -1 one fewer (it slows down).  Applied at the timeline read below. */
  int drift_adjust = 0;
  if (scheduler->state == AUDIO_SCHED_PLAYING) {
    /* Compare the midpoint of the block that is about to be submitted with
     * the RTP position scheduled for that same midpoint.  Measuring only the
     * block start aliases the 352-frame callback cadence into a 0..8 ms
     * sawtooth even when the underlying clock is stable. */
    uint32_t midpoint_samples = (uint32_t)(samples / 2U);
    int64_t midpoint_network_ns =
        output_network_ns +
        ((int64_t)midpoint_samples * 1000000000LL) / clock_map->sample_rate;
    uint32_t wanted_mid_rtp = wanted_rtp;
    (void)audio_clock_map_network_to_rtp(clock_map, midpoint_network_ns,
                                         &wanted_mid_rtp);
    uint32_t actual_mid_rtp = scheduler->cursor_rtp + midpoint_samples;
    int32_t raw_error = (int32_t)(actual_mid_rtp - wanted_mid_rtp);
    scheduler->raw_playout_error_samples = raw_error;
    if (!scheduler->raw_error_span_valid) {
      scheduler->raw_error_span_valid = true;
      scheduler->raw_error_min_samples = raw_error;
      scheduler->raw_error_max_samples = raw_error;
    } else {
      if (raw_error < scheduler->raw_error_min_samples) {
        scheduler->raw_error_min_samples = raw_error;
      }
      if (raw_error > scheduler->raw_error_max_samples) {
        scheduler->raw_error_max_samples = raw_error;
      }
    }

    int64_t raw_q16 = (int64_t)raw_error * 65536LL;
    if (!scheduler->error_filter_valid) {
      scheduler->filtered_playout_error_q16 = raw_q16;
      scheduler->error_filter_valid = true;
      scheduler->drift_reference_error_q16 = raw_q16;
      scheduler->drift_reference_network_ns = midpoint_network_ns;
    } else {
      /* alpha = 1/8: removes callback phase jitter while still following
       * real clock drift within a few hundred milliseconds. */
      scheduler->filtered_playout_error_q16 +=
          (raw_q16 - scheduler->filtered_playout_error_q16) / 8;
    }
    scheduler->playout_error_samples =
        scheduler->filtered_playout_error_q16 >> 16;

    int32_t abs_error = scheduler->playout_error_samples < 0
                            ? -scheduler->playout_error_samples
                            : scheduler->playout_error_samples;
    if (abs_error > scheduler->max_abs_playout_error_samples) {
      scheduler->max_abs_playout_error_samples = abs_error;
    }

    if (scheduler->drift_reference_network_ns != 0 &&
        midpoint_network_ns - scheduler->drift_reference_network_ns >=
            1000000000LL) {
      int64_t elapsed_ns =
          midpoint_network_ns - scheduler->drift_reference_network_ns;
      int64_t delta_q16 = scheduler->filtered_playout_error_q16 -
                          scheduler->drift_reference_error_q16;
      int64_t elapsed_samples =
          (elapsed_ns * (int64_t)clock_map->sample_rate) / 1000000000LL;
      if (elapsed_samples > 0) {
        /* Divide in q16: truncating delta to whole samples first would
         * quantise the result to one sample per window, 22 ppm at 44.1 kHz. */
        int64_t ppm = (delta_q16 * 1000000LL) / (elapsed_samples * 65536LL);
        if (ppm > 20000)
          ppm = 20000;
        if (ppm < -20000)
          ppm = -20000;
        scheduler->estimated_drift_ppm = (int32_t)ppm;
      }
      scheduler->drift_reference_error_q16 =
          scheduler->filtered_playout_error_q16;
      scheduler->drift_reference_network_ns = midpoint_network_ns;
    }

    /* A trim is spread over its block, which needs room for the ramp and
     * somewhere to keep the frames waiting to be written back. */
    const bool trimmable =
        samples >= TRIM_MIN_FRAMES && channels <= AUDIO_V2_MAX_CHANNELS;
    if (scheduler->drift_servo_warmup < DRIFT_SERVO_WARMUP_RENDERS) {
      scheduler->drift_servo_warmup++;
    } else {
      scheduler->drift_servo_accum +=
          (int64_t)scheduler->playout_error_samples * (int64_t)samples;
      if (scheduler->drift_servo_accum > DRIFT_SERVO_ACCUM_LIMIT) {
        scheduler->drift_servo_accum = DRIFT_SERVO_ACCUM_LIMIT;
      } else if (scheduler->drift_servo_accum < -DRIFT_SERVO_ACCUM_LIMIT) {
        scheduler->drift_servo_accum = -DRIFT_SERVO_ACCUM_LIMIT;
      }
      if (scheduler->drift_servo_phase < DRIFT_SERVO_MIN_TRIM_INTERVAL) {
        scheduler->drift_servo_phase++;
      } else if (trimmable &&
                 scheduler->drift_servo_accum >= DRIFT_SERVO_TRIM_THRESHOLD) {
        /* Cursor ahead of schedule means this device is playing early, so
         * hold it back by a sample. */
        scheduler->drift_servo_accum -= DRIFT_SERVO_TRIM_THRESHOLD;
        drift_adjust = -1;
        scheduler->drift_servo_phase = 0;
        scheduler->drift_servo_trims++;
      } else if (trimmable &&
                 scheduler->drift_servo_accum <= -DRIFT_SERVO_TRIM_THRESHOLD) {
        /* Behind schedule: take one sample more to catch up. */
        scheduler->drift_servo_accum += DRIFT_SERVO_TRIM_THRESHOLD;
        drift_adjust = 1;
        scheduler->drift_servo_phase = 0;
        scheduler->drift_servo_trims++;
      }
    }
  }

  if (scheduler->state != AUDIO_SCHED_PLAYING) {
    uint32_t start_rtp = 0;
    scheduler->start_attempts++;

    /* Audio behind the playout position can never be used, but the ring origin
     * is pinned at the first block received after a flush.  A skip whose anchor
     * is already seconds old therefore fills the whole ring with unplayable
     * audio, at which point backpressure throttles the reader and reserve()
     * fails — wanted_rtp is never reached and the stream wedges silently.
     * Publishing the floor makes that audio recyclable; trimming keeps the
     * occupancy count honest so the reader is not throttled against it. */
    audio_timeline_set_playback_floor(timeline, scheduler->epoch, wanted_rtp);
    if (audio_timeline_is_nearly_full(timeline)) {
      (void)audio_timeline_trim_before(timeline, scheduler->epoch, wanted_rtp);
    }

    /* Start in sample coordinates, not block coordinates.  The requested RTP
     * may fall anywhere inside a 1024-sample AAC PCM frame.  The timeline
     * verifies that a continuous preroll exists from that exact sample and
     * returns the same RTP value, rather than rounding to the next block
     * boundary. */
    if (audio_timeline_find_contiguous_from(
            timeline, scheduler->epoch, wanted_rtp, scheduler->preroll_samples,
            0U, &start_rtp)) {
      scheduler->cursor_rtp = start_rtp;
      /* O(1): older preroll becomes lazily reclaimable on ring collision.
       * No 192-slot cleanup scan is performed at start. */
      audio_timeline_set_playback_floor(timeline, scheduler->epoch,
                                        scheduler->cursor_rtp);
      scheduler->state = AUDIO_SCHED_PLAYING;
      scheduler->wait_reason = AUDIO_SCHED_WAIT_NONE;
      scheduler->error_filter_valid = false;
      scheduler->raw_playout_error_samples = 0;
      scheduler->playout_error_samples = 0;
      scheduler->filtered_playout_error_q16 = 0;
      scheduler->drift_reference_error_q16 = 0;
      scheduler->drift_reference_network_ns = 0;
      scheduler->drift_servo_accum = 0;
      scheduler->drift_servo_phase = 0;
      scheduler->drift_servo_warmup = 0;
    } else {
      /* fallback_after_us is an elapsed-time timeout.  Both timestamps
       * must use the same monotonic local clock.  preroll_started_us is set
       * from esp_timer_get_time() when an epoch/anchor wait begins, while
       * output_network_ns belongs to the sender's clock domain and must not
       * be compared with it. */
      int64_t now_us = esp_timer_get_time();
      bool fallback_due = scheduler->fallback_after_us > 0 &&
                          scheduler->preroll_started_us > 0 &&
                          now_us >= scheduler->preroll_started_us &&
                          now_us - scheduler->preroll_started_us >=
                              scheduler->fallback_after_us;

      /* Fallback stays sample-granular, but one render quantum of runway is
       * not enough: playback underruns on the very next callback, re-enters
       * preroll and starts again, which is the double `start decision' plus
       * conceal seen after a seek.  Require a quarter of the configured
       * preroll so arriving AAC frames have somewhere to land first. */
      uint32_t fallback_samples = scheduler->preroll_samples / 4U;
      if (fallback_samples < AUDIO_V2_BLOCK_SAMPLES) {
        fallback_samples = AUDIO_V2_BLOCK_SAMPLES;
      }
      if (fallback_due) {
        scheduler->fallback_attempts++;
      }
      if (fallback_due &&
          audio_timeline_find_contiguous_from(
              timeline, scheduler->epoch, wanted_rtp, fallback_samples,
              AUDIO_V2_BLOCK_SAMPLES, &start_rtp)) {
        scheduler->cursor_rtp = start_rtp;
        /* O(1) recovery jump: skipped READY slots are reclaimed lazily. */
        audio_timeline_set_playback_floor(timeline, scheduler->epoch,
                                          scheduler->cursor_rtp);
        scheduler->wait_reason = AUDIO_SCHED_WAIT_NONE;
        scheduler->state = AUDIO_SCHED_PLAYING;
        scheduler->error_filter_valid = false;
        scheduler->raw_playout_error_samples = 0;
        scheduler->playout_error_samples = 0;
        scheduler->filtered_playout_error_q16 = 0;
        scheduler->drift_reference_error_q16 = 0;
        scheduler->drift_reference_network_ns = 0;
        scheduler->drift_servo_accum = 0;
        scheduler->drift_servo_phase = 0;
        scheduler->drift_servo_warmup = 0;
      } else {
        scheduler->state = AUDIO_SCHED_PREROLL;
        scheduler->wait_reason = fallback_due ? AUDIO_SCHED_WAIT_FALLBACK_DATA
                                              : AUDIO_SCHED_WAIT_PREROLL;
        scheduler->silent_render_calls++;
        output_silence(out, samples, channels);
        return samples;
      }
    }
  }

  /* A short hole with a known next block can be concealed safely by the
   * timeline reader.  A completely empty/unusable timeline is different:
   * advancing cursor_rtp through unlimited silence makes newly arriving PCM
   * permanently stale and leaves playout hundreds of milliseconds away from
   * the PTP clock.  Stop advancing the RTP cursor and re-enter preroll so the
   * next usable island is selected from the current wanted_rtp. */
  if (!audio_timeline_has_playable_from(timeline, scheduler->epoch,
                                        scheduler->cursor_rtp)) {
    scheduler->state = AUDIO_SCHED_RECOVERING;
    scheduler->wait_reason = AUDIO_SCHED_WAIT_FALLBACK_DATA;
    scheduler->preroll_started_us = esp_timer_get_time();
    scheduler->error_filter_valid = false;
    scheduler->raw_playout_error_samples = 0;
    scheduler->playout_error_samples = 0;
    scheduler->filtered_playout_error_q16 = 0;
    scheduler->drift_reference_error_q16 = 0;
    scheduler->drift_reference_network_ns = 0;
    scheduler->drift_servo_accum = 0;
    scheduler->drift_servo_phase = 0;
    scheduler->drift_servo_warmup = 0;
    scheduler->silent_render_calls++;
    output_silence(out, samples, channels);
    return samples;
  }

  /* Stretch: read one sample fewer and resample it to the full block, so the
   * block the caller writes stays the same length while the source cursor
   * advances one sample less.  Shrink is the mirror -- read the full block
   * plus one spare frame and resample all of it into the block.  Rewinding the
   * cursor is not an option because audio_timeline_read() retires a block as
   * soon as it is fully consumed. */
  size_t request = samples;
  if (drift_adjust < 0) {
    request--;
  }

  size_t produced =
      audio_timeline_read(timeline, scheduler->epoch, scheduler->cursor_rtp,
                          out, request, channels, true, concealed_samples);
  scheduler->cursor_rtp += (uint32_t)produced;
  scheduler->rendered_samples += produced;
  if (produced < request) {
    output_silence(&out[produced * channels], request - produced, channels);
    produced = request;
  }
  if (drift_adjust < 0) {
    trim_resample(out, samples, channels, -1, NULL);
    produced = samples;
  } else if (drift_adjust > 0) {
    int16_t spare[AUDIO_V2_MAX_CHANNELS];
    size_t spare_concealed = 0;
    if (audio_timeline_read(timeline, scheduler->epoch, scheduler->cursor_rtp,
                            spare, 1U, channels, true,
                            &spare_concealed) == 1U) {
      scheduler->cursor_rtp++;
      scheduler->rendered_samples++;
      trim_resample(out, samples, channels, 1, spare);
    } else {
      /* No spare frame available: fall back to skipping the next one. */
      scheduler->cursor_rtp++;
    }
    if (concealed_samples) {
      *concealed_samples += spare_concealed;
    }
  }
  return produced;
}
