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

/* Index of the quietest frame in a block (smallest summed magnitude across the
 * channels).  A servo trim duplicates or drops exactly one frame; doing that
 * where the waveform is near zero leaves a seam proportional to the local
 * slope, so it stays inaudible on loud tonal content that would click if the
 * block's last frame were trimmed regardless of amplitude. */
static size_t quietest_frame_index(const int16_t *pcm, size_t frames,
                                   uint8_t channels) {
  size_t best = frames > 0U ? frames - 1U : 0U;
  int32_t best_mag = INT32_MAX;
  for (size_t i = 0; i < frames; i++) {
    int32_t mag = 0;
    for (uint8_t ch = 0; ch < channels; ch++) {
      const int32_t s = pcm[i * channels + ch];
      mag += s < 0 ? -s : s;
    }
    if (mag < best_mag) {
      best_mag = mag;
      best = i;
      if (mag == 0) {
        break;
      }
    }
  }
  return best;
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
 * seam per second.  Spreading them out is therefore both tighter and quieter.
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
/* Stack scratch for the one spare frame a shrink trim needs. */
#define AUDIO_SCHED_TRIM_MAX_CHANNELS 8
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
  /* +1 skips one source sample (playout speeds up), -1 repeats one (it slows
   * down).  Applied at the timeline read below. */
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
      } else if (scheduler->drift_servo_accum >= DRIFT_SERVO_TRIM_THRESHOLD) {
        /* Cursor ahead of schedule means this device is playing early, so
         * hold it back by repeating a sample. */
        scheduler->drift_servo_accum -= DRIFT_SERVO_TRIM_THRESHOLD;
        drift_adjust = -1;
        scheduler->drift_servo_phase = 0;
        scheduler->drift_servo_trims++;
      } else if (scheduler->drift_servo_accum <= -DRIFT_SERVO_TRIM_THRESHOLD) {
        /* Behind schedule: skip one sample to catch up. */
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

  /* Stretch: read one sample fewer, then duplicate a frame so the block the
   * caller writes stays the same length while the source cursor advances one
   * sample less.  Shrink is the mirror -- read the full block plus one spare,
   * then emit every frame but one.  Both pick the quietest frame in the block
   * rather than its edge, so the seam is inaudible.  Rewinding the cursor is
   * not an option because audio_timeline_read() retires a block as soon as it
   * is fully consumed. */
  size_t request = samples;
  if (drift_adjust < 0 && request > 1U) {
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
  if (produced < samples) {
    const size_t m = quietest_frame_index(out, produced, channels);
    memmove(&out[(m + 1U) * channels], &out[m * channels],
            (produced - m) * channels * sizeof(int16_t));
    produced = samples;
  } else if (drift_adjust > 0) {
    int16_t spare[AUDIO_SCHED_TRIM_MAX_CHANNELS];
    if (channels <= AUDIO_SCHED_TRIM_MAX_CHANNELS &&
        audio_timeline_read(timeline, scheduler->epoch, scheduler->cursor_rtp,
                            spare, 1U, channels, true,
                            concealed_samples) == 1U) {
      scheduler->cursor_rtp++;
      scheduler->rendered_samples++;
      const size_t m = quietest_frame_index(out, samples, channels);
      memmove(&out[m * channels], &out[(m + 1U) * channels],
              (samples - 1U - m) * channels * sizeof(int16_t));
      memcpy(&out[(samples - 1U) * channels], spare,
             (size_t)channels * sizeof(int16_t));
    } else {
      /* No spare frame available: fall back to skipping the next one. */
      scheduler->cursor_rtp++;
    }
  }
  return produced;
}
