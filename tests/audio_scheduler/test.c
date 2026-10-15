// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Host tests for the drift servo's trims in main/audio/audio_scheduler.c.  A
 * trim moves the source one frame against the output, and on a sine tone that
 * must not click.  The file is included whole so the tests can reach the
 * resampler as well as audio_scheduler_render(). */

#include "audio_scheduler.c"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define RATE 44100
/* What every playback task asks for. */
#define BLOCK (AUDIO_V2_BLOCK_SAMPLES + 1)
#define AMP   20000.0
/* 20 s of playback. */
#define RENDERS 2500

static int failures;

#define CHECK(cond, ...)                            \
  do {                                              \
    if (!(cond)) {                                  \
      failures++;                                   \
      printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
      printf(__VA_ARGS__);                          \
      printf("\n");                                 \
    }                                               \
  } while (0)

/* ---------- mocks ---------- */

int64_t mock_now_us = 1000000;

/* The timeline holds a tone on each channel, addressed by RTP: 1600 Hz, which
 * popped at every trim on the board, on the left and 1000 Hz on the right. */
static const double tone_hz[AUDIO_V2_MAX_CHANNELS] = {1600.0, 1000.0};
static bool mock_conceal;

static double tone(double rtp, uint8_t ch) {
  return AMP * sin(2.0 * M_PI * tone_hz[ch] * rtp / RATE + 0.3 * ch);
}

static int16_t tone_sample(uint32_t rtp, uint8_t ch) {
  return (int16_t)lround(tone((double)rtp, ch));
}

size_t audio_timeline_read(audio_timeline_t *timeline, uint32_t epoch,
                           uint32_t start_rtp, int16_t *out,
                           size_t requested_samples, uint8_t channels,
                           bool conceal_missing, size_t *concealed_samples) {
  for (size_t i = 0; i < requested_samples; i++) {
    for (uint8_t ch = 0; ch < channels; ch++) {
      out[i * channels + ch] = tone_sample(start_rtp + (uint32_t)i, ch);
    }
  }
  if (concealed_samples) {
    *concealed_samples = mock_conceal ? requested_samples : 0U;
  }
  return requested_samples;
}

bool audio_timeline_has_playable_from(audio_timeline_t *timeline,
                                      uint32_t epoch, uint32_t target_rtp) {
  return true;
}

bool audio_timeline_find_contiguous_from(audio_timeline_t *timeline,
                                         uint32_t epoch, uint32_t target_rtp,
                                         uint32_t required_samples,
                                         uint32_t max_future_samples,
                                         uint32_t *start_rtp) {
  *start_rtp = target_rtp;
  return true;
}

void audio_timeline_set_playback_floor(audio_timeline_t *timeline,
                                       uint32_t epoch, uint32_t floor_rtp) {
}

bool audio_timeline_is_nearly_full(audio_timeline_t *timeline) {
  return false;
}

size_t audio_timeline_trim_before(audio_timeline_t *timeline, uint32_t epoch,
                                  uint32_t rtp) {
  return 0;
}

/* The sender's clock runs drift_ppm faster than the DAC's. */
static double drift_ppm;

bool audio_clock_map_network_to_rtp(const audio_clock_map_t *map,
                                    int64_t network_ns, uint32_t *rtp) {
  const double elapsed_s =
      (double)(network_ns - (int64_t)map->anchor_network_ns) * 1e-9;
  *rtp = map->anchor_rtp + (uint32_t)llround(elapsed_s * map->sample_rate *
                                             (1.0 + drift_ppm * 1e-6));
  return true;
}

/* ---------- helpers ---------- */

static const audio_clock_map_t clock_map = {
    .valid = true,
    .sample_rate = RATE,
    .anchor_rtp = 5000,
    .anchor_network_ns = 2000000000ULL,
};

static audio_timeline_t timeline;

/* Start playing, as the first render after an anchor does. */
static void start(audio_scheduler_t *scheduler) {
  int16_t block[BLOCK * AUDIO_V2_MAX_CHANNELS];
  audio_scheduler_init(scheduler, RATE / 4, 0);
  audio_scheduler_begin_epoch(scheduler, 1, mock_now_us);
  (void)audio_scheduler_render(scheduler, &timeline, &clock_map,
                               (int64_t)clock_map.anchor_network_ns, block,
                               BLOCK, AUDIO_V2_MAX_CHANNELS, NULL);
}

/* Arm the servo so the next render trims: warmed up, rate limit expired, and
 * a full queue of correction behind it. */
static void arm_trim(audio_scheduler_t *scheduler, int direction) {
  scheduler->drift_servo_warmup = DRIFT_SERVO_WARMUP_RENDERS;
  scheduler->drift_servo_phase = DRIFT_SERVO_MIN_TRIM_INTERVAL;
  scheduler->drift_servo_accum = -direction * DRIFT_SERVO_ACCUM_LIMIT;
}

/* ---------- tests ---------- */

/* Every set of weights sums to exactly 1 and reads a tone at the position it
 * was asked for, within the -78 dB the comment on trim_kernel() claims. */
static void test_kernel(void) {
  printf("kernel\n");
  static const double freqs[] = {400, 1600, 5000, 8000, 10000, 12000};
  double worst = 0.0;
  for (int32_t mu = 1; mu < 65536; mu += 13) {
    int32_t weight[TRIM_TAPS];
    trim_kernel(mu, weight);
    int64_t sum = 0;
    for (int t = 0; t < TRIM_TAPS; t++) {
      sum += weight[t];
    }
    CHECK(sum == 1 << 20, "mu %d: weights sum to %lld", (int)mu,
          (long long)sum);
    for (size_t f = 0; f < sizeof(freqs) / sizeof(freqs[0]); f++) {
      const double w = 2.0 * M_PI * freqs[f] / RATE;
      double re = 0.0;
      double im = 0.0;
      for (int t = 0; t < TRIM_TAPS; t++) {
        re += weight[t] / 1048576.0 * cos(w * (t + 1 - TRIM_REACH));
        im += weight[t] / 1048576.0 * sin(w * (t + 1 - TRIM_REACH));
      }
      const double error =
          hypot(re - cos(w * mu / 65536.0), im - sin(w * mu / 65536.0));
      if (error > worst) {
        worst = error;
      }
    }
  }
  printf("  worst %.1f dB\n", 20.0 * log10(worst));
  CHECK(20.0 * log10(worst) < -78.0, "kernel off by %.1f dB",
        20.0 * log10(worst));
}

/* A trimmed block of the tone is the tone read at the positions the ramp
 * asks for.  Outside the ramp it is the source exactly as read, one frame
 * apart by the end of the block. */
static void test_block(int direction) {
  printf("%s block\n", direction < 0 ? "stretch" : "shrink");
  const uint32_t first = 123456;
  const size_t sources = direction < 0 ? BLOCK - 1U : BLOCK;
  int16_t out[BLOCK * AUDIO_V2_MAX_CHANNELS];
  int16_t spare[AUDIO_V2_MAX_CHANNELS];
  for (size_t k = 0; k < BLOCK; k++) {
    for (uint8_t ch = 0; ch < AUDIO_V2_MAX_CHANNELS; ch++) {
      /* A stretch leaves the last frame unread; make reading it show. */
      out[k * AUDIO_V2_MAX_CHANNELS + ch] =
          k < sources ? tone_sample(first + (uint32_t)k, ch) : INT16_MAX;
    }
  }
  for (uint8_t ch = 0; ch < AUDIO_V2_MAX_CHANNELS; ch++) {
    spare[ch] = tone_sample(first + BLOCK, ch);
  }
  trim_resample(out, BLOCK, AUDIO_V2_MAX_CHANNELS, direction,
                direction > 0 ? spare : NULL);

  double worst = 0.0;
  for (size_t k = 0; k < BLOCK; k++) {
    const double pos =
        (double)k + direction * trim_progress(k, BLOCK) / 65536.0;
    for (uint8_t ch = 0; ch < AUDIO_V2_MAX_CHANNELS; ch++) {
      const int16_t got = out[k * AUDIO_V2_MAX_CHANNELS + ch];
      const double error = fabs(got - tone(first + pos, ch));
      if (error > worst) {
        worst = error;
      }
      if (k <= TRIM_REACH) {
        CHECK(got == tone_sample(first + (uint32_t)k, ch),
              "frame %zu changed before the ramp", k);
      }
      if (k >= BLOCK - TRIM_REACH) {
        CHECK(got == tone_sample(first + (uint32_t)(k + direction), ch),
              "frame %zu not the source frame %+d", k, direction);
      }
    }
  }
  printf("  worst %.2f LSB\n", worst);
  /* Rounding of the source and of the result, and the kernel's error. */
  CHECK(worst < 2.0, "%.2f LSB from the tone", worst);
}

/* Through audio_scheduler_render(), with the sender's clock off by `ppm`: the
 * servo trims, playout stays put, and the trims cannot be found in the second
 * difference of either tone.  A frame repeated or dropped near a zero crossing
 * of the 1600 Hz tone makes it about four times the tone's own. */
static void test_render(double ppm) {
  printf("render, sender %+.0f ppm\n", ppm);
  drift_ppm = ppm;
  audio_scheduler_t scheduler;
  start(&scheduler);

  double limit[AUDIO_V2_MAX_CHANNELS];
  for (uint8_t ch = 0; ch < AUDIO_V2_MAX_CHANNELS; ch++) {
    /* The tone's own, played up to 0.56 % fast, plus rounding. */
    const double s = sin(M_PI * tone_hz[ch] / RATE);
    limit[ch] = 4.0 * s * s * AMP * 1.012 + 8.0;
  }
  double worst[AUDIO_V2_MAX_CHANNELS] = {0};
  int32_t last[2][AUDIO_V2_MAX_CHANNELS] = {{0}};
  size_t frames = 0;
  int16_t block[BLOCK * AUDIO_V2_MAX_CHANNELS];
  for (int64_t i = 1; i <= RENDERS; i++) {
    const int64_t network_ns =
        (int64_t)clock_map.anchor_network_ns + i * BLOCK * 1000000000LL / RATE;
    const size_t produced =
        audio_scheduler_render(&scheduler, &timeline, &clock_map, network_ns,
                               block, BLOCK, AUDIO_V2_MAX_CHANNELS, NULL);
    CHECK(produced == BLOCK, "render %lld produced %zu", (long long)i,
          produced);
    for (size_t k = 0; k < produced; k++, frames++) {
      for (uint8_t ch = 0; ch < AUDIO_V2_MAX_CHANNELS; ch++) {
        const int32_t now = block[k * AUDIO_V2_MAX_CHANNELS + ch];
        const double d2 = fabs((double)now - 2.0 * last[1][ch] + last[0][ch]);
        if (frames >= 2 && d2 > worst[ch]) {
          worst[ch] = d2;
        }
        last[0][ch] = last[1][ch];
        last[1][ch] = now;
      }
    }
  }
  printf("  %u trims, error %d samples, second difference %.0f/%.0f and "
         "%.0f/%.0f\n",
         (unsigned)scheduler.drift_servo_trims,
         (int)scheduler.playout_error_samples, worst[0], limit[0], worst[1],
         limit[1]);
  /* Every trim makes up one frame of the drift, and what is left of it is the
   * error the servo settles at: ~46 samples at 200 ppm. */
  const double drift = RENDERS * BLOCK * fabs(ppm) * 1e-6;
  const double made_up = drift - abs(scheduler.playout_error_samples);
  CHECK(fabs(scheduler.drift_servo_trims - made_up) < 3.0,
        "%u trims for %.1f frames of drift",
        (unsigned)scheduler.drift_servo_trims, made_up);
  CHECK(abs(scheduler.playout_error_samples) < 80, "playout %d samples off",
        (int)scheduler.playout_error_samples);
  for (uint8_t ch = 0; ch < AUDIO_V2_MAX_CHANNELS; ch++) {
    CHECK(worst[ch] <= limit[ch], "channel %u: second difference %.0f > %.0f",
          ch, worst[ch], limit[ch]);
  }
}

/* A shrink reads a frame past the block.  Concealment in either read is
 * counted; the second read used to overwrite the first's count. */
static void test_concealed_count(void) {
  printf("concealed count\n");
  drift_ppm = 0.0;
  audio_scheduler_t scheduler;
  start(&scheduler);
  arm_trim(&scheduler, 1);
  mock_conceal = true;
  int16_t block[BLOCK * AUDIO_V2_MAX_CHANNELS];
  size_t concealed = 0;
  const uint32_t trims = scheduler.drift_servo_trims;
  (void)audio_scheduler_render(&scheduler, &timeline, &clock_map,
                               (int64_t)clock_map.anchor_network_ns, block,
                               BLOCK, AUDIO_V2_MAX_CHANNELS, &concealed);
  mock_conceal = false;
  CHECK(scheduler.drift_servo_trims == trims + 1U, "no trim");
  CHECK(concealed == BLOCK + 1U, "%zu concealed, %u read", concealed,
        (unsigned)BLOCK + 1U);
}

/* A block too short to carry a ramp is not trimmed; the correction waits. */
static void test_short_block(void) {
  printf("short block\n");
  drift_ppm = 0.0;
  audio_scheduler_t scheduler;
  start(&scheduler);
  arm_trim(&scheduler, 1);
  int16_t block[BLOCK * AUDIO_V2_MAX_CHANNELS];
  const uint32_t cursor = scheduler.cursor_rtp;
  (void)audio_scheduler_render(
      &scheduler, &timeline, &clock_map, (int64_t)clock_map.anchor_network_ns,
      block, TRIM_MIN_FRAMES - 1U, AUDIO_V2_MAX_CHANNELS, NULL);
  CHECK(scheduler.drift_servo_trims == 0, "trimmed a short block");
  CHECK(scheduler.cursor_rtp - cursor == TRIM_MIN_FRAMES - 1U,
        "cursor moved %u", (unsigned)(scheduler.cursor_rtp - cursor));
}

int main(void) {
  test_kernel();
  test_block(-1);
  test_block(1);
  test_render(200.0);
  test_render(-200.0);
  test_concealed_count();
  test_short_block();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}
