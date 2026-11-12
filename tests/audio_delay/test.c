// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Host tests for audio_delay.c: an impulse on each output comes out the set
 * number of samples later, the other output untouched, across blocks, rate
 * changes, resets and the switch that disables it. */

#include "audio_delay.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, ...)                            \
  do {                                              \
    if (!(cond)) {                                  \
      printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
      printf(__VA_ARGS__);                          \
      printf("\n");                                 \
      failures++;                                   \
    }                                               \
  } while (0)

#define FRAMES 4096
#define BLOCK  100 /* not a divisor of the ring, so blocks straddle its end */

static audio_delay_word_t s_buf[FRAMES * 2];

/* A distinct, non-zero sample on every frame of each channel, so any shift,
 * swap or repeat shows. */
static audio_delay_word_t sample(size_t i, int ch) {
  return (audio_delay_word_t)((int)(i % 9973) * 3 + 1 + ch * 15000);
}

static void fill(size_t frames) {
  for (size_t i = 0; i < frames; i++) {
    s_buf[2 * i] = sample(i, 0);
    s_buf[2 * i + 1] = sample(i, 1);
  }
}

static void run(size_t frames, bool enabled) {
  for (size_t i = 0; i < frames; i += BLOCK) {
    audio_delay_process(s_buf + 2 * i, frames - i < BLOCK ? frames - i : BLOCK,
                        enabled);
  }
}

/* Each channel delayed by d[ch] frames, silence before its first sample. */
static size_t mismatches(size_t frames, const unsigned d[2]) {
  size_t bad = 0;
  for (size_t i = 0; i < frames; i++) {
    for (int ch = 0; ch < 2; ch++) {
      audio_delay_word_t want = i < d[ch] ? 0 : sample(i - d[ch], ch);
      bad += s_buf[2 * i + ch] != want;
    }
  }
  return bad;
}

static void test_shifts(void) {
  printf("each output comes out its own number of samples late\n");
  static const struct {
    uint32_t rate, us[2];
    unsigned want[2];
  } cases[] = {
      {48000, {0, 0}, {0, 0}},      /* off: bit-exact passthrough */
      {48000, {0, 21}, {0, 1}},     /* 20.8 us is one sample */
      {48000, {146, 0}, {7, 0}},    /* 7.0 samples, left only */
      {44100, {58, 113}, {3, 5}},   /* both, rounded: 2.56 and 4.98 */
      {96000, {2000, 0}, {192, 0}}, /* the longest, at the highest rate */
      {48000, {5000, 0}, {96, 0}},  /* clamped to 2000 us */
  };
  for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
    audio_delay_set_rate(cases[k].rate);
    audio_delay_set_us(0, cases[k].us[0]);
    audio_delay_set_us(1, cases[k].us[1]);
    fill(FRAMES);
    run(FRAMES, true);
    size_t bad = mismatches(FRAMES, cases[k].want);
    CHECK(bad == 0, "%u Hz, %u/%u us: %zu samples wrong (want %u/%u)",
          (unsigned)cases[k].rate, (unsigned)cases[k].us[0],
          (unsigned)cases[k].us[1], bad, cases[k].want[0], cases[k].want[1]);
  }
  CHECK(audio_delay_get_us(0) == AUDIO_DELAY_MAX_US, "clamp not reported");
}

static void test_rate_change_restarts(void) {
  printf("a rate change re-converts microseconds and starts from silence\n");
  audio_delay_set_rate(48000);
  audio_delay_set_us(0, 0);
  audio_delay_set_us(1, 146);
  fill(FRAMES);
  run(FRAMES, true);
  audio_delay_set_rate(96000); /* 146 us is now 14 samples */
  fill(FRAMES);
  run(FRAMES, true);
  const unsigned d[2] = {0, 14};
  CHECK(mismatches(FRAMES, d) == 0, "after 48 -> 96 kHz: %zu wrong",
        mismatches(FRAMES, d));
}

static void test_reset_drops_tail(void) {
  printf("a reset drops the previous stream's tail\n");
  audio_delay_set_rate(48000);
  audio_delay_set_us(0, 0);
  audio_delay_set_us(1, 1000); /* 48 samples */
  fill(FRAMES);
  run(FRAMES, true);
  audio_delay_reset();
  fill(FRAMES);
  run(FRAMES, true);
  const unsigned d[2] = {0, 48};
  CHECK(mismatches(FRAMES, d) == 0, "after a reset: %zu wrong",
        mismatches(FRAMES, d));
}

static void test_disabled_passes_through(void) {
  printf("disabled, the words pass untouched; re-enabled, from silence\n");
  audio_delay_set_rate(48000);
  audio_delay_set_us(0, 500); /* 24 samples */
  audio_delay_set_us(1, 0);
  fill(FRAMES);
  run(FRAMES, true);
  fill(FRAMES);
  run(FRAMES, false);
  const unsigned none[2] = {0, 0};
  CHECK(mismatches(FRAMES, none) == 0, "disabled: %zu changed",
        mismatches(FRAMES, none));
  fill(FRAMES);
  run(FRAMES, true);
  const unsigned d[2] = {24, 0};
  CHECK(mismatches(FRAMES, d) == 0, "re-enabled: %zu wrong",
        mismatches(FRAMES, d));
}

static void test_active(void) {
  printf("active only while an output has a delay\n");
  audio_delay_set_us(0, 0);
  audio_delay_set_us(1, 0);
  CHECK(!audio_delay_active(), "active with no delay");
  audio_delay_set_us(1, 1);
  CHECK(audio_delay_active(), "inactive with a delay");
  audio_delay_set_us(1, 0);
  audio_delay_set_us(7, 100); /* out of range: ignored */
  CHECK(!audio_delay_active(), "an out-of-range output was stored");
}

int main(void) {
  test_shifts();
  test_rate_change_restarts();
  test_reset_drops_tail();
  test_disabled_passes_through();
  test_active();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}
