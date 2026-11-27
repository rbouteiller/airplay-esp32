// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// The DAC dispatch layer on the host: the output delay a driver or the
// plain-DAC preset reports, and the latency breakdown built on it.

#include "mocks.h"

#include "../../components/dac/dac.c"
#include "../../main/audio/audio_latency.c"

#include <stdio.h>
#include <stdlib.h>

static int failures;
#define CHECK(cond, ...)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("  FAIL %s:%d: ", __FILE__, __LINE__);                            \
      printf(__VA_ARGS__);                                                     \
      printf("\n");                                                            \
      failures++;                                                              \
    }                                                                          \
  } while (0)

/* ---- A driver that reports a delay, and one that has none ---- */

static uint32_t driver_delay_q4 = DAC_OUTPUT_DELAY_UNKNOWN;

static uint32_t fake_output_delay_q4(uint32_t sample_rate_hz) {
  (void)sample_rate_hz;
  return driver_delay_q4;
}

static const dac_ops_t fake_ops = {
    .output_delay_q4 = fake_output_delay_q4,
};

static const dac_ops_t plain_ops = {0};

/* What each build's preset gives, at a 44.1 kHz and a 96 kHz output. */
static void test_delay_sources(void) {
  printf("output delay: driver, preset (%s), unknown\n",
         dac_output_delay_preset_name());
  dac_delay_source_t source;
#if defined(CONFIG_DAC_PLAIN_DELAY_PCM510X_NORMAL)
  const uint32_t want44 = 352U, want96 = 352U;
#elif defined(CONFIG_DAC_PLAIN_DELAY_PCM510X_LOW_LATENCY)
  const uint32_t want44 = 56U, want96 = 56U;
#elif defined(CONFIG_DAC_PLAIN_DELAY_CS434X)
  const uint32_t want44 = 160U, want96 = 80U;
#elif defined(CONFIG_DAC_PLAIN_DELAY_CUSTOM)
  const uint32_t want44 = CONFIG_DAC_PLAIN_DELAY_CUSTOM_Q4,
                 want96 = CONFIG_DAC_PLAIN_DELAY_CUSTOM_Q4;
#else
  const uint32_t want44 = 0U, want96 = 0U;
#endif
#if defined(CONFIG_DAC_PLAIN_DELAY_UNKNOWN)
  const dac_delay_source_t preset = DAC_DELAY_UNKNOWN;
#else
  const dac_delay_source_t preset = DAC_DELAY_FROM_PRESET;
#endif

  dac_register(&plain_ops);
  uint32_t q4 = dac_get_output_delay_q4(44100, &source);
  CHECK(q4 == want44 && source == preset, "no driver: %u from %s",
        (unsigned)q4, dac_delay_source_name(source));
  q4 = dac_get_output_delay_q4(96000, &source);
  CHECK(q4 == want96 && source == preset, "no driver, 96 kHz: %u",
        (unsigned)q4);

  /* A driver with no figure for its mode: the preset stands in. */
  dac_register(&fake_ops);
  driver_delay_q4 = DAC_OUTPUT_DELAY_UNKNOWN;
  q4 = dac_get_output_delay_q4(44100, &source);
  CHECK(q4 == want44 && source == preset, "driver unknown: %u from %s",
        (unsigned)q4, dac_delay_source_name(source));

  /* A driver figure always wins, 0 included. */
  driver_delay_q4 = 0;
  q4 = dac_get_output_delay_q4(44100, &source);
  CHECK(q4 == 0 && source == DAC_DELAY_FROM_DRIVER, "driver 0: %u from %s",
        (unsigned)q4, dac_delay_source_name(source));
  driver_delay_q4 = 539;
  q4 = dac_get_output_delay_q4(44100, NULL);
  CHECK(q4 == 539, "driver 33.7 samples: %u", (unsigned)q4);
}

/* The breakdown: each part in microseconds, rounded, and the trim. */
static void test_breakdown(void) {
  printf("latency breakdown\n");
  dac_register(&fake_ops);
  driver_delay_q4 = 22U * 16U; /* 22 samples */
  audio_latency_t l;
  (void)audio_latency_set_trim_us(0);
  audio_latency_compute(44100, 32, 726, 0, &l);
  CHECK(l.fifo_us == 726, "FIFO %u us", (unsigned)l.fifo_us); /* 32/44.1k */
  CHECK(l.dac_us == 499, "DAC %u us", (unsigned)l.dac_us);    /* 22/44.1k */
  CHECK(l.dac_source == DAC_DELAY_FROM_DRIVER, "source");
  CHECK(l.post_ring_us == 726 + 726 + 499, "sum %d", (int)l.post_ring_us);

  audio_latency_compute(48000, 32, 0, 1000, &l);
  CHECK(l.dac_us == 458 && l.fifo_us == 667, "48 kHz: DAC %u FIFO %u",
        (unsigned)l.dac_us, (unsigned)l.fifo_us);
  CHECK(l.post_ring_us == 667 + 1000 + 458, "sum %d", (int)l.post_ring_us);

  CHECK(audio_latency_set_trim_us(-3500) == -3500, "trim");
  audio_latency_compute(48000, 32, 0, 0, &l);
  CHECK(l.trim_us == -3500 && l.post_ring_us == 667 + 458 - 3500,
        "trimmed sum %d", (int)l.post_ring_us);
  CHECK(audio_latency_set_trim_us(80000) == AUDIO_LATENCY_TRIM_MAX_US &&
            audio_latency_set_trim_us(-80000) == -AUDIO_LATENCY_TRIM_MAX_US,
        "trim not clamped");
  audio_latency_compute(0, 32, 0, 0, &l);
  CHECK(l.fifo_us == 0 && l.dac_us == 0, "rate 0 divides");
  (void)audio_latency_set_trim_us(0);
}

int main(void) {
  test_delay_sources();
  test_breakdown();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}
