// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * A TAS5805M runs its biquads after a sample-rate converter, at 96 kHz or
 * 88.2 kHz whatever the I2S rate, so a section has to be designed at that
 * rate to land where it was asked for.
 */

#include "tas58xx_biquad.h"

#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

static int s_failed;

#define CHECK(cond, ...)                          \
  do {                                            \
    if (!(cond)) {                                \
      printf("FAIL %s:%d: ", __FILE__, __LINE__); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
      s_failed++;                                 \
    }                                             \
  } while (0)

/* Magnitude in dB of a section in the part's form (a1 and a2 negated). */
static double mag_db(const double c[5], double f, double fs) {
  double complex z1 = cexp(-I * 2.0 * M_PI * f / fs);
  double complex num = c[0] + c[1] * z1 + c[2] * z1 * z1;
  double complex den = 1.0 - c[3] * z1 - c[4] * z1 * z1;
  return 20.0 * log10(cabs(num / den));
}

/* Where a cut is deepest when the section runs at run_fs. */
static double deepest_hz(const double c[5], double run_fs) {
  double best_f = 0.0, best = 1e9;
  for (double f = 20.0; f < run_fs * 0.49; f *= 1.0005) {
    double m = mag_db(c, f, run_fs);
    if (m < best) {
      best = m;
      best_f = f;
    }
  }
  return best_f;
}

static void test_rates(void) {
  static const struct {
    double i2s, dsp;
  } cases[] = {
      {44100, 88200}, {88200, 88200}, {48000, 96000},
      {96000, 96000}, {32000, 96000},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    double got = tas5805m_dsp_rate(cases[i].i2s);
    CHECK(got == cases[i].dsp, "%.0f Hz in runs at %.0f, got %.0f",
          cases[i].i2s, cases[i].dsp, got);
  }
}

/* The fault this guards against: a cut asked for at 10 kHz, designed at the
 * 48 kHz I2S rate, plays at 20 kHz in the part. */
static void test_cut_lands_where_asked(void) {
  tas58xx_bq_t bq;
  tas58xx_bq_init_bypass(&bq);
  bq.type = TAS58XX_BQ_PEAKING_Q;
  bq.freq_hz = 10000.0f;
  bq.q = 5.0f;
  bq.gain_db = -12.0f;

  const double run_fs = tas5805m_dsp_rate(48000.0);
  double c[5];

  tas58xx_bq_design(&bq, run_fs, c);
  double f = deepest_hz(c, run_fs);
  CHECK(fabs(f / 10000.0 - 1.0) < 0.005, "cut at %.0f Hz, asked for 10000", f);

  tas58xx_bq_design(&bq, 48000.0, c);
  f = deepest_hz(c, run_fs);
  CHECK(fabs(f / 20000.0 - 1.0) < 0.005,
        "designed at the I2S rate, the cut should play an octave up, at "
        "%.0f Hz",
        f);
}

int main(void) {
  test_rates();
  test_cut_lands_where_asked();
  if (s_failed) {
    printf("%d check(s) failed\n", s_failed);
    return EXIT_FAILURE;
  }
  printf("all TAS5805M filter rate tests passed\n");
  return EXIT_SUCCESS;
}
