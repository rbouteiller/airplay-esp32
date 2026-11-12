// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * The board sets its digital gain from how far the EQ lifts a full-scale tone,
 * so the peak it finds in single precision has to agree with a dense sweep in
 * double, including for corners near DC and for narrow peaks.
 */

#include "tas58xx_biquad.h"

#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

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

/* Chain magnitude in dB, in double, sections in the part's form. */
static double chain_db(const double (*c)[5], int n, double f, double fs) {
  double complex z1 = cexp(-I * 2.0 * M_PI * f / fs);
  double complex h = 1.0;
  for (int i = 0; i < n; i++) {
    h *= (c[i][0] + c[i][1] * z1 + c[i][2] * z1 * z1) /
         (1.0 - c[i][3] * z1 - c[i][4] * z1 * z1);
  }
  return 20.0 * log10(cabs(h));
}

/* The same range swept 1000 points per octave. */
static double reference_db(const double (*c)[5], int n, double fs) {
  const double top = fmin(20000.0, fs * 0.45);
  double best = -1e9;
  for (double f = 10.0; f <= top; f *= pow(2.0, 1.0 / 1000.0)) {
    best = fmax(best, chain_db(c, n, f, fs));
  }
  return best;
}

static tas58xx_bq_t section(int type, int sub, float freq, float q,
                            float gain) {
  tas58xx_bq_t bq;
  tas58xx_bq_init_bypass(&bq);
  bq.type = (uint8_t)type;
  bq.sub = (uint8_t)sub;
  bq.freq_hz = freq;
  bq.q = q;
  bq.gain_db = gain;
  return bq;
}

static void check_chain(const char *name, const tas58xx_bq_t *chain, int n,
                        double fs, double expect_db, double expect_hz) {
  double c[TAS58XX_BQ_SLOTS][5];
  for (int i = 0; i < n; i++) {
    tas58xx_bq_design(&chain[i], fs, c[i]);
  }
  float at = 0.0f;
  const float got =
      tas58xx_bq_chain_peak_db((const double (*)[5])c, n, fs, &at);
  const double ref = reference_db((const double (*)[5])c, n, fs);
  printf("%-28s %6.0f Hz: %+7.3f dB at %7.1f Hz (dense sweep %+7.3f)\n", name,
         fs, got, at, ref);
  CHECK(fabs(got - ref) < 0.01, "%s: %.4f vs %.4f", name, got, ref);
  if (!isnan(expect_db)) {
    CHECK(fabs(got - expect_db) < 0.05, "%s: %.3f, expected %.3f", name, got,
          expect_db);
  }
  if (!isnan(expect_hz)) {
    CHECK(fabs(at / expect_hz - 1.0) < 0.01, "%s: at %.1f Hz, expected %.1f",
          name, at, expect_hz);
  }
}

int main(void) {
  const double rates[] = {44100.0, 48000.0, 96000.0};
  for (int r = 0; r < 3; r++) {
    const double fs = rates[r];

    check_chain("empty", NULL, 0, fs, 0.0, NAN);

    tas58xx_bq_t peak = section(TAS58XX_BQ_PEAKING_Q, 0, 1000, 1, 6);
    check_chain("peak +6 dB Q1 1 kHz", &peak, 1, fs, 6.0, 1000.0);

    tas58xx_bq_t narrow = section(TAS58XX_BQ_PEAKING_Q, 0, 3333, 20, 12);
    check_chain("peak +12 dB Q20 3333 Hz", &narrow, 1, fs, 12.0, 3333.0);

    tas58xx_bq_t shelf = section(TAS58XX_BQ_BASS_SHELF, 0, 80, 0, 10);
    check_chain("bass shelf +10 dB", &shelf, 1, fs, NAN, NAN);

    /* A resonant corner near DC is where single precision would fail. */
    tas58xx_bq_t sub =
        section(TAS58XX_BQ_HIGHPASS, TAS58XX_BQ_SUB_VARIABLE_Q_2, 25, 2, 0);
    check_chain("high pass Q2 25 Hz", &sub, 1, fs, NAN, NAN);

    tas58xx_bq_t cuts[3] = {
        section(TAS58XX_BQ_PEAKING_Q, 0, 200, 2, -6),
        section(TAS58XX_BQ_PEAKING_Q, 0, 2000, 1, -3),
        section(TAS58XX_BQ_LOWPASS, TAS58XX_BQ_SUB_LINKWITZ_RILEY_2, 2500, 0,
                0),
    };
    check_chain("cuts and a low pass", cuts, 3, fs, NAN, NAN);

    /* Close to the tuning on the 55 mm Mini: cuts, a shelf, a high pass. */
    tas58xx_bq_t mini[7] = {
        section(TAS58XX_BQ_PEAKING_Q, 0, 6900, 2.02f, -8.8f),
        section(TAS58XX_BQ_PEAKING_Q, 0, 1286, 3.38f, -6),
        section(TAS58XX_BQ_PEAKING_Q, 0, 17256, 2.44f, -4.6f),
        section(TAS58XX_BQ_PEAKING_Q, 0, 13408, 3.89f, -3.3f),
        section(TAS58XX_BQ_PEAKING_Q, 0, 4437, 1.13f, -1.9f),
        section(TAS58XX_BQ_BASS_SHELF, 0, 74.25f, 0, 10.9f),
        section(TAS58XX_BQ_HIGHPASS, TAS58XX_BQ_SUB_LINKWITZ_RILEY_2, 35, 0, 0),
    };
    check_chain("Mini tuning", mini, 7, fs, NAN, NAN);

    /* Two peaks: the higher one wins wherever it sits. */
    tas58xx_bq_t two[2] = {
        section(TAS58XX_BQ_PEAKING_Q, 0, 60, 4, 5),
        section(TAS58XX_BQ_PEAKING_Q, 0, 9000, 8, 7),
    };
    check_chain("two peaks", two, 2, fs, 7.0, 9000.0);
  }

  if (s_failed) {
    printf("%d check(s) failed\n", s_failed);
    return 1;
  }
  printf("All chain peak checks passed\n");
  return 0;
}
