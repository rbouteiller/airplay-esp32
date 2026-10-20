// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/*
 * Every TAS58xx filter shape against the properties that define it, at each
 * rate a chain is designed for, and then again after rounding to the 5.27
 * words the chip runs: the filter in coefficient RAM has to be the one that
 * was asked for, without overshoot it was not asked for.
 */

#include "tas58xx_biquad.h"

#include <complex.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static int s_failed;
static int s_checks;

#define CHECK(cond, ...)                          \
  do {                                            \
    s_checks++;                                   \
    if (!(cond)) {                                \
      printf("FAIL %s:%d: ", __FILE__, __LINE__); \
      printf(__VA_ARGS__);                        \
      printf("\n");                               \
      s_failed++;                                 \
    }                                             \
  } while (0)

/* -3 dB, -4.77 dB and -6 dB exactly, the corners of the fixed alignments. */
#define HALF_POWER_DB    (-10.0 * log10(2.0))
#define THIRD_POWER_DB   (-10.0 * log10(3.0))
#define QUARTER_POWER_DB (-20.0 * log10(2.0))

/* A zero of the response, which double precision leaves near -300 dB. */
#define ZERO_DB (-120.0)

static const double rates[] = {44100.0, 48000.0, 88200.0, 96000.0};
#define RATE_COUNT ((int)(sizeof(rates) / sizeof(rates[0])))

/* ---------------- evaluation ---------------- */

/* Response of one section in the part's form, {b0, b1, b2, -a1, -a2}. */
static double complex response(const double c[5], double f, double fs) {
  const double complex z1 = cexp(-I * 2.0 * M_PI * f / fs);
  return (c[0] + c[1] * z1 + c[2] * z1 * z1) /
         (1.0 - c[3] * z1 - c[4] * z1 * z1);
}

static double mag_db(const double c[5], double f, double fs) {
  return 20.0 * log10(cabs(response(c, f, fs)));
}

static double phase_deg(const double c[5], double f, double fs) {
  return carg(response(c, f, fs)) * 180.0 / M_PI;
}

/* Top of the band every sweep covers. */
static double sweep_top(double fs) {
  return fmin(20000.0, 0.45 * fs);
}

#define SWEEP_STEP pow(2.0, 1.0 / 48.0) /* 48 points per octave */

/* Lowest and highest point of the response over [lo, hi]. */
static void extremes(const double c[5], double fs, double lo, double hi,
                     double *min_db, double *max_db) {
  *min_db = INFINITY;
  *max_db = -INFINITY;
  for (double f = lo; f <= hi * 1.0001; f *= SWEEP_STEP) {
    const double db = mag_db(c, f, fs);
    *min_db = fmin(*min_db, db);
    *max_db = fmax(*max_db, db);
  }
}

/* Where the response crosses @p level_db between @p lo and @p hi, found by
 * bisection in log frequency. The response must be monotonic there. */
static double crossing(const double c[5], double fs, double lo, double hi,
                       double level_db) {
  const bool rising = mag_db(c, lo, fs) < mag_db(c, hi, fs);
  for (int i = 0; i < 200; i++) {
    const double mid = sqrt(lo * hi);
    if ((mag_db(c, mid, fs) < level_db) == rising) {
      lo = mid;
    } else {
      hi = mid;
    }
  }
  return sqrt(lo * hi);
}

/* Top of a single peak between @p lo and @p hi, by golden-section search in
 * log frequency, which a fixed sweep would step over on a narrow band. */
static double top_db(const double c[5], double fs, double lo, double hi) {
  const double r = (sqrt(5.0) - 1.0) / 2.0;
  double a = log(lo), b = log(hi);
  for (int i = 0; i < 200; i++) {
    const double x1 = b - r * (b - a), x2 = a + r * (b - a);
    if (mag_db(c, exp(x1), fs) < mag_db(c, exp(x2), fs)) {
      a = x1;
    } else {
      b = x2;
    }
  }
  return mag_db(c, exp((a + b) / 2.0), fs);
}

/* ---------------- designing ---------------- */

static tas58xx_bq_t shape(int type, int sub, double freq) {
  tas58xx_bq_t bq;
  tas58xx_bq_init_bypass(&bq);
  bq.type = (uint8_t)type;
  bq.sub = (uint8_t)sub;
  bq.freq_hz = (float)freq;
  return bq;
}

static tas58xx_bq_t peak(double freq, double q, double gain_db) {
  tas58xx_bq_t bq = shape(TAS58XX_BQ_PEAKING_Q, 0, freq);
  bq.q = (float)q;
  bq.gain_db = (float)gain_db;
  return bq;
}

static tas58xx_bq_t shelf(int type, double freq, double gain_db) {
  tas58xx_bq_t bq = shape(type, 0, freq);
  bq.gain_db = (float)gain_db;
  return bq;
}

static tas58xx_bq_t pass(int type, int sub, double freq, double q,
                         double ripple_db) {
  tas58xx_bq_t bq = shape(type, sub, freq);
  bq.q = (float)q;
  bq.ripple_db = (float)ripple_db;
  return bq;
}

static tas58xx_bq_t banded(int type, double freq, double bw) {
  tas58xx_bq_t bq = shape(type, 0, freq);
  bq.bandwidth_hz = (float)bw;
  return bq;
}

/* What the chip runs: the design packed to 5.27 and read back exactly, not
 * through tas58xx_bq_unpack(), whose float would add rounding of its own. */
static void on_chip(const double in[5], double out[5], bool *saturated) {
  uint8_t packed[TAS58XX_BQ_COEFF_BYTES];
  tas58xx_bq_pack(in, packed);
  *saturated = false;
  for (int i = 0; i < 5; i++) {
    const int32_t fixed = (int32_t)(((uint32_t)packed[i * 4 + 0] << 24) |
                                    ((uint32_t)packed[i * 4 + 1] << 16) |
                                    ((uint32_t)packed[i * 4 + 2] << 8) |
                                    (uint32_t)packed[i * 4 + 3]);
    *saturated = *saturated || fixed == INT32_MAX || fixed == INT32_MIN;
    out[i] = (double)fixed / (double)(1 << 27);
  }
}

/* ---------------- shapes ---------------- */

/*
 * A peak lifts its centre by exactly the gain, leaves DC and Nyquist alone,
 * and is as wide as its Q says between the points halfway in power between
 * flat and the peak. A cut is the exact mirror of the boost: the two in
 * series are unity at every frequency, magnitude and phase.
 */
static void check_peaking(double fs) {
  const double freqs[] = {30.0, 1000.0, 10000.0};
  const double qs[] = {0.5, 2.0, 8.0};
  const double gains[] = {3.0, 6.0, 12.0, 20.0};
  int checked = 0;
  double worst_mirror = 0.0;

  for (int fi = 0; fi < 3; fi++) {
    for (int qi = 0; qi < 3; qi++) {
      for (int gi = 0; gi < 4; gi++) {
        const double f0 = freqs[fi], q = qs[qi], g = gains[gi];
        double boost[5], cut[5];
        tas58xx_bq_t bq = peak(f0, q, g);
        tas58xx_bq_design(&bq, fs, boost);
        bq.gain_db = (float)-g;
        tas58xx_bq_design(&bq, fs, cut);

        CHECK(fabs(mag_db(boost, f0, fs) - g) < 0.001,
              "peak %g Hz Q%g %+g dB at %g: centre %+.4f dB", f0, q, g, fs,
              mag_db(boost, f0, fs));
        CHECK(fabs(mag_db(boost, 0.0, fs)) < 0.001 &&
                  fabs(mag_db(boost, fs / 2.0, fs)) < 0.001,
              "peak %g Hz Q%g %+g dB at %g: DC %+.4f, Nyquist %+.4f dB", f0, q,
              g, fs, mag_db(boost, 0.0, fs), mag_db(boost, fs / 2.0, fs));

        /* The model's bandwidth, 2 atan(pi f0 / (fs Q)) in radians, which
         * is f0 / Q until the centre nears Nyquist. */
        const double lin = pow(10.0, g / 20.0);
        const double edge_db = 10.0 * log10((1.0 + lin * lin) / 2.0);
        const double lower = crossing(boost, fs, 1e-3, f0, edge_db);
        const double upper = crossing(boost, fs, f0, fs / 2.0, edge_db);
        const double want = fs * atan(M_PI * f0 / (fs * q)) / M_PI;
        CHECK(fabs((upper - lower) / want - 1.0) < 1e-4,
              "peak %g Hz Q%g %+g dB at %g: %.2f Hz wide, model says %.2f", f0,
              q, g, fs, upper - lower, want);
        if (f0 <= fs / 40.0) {
          CHECK(fabs((upper - lower) * q / f0 - 1.0) < 0.01,
                "peak %g Hz Q%g at %g: %.2f Hz wide, f0/Q is %.2f", f0, q, fs,
                upper - lower, f0 / q);
        }

        for (double f = 10.0; f <= sweep_top(fs); f *= SWEEP_STEP) {
          const double complex both =
              response(boost, f, fs) * response(cut, f, fs);
          worst_mirror = fmax(worst_mirror, cabs(both - 1.0));
        }
        checked++;
      }
    }
  }
  CHECK(worst_mirror < 1e-9, "peak at %g: boost x cut strays %.3g from unity",
        fs, worst_mirror);

  /* The bandwidth form is the Q form with Q = f0 / bandwidth. */
  double by_q[5], by_bw[5];
  tas58xx_bq_t bq = peak(1000.0, 4.0, 6.0);
  tas58xx_bq_design(&bq, fs, by_q);
  bq = banded(TAS58XX_BQ_PEAKING_BW, 1000.0, 250.0);
  bq.gain_db = 6.0f;
  tas58xx_bq_design(&bq, fs, by_bw);
  double diff = 0.0;
  for (int i = 0; i < 5; i++) {
    diff = fmax(diff, fabs(by_q[i] - by_bw[i]));
  }
  CHECK(diff < 1e-12, "peak at %g: 250 Hz bandwidth differs from Q4 by %.3g",
        fs, diff);

  printf("  peaking: %d designs, boost x cut within %.1g of unity\n", checked,
         worst_mirror);
}

/* Gain a PPC3 shelf has at its corner: halfway in dB up to 6 dB, and 3 dB
 * short of the plateau beyond. */
static double shelf_corner_db(double g) {
  if (fabs(g) <= 6.0) {
    return g / 2.0;
  }
  return g > 0.0 ? g + HALF_POWER_DB : g - HALF_POWER_DB;
}

/*
 * A shelf reaches its gain at one end and unity at the other, passes its
 * corner at the level above, and never goes outside the two.
 */
static void check_shelves(double fs) {
  const double freqs[] = {50.0, 1000.0, 8000.0};
  const double gains[] = {-20.0, -15.0, -10.0, -6.0, -3.0,
                          3.0,   6.0,   10.0,  15.0, 20.0};
  double worst_overshoot = 0.0;
  int checked = 0;

  for (int t = 0; t < 2; t++) {
    const int type = t ? TAS58XX_BQ_TREBLE_SHELF : TAS58XX_BQ_BASS_SHELF;
    const char *name = t ? "treble shelf" : "bass shelf";
    for (int fi = 0; fi < 3; fi++) {
      for (int gi = 0; gi < 10; gi++) {
        const double f0 = freqs[fi], g = gains[gi];
        double c[5];
        const tas58xx_bq_t bq = shelf(type, f0, g);
        tas58xx_bq_design(&bq, fs, c);

        const double low = mag_db(c, 0.0, fs);
        const double high = mag_db(c, fs / 2.0, fs);
        CHECK(fabs((t ? high : low) - g) < 0.001 &&
                  fabs(t ? low : high) < 0.001,
              "%s %g Hz %+g dB at %g: DC %+.4f, Nyquist %+.4f dB", name, f0, g,
              fs, low, high);
        CHECK(fabs(mag_db(c, f0, fs) - shelf_corner_db(g)) < 0.005,
              "%s %g Hz %+g dB at %g: corner %+.4f dB, expected %+.4f", name,
              f0, g, fs, mag_db(c, f0, fs), shelf_corner_db(g));

        double lo_db, hi_db;
        extremes(c, fs, 1.0, fs / 2.0, &lo_db, &hi_db);
        const double over = fmax(hi_db - fmax(g, 0.0), fmin(g, 0.0) - lo_db);
        worst_overshoot = fmax(worst_overshoot, over);
        CHECK(over < 0.001, "%s %g Hz %+g dB at %g: overshoots by %.4f dB",
              name, f0, g, fs, over);
        checked++;
      }
    }
  }
  printf("  shelves: %d designs, worst overshoot %+.4f dB\n", checked,
         worst_overshoot);
}

/*
 * Low and high pass: unity in the passband, a zero at the far end, the
 * alignment's level and phase at the corner, and no peaking for the
 * alignments that should have none. Chebyshev ripples between unity and
 * the ripple depth. An LR2 pair with the high pass inverted is all-pass,
 * which is what makes it a crossover; a first-order pair adds to exactly one.
 */
static void check_passes(double fs) {
  const double freqs[] = {20.0, 1000.0, 8000.0};
  int checked = 0;

  for (int fi = 0; fi < 3; fi++) {
    const double f0 = freqs[fi];
    const double lo_band = f0 / 1000.0;

    struct {
      int sub;
      double q, ripple, corner_db, corner_deg;
      bool flat; /* no peaking anywhere */
    } cases[] = {
        {TAS58XX_BQ_SUB_BUTTERWORTH_1, 0, 0, HALF_POWER_DB, 45, true},
        {TAS58XX_BQ_SUB_BUTTERWORTH_2, 0, 0, HALF_POWER_DB, 90, true},
        {TAS58XX_BQ_SUB_BESSEL_2, 0, 0, THIRD_POWER_DB, 90, true},
        {TAS58XX_BQ_SUB_LINKWITZ_RILEY_2, 0, 0, QUARTER_POWER_DB, 90, true},
        {TAS58XX_BQ_SUB_VARIABLE_Q_2, 0.5, 0, 20.0 * log10(0.5), 90, true},
        {TAS58XX_BQ_SUB_VARIABLE_Q_2, M_SQRT1_2, 0, HALF_POWER_DB, 90, true},
        {TAS58XX_BQ_SUB_VARIABLE_Q_2, 2.0, 0, 20.0 * log10(2.0), 90, false},
        {TAS58XX_BQ_SUB_VARIABLE_Q_2, 10.0, 0, 20.0, 90, false},
        {TAS58XX_BQ_SUB_CHEBYSHEV_2, 0, 0.5, -0.5, NAN, false},
        {TAS58XX_BQ_SUB_CHEBYSHEV_2, 0, 1.0, -1.0, NAN, false},
        {TAS58XX_BQ_SUB_CHEBYSHEV_2, 0, 3.0, -3.0, NAN, false},
    };
    const int n = (int)(sizeof(cases) / sizeof(cases[0]));

    for (int k = 0; k < n; k++) {
      double lp[5], hp[5];
      tas58xx_bq_t bq = pass(TAS58XX_BQ_LOWPASS, cases[k].sub, f0, cases[k].q,
                             cases[k].ripple);
      tas58xx_bq_design(&bq, fs, lp);
      bq.type = TAS58XX_BQ_HIGHPASS;
      tas58xx_bq_design(&bq, fs, hp);
      const bool cheby = cases[k].sub == TAS58XX_BQ_SUB_CHEBYSHEV_2;
      const double pass_db = cheby ? -cases[k].ripple : 0.0;

      CHECK(fabs(mag_db(lp, 0.0, fs) - pass_db) < 0.001 &&
                mag_db(lp, fs / 2.0, fs) < ZERO_DB,
            "low pass sub %d Q%g %g Hz at %g: DC %+.4f, Nyquist %+.1f dB",
            cases[k].sub, cases[k].q, f0, fs, mag_db(lp, 0.0, fs),
            mag_db(lp, fs / 2.0, fs));
      CHECK(fabs(mag_db(hp, fs / 2.0, fs) - pass_db) < 0.001 &&
                mag_db(hp, 0.0, fs) < ZERO_DB,
            "high pass sub %d Q%g %g Hz at %g: Nyquist %+.4f, DC %+.1f dB",
            cases[k].sub, cases[k].q, f0, fs, mag_db(hp, fs / 2.0, fs),
            mag_db(hp, 0.0, fs));

      CHECK(fabs(mag_db(lp, f0, fs) - cases[k].corner_db) < 0.001 &&
                fabs(mag_db(hp, f0, fs) - cases[k].corner_db) < 0.001,
            "sub %d Q%g %g Hz at %g: corner LP %+.4f HP %+.4f, expected %+.4f",
            cases[k].sub, cases[k].q, f0, fs, mag_db(lp, f0, fs),
            mag_db(hp, f0, fs), cases[k].corner_db);
      if (!isnan(cases[k].corner_deg)) {
        CHECK(fabs(phase_deg(lp, f0, fs) + cases[k].corner_deg) < 0.01 &&
                  fabs(phase_deg(hp, f0, fs) - cases[k].corner_deg) < 0.01,
              "sub %d %g Hz at %g: corner phase LP %+.3f HP %+.3f, expected "
              "-/+%g",
              cases[k].sub, f0, fs, phase_deg(lp, f0, fs),
              phase_deg(hp, f0, fs), cases[k].corner_deg);
      }

      double lo_db, hi_db;
      if (cases[k].flat) {
        extremes(lp, fs, 1.0, fs / 2.0, &lo_db, &hi_db);
        CHECK(hi_db < 0.001, "low pass sub %d Q%g %g Hz at %g peaks %+.4f dB",
              cases[k].sub, cases[k].q, f0, fs, hi_db);
        extremes(hp, fs, 1.0, fs / 2.0, &lo_db, &hi_db);
        CHECK(hi_db < 0.001, "high pass sub %d Q%g %g Hz at %g peaks %+.4f dB",
              cases[k].sub, cases[k].q, f0, fs, hi_db);
      } else if (cheby) {
        /* The ripple band runs up to the corner on a low pass, and from it
         * on a high pass. */
        const double r = cases[k].ripple;
        extremes(lp, fs, lo_band, f0, &lo_db, &hi_db);
        CHECK(fabs(hi_db) < 0.01 && fabs(lo_db + r) < 0.01,
              "Chebyshev %g dB low pass %g Hz at %g: passband %+.4f..%+.4f", r,
              f0, fs, lo_db, hi_db);
        extremes(hp, fs, f0, fs / 2.0, &lo_db, &hi_db);
        CHECK(fabs(hi_db) < 0.01 && fabs(lo_db + r) < 0.01,
              "Chebyshev %g dB high pass %g Hz at %g: passband %+.4f..%+.4f", r,
              f0, fs, lo_db, hi_db);
      }

      if (cases[k].sub == TAS58XX_BQ_SUB_LINKWITZ_RILEY_2) {
        double worst_db = 0.0, worst_deg = 0.0;
        for (double f = 1.0; f <= sweep_top(fs); f *= SWEEP_STEP) {
          const double complex l = response(lp, f, fs);
          const double complex h = response(hp, f, fs);
          worst_db = fmax(worst_db, fabs(20.0 * log10(cabs(l - h))));
          worst_deg = fmax(worst_deg, 180.0 - fabs(carg(h / l) * 180.0 / M_PI));
        }
        CHECK(worst_db < 0.001 && worst_deg < 0.001,
              "LR2 %g Hz at %g: LP - HP strays %.4f dB, pair %.4f deg off 180",
              f0, fs, worst_db, worst_deg);
      }
      if (cases[k].sub == TAS58XX_BQ_SUB_BUTTERWORTH_1) {
        double worst = 0.0;
        for (double f = 1.0; f <= sweep_top(fs); f *= SWEEP_STEP) {
          worst = fmax(worst,
                       cabs(response(lp, f, fs) + response(hp, f, fs) - 1.0));
        }
        CHECK(worst < 1e-12, "1st order %g Hz at %g: LP + HP strays %.3g", f0,
              fs, worst);
      }
      checked += 2;
    }
  }
  printf("  low and high pass: %d designs\n", checked);
}

/*
 * Band pass: rising to unity and no further, -3 dB at the band edges. Notch:
 * a zero at the centre, -3 dB edges the bandwidth apart. Phase shift: unity
 * everywhere, half a turn at the centre. Any shape inverted is its negative.
 */
static void check_banded(double fs) {
  const double freqs[] = {100.0, 1000.0, 10000.0};
  const double widths[] = {20.0, 50.0, 180.0};
  int checked = 0;

  for (int fi = 0; fi < 3; fi++) {
    for (int wi = 0; wi < 3; wi++) {
      const double f0 = freqs[fi], bw = widths[wi] * f0 / 100.0;
      double c[5];

      tas58xx_bq_t bq = banded(TAS58XX_BQ_BANDPASS, f0, bw);
      tas58xx_bq_design(&bq, fs, c);
      const double fl = f0 - bw / 2.0, fu = f0 + bw / 2.0;
      CHECK(fabs(mag_db(c, fl, fs) - HALF_POWER_DB) < 0.001 &&
                fabs(mag_db(c, fu, fs) - HALF_POWER_DB) < 0.001,
            "band pass %g Hz %g wide at %g: edges %+.4f, %+.4f dB", f0, bw, fs,
            mag_db(c, fl, fs), mag_db(c, fu, fs));
      CHECK(mag_db(c, 0.0, fs) < ZERO_DB && mag_db(c, fs / 2.0, fs) < ZERO_DB,
            "band pass %g Hz at %g: DC %+.1f, Nyquist %+.1f dB", f0, fs,
            mag_db(c, 0.0, fs), mag_db(c, fs / 2.0, fs));
      double lo_db, hi_db;
      extremes(c, fs, 1.0, fs / 2.0, &lo_db, &hi_db);
      const double top = top_db(c, fs, fl, fu);
      CHECK(fabs(top) < 0.001 && hi_db < 0.001,
            "band pass %g Hz %g wide at %g: peaks at %+.4f dB", f0, bw, fs,
            fmax(top, hi_db));

      bq = banded(TAS58XX_BQ_NOTCH, f0, bw);
      tas58xx_bq_design(&bq, fs, c);
      CHECK(mag_db(c, f0, fs) < ZERO_DB, "notch %g Hz at %g: centre %+.1f dB",
            f0, fs, mag_db(c, f0, fs));
      CHECK(fabs(mag_db(c, 0.0, fs)) < 0.001 &&
                fabs(mag_db(c, fs / 2.0, fs)) < 0.001,
            "notch %g Hz at %g: DC %+.4f, Nyquist %+.4f dB", f0, fs,
            mag_db(c, 0.0, fs), mag_db(c, fs / 2.0, fs));
      const double lower = crossing(c, fs, 1e-3, f0, HALF_POWER_DB);
      const double upper = crossing(c, fs, f0, fs / 2.0, HALF_POWER_DB);
      CHECK(fabs((upper - lower) / bw - 1.0) < 1e-4,
            "notch %g Hz %g wide at %g: -3 dB points %.2f Hz apart", f0, bw, fs,
            upper - lower);

      bq = banded(TAS58XX_BQ_PHASE_SHIFT, f0, bw);
      tas58xx_bq_design(&bq, fs, c);
      extremes(c, fs, 1.0, fs / 2.0, &lo_db, &hi_db);
      CHECK(fabs(lo_db) < 1e-6 && fabs(hi_db) < 1e-6,
            "phase shift %g Hz at %g: magnitude %+.2g..%+.2g dB", f0, fs, lo_db,
            hi_db);
      CHECK(fabs(fabs(phase_deg(c, f0, fs)) - 180.0) < 0.001,
            "phase shift %g Hz at %g: %+.3f deg at the centre", f0, fs,
            phase_deg(c, f0, fs));
      checked += 3;
    }
  }

  /* Inverting negates the whole response, a bypassed slot included. */
  const tas58xx_bq_t shapes[] = {
      peak(1000.0, 2.0, 6.0),
      shelf(TAS58XX_BQ_BASS_SHELF, 80.0, 10.0),
      pass(TAS58XX_BQ_HIGHPASS, TAS58XX_BQ_SUB_LINKWITZ_RILEY_2, 2800, 0, 0),
      shape(TAS58XX_BQ_BYPASS, 0, 1000.0),
  };
  for (int i = 0; i < (int)(sizeof(shapes) / sizeof(shapes[0])); i++) {
    double plain[5], flipped[5];
    tas58xx_bq_t bq = shapes[i];
    tas58xx_bq_design(&bq, fs, plain);
    bq.invert = 1;
    tas58xx_bq_design(&bq, fs, flipped);
    const double complex sum =
        response(plain, 1234.0, fs) + response(flipped, 1234.0, fs);
    CHECK(cabs(sum) < 1e-12 && plain[3] == flipped[3] && plain[4] == flipped[4],
          "type %d at %g: inverting does not negate the response", bq.type, fs);
  }
  printf("  band pass, notch, phase shift: %d designs\n", checked);
}

/* ---------------- on the chip ---------------- */

static const char *type_name(int type) {
  static const char *const names[TAS58XX_BQ_TYPE_COUNT] = {
      "bypass",       "peak",        "peak (bw)", "bass shelf",
      "treble shelf", "low pass",    "high pass", "band pass",
      "notch",        "phase shift", "custom",
  };
  return type < TAS58XX_BQ_TYPE_COUNT ? names[type] : "?";
}

/* The pass-through a design falls back to, in either polarity. */
static bool is_unity(const double c[5]) {
  return fabs(c[0]) == 1.0 && c[1] == 0.0 && c[2] == 0.0 && c[3] == 0.0 &&
         c[4] == 0.0;
}

/*
 * Every shape at the ends of the range the API accepts, as the chip is given
 * it: once rounded to 5.27 nothing may saturate, which would leave it running
 * a different filter altogether, and every section must stay stable. What
 * cannot be held at some rate tas58xx_bq_fits() must refuse, and the chip
 * design play as a pass-through there; nothing in this set is meant to be
 * flat.
 */
static void check_range(double fs) {
  int n = 0, refused = 0;
  const double freqs[] = {10.0, 20.0, 100.0, 1000.0, 10000.0, 20000.0};
  const double qs[] = {TAS58XX_BQ_Q_MIN, 0.5, 5.0, TAS58XX_BQ_Q_MAX};
  const double gains[] = {TAS58XX_BQ_GAIN_MIN_DB, -6.0, 6.0,
                          TAS58XX_BQ_GAIN_MAX_DB};

  for (int fi = 0; fi < 6; fi++) {
    const double f0 = freqs[fi];
    tas58xx_bq_t designs[160];
    int count = 0;
    for (int qi = 0; qi < 4; qi++) {
      for (int gi = 0; gi < 4; gi++) {
        designs[count++] = peak(f0, qs[qi], gains[gi]);
      }
    }
    for (int gi = 0; gi < 4; gi++) {
      designs[count++] = shelf(TAS58XX_BQ_BASS_SHELF, f0, gains[gi]);
      designs[count++] = shelf(TAS58XX_BQ_TREBLE_SHELF, f0, gains[gi]);
    }
    for (int t = 0; t < 2; t++) {
      const int type = t ? TAS58XX_BQ_HIGHPASS : TAS58XX_BQ_LOWPASS;
      for (int sub = 0; sub < TAS58XX_BQ_SUB_COUNT; sub++) {
        for (int qi = 0; qi < 4; qi++) {
          designs[count++] = pass(type, sub, f0, qs[qi],
                                  qi < 2 ? TAS58XX_BQ_RIPPLE_MIN_DB
                                         : TAS58XX_BQ_RIPPLE_MAX_DB);
        }
      }
    }
    const double widths[] = {0.01, 1.0};
    for (int wi = 0; wi < 2; wi++) {
      designs[count++] = banded(TAS58XX_BQ_BANDPASS, f0, f0 * widths[wi]);
      designs[count++] = banded(TAS58XX_BQ_NOTCH, f0, f0 * widths[wi]);
      designs[count++] = banded(TAS58XX_BQ_PHASE_SHIFT, f0, f0 * widths[wi]);
    }

    for (int i = 0; i < count; i++) {
      const tas58xx_bq_t *bq = &designs[i];
      double ideal[5], chip[5];
      bool saturated;
      tas58xx_bq_design_chip(bq, fs, ideal);
      on_chip(ideal, chip, &saturated);
      CHECK(!saturated, "%s %g Hz Q%g %+g dB at %g: does not fit 5.27",
            type_name(bq->type), bq->freq_hz, bq->q, bq->gain_db, fs);

      bool flat_somewhere = false;
      for (int r = 0; r < RATE_COUNT; r++) {
        double at[5];
        tas58xx_bq_design_chip(bq, rates[r], at);
        flat_somewhere = flat_somewhere || is_unity(at);
      }
      const bool fits = tas58xx_bq_fits(bq);
      refused += !fits;
      CHECK(fits == !flat_somewhere,
            "%s %g Hz Q%g %+g dB: fits says %d, but flat at some rate is %d",
            type_name(bq->type), bq->freq_hz, bq->q, bq->gain_db, fits,
            flat_somewhere);
      /* Poles of 1 - a1 z^-1 - a2 z^-2 inside the unit circle. */
      CHECK(fabs(chip[4]) < 1.0 && fabs(chip[3]) < 1.0 - chip[4],
            "%s sub %d %g Hz Q%g at %g: unstable once rounded (%.9f, %.9f)",
            type_name(bq->type), bq->sub, bq->freq_hz, bq->q, fs, chip[3],
            chip[4]);
      n++;
    }
  }
  printf("  setting range: %d designs, %d refused for 5.27\n", n, refused);
}

/*
 * Where the limit falls. A treble shelf with a low corner needs b1 of nearly
 * twice its gain, negated, so +18 dB (b1 about -15.9) is the most that fits
 * at every corner, and +19 dB is refused below about 2 kHz. A bass shelf only
 * gets there with its corner at the top of the band at 44.1 kHz.
 */
static void check_limits(void) {
  for (double f0 = 10.0; f0 <= 20000.0; f0 *= 1.12) {
    const tas58xx_bq_t ok = shelf(TAS58XX_BQ_TREBLE_SHELF, f0, 18.0);
    CHECK(tas58xx_bq_fits(&ok), "treble shelf %g Hz +18 dB refused", f0);
    const tas58xx_bq_t cut = shelf(TAS58XX_BQ_TREBLE_SHELF, f0, -20.0);
    CHECK(tas58xx_bq_fits(&cut), "treble shelf %g Hz -20 dB refused", f0);
  }
  const tas58xx_bq_t steep = shelf(TAS58XX_BQ_TREBLE_SHELF, 1000.0, 19.0);
  CHECK(!tas58xx_bq_fits(&steep), "treble shelf 1 kHz +19 dB accepted");
  const tas58xx_bq_t high = shelf(TAS58XX_BQ_BASS_SHELF, 20000.0, 20.0);
  CHECK(!tas58xx_bq_fits(&high), "bass shelf 20 kHz +20 dB accepted");

  /* The chip's fallback keeps the section's polarity and nothing else, and
   * only the chip falls back: the software EQ runs in floating point. */
  tas58xx_bq_t flipped = steep;
  flipped.invert = true;
  double c[5];
  tas58xx_bq_design_chip(&flipped, 48000.0, c);
  CHECK(c[0] == -1.0 && is_unity(c), "refused inverted shelf is not -1");
  tas58xx_bq_design(&flipped, 48000.0, c);
  CHECK(!is_unity(c), "the plain design falls back too");

  /* Raw coefficients the part cannot hold are refused outright. */
  tas58xx_bq_t raw = shape(TAS58XX_BQ_CUSTOM, 0, 1000.0);
  raw.coeff[0] = 16.0f;
  CHECK(!tas58xx_bq_validate(&raw, NULL), "custom b0 of 16 accepted");
}

/*
 * The settings a speaker is actually tuned with, rounded to 5.27: the
 * response must not move by more than a quarter of a dB anywhere it passes
 * within 20 dB of unity. Below that the error is in a stopband no one hears.
 * The TAS5805M designs at 96 kHz, which puts low corners closer to DC in
 * the z-plane than at 48 kHz, and so rounds them about three times coarser.
 */
static void check_accuracy(double fs) {
  static const char *const groups[] = {"peaks", "shelves", "low/high pass",
                                       "band shapes"};
  for (int g = 0; g < 4; g++) {
    double worst = 0.0;
    tas58xx_bq_t worst_bq;
    tas58xx_bq_init_bypass(&worst_bq);
    int n = 0;

    for (double f0 = 20.0; f0 <= 20000.0; f0 *= 1.12) {
      tas58xx_bq_t designs[160];
      int count = 0;
      if (g == 0) {
        for (double q = 0.5; q <= 10.01; q *= 1.25) {
          for (double gain = -12.0; gain <= 12.0; gain += 3.0) {
            designs[count++] = peak(f0, q, gain);
          }
        }
      } else if (g == 1 && f0 >= 30.0 && f0 <= 15000.0) {
        for (double gain = -12.0; gain <= 12.0; gain += 3.0) {
          designs[count++] = shelf(TAS58XX_BQ_BASS_SHELF, f0, gain);
          designs[count++] = shelf(TAS58XX_BQ_TREBLE_SHELF, f0, gain);
        }
      } else if (g == 2) {
        for (int sub = 0; sub < TAS58XX_BQ_SUB_COUNT; sub++) {
          designs[count++] = pass(TAS58XX_BQ_LOWPASS, sub, f0, 2.0, 1.0);
          designs[count++] = pass(TAS58XX_BQ_HIGHPASS, sub, f0, 2.0, 1.0);
        }
      } else if (g == 3 && f0 >= 50.0) {
        designs[count++] = banded(TAS58XX_BQ_BANDPASS, f0, f0 / 5.0);
        designs[count++] = banded(TAS58XX_BQ_NOTCH, f0, f0 / 5.0);
        designs[count++] = banded(TAS58XX_BQ_PHASE_SHIFT, f0, f0 / 5.0);
      }

      for (int i = 0; i < count; i++) {
        double ideal[5], chip[5];
        bool saturated;
        CHECK(tas58xx_bq_fits(&designs[i]), "%s %g Hz %+g dB refused",
              type_name(designs[i].type), designs[i].freq_hz,
              designs[i].gain_db);
        tas58xx_bq_design(&designs[i], fs, ideal);
        on_chip(ideal, chip, &saturated);
        double err = 0.0;
        for (double f = 10.0; f <= sweep_top(fs); f *= SWEEP_STEP) {
          const double want = cabs(response(ideal, f, fs));
          if (want > 0.1) {
            err = fmax(err,
                       fabs(20.0 * log10(cabs(response(chip, f, fs)) / want)));
          }
        }
        if (err > worst) {
          worst = err;
          worst_bq = designs[i];
        }
        n++;
      }
    }
    CHECK(worst < 0.25, "%s at %g: rounding moves %s %g Hz Q%g %+g dB by %.3f",
          groups[g], fs, type_name(worst_bq.type), worst_bq.freq_hz, worst_bq.q,
          worst_bq.gain_db, worst);
    printf("  %s rounded: %d designs, worst %.3f dB (%s %.0f Hz", groups[g], n,
           worst, type_name(worst_bq.type), worst_bq.freq_hz);
    if (g == 0) {
      printf(" Q%.2f %+g dB", worst_bq.q, worst_bq.gain_db);
    }
    printf(")\n");
  }
}

/* The packing itself: 5.27 big-endian, rounded, saturating at +/-16. */
static void check_packing(void) {
  const double in[5] = {1.0, -1.0, 0.5, 16.0, -17.0};
  const uint8_t want[TAS58XX_BQ_COEFF_BYTES] = {
      0x08, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
  };
  uint8_t got[TAS58XX_BQ_COEFF_BYTES];
  tas58xx_bq_pack(in, got);
  CHECK(memcmp(got, want, sizeof(want)) == 0, "5.27 packing is wrong");

  /* Half an LSB rounds away from zero, in both directions. */
  const double lsb = 1.0 / (double)(1 << 27);
  const double halves[5] = {0.5 * lsb, -0.5 * lsb, 0.49 * lsb, 0, 0};
  tas58xx_bq_pack(halves, got);
  CHECK(got[3] == 0x01 && got[4] == 0xFF && got[7] == 0xFF && got[11] == 0x00,
        "5.27 rounding is wrong");

  /* A pass-through block reads back as bypass, anything else as raw
   * coefficients that land on the packed words. */
  tas58xx_bq_t unity = shape(TAS58XX_BQ_BYPASS, 0, 1000.0), back;
  tas58xx_bq_design_packed(&unity, 48000.0, got);
  tas58xx_bq_unpack(got, &back);
  CHECK(back.type == TAS58XX_BQ_BYPASS, "unity unpacks as type %d", back.type);

  double c[5];
  const tas58xx_bq_t p = peak(1000.0, 2.0, 6.0);
  tas58xx_bq_design(&p, 96000.0, c);
  tas58xx_bq_pack(c, got);
  tas58xx_bq_unpack(got, &back);
  bool close = back.type == TAS58XX_BQ_CUSTOM;
  for (int i = 0; i < 5; i++) {
    close = close && fabs(back.coeff[i] - c[i]) < 1e-6;
  }
  CHECK(close, "a packed peak does not unpack to its coefficients");
}

int main(void) {
  for (int r = 0; r < RATE_COUNT; r++) {
    printf("%.0f Hz\n", rates[r]);
    check_peaking(rates[r]);
    check_shelves(rates[r]);
    check_passes(rates[r]);
    check_banded(rates[r]);
    check_range(rates[r]);
    check_accuracy(rates[r]);
  }
  check_limits();
  check_packing();

  if (s_failed) {
    printf("%d of %d check(s) failed\n", s_failed, s_checks);
    return 1;
  }
  printf("All %d biquad checks passed\n", s_checks);
  return 0;
}
