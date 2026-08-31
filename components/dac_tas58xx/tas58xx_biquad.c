/**
 * PurePath Console 3 biquad filter models.
 *
 * Transcribed from the PPC3 biquad model so that a filter configured here
 * produces the same coefficients TI's tool would have written for the same
 * settings. Everything is evaluated in double precision: the low-frequency
 * corners a subwoofer crossover needs lose most of their significant digits
 * to cancellation in (1 - cos w0) at single precision.
 */

#include "tas58xx_biquad.h"

#include <math.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* Highest fraction of the sample rate a corner may sit at. */
#define BQ_NYQUIST_MARGIN 0.49

/* Below this the shelves degenerate to 0/0, so treat them as unity. */
#define BQ_GAIN_EPSILON_DB 1e-4

typedef struct {
  double b0, b1, b2, a1, a2; /* a1/a2 negated, i.e. device convention */
} bq_coeff_t;

static const bq_coeff_t bq_unity = {1.0, 0.0, 0.0, 0.0, 0.0};

static double clampd(double v, double lo, double hi) {
  if (!(v > lo)) { /* also catches NaN */
    return lo;
  }
  return (v > hi) ? hi : v;
}

void tas58xx_bq_init_bypass(tas58xx_bq_t *bq) {
  if (!bq) {
    return;
  }
  memset(bq, 0, sizeof(*bq));
  bq->type = TAS58XX_BQ_BYPASS;
  bq->freq_hz = 1000.0f;
  bq->q = 0.707f;
  bq->bandwidth_hz = 100.0f;
  bq->ripple_db = 0.5f;
  bq->coeff[0] = 1.0f;
}

/* ---------------- shape models ---------------- */

/*
 * "Equalizer (Q Factor)" and "Equalizer (Bandwidth)" are the same model; the
 * bandwidth form just derives Q from freq/bandwidth first. Below unity gain
 * the bandwidth is widened by the gain so a cut is as wide as the matching
 * boost, which is what makes this differ from a plain RBJ peaking section.
 */
static bq_coeff_t bq_peaking(double gain_db, double freq, double fs, double q) {
  bq_coeff_t o;
  const double g = pow(10.0, gain_db / 20.0);
  const double t0 = 2.0 * M_PI * freq / fs;
  const double beta = (g >= 1.0) ? t0 / (2.0 * q) : t0 / (2.0 * g * q);

  double a2 = -0.5 * (1.0 - beta) / (1.0 + beta);
  double a1 = (0.5 - a2) * cos(t0);
  double b0 = (g - 1.0) * (0.25 + 0.5 * a2) + 0.5;
  double b1 = -a1;
  double b2 = -(g - 1.0) * (0.25 + 0.5 * a2) - a2;

  o.b0 = 2.0 * b0;
  o.b1 = 2.0 * b1;
  o.b2 = 2.0 * b2;
  o.a1 = 2.0 * a1;
  o.a2 = 2.0 * a2;
  return o;
}

/* Shared front half of both shelves: the numerator and denominator gain
 * factors PPC3 calls gainN and gainD. */
static bool shelf_gains(double gain_db, double *gain_n, double *gain_d) {
  const double gain_a = pow(10.0, gain_db / 20.0);
  const double root2 = sqrt(2.0);
  double gain_f;

  if (gain_db >= -6.0 && gain_db <= 6.0) {
    gain_f = sqrt(gain_a);
  } else if (gain_a > 1.0) {
    gain_f = gain_a / root2;
  } else {
    gain_f = gain_a * root2;
  }

  const double num = gain_f * gain_f - 1.0;
  const double den = gain_a * gain_a - gain_f * gain_f;
  if (fabs(den) < 1e-12 || num / den < 0.0) {
    return false;
  }
  *gain_d = pow(num / den, 0.25);
  *gain_n = sqrt(gain_a) * (*gain_d);
  return isfinite(*gain_d) && isfinite(*gain_n);
}

static bq_coeff_t bq_bass_shelf(double gain_db, double freq, double fs) {
  double gn, gd;
  if (fabs(gain_db) < BQ_GAIN_EPSILON_DB || !shelf_gains(gain_db, &gn, &gd)) {
    return bq_unity;
  }

  const double s = sqrt(2.0) / 2.0;
  const double a = tan(M_PI * (freq / fs - 0.25));
  const double a2 = a * a;
  const double gn2 = gn * gn;
  const double gd2 = gd * gd;
  const double den = 2.0 * s * gd + 1.0 - 2.0 * s * gd * a2 + gd2 * a2 +
                     2.0 * gd2 * a + a2 + gd2 - 2.0 * a;

  bq_coeff_t o;
  o.b0 = (1.0 + gn2 * a2 + a2 + 2.0 * gn2 * a + gn2 + 2.0 * s * gn -
          2.0 * s * gn * a2 - 2.0 * a) /
         den;
  o.b1 =
      (-2.0 + 4.0 * a + 4.0 * gn2 * a + 2.0 * gn2 * a2 + 2.0 * gn2 - 2.0 * a2) /
      den;
  o.b2 = (1.0 + 2.0 * s * gn * a2 - 2.0 * a + gn2 - 2.0 * s * gn +
          2.0 * gn2 * a + a2 + gn2 * a2) /
         den;
  o.a1 =
      (2.0 - 2.0 * gd2 * a2 - 4.0 * gd2 * a + 2.0 * a2 - 2.0 * gd2 - 4.0 * a) /
      den;
  o.a2 = (-gd2 * a2 + 2.0 * a - 1.0 - 2.0 * gd2 * a + 2.0 * s * gd - a2 -
          2.0 * s * gd * a2 - gd2) /
         den;
  return o;
}

static bq_coeff_t bq_treble_shelf(double gain_db, double freq, double fs) {
  double gn, gd;
  if (fabs(gain_db) < BQ_GAIN_EPSILON_DB || !shelf_gains(gain_db, &gn, &gd)) {
    return bq_unity;
  }

  const double s = sqrt(2.0) / 2.0;
  const double a = tan(M_PI * (freq / fs - 0.25));
  const double a2 = a * a;
  const double gn2 = gn * gn;
  const double gd2 = gd * gd;
  const double den = 1.0 + gd2 + 2.0 * s * gd - 2.0 * s * gd * a2 + gd2 * a2 -
                     2.0 * gd2 * a + a2 + 2.0 * a;

  bq_coeff_t o;
  o.b0 = (gn2 * a2 + 2.0 * s * gn - 2.0 * gn2 * a + 1.0 - 2.0 * s * gn * a2 +
          a2 + gn2 + 2.0 * a) /
         den;
  o.b1 =
      (2.0 - 2.0 * gn2 * a2 + 4.0 * gn2 * a + 4.0 * a - 2.0 * gn2 + 2.0 * a2) /
      den;
  o.b2 = (1.0 + 2.0 * s * gn * a2 - 2.0 * s * gn + 2.0 * a + a2 + gn2 -
          2.0 * gn2 * a + gn2 * a2) /
         den;
  o.a1 =
      -(2.0 - 2.0 * gd2 * a2 + 4.0 * gd2 * a + 2.0 * a2 - 2.0 * gd2 + 4.0 * a) /
      den;
  o.a2 = -(1.0 - 2.0 * gd2 * a + 2.0 * a + gd2 - 2.0 * s * gd + a2 + gd2 * a2 +
           2.0 * s * gd * a2) /
         den;
  return o;
}

/*
 * Chebyshev pole pair for a 2nd-order section. Returns the three quantities
 * PPC3 calls a, b and c; a negative ripple asks for a passband that starts at
 * unity rather than at the top of the ripple band.
 */
static bool cheby_terms(double ripple_db, double *a, double *b, double *c) {
  const double r = fabs(ripple_db);
  if (r < 1e-6) {
    return false; /* no ripple leaves nothing to place the poles with */
  }
  const double epsilon = sqrt(pow(10.0, r / 10.0) - 1.0);
  const double alpha = asinh(1.0 / epsilon) / 2.0;
  const double sh = sinh(alpha), ch = cosh(alpha);
  /* beta1 = 3pi/4 and beta2 = 5pi/4, so the trig folds to exact constants. */
  *a = -sqrt(2.0) * sh;
  *b = 0.5 * (sh * sh + ch * ch);
  if (!(fabs(*b) > 1e-12)) {
    return false;
  }
  *c = (ripple_db > 0.0) ? *b / sqrt(1.0 + epsilon * epsilon) : *b;
  return isfinite(*a) && isfinite(*b) && isfinite(*c);
}

/*
 * Analog prototype denominator for the fixed-alignment 2nd-order pass
 * filters. Chebyshev is not here: PPC3 normalises its low-pass and high-pass
 * prototypes differently, so each assembles its own.
 */
static bool pass_prototype(int sub, double wc, double q, double *a1,
                           double *a2) {
  *a2 = wc * wc;
  switch (sub) {
  case TAS58XX_BQ_SUB_BUTTERWORTH_2:
    *a1 = wc * sqrt(2.0);
    return true;
  case TAS58XX_BQ_SUB_BESSEL_2:
    *a1 = wc * sqrt(3.0);
    return true;
  case TAS58XX_BQ_SUB_LINKWITZ_RILEY_2:
    *a1 = 2.0 * wc;
    return true;
  case TAS58XX_BQ_SUB_VARIABLE_Q_2:
    *a1 = wc / q;
    return true;
  default:
    return false;
  }
}

/* Bilinear transform of B0/(s^2 + A1 s + A2) or B2 s^2/(...). */
static bq_coeff_t pass_bilinear(double k, double a1, double a2, double num,
                                bool highpass) {
  const double den = k * k + a2 + a1 * k;
  if (!(fabs(den) > 1e-12)) {
    return bq_unity;
  }
  bq_coeff_t o;
  o.b0 = num / den;
  o.b1 = (highpass ? -2.0 : 2.0) * num / den;
  o.b2 = num / den;
  o.a1 = (2.0 * k * k - 2.0 * a2) / den;
  o.a2 = (a1 * k - k * k - a2) / den;
  return o;
}

static bq_coeff_t bq_lowpass(int sub, double freq, double fs, double q,
                             double ripple_db) {
  const double wc = 2.0 * M_PI * freq;
  const double k = wc / tan(M_PI * freq / fs);

  if (sub == TAS58XX_BQ_SUB_BUTTERWORTH_1) {
    bq_coeff_t o;
    o.b0 = wc / (k + wc);
    o.b1 = o.b0;
    o.b2 = 0.0;
    o.a1 = (k - wc) / (k + wc);
    o.a2 = 0.0;
    return o;
  }

  double a1, a2;
  if (sub == TAS58XX_BQ_SUB_CHEBYSHEV_2) {
    double a, b, c;
    if (!cheby_terms(ripple_db, &a, &b, &c)) {
      return bq_unity;
    }
    return pass_bilinear(k, -wc * a, b * wc * wc, c * wc * wc, false);
  }
  if (!pass_prototype(sub, wc, q, &a1, &a2)) {
    return bq_unity;
  }
  return pass_bilinear(k, a1, a2, wc * wc, false);
}

static bq_coeff_t bq_highpass(int sub, double freq, double fs, double q,
                              double ripple_db) {
  const double wc = 2.0 * M_PI * freq;
  const double k = wc / tan(M_PI * freq / fs);

  if (sub == TAS58XX_BQ_SUB_BUTTERWORTH_1) {
    bq_coeff_t o;
    o.b0 = k / (k + wc);
    o.b1 = -o.b0;
    o.b2 = 0.0;
    o.a1 = (k - wc) / (k + wc);
    o.a2 = 0.0;
    return o;
  }

  double a1, a2;
  if (sub == TAS58XX_BQ_SUB_CHEBYSHEV_2) {
    double a, b, c;
    if (!cheby_terms(ripple_db, &a, &b, &c)) {
      return bq_unity;
    }
    return pass_bilinear(k, -wc * a / b, wc * wc / b, (c / b) * k * k, true);
  }
  if (!pass_prototype(sub, wc, q, &a1, &a2)) {
    return bq_unity;
  }
  return pass_bilinear(k, a1, a2, k * k, true);
}

static bq_coeff_t bq_bandpass(double freq, double bw, double fs) {
  const double fl = freq - bw / 2.0;
  const double fu = freq + bw / 2.0;
  const double wu = 2.0 * M_PI * fu / fs;
  const double wl = 2.0 * M_PI * fl / fs;
  const double wc = sqrt(wu * wl);
  const double c = tan(wc / 2.0);
  const double half_bw = (wu - wl) / 2.0;
  const double t = tan(half_bw);
  if (!(fabs(t) > 1e-12)) {
    return bq_unity;
  }
  const double k = c / t;
  const double alpha = cos((wu + wl) / 2.0) / cos(half_bw);
  const double abp1 = -2.0 * alpha * k / (k + 1.0);
  const double abp2 = (k - 1.0) / (k + 1.0);
  const double a0 = (abp2 + 1.0) + c * (1.0 - abp2);
  if (!(fabs(a0) > 1e-12)) {
    return bq_unity;
  }

  bq_coeff_t o;
  o.b0 = c * (1.0 - abp2) / a0;
  o.b1 = 0.0;
  o.b2 = c * (abp2 - 1.0) / a0;
  o.a1 = -2.0 * abp1 / a0;
  o.a2 = (-c * (abp2 - 1.0) - (1.0 + abp2)) / a0;
  return o;
}

static bq_coeff_t bq_notch(double freq, double bw, double fs) {
  const double interim = tan(M_PI * bw / fs);
  const double a = (1.0 - interim) / (1.0 + interim);
  const double d = -cos(2.0 * M_PI * freq / fs);
  bq_coeff_t o;
  o.b0 = (1.0 + a) / 2.0;
  o.b1 = d * (1.0 + a);
  o.b2 = (1.0 + a) / 2.0;
  o.a1 = -o.b1;
  o.a2 = -a;
  return o;
}

static bq_coeff_t bq_phase_shift(double freq, double bw, double fs) {
  const double interim = tan(M_PI * bw / fs);
  const double a = (1.0 - interim) / (1.0 + interim);
  const double d = -cos(2.0 * M_PI * freq / fs);
  bq_coeff_t o;
  o.b0 = a;
  o.b1 = d * (1.0 + a);
  o.b2 = 1.0;
  o.a1 = -o.b1;
  o.a2 = -a;
  return o;
}

/* ---------------- public entry points ---------------- */

void tas58xx_bq_design(const tas58xx_bq_t *bq, double sample_rate_hz,
                       double out[5]) {
  bq_coeff_t o = bq_unity;

  if (!bq || !out) {
    return;
  }
  const double fs = (sample_rate_hz > 1000.0) ? sample_rate_hz : 48000.0;
  const double f_max = fs * BQ_NYQUIST_MARGIN;
  const double f = clampd((double)bq->freq_hz, 1.0, f_max);
  const double q = clampd((double)bq->q, TAS58XX_BQ_Q_MIN, TAS58XX_BQ_Q_MAX);
  const double gain = clampd((double)bq->gain_db, TAS58XX_BQ_GAIN_MIN_DB,
                             TAS58XX_BQ_GAIN_MAX_DB);
  const double ripple = clampd((double)bq->ripple_db, TAS58XX_BQ_RIPPLE_MIN_DB,
                               TAS58XX_BQ_RIPPLE_MAX_DB);
  /* Keep both band edges inside the audio band, otherwise the geometric
   * mean the band-pass takes goes imaginary. */
  const double bw =
      clampd((double)bq->bandwidth_hz, 1.0, 2.0 * fmin(f - 1.0, f_max - f));

  switch (bq->type) {
  case TAS58XX_BQ_PEAKING_Q:
    o = bq_peaking(gain, f, fs, q);
    break;
  case TAS58XX_BQ_PEAKING_BW:
    o = bq_peaking(gain, f, fs, f / fmax(bw, 1.0));
    break;
  case TAS58XX_BQ_BASS_SHELF:
    o = bq_bass_shelf(gain, f, fs);
    break;
  case TAS58XX_BQ_TREBLE_SHELF:
    o = bq_treble_shelf(gain, f, fs);
    break;
  case TAS58XX_BQ_LOWPASS:
    o = bq_lowpass(bq->sub, f, fs, q, ripple);
    break;
  case TAS58XX_BQ_HIGHPASS:
    o = bq_highpass(bq->sub, f, fs, q, ripple);
    break;
  case TAS58XX_BQ_BANDPASS:
    o = bq_bandpass(f, bw, fs);
    break;
  case TAS58XX_BQ_NOTCH:
    o = bq_notch(f, bw, fs);
    break;
  case TAS58XX_BQ_PHASE_SHIFT:
    o = bq_phase_shift(f, bw, fs);
    break;
  case TAS58XX_BQ_CUSTOM:
    o.b0 = bq->coeff[0];
    o.b1 = bq->coeff[1];
    o.b2 = bq->coeff[2];
    o.a1 = bq->coeff[3];
    o.a2 = bq->coeff[4];
    break;
  case TAS58XX_BQ_BYPASS:
  default:
    break;
  }

  /* A model that produced a non-finite value would otherwise be packed as a
   * saturated coefficient and left running in the chain. */
  if (!isfinite(o.b0) || !isfinite(o.b1) || !isfinite(o.b2) ||
      !isfinite(o.a1) || !isfinite(o.a2)) {
    o = bq_unity;
  }

  /* Polarity is the numerator's sign, so a bypassed slot inverts on its own. */
  if (bq->invert) {
    o.b0 = -o.b0;
    o.b1 = -o.b1;
    o.b2 = -o.b2;
  }

  out[0] = o.b0;
  out[1] = o.b1;
  out[2] = o.b2;
  out[3] = o.a1;
  out[4] = o.a2;
}

void tas58xx_bq_pack(const double coeff[5],
                     uint8_t out[TAS58XX_BQ_COEFF_BYTES]) {
  for (int i = 0; i < 5; i++) {
    const double scaled = coeff[i] * (double)(1 << 27);
    int32_t fixed;
    if (scaled >= (double)INT32_MAX) {
      fixed = INT32_MAX;
    } else if (scaled <= (double)INT32_MIN) {
      fixed = INT32_MIN;
    } else {
      fixed = (int32_t)llround(scaled);
    }
    out[i * 4 + 0] = (uint8_t)(fixed >> 24);
    out[i * 4 + 1] = (uint8_t)(fixed >> 16);
    out[i * 4 + 2] = (uint8_t)(fixed >> 8);
    out[i * 4 + 3] = (uint8_t)fixed;
  }
}

void tas58xx_bq_unpack(const uint8_t in[TAS58XX_BQ_COEFF_BYTES],
                       tas58xx_bq_t *bq) {
  static const int32_t unity[5] = {1 << 27, 0, 0, 0, 0};

  if (!in || !bq) {
    return;
  }
  tas58xx_bq_init_bypass(bq);

  int32_t fixed[5];
  bool pass_through = true;
  for (int i = 0; i < 5; i++) {
    fixed[i] =
        (int32_t)(((uint32_t)in[i * 4 + 0] << 24) |
                  ((uint32_t)in[i * 4 + 1] << 16) |
                  ((uint32_t)in[i * 4 + 2] << 8) | (uint32_t)in[i * 4 + 3]);
    pass_through = pass_through && fixed[i] == unity[i];
  }
  if (pass_through) {
    return; /* an untouched slot already reads back as bypass */
  }

  bq->type = TAS58XX_BQ_CUSTOM;
  for (int i = 0; i < 5; i++) {
    bq->coeff[i] = (float)((double)fixed[i] / (double)(1 << 27));
  }
}

void tas58xx_bq_design_packed(const tas58xx_bq_t *bq, double sample_rate_hz,
                              uint8_t out[TAS58XX_BQ_COEFF_BYTES]) {
  double coeff[5];
  tas58xx_bq_design(bq, sample_rate_hz, coeff);
  tas58xx_bq_pack(coeff, out);
}

bool tas58xx_bq_validate(const tas58xx_bq_t *bq, const char **why) {
  const char *err = NULL;

  if (!bq) {
    err = "missing filter";
  } else if (bq->type >= TAS58XX_BQ_TYPE_COUNT) {
    err = "unknown filter type";
  } else if ((bq->type == TAS58XX_BQ_LOWPASS ||
              bq->type == TAS58XX_BQ_HIGHPASS) &&
             bq->sub >= TAS58XX_BQ_SUB_COUNT) {
    err = "unknown filter alignment";
  } else if (bq->type == TAS58XX_BQ_CUSTOM) {
    for (int i = 0; i < 5; i++) {
      if (!isfinite(bq->coeff[i]) || fabsf(bq->coeff[i]) >= 16.0f) {
        err = "custom coefficient out of range";
        break;
      }
    }
  } else if (bq->type != TAS58XX_BQ_BYPASS) {
    if (!isfinite(bq->freq_hz) || bq->freq_hz < 1.0f ||
        bq->freq_hz > 30000.0f) {
      err = "frequency out of range";
    } else if (!isfinite(bq->q) || !isfinite(bq->gain_db) ||
               !isfinite(bq->bandwidth_hz) || !isfinite(bq->ripple_db)) {
      err = "filter parameter is not a number";
    }
  }

  if (why) {
    *why = err;
  }
  return err == NULL;
}
