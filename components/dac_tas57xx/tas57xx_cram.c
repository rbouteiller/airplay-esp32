#include "tas57xx_cram.h"

#include "board_utils.h"
#include "esp_log.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "tas57xx_cram";

#define CRAM_PAGE_FIRST 0x2C
#define CRAM_FIRST_REG  0x08
/** Bank B mirrors bank A nine pages further up. */
#define CRAM_BANK_B_OFFSET 0x12

// P44-R1: bit 2 keeps adaptive mode on, bit 0 requests the bank swap.
#define CRAM_CTRL_PAGE 0x2C
#define CRAM_CTRL_REG  0x01
#define CRAM_CTRL_SWAP 0x05

#define REG_PAGE 0x00

// Coefficients are signed 1.23 in the top 3 bytes of a 32-bit big-endian word.
#define Q23_ONE 8388607.0 // 0x7FFFFF

bool tas57xx_cram_addr(int word, uint8_t *page, uint8_t *reg) {
  if (word < 0 || word >= TAS57XX_CRAM_WORD_COUNT) {
    return false;
  }
  *page = (uint8_t)(CRAM_PAGE_FIRST + word / TAS57XX_CRAM_WORDS_PER_PAGE);
  *reg = (uint8_t)(CRAM_FIRST_REG +
                   (word % TAS57XX_CRAM_WORDS_PER_PAGE) * sizeof(int32_t));
  return true;
}

static int32_t q23(double v) {
  double scaled = round(v * Q23_ONE);
  if (scaled > Q23_ONE) {
    scaled = Q23_ONE;
  } else if (scaled < -Q23_ONE - 1.0) {
    scaled = -Q23_ONE - 1.0;
  }
  return (int32_t)scaled;
}

void tas57xx_bq_unity(tas57xx_bq_layout_t layout,
                      int32_t out[TAS57XX_BQ_WORDS]) {
  memset(out, 0, TAS57XX_BQ_WORDS * sizeof(out[0]));
  if (layout == TAS57XX_BQ_DEN_FIRST) {
    out[2] = (int32_t)(Q23_ONE / 2.0);
  } else {
    out[0] = (int32_t)Q23_ONE;
  }
}

void tas57xx_bq_unpack(const int32_t c[TAS57XX_BQ_WORDS],
                       tas57xx_bq_layout_t layout, uint32_t sample_rate_hz,
                       tas57xx_bq_t *bq) {
  if (!c || !bq) {
    return;
  }
  double b0, b1, b2, a1, a2;
  if (layout == TAS57XX_BQ_DEN_FIRST) {
    a1 = -2.0 * c[0] / Q23_ONE;
    a2 = -c[1] / Q23_ONE;
    b0 = 2.0 * c[2] / Q23_ONE;
    b1 = 4.0 * c[3] / Q23_ONE;
    b2 = 2.0 * c[4] / Q23_ONE;
  } else {
    b0 = c[0] / Q23_ONE;
    b1 = 2.0 * c[1] / Q23_ONE;
    b2 = c[2] / Q23_ONE;
    a1 = -2.0 * c[3] / Q23_ONE;
    a2 = -c[4] / Q23_ONE;
  }

  memset(bq, 0, sizeof(*bq));
  bq->type = TAS57XX_BQ_CUSTOM;
  bq->coeff[0] = (float)b0;
  bq->coeff[1] = (float)b1;
  bq->coeff[2] = (float)b2;
  bq->coeff[3] = (float)a1;
  bq->coeff[4] = (float)a2;

  /* An untouched slot is a pure gain of one. Left as CUSTOM it would go
   * through the first-order branch below and be reported as a filter at a
   * quarter of the sample rate, which is how most of a flow would look. */
  if (fabs(b0 - 1.0) < 1e-5 && fabs(b1) < 1e-5 && fabs(b2) < 1e-5 &&
      fabs(a1) < 1e-5 && fabs(a2) < 1e-5) {
    bq->type = TAS57XX_BQ_BYPASS;
    bq->subtype = TAS57XX_BQ_SUB_BUTTERWORTH_2;
    bq->freq_hz = 1000.0f;
    bq->q = 0.707f;
    return;
  }

  /* A first-order section has no pole pair to solve for, and putting it
   * through the biquad inversion lands the corner near Nyquist. Crossovers are
   * routinely first order, so this is a common case rather than an edge one. */
  if (fabs(a2) < 1e-5 && fabs(b2) < 1e-5) {
    bq->freq_hz =
        (float)(sample_rate_hz / M_PI * atan((1.0 + a1) / (1.0 - a1)));
    bq->q = 0.0f;
    return;
  }

  const double alpha = (1.0 + a2) != 0.0 ? (1.0 - a2) / (1.0 + a2) : 0.0;
  double cw = (1.0 + a2) != 0.0 ? -a1 / (1.0 + a2) : 1.0;
  if (cw > 1.0) {
    cw = 1.0;
  } else if (cw < -1.0) {
    cw = -1.0;
  }
  const double w0 = acos(cw);
  bq->freq_hz = (float)(w0 * sample_rate_hz / (2.0 * M_PI));
  bq->q = alpha > 1e-9 ? (float)(sin(w0) / (2.0 * alpha)) : 0.0f;
}

/** Q implied by a low-pass or high-pass alignment. */
static double subtype_q(tas57xx_bq_subtype_t subtype, double q) {
  switch (subtype) {
  case TAS57XX_BQ_SUB_BUTTERWORTH_2:
    // The tuning tool stores rounded literals rather than the exact algebraic
    // values, so 0.707 rather than 1/sqrt(2). Worth 30 LSB.
    return 0.707;
  case TAS57XX_BQ_SUB_BESSEL_2:
    // Also a rounded literal, not sqrt(3)/3; exact against 30 Hz and 1 kHz
    // captures.
    return 0.58;
  case TAS57XX_BQ_SUB_CHEBYSHEV_2:
    // Chebyshev is the exception: exact algebraic values, not rounded ones.
    return 0.8637210; // 0.5 dB passband ripple
  case TAS57XX_BQ_SUB_LINKWITZ_RILEY_2:
    return 0.5;
  default:
    return q;
  }
}

/**
 * Pole radius relative to the passband edge. Butterworth, Bessel and
 * Linkwitz-Riley put the pole on the edge; Chebyshev trades that for its
 * ripple, so the entered frequency is the ripple edge and the pole sits outside
 * it for a low-pass, inside for a high-pass.
 */
static double subtype_freq_scale(tas57xx_bq_subtype_t subtype) {
  switch (subtype) {
  case TAS57XX_BQ_SUB_CHEBYSHEV_2:
    return 1.2313418; // 0.5 dB ripple
  default:
    return 1.0;
  }
}

/**
 * Bandwidth parameter of a peaking section, in PurePath Console's convention.
 *
 * It measures Q between the points 3 dB back from the peak rather than at the
 * half-gain points RBJ uses, so the same number is a different filter: they
 * differ by a factor of 2.8 at -3.4 dB and coincide exactly at +/-6 dB, where
 * half the gain is 3 dB. A section shallower than 3 dB never gets 3 dB back
 * from its peak at all, and the tool falls back to the half-power points.
 *
 * Returns beta, which is what the denominator is built from. RBJ's alpha is
 * beta * A, and its own convention is the special case c == 1/A.
 */
static double peaking_beta(double w, double q, double gain_db) {
  const double g = pow(10.0, gain_db / 20.0);
  // The two definitions do not meet as the gain approaches 3 dB, and a gain
  // solved back out of quantised coefficients lands either side of it, so the
  // boundary carries a tolerance: far wider than that noise, far narrower than
  // anything anyone would dial in.
  const double gb = fabs(gain_db) > 3.001
                        ? pow(10.0, (gain_db - copysign(3.0, gain_db)) / 20.0)
                        : sqrt((1.0 + g * g) / 2.0);
  const double num = gb * gb - 1.0;
  const double den = g * g - gb * gb;
  // Both vanish at unity gain, where the section passes audio through whatever
  // c is, so anything finite will do.
  const double c = num * den > 0.0 ? sqrt(num / den) : 1.0;
  // Half the bandwidth in rad, which the prewarp sends to infinity as it
  // approaches the whole band.
  double half_bw = w / (2.0 * q);
  if (half_bw > 1.5533) {
    half_bw = 1.5533;
  }
  return c * tan(half_bw);
}

/**
 * Design one section as normalised transfer function coefficients.
 * b[] and a[] are the usual direct-form numerator and denominator with
 * a[0] == 1, i.e. before the DSP's sign and scaling conventions are applied.
 */
static void design(const tas57xx_bq_t *bq, double fs, double b[3],
                   double a[3]) {
  b[0] = 1.0;
  b[1] = b[2] = a[1] = a[2] = 0.0;
  a[0] = 1.0;

  if (bq->type == TAS57XX_BQ_CUSTOM) {
    b[0] = bq->coeff[0];
    b[1] = bq->coeff[1];
    b[2] = bq->coeff[2];
    a[1] = bq->coeff[3];
    a[2] = bq->coeff[4];
    return;
  }

  double f0 = bq->freq_hz;
  if (f0 < 1.0) {
    f0 = 1.0;
  } else if (f0 > fs * 0.49) {
    f0 = fs * 0.49;
  }
  bool is_pass =
      bq->type == TAS57XX_BQ_LOWPASS || bq->type == TAS57XX_BQ_HIGHPASS;
  const double scale = is_pass ? subtype_freq_scale(bq->subtype) : 1.0;
  if (scale != 1.0) {
    // The ratio scales the analog prototype, so it lands on the prewarped
    // frequency rather than the entered one.
    double k = tan(M_PI * f0 / fs);
    k = bq->type == TAS57XX_BQ_LOWPASS ? k * scale : k / scale;
    f0 = atan(k) * fs / M_PI;
    if (f0 > fs * 0.49) {
      f0 = fs * 0.49;
    }
  }
  double w = 2.0 * M_PI * f0 / fs;
  double cw = cos(w), sw = sin(w);

  if (bq->type == TAS57XX_BQ_PHASE_1 ||
      (is_pass && bq->subtype == TAS57XX_BQ_SUB_BUTTERWORTH_1)) {
    // Bilinear 1st order. The pole doubles as the crossover parameter that
    // PurePath Console writes for a 1st-order split.
    double t = tan(M_PI * f0 / fs);
    double p = (1.0 - t) / (1.0 + t);
    if (bq->type == TAS57XX_BQ_LOWPASS) {
      b[0] = (1.0 - p) / 2.0;
      b[1] = b[0];
    } else if (bq->type == TAS57XX_BQ_HIGHPASS) {
      b[0] = (1.0 + p) / 2.0;
      b[1] = -b[0];
    } else {
      b[0] = -p;
      b[1] = 1.0;
    }
    a[1] = -p;
    return;
  }

  double q = bq->q > 0.01 ? bq->q : 0.01;
  if (is_pass) {
    q = subtype_q(bq->subtype, q);
  } else if (bq->type == TAS57XX_BQ_LOW_SHELF ||
             bq->type == TAS57XX_BQ_HIGH_SHELF) {
    if (q > TAS57XX_BQ_SHELF_Q_MAX) {
      q = TAS57XX_BQ_SHELF_Q_MAX;
    }
  } else if (bq->type == TAS57XX_BQ_NOTCH) {
    q = f0 / q; // the notch is specified by its width in Hz
  }

  double gain_db = bq->gain_db;
  if (gain_db < TAS57XX_BQ_GAIN_MIN_DB) {
    gain_db = TAS57XX_BQ_GAIN_MIN_DB;
  } else if (gain_db > TAS57XX_BQ_GAIN_MAX_DB) {
    gain_db = TAS57XX_BQ_GAIN_MAX_DB;
  }
  double A = pow(10.0, gain_db / 40.0);

  double alpha;
  switch (bq->type) {
  case TAS57XX_BQ_PEAKING:
    // Carried as RBJ's alpha so the clamp below and the branch further down
    // stay shared; the peaking branch divides the A back out again.
    alpha = A * peaking_beta(w, q, gain_db);
    break;
  case TAS57XX_BQ_PEAKING_BW:
  case TAS57XX_BQ_PHASE_2:
    // Here `q` is bandwidth in octaves, measured between the half-gain points.
    // Unverified against the tuning tool, unlike the Q form above.
    alpha = sw * sinh(M_LN2 / 2.0 * q * w / sw);
    break;
  default:
    alpha = sw / (2.0 * q);
    break;
  }
  // Beyond about Q=100 the pole pair stops being distinguishable from the unit
  // circle once rounded to 1.23, so the section rings instead of resolving.
  if (alpha < sw / 200.0) {
    alpha = sw / 200.0;
  }
  double a0;

  switch (bq->type) {
  case TAS57XX_BQ_PEAKING:
  case TAS57XX_BQ_PEAKING_BW:
    a0 = 1.0 + alpha / A;
    b[0] = (1.0 + alpha * A) / a0;
    b[1] = -2.0 * cw / a0;
    b[2] = (1.0 - alpha * A) / a0;
    a[1] = -2.0 * cw / a0;
    a[2] = (1.0 - alpha / A) / a0;
    break;
  case TAS57XX_BQ_LOW_SHELF: {
    double s = 2.0 * sqrt(A) * alpha;
    a0 = (A + 1.0) + (A - 1.0) * cw + s;
    b[0] = A * ((A + 1.0) - (A - 1.0) * cw + s) / a0;
    b[1] = 2.0 * A * ((A - 1.0) - (A + 1.0) * cw) / a0;
    b[2] = A * ((A + 1.0) - (A - 1.0) * cw - s) / a0;
    a[1] = -2.0 * ((A - 1.0) + (A + 1.0) * cw) / a0;
    a[2] = ((A + 1.0) + (A - 1.0) * cw - s) / a0;
    break;
  }
  case TAS57XX_BQ_HIGH_SHELF: {
    double s = 2.0 * sqrt(A) * alpha;
    a0 = (A + 1.0) - (A - 1.0) * cw + s;
    b[0] = A * ((A + 1.0) + (A - 1.0) * cw + s) / a0;
    b[1] = -2.0 * A * ((A - 1.0) + (A + 1.0) * cw) / a0;
    b[2] = A * ((A + 1.0) + (A - 1.0) * cw - s) / a0;
    a[1] = 2.0 * ((A - 1.0) - (A + 1.0) * cw) / a0;
    a[2] = ((A + 1.0) - (A - 1.0) * cw - s) / a0;
    break;
  }
  case TAS57XX_BQ_LOWPASS:
    a0 = 1.0 + alpha;
    b[0] = (1.0 - cw) / 2.0 / a0;
    b[1] = (1.0 - cw) / a0;
    b[2] = b[0];
    a[1] = -2.0 * cw / a0;
    a[2] = (1.0 - alpha) / a0;
    break;
  case TAS57XX_BQ_HIGHPASS:
    a0 = 1.0 + alpha;
    b[0] = (1.0 + cw) / 2.0 / a0;
    b[1] = -(1.0 + cw) / a0;
    b[2] = b[0];
    a[1] = -2.0 * cw / a0;
    a[2] = (1.0 - alpha) / a0;
    break;
  case TAS57XX_BQ_BANDPASS:
    a0 = 1.0 + alpha;
    b[0] = alpha / a0;
    b[1] = 0.0;
    b[2] = -alpha / a0;
    a[1] = -2.0 * cw / a0;
    a[2] = (1.0 - alpha) / a0;
    break;
  case TAS57XX_BQ_NOTCH:
    a0 = 1.0 + alpha;
    b[0] = 1.0 / a0;
    b[1] = -2.0 * cw / a0;
    b[2] = b[0];
    a[1] = -2.0 * cw / a0;
    a[2] = (1.0 - alpha) / a0;
    break;
  case TAS57XX_BQ_PHASE_2:
    a0 = 1.0 + alpha;
    b[0] = (1.0 - alpha) / a0;
    b[1] = -2.0 * cw / a0;
    b[2] = 1.0;
    a[1] = -2.0 * cw / a0;
    a[2] = (1.0 - alpha) / a0;
    break;
  case TAS57XX_BQ_BYPASS:
  default:
    break;
  }
}

float tas57xx_bq_pack(const tas57xx_bq_t *bq, uint32_t sample_rate_hz,
                      tas57xx_bq_layout_t layout,
                      int32_t out[TAS57XX_BQ_WORDS]) {
  if (bq->type == TAS57XX_BQ_BYPASS) {
    tas57xx_bq_unity(layout, out);
    return 0.0f;
  }

  double b[3], a[3];
  design(bq, (double)sample_rate_hz, b, a);

  // A boosting section always has b0 > 1, which 1.23 cannot hold. Scale the
  // numerator down and report the shortfall so the caller can make it up in
  // the digital volume. The denominator-first slots store the numerator
  // halved, so they have a factor of two more headroom before that bites.
  double limit = layout == TAS57XX_BQ_DEN_FIRST ? 2.0 : 1.0;
  double peak = fabs(b[0]);
  for (int i = 1; i < 3; i++) {
    double mag = i == 1 ? fabs(b[i]) / 2.0 : fabs(b[i]);
    if (mag > peak) {
      peak = mag;
    }
  }
  double scale = peak > limit ? limit / peak : 1.0;

  // The DSP doubles the two z^-1 taps internally, so they are stored halved.
  // The feedback terms are stored pre-negated.
  if (layout == TAS57XX_BQ_DEN_FIRST) {
    out[0] = q23(-a[1] / 2.0);
    out[1] = q23(-a[2]);
    out[2] = q23(b[0] * scale / 2.0);
    out[3] = q23(b[1] * scale / 4.0);
    out[4] = q23(b[2] * scale / 2.0);
  } else {
    out[0] = q23(b[0] * scale);
    out[1] = q23(b[1] * scale / 2.0);
    out[2] = q23(b[2] * scale);
    out[3] = q23(-a[1] / 2.0);
    out[4] = q23(-a[2]);
  }

  return (float)(20.0 * log10(scale));
}

/**
 * Rewrite the bytes a flow image would send for one coefficient word.
 *
 * The image is a run of [reg, len, data...] records ended by 0xFF 0xFF, with
 * page selects encoded as single-byte writes to register 0. Both banks carry a
 * copy, and a flow may write a slot more than once, so every match is patched.
 */
static esp_err_t cram_patch_image(uint8_t *img, size_t size, int word,
                                  int32_t value) {
  uint8_t page, reg;
  if (!tas57xx_cram_addr(word, &page, &reg)) {
    return ESP_ERR_INVALID_ARG;
  }
  int found = 0;
  size_t pos = 0;
  int cur = -1;
  while (pos + 1 < size && !(img[pos] == 0xFF && img[pos + 1] == 0xFF)) {
    const int r = img[pos];
    const int len = img[pos + 1];
    if (pos + 2 + (size_t)len > size) {
      break;
    }
    if (r == REG_PAGE && len == 1) {
      cur = img[pos + 2];
    } else if ((cur == page || cur == page + CRAM_BANK_B_OFFSET) && reg >= r &&
               reg + 4 <= r + len) {
      uint8_t *p = &img[pos + 2 + (reg - r)];
      p[0] = (uint8_t)((value >> 16) & 0xFF);
      p[1] = (uint8_t)((value >> 8) & 0xFF);
      p[2] = (uint8_t)(value & 0xFF);
      found++;
    }
    pos += 2 + (size_t)len;
  }
  return found ? ESP_OK : ESP_ERR_NOT_FOUND;
}

static bool cram_read_word(const uint8_t *img, size_t size, int word,
                           int32_t *out) {
  uint8_t page, reg;
  if (!tas57xx_cram_addr(word, &page, &reg)) {
    return false;
  }
  bool found = false;
  size_t pos = 0;
  int cur = -1;
  while (pos + 1 < size && !(img[pos] == 0xFF && img[pos + 1] == 0xFF)) {
    const int r = img[pos];
    const int len = img[pos + 1];
    if (pos + 2 + (size_t)len > size) {
      break;
    }
    if (r == REG_PAGE && len == 1) {
      cur = img[pos + 2];
    } else if ((cur == page || cur == page + CRAM_BANK_B_OFFSET) && reg >= r &&
               reg + 4 <= r + len) {
      const uint8_t *p = &img[pos + 2 + (reg - r)];
      int32_t v = ((int32_t)p[0] << 16) | ((int32_t)p[1] << 8) | p[2];
      *out = v & 0x800000 ? v - 0x1000000 : v; // 24-bit two's complement
      found = true;
    }
    pos += 2 + (size_t)len;
  }
  return found;
}

esp_err_t tas57xx_cram_read_image(const uint8_t *img, size_t size, int word,
                                  int32_t *out, int count) {
  if (!img || !out || count < 1 || word < 0) {
    return ESP_ERR_INVALID_ARG;
  }
  for (int i = 0; i < count; i++) {
    if (!cram_read_word(img, size, word + i, &out[i])) {
      return ESP_ERR_NOT_FOUND;
    }
  }
  return ESP_OK;
}

static esp_err_t cram_write_i2c(i2c_master_dev_handle_t handle, int word,
                                const int32_t *words, int count) {
  // GCC 14 cannot see through tas57xx_cram_addr() that both are always set.
  uint8_t page = 0, reg = 0;
  const uint8_t page0 = REG_PAGE;
  const uint8_t ctrl_page = CRAM_CTRL_PAGE;
  const uint8_t swap = CRAM_CTRL_SWAP;
  esp_err_t err = ESP_OK;

  for (int bank = 0; bank < 2 && err == ESP_OK; bank++) {
    int i = 0;
    while (i < count && err == ESP_OK) {
      tas57xx_cram_addr(word + i, &page, &reg);
      // A burst may not cross a page boundary; the next page restarts at 0x08.
      int room = TAS57XX_CRAM_WORDS_PER_PAGE -
                 (word + i) % TAS57XX_CRAM_WORDS_PER_PAGE;
      int n = count - i < room ? count - i : room;

      uint8_t buf[TAS57XX_CRAM_WORDS_PER_PAGE * sizeof(int32_t)];
      for (int k = 0; k < n; k++) {
        int32_t v = words[i + k];
        buf[k * 4 + 0] = (uint8_t)((v >> 16) & 0xFF);
        buf[k * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
        buf[k * 4 + 2] = (uint8_t)(v & 0xFF);
        buf[k * 4 + 3] = 0;
      }

      err = board_i2c_write(handle, REG_PAGE, &page, sizeof(page));
      if (err == ESP_OK) {
        // Bit 7 selects auto-increment, without it every byte lands in `reg`.
        err = board_i2c_write(handle, (uint8_t)(reg | 0x80), buf,
                              (size_t)n * sizeof(int32_t));
      }
      i += n;
    }
    if (bank == 0 && err == ESP_OK) {
      err = board_i2c_write(handle, REG_PAGE, &ctrl_page, sizeof(ctrl_page));
      if (err == ESP_OK) {
        err = board_i2c_write(handle, CRAM_CTRL_REG, &swap, sizeof(swap));
      }
    }
  }

  board_i2c_write(handle, REG_PAGE, &page0, sizeof(page0));
  return err;
}

struct tas57xx_cram_batch {
  int32_t word[TAS57XX_CRAM_WORD_COUNT];
  bool dirty[TAS57XX_CRAM_WORD_COUNT];
};

esp_err_t tas57xx_cram_begin(tas57xx_cram_sink_t *sink) {
  if (!sink || sink->batch) {
    return ESP_ERR_INVALID_STATE;
  }
  sink->batch = calloc(1, sizeof(*sink->batch));
  return sink->batch ? ESP_OK : ESP_ERR_NO_MEM;
}

void tas57xx_cram_abort(tas57xx_cram_sink_t *sink) {
  if (sink) {
    free(sink->batch);
    sink->batch = NULL;
  }
}

/** Send one pass over the staged words, longest burst per page. */
static esp_err_t cram_flush_pass(i2c_master_dev_handle_t handle,
                                 const tas57xx_cram_batch_t *b) {
  esp_err_t err = ESP_OK;
  int w = 0;
  while (w < TAS57XX_CRAM_WORD_COUNT && err == ESP_OK) {
    if (!b->dirty[w]) {
      w++;
      continue;
    }
    int n = 0;
    int room = TAS57XX_CRAM_WORDS_PER_PAGE - w % TAS57XX_CRAM_WORDS_PER_PAGE;
    while (n < room && b->dirty[w + n]) {
      n++;
    }

    uint8_t page = 0, reg = 0;
    tas57xx_cram_addr(w, &page, &reg);
    uint8_t buf[TAS57XX_CRAM_WORDS_PER_PAGE * sizeof(int32_t)];
    for (int k = 0; k < n; k++) {
      int32_t v = b->word[w + k];
      buf[k * 4 + 0] = (uint8_t)((v >> 16) & 0xFF);
      buf[k * 4 + 1] = (uint8_t)((v >> 8) & 0xFF);
      buf[k * 4 + 2] = (uint8_t)(v & 0xFF);
      buf[k * 4 + 3] = 0;
    }
    err = board_i2c_write(handle, REG_PAGE, &page, sizeof(page));
    if (err == ESP_OK) {
      err = board_i2c_write(handle, (uint8_t)(reg | 0x80), buf,
                            (size_t)n * sizeof(int32_t));
    }
    w += n;
  }
  return err;
}

esp_err_t tas57xx_cram_commit(tas57xx_cram_sink_t *sink) {
  if (!sink || !sink->batch) {
    return ESP_ERR_INVALID_STATE;
  }
  tas57xx_cram_batch_t *b = sink->batch;
  esp_err_t err = ESP_OK;

  if (sink->dry_run) {
    free(b);
    sink->batch = NULL;
    return ESP_OK;
  }

  if (sink->image) {
    for (int w = 0; w < TAS57XX_CRAM_WORD_COUNT && err == ESP_OK; w++) {
      if (b->dirty[w]) {
        err = cram_patch_image(sink->image, sink->image_size, w, b->word[w]);
        if (err != ESP_OK) {
          ESP_LOGE(TAG, "word %d not present in flow image", w);
        }
      }
    }
  } else {
    const uint8_t page0 = REG_PAGE;
    const uint8_t ctrl_page = CRAM_CTRL_PAGE;
    const uint8_t swap = CRAM_CTRL_SWAP;
    err = cram_flush_pass(sink->handle, b);
    if (err == ESP_OK) {
      err = board_i2c_write(sink->handle, REG_PAGE, &ctrl_page,
                            sizeof(ctrl_page));
    }
    if (err == ESP_OK) {
      err = board_i2c_write(sink->handle, CRAM_CTRL_REG, &swap, sizeof(swap));
    }
    if (err == ESP_OK) {
      err = cram_flush_pass(sink->handle, b);
    }
    board_i2c_write(sink->handle, REG_PAGE, &page0, sizeof(page0));
  }

  free(b);
  sink->batch = NULL;
  return err;
}

esp_err_t tas57xx_cram_write(const tas57xx_cram_sink_t *sink, int word,
                             const int32_t *words, int count) {
  if (!sink || (!sink->handle && !sink->image && !sink->dry_run) || !words ||
      count <= 0) {
    return ESP_ERR_INVALID_ARG;
  }
  uint8_t page, reg;
  if (!tas57xx_cram_addr(word, &page, &reg) ||
      !tas57xx_cram_addr(word + count - 1, &page, &reg)) {
    ESP_LOGE(TAG, "word range %d..%d outside coefficient RAM", word,
             word + count - 1);
    return ESP_ERR_INVALID_ARG;
  }

  if (sink->batch) {
    for (int i = 0; i < count; i++) {
      sink->batch->word[word + i] = words[i];
      sink->batch->dirty[word + i] = true;
    }
    return ESP_OK;
  }

  if (sink->image) {
    for (int i = 0; i < count; i++) {
      esp_err_t err =
          cram_patch_image(sink->image, sink->image_size, word + i, words[i]);
      if (err != ESP_OK) {
        ESP_LOGE(TAG, "word %d not present in flow image", word + i);
        return err;
      }
    }
    return ESP_OK;
  }

  return cram_write_i2c(sink->handle, word, words, count);
}
