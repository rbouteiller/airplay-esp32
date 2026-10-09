// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Host tests for main/audio/audio_eq.c: the audio path against a
 * double-precision direct-form reference built from the same designer, the
 * anti-clipping preamp against a dense search, and edits that must not
 * restart the filters or step the level. */

#include "audio_eq.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECONDS(fs, s) ((size_t)((fs) * (s)))
#define MAX_FRAMES     (48000 * 2)
#define BLOCK          352 /* frames per call, as the AirPlay path writes */

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

void mock_log(const char *tag, const char *format, ...) {
  if (getenv("EQ_TEST_VERBOSE") == NULL) {
    return;
  }
  va_list args;
  va_start(args, format);
  printf("  [%s] ", tag);
  vprintf(format, args);
  printf("\n");
  va_end(args);
}

static float s_saved_gain[SETTINGS_AMP_OUTPUTS];
static uint8_t s_saved_mute[SETTINGS_AMP_OUTPUTS];

esp_err_t settings_get_amp_gain(float gain[SETTINGS_AMP_OUTPUTS]) {
  memcpy(gain, s_saved_gain, sizeof(s_saved_gain));
  return ESP_OK;
}
esp_err_t settings_set_amp_gain(const float gain[SETTINGS_AMP_OUTPUTS]) {
  memcpy(s_saved_gain, gain, sizeof(s_saved_gain));
  return ESP_OK;
}
esp_err_t settings_get_amp_mute(uint8_t mute[SETTINGS_AMP_OUTPUTS]) {
  memcpy(mute, s_saved_mute, sizeof(s_saved_mute));
  return ESP_OK;
}
esp_err_t settings_set_amp_mute(const uint8_t mute[SETTINGS_AMP_OUTPUTS]) {
  memcpy(s_saved_mute, mute, sizeof(s_saved_mute));
  return ESP_OK;
}

/* ---------- helpers ---------- */

static int16_t s_in[MAX_FRAMES * 2];
static int16_t s_out[MAX_FRAMES * 2];

static void process(int16_t *buf, size_t frames) {
  for (size_t i = 0; i < frames; i += BLOCK) {
    audio_eq_process(buf + 2 * i, frames - i < BLOCK ? frames - i : BLOCK);
  }
}

static void chain_flat(tas58xx_bq_t chain[AUDIO_EQ_SLOTS]) {
  for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
    tas58xx_bq_init_bypass(&chain[i]);
  }
}

static tas58xx_bq_t peak(float f, float q, float gain_db) {
  tas58xx_bq_t bq;
  tas58xx_bq_init_bypass(&bq);
  bq.type = TAS58XX_BQ_PEAKING_Q;
  bq.freq_hz = f;
  bq.q = q;
  bq.gain_db = gain_db;
  return bq;
}

static tas58xx_bq_t highpass(float f) {
  tas58xx_bq_t bq;
  tas58xx_bq_init_bypass(&bq);
  bq.type = TAS58XX_BQ_HIGHPASS;
  bq.sub = TAS58XX_BQ_SUB_BUTTERWORTH_2;
  bq.freq_hz = f;
  bq.q = 0.7071f;
  return bq;
}

/* Start from a clean slate: flat and unmuted, every section at rest (a flat
 * chain drops them all, so the next chain starts its sections from zero),
 * and any level glide run out. */
static void reset(uint32_t rate) {
  tas58xx_bq_t flat[AUDIO_EQ_SLOTS];
  chain_flat(flat);
  audio_eq_set_rate(rate);
  audio_eq_set_ganged(true);
  audio_eq_set_chain(0, flat);
  audio_eq_set_chain(1, flat);
  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    audio_eq_set_trim_db(ch, 0.0f);
    audio_eq_set_mute(ch, false);
  }
  static int16_t silence[24000 * 2];
  memset(silence, 0, sizeof(silence));
  process(silence, 24000);
}

static void signal_mix(size_t frames, double fs, unsigned seed) {
  srand(seed);
  for (size_t i = 0; i < frames; i++) {
    double t = (double)i / fs;
    double x = 0.10 * sin(2 * M_PI * 35 * t) + 0.07 * sin(2 * M_PI * 120 * t) +
               0.05 * sin(2 * M_PI * 1000 * t) +
               0.03 * sin(2 * M_PI * 9000 * t) +
               0.02 * (rand() / (double)RAND_MAX - 0.5);
    s_in[2 * i] = (int16_t)lrint(x * 32767 * 1.4);
    s_in[2 * i + 1] = (int16_t)(s_in[2 * i] / 2);
  }
}

static void signal_sine(size_t frames, double fs, double f, double amp) {
  for (size_t i = 0; i < frames; i++) {
    int16_t x = (int16_t)lrint(amp * sin(2 * M_PI * f * (double)i / fs));
    s_in[2 * i] = x;
    s_in[2 * i + 1] = x;
  }
}

/* Direct-form I in double, with the designer's own coefficients. */
typedef struct {
  double c[AUDIO_EQ_SLOTS][5];
  double x1[AUDIO_EQ_SLOTS], x2[AUDIO_EQ_SLOTS];
  double y1[AUDIO_EQ_SLOTS], y2[AUDIO_EQ_SLOTS];
  int n;
} ref_t;

static void ref_init(ref_t *r, const tas58xx_bq_t chain[AUDIO_EQ_SLOTS],
                     double fs) {
  memset(r, 0, sizeof(*r));
  for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
    if (chain[i].type != TAS58XX_BQ_BYPASS) {
      tas58xx_bq_design(&chain[i], fs, r->c[r->n++]);
    }
  }
}

static double ref_step(ref_t *r, double x) {
  for (int s = 0; s < r->n; s++) {
    const double *c = r->c[s];
    double y = c[0] * x + c[1] * r->x1[s] + c[2] * r->x2[s] + c[3] * r->y1[s] +
               c[4] * r->y2[s];
    r->x2[s] = r->x1[s];
    r->x1[s] = x;
    r->y2[s] = r->y1[s];
    r->y1[s] = y;
    x = y;
  }
  return x;
}

static double clip16(double x) {
  return x > 32767.0 ? 32767.0 : (x < -32768.0 ? -32768.0 : x);
}

/* Response of the designed chain in double, the slow and obvious way. */
static double ref_mag2(const ref_t *r, double f, double fs) {
  double w = 2 * M_PI * f / fs;
  double mag2 = 1.0;
  for (int s = 0; s < r->n; s++) {
    const double *c = r->c[s];
    double nr = c[0] + c[1] * cos(w) + c[2] * cos(2 * w);
    double ni = -(c[1] * sin(w) + c[2] * sin(2 * w));
    double dr = 1.0 - c[3] * cos(w) - c[4] * cos(2 * w);
    double di = c[3] * sin(w) + c[4] * sin(2 * w);
    mag2 *= (nr * nr + ni * ni) / (dr * dr + di * di);
  }
  return mag2;
}

static double ref_peak_db(const tas58xx_bq_t chain[AUDIO_EQ_SLOTS], double fs) {
  ref_t r;
  ref_init(&r, chain, fs);
  double f_hi = fs / 2 < 20000 ? fs / 2 * 0.99 : 20000;
  double peak = 0.0;
  for (int p = 0; p < 200000; p++) {
    double f = 20.0 * pow(f_hi / 20.0, p / 199999.0);
    double m = ref_mag2(&r, f, fs);
    if (m > peak) {
      peak = m;
    }
  }
  return 10 * log10(peak);
}

/* ---------- tests ---------- */

static void test_flat_is_bit_exact(void) {
  printf("flat chain passes samples through untouched\n");
  reset(48000);
  signal_mix(SECONDS(48000, 1), 48000, 1);
  memcpy(s_out, s_in, sizeof(s_in));
  process(s_out, SECONDS(48000, 1));
  CHECK(memcmp(s_out, s_in, SECONDS(48000, 1) * 4) == 0, "flat output differs");
}

/* Output against the double reference, level included: after the settle
 * time the only difference should be rounding. */
static void check_against_reference(const char *name,
                                    const tas58xx_bq_t chain[AUDIO_EQ_SLOTS],
                                    uint32_t rate) {
  reset(rate);
  if (audio_eq_set_chain(0, chain) != ESP_OK) {
    CHECK(false, "%s rejected", name);
    return;
  }
  const size_t frames = SECONDS(rate, 1.5);
  const size_t settle = SECONDS(rate, 0.5);
  signal_mix(frames, rate, 2);
  memcpy(s_out, s_in, frames * 4);
  process(s_out, frames);

  double pre = pow(10.0, audio_eq_get_preamp_db() / 20.0);
  ref_t r[2];
  ref_init(&r[0], chain, rate);
  ref_init(&r[1], chain, rate);
  double e2 = 0, emax = 0;
  long count = 0;
  for (size_t i = 0; i < frames; i++) {
    for (int ch = 0; ch < 2; ch++) {
      double y = clip16(ref_step(&r[ch], s_in[2 * i + ch] * pre));
      double e = s_out[2 * i + ch] - y;
      if (i >= settle) {
        e2 += e * e;
        count++;
        emax = fmax(emax, fabs(e));
      }
    }
  }
  double rms = sqrt(e2 / (double)count);
  printf("  %-34s %5u Hz  preamp %6.2f dB  err rms %.3f max %.2f LSB\n", name,
         (unsigned)rate, audio_eq_get_preamp_db(), rms, emax);
  CHECK(rms < 0.40 && emax < 3.0, "%s at %u Hz off the reference", name,
        (unsigned)rate);
}

static void test_matches_reference(void) {
  printf("every filter type matches a double-precision reference\n");
  static const char *names[TAS58XX_BQ_TYPE_COUNT] = {
      "bypass",       "peak Q",      "peak BW",  "bass shelf",
      "treble shelf", "lowpass",     "highpass", "bandpass",
      "notch",        "phase shift", "custom"};
  static const uint32_t rates[] = {32000, 44100, 48000};
  for (size_t r = 0; r < sizeof(rates) / sizeof(rates[0]); r++) {
    for (int t = 1; t < TAS58XX_BQ_TYPE_COUNT; t++) {
      int subs = (t == TAS58XX_BQ_LOWPASS || t == TAS58XX_BQ_HIGHPASS)
                     ? TAS58XX_BQ_SUB_COUNT
                     : 1;
      for (int sub = 0; sub < subs; sub++) {
        tas58xx_bq_t chain[AUDIO_EQ_SLOTS];
        chain_flat(chain);
        chain[0].type = t;
        chain[0].sub = sub;
        chain[0].freq_hz = t == TAS58XX_BQ_TREBLE_SHELF ? 6000.0f
                           : t == TAS58XX_BQ_LOWPASS    ? 2000.0f
                                                        : 40.0f;
        chain[0].q = 2.0f;
        chain[0].bandwidth_hz = 20.0f;
        chain[0].gain_db = 12.0f;
        chain[0].ripple_db = 1.0f;
        if (t == TAS58XX_BQ_CUSTOM) {
          tas58xx_bq_t p = peak(40.0f, 2.0f, 12.0f);
          double c[5];
          tas58xx_bq_design(&p, rates[r], c);
          for (int k = 0; k < 5; k++) {
            chain[0].coeff[k] = (float)c[k];
          }
        }
        char name[48];
        snprintf(name, sizeof(name), subs > 1 ? "%s (alignment %d)" : "%s",
                 names[t], sub);
        check_against_reference(name, chain, rates[r]);
      }
    }
    tas58xx_bq_t chain[AUDIO_EQ_SLOTS];
    for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
      chain[i] = peak(25.0f * powf(2.0f, i * 0.7f), 1.4f, i % 2 ? -9 : 9);
    }
    chain[0] = chain[1] = highpass(100.0f);
    check_against_reference("2x HPF + 13 peaks of +/-9 dB", chain, rates[r]);
  }
}

/* The preamp must cover the true peak (to within 0.05 dB) without taking
 * off much more than it needs. */
static void check_preamp(const char *name,
                         const tas58xx_bq_t chain[AUDIO_EQ_SLOTS],
                         uint32_t rate) {
  reset(rate);
  CHECK(audio_eq_set_chain(0, chain) == ESP_OK, "%s rejected", name);
  double want = -fmax(ref_peak_db(chain, rate), 0.0);
  double got = audio_eq_get_preamp_db();
  printf("  %-34s %5u Hz  preamp %7.3f dB, true peak %7.3f dB\n", name,
         (unsigned)rate, got, -want);
  CHECK(got <= want + 0.05 && got >= want - 0.2,
        "%s: preamp %.3f dB for a %.3f dB peak", name, got, -want);
}

static void test_preamp_covers_peak(void) {
  printf("preamp covers the peak of the summed response\n");
  static const uint32_t rates[] = {44100, 48000};
  for (size_t r = 0; r < 2; r++) {
    tas58xx_bq_t chain[AUDIO_EQ_SLOTS];

    chain_flat(chain);
    chain[0] = peak(1000.0f, 1.0f, 6.0f);
    check_preamp("one broad peak", chain, rates[r]);

    /* Narrow enough to fall between grid points. */
    chain_flat(chain);
    chain[0] = peak(1234.5f, 20.0f, 20.0f);
    check_preamp("one Q=20 peak", chain, rates[r]);

    chain_flat(chain);
    chain[0] = peak(100.0f, 0.7f, 6.0f);
    chain[1] = peak(140.0f, 0.7f, 6.0f);
    chain[2] = peak(200.0f, 0.7f, 6.0f);
    check_preamp("three overlapping peaks", chain, rates[r]);

    chain_flat(chain);
    chain[0] = peak(3000.0f, 1.0f, -12.0f);
    check_preamp("cut only", chain, rates[r]);

    chain_flat(chain);
    chain[0].type = TAS58XX_BQ_BASS_SHELF;
    chain[0].freq_hz = 80.0f;
    chain[0].gain_db = 10.0f;
    chain[1] = peak(9000.0f, 8.0f, 12.0f);
    chain[2] = highpass(30.0f);
    check_preamp("shelf + narrow peak + HPF", chain, rates[r]);
  }

  /* Trims come off the peak before the preamp is worked out. */
  tas58xx_bq_t chain[AUDIO_EQ_SLOTS];
  chain_flat(chain);
  chain[0] = peak(1000.0f, 1.0f, 6.0f);
  reset(48000);
  audio_eq_set_chain(0, chain);
  audio_eq_set_trim_db(0, -4.0f);
  audio_eq_set_trim_db(1, -4.0f);
  CHECK(fabs(audio_eq_get_preamp_db() + 2.0) < 0.05,
        "preamp %.3f dB with 6 dB boost and -4 dB trims",
        audio_eq_get_preamp_db());
  audio_eq_set_mute(0, true);
  audio_eq_set_mute(1, true);
  CHECK(audio_eq_get_preamp_db() == 0.0f, "preamp %.3f dB with both muted",
        audio_eq_get_preamp_db());
}

static void test_rate_follows_clock(void) {
  printf("design follows the clock, cached or not\n");
  tas58xx_bq_t chain[AUDIO_EQ_SLOTS];
  chain_flat(chain);
  chain[0] = peak(15000.0f, 4.0f, 9.0f);
  reset(48000);
  audio_eq_set_chain(0, chain);
  float at48 = audio_eq_get_preamp_db();
  audio_eq_set_rate(44100);
  float at44 = audio_eq_get_preamp_db();
  audio_eq_set_rate(32000);
  float at32 = audio_eq_get_preamp_db();
  audio_eq_set_rate(48000);
  CHECK(audio_eq_get_rate() == 48000, "rate %u", (unsigned)audio_eq_get_rate());
  CHECK(audio_eq_get_preamp_db() == at48, "48 kHz preamp changed on return");
  CHECK(fabs(at48 + 9.0) < 0.1 && fabs(at44 + 9.0) < 0.1,
        "preamp %.2f / %.2f dB at 48 / 44.1 kHz", at48, at44);
  /* 15 kHz is past the designer's margin at 32 kHz: clamped, still boosts. */
  CHECK(at32 < 0.0f, "preamp %.2f dB at 32 kHz", at32);
}

/* The largest gap between a filter's output and its steady state once an
 * edit has gone in at @p at. */
static double deviation_after(const int16_t *out, ref_t *steady, size_t frames,
                              size_t at, int ch) {
  double dev = 0;
  for (size_t i = 0; i < frames; i++) {
    double y = clip16(ref_step(steady, s_in[2 * i + ch]));
    if (i >= at && i < at + SECONDS(48000, 0.1)) {
      dev = fmax(dev, fabs(out[2 * i + ch] - y));
    }
  }
  return dev;
}

static void test_edits_keep_state(void) {
  printf("edits carry the filters' state across\n");
  const size_t frames = SECONDS(48000, 1);
  const size_t at = SECONDS(48000, 0.5);
  tas58xx_bq_t before[AUDIO_EQ_SLOTS], after[AUDIO_EQ_SLOTS];
  chain_flat(before);
  before[0] = highpass(150.0f);
  before[7] = peak(5000.0f, 1.0f, -3.0f);
  memcpy(after, before, sizeof(after));
  after[7].gain_db = -4.0f; /* retune one section, cut only: no preamp */

  /* A 200 Hz tone sits where a restarted high-pass rings the longest. */
  signal_sine(frames, 48000, 200.0, 12000.0);
  reset(48000);
  audio_eq_set_chain(0, before);
  memcpy(s_out, s_in, frames * 4);
  process(s_out, at);
  audio_eq_set_chain(0, after);
  process(s_out + 2 * at, frames - at);

  ref_t steady;
  ref_init(&steady, after, 48000);
  double dev = deviation_after(s_out, &steady, frames, at, 0);

  /* What a restart from rest would have cost, for scale. */
  ref_t restarted, steady2;
  ref_init(&restarted, after, 48000);
  ref_init(&steady2, after, 48000);
  double restart_dev = 0;
  for (size_t i = 0; i < frames; i++) {
    double y = ref_step(&steady2, s_in[2 * i]);
    if (i >= at) {
      double z = ref_step(&restarted, s_in[2 * i]);
      if (i < at + SECONDS(48000, 0.1)) {
        restart_dev = fmax(restart_dev, fabs(z - y));
      }
    }
  }
  printf("  retune: %.1f LSB from steady state (a restart: %.1f LSB)\n", dev,
         restart_dev);
  CHECK(dev < restart_dev / 20, "retune disturbed the output by %.1f LSB", dev);

  /* Inserting a section ahead of running ones renumbers them; each must
   * still find its own state. The high-pass, whose state matters most, is
   * the one that moves. */
  chain_flat(before);
  before[0] = peak(5000.0f, 1.0f, -3.0f);
  before[7] = highpass(150.0f);
  memcpy(after, before, sizeof(after));
  after[3] = peak(12000.0f, 2.0f, -1.0f);
  reset(48000);
  audio_eq_set_chain(0, before);
  memcpy(s_out, s_in, frames * 4);
  process(s_out, at);
  audio_eq_set_chain(0, after);
  process(s_out + 2 * at, frames - at);
  ref_init(&steady, after, 48000);
  dev = deviation_after(s_out, &steady, frames, at, 0);
  printf("  insert: %.1f LSB from steady state\n", dev);
  CHECK(dev < restart_dev / 20, "insert disturbed the output by %.1f LSB", dev);
}

static void test_levels_glide(void) {
  printf("level changes glide, and flat returns to bit-exact\n");
  const size_t frames = SECONDS(48000, 1.5);
  /* Off any round number of cycles, so no edit lands on a zero crossing. */
  const double amp = 16000.0, f = 997.0;
  /* Largest step a clean sine takes from one sample to the next. */
  const double sine_step = amp * 2 * M_PI * f / 48000.0;
  signal_sine(frames, 48000, f, amp);
  reset(48000);
  memcpy(s_out, s_in, frames * 4);

  size_t t = SECONDS(48000, 0.25);
  process(s_out, t);
  audio_eq_set_mute(0, true);
  process(s_out + 2 * t, SECONDS(48000, 0.25));
  t += SECONDS(48000, 0.25);
  CHECK(s_out[2 * (t - 1)] == 0 && s_out[2 * (t - 2)] == 0,
        "muted output did not reach silence");
  audio_eq_set_mute(0, false);
  audio_eq_set_trim_db(1, -6.0f);
  process(s_out + 2 * t, SECONDS(48000, 0.25));
  t += SECONDS(48000, 0.25);
  audio_eq_set_trim_db(1, 0.0f);
  process(s_out + 2 * t, frames - t);

  double worst = 0;
  for (size_t i = 1; i < frames; i++) {
    for (int ch = 0; ch < 2; ch++) {
      worst = fmax(worst, abs(s_out[2 * i + ch] - s_out[2 * (i - 1) + ch]));
    }
  }
  printf("  largest step %.1f LSB, a clean sine's %.1f\n", worst, sine_step);
  CHECK(worst <= sine_step + 2, "a level change stepped by %.1f LSB", worst);

  size_t tail = SECONDS(48000, 0.4);
  CHECK(memcmp(s_out + 2 * (frames - tail), s_in + 2 * (frames - tail),
               tail * 4) == 0,
        "not back to bit-exact after the glide");
  /* Once glided, the trimmed channel sat 6 dB down. */
  double out2 = 0, in2 = 0;
  for (size_t i = SECONDS(48000, 0.6); i < SECONDS(48000, 0.75); i++) {
    out2 += (double)s_out[2 * i + 1] * s_out[2 * i + 1];
    in2 += (double)s_in[2 * i + 1] * s_in[2 * i + 1];
  }
  double trim_db = 10 * log10(out2 / in2);
  CHECK(fabs(trim_db + 6.0) < 0.02, "-6 dB trim gave %.3f dB", trim_db);
}

/* Silence written while a source idles lets the tails ring out, then leaves
 * the filters at rest, so the next audio starts clean rather than on top of
 * whatever was playing before the gap. */
static void test_silence_rests(void) {
  printf("silence rings the filters out and leaves them at rest\n");
  const uint32_t rate = 48000;
  tas58xx_bq_t chain[AUDIO_EQ_SLOTS];
  chain_flat(chain);
  chain[0] = highpass(30.0f);
  chain[1] = peak(60.0f, 4.0f, 9.0f);
  reset(rate);
  audio_eq_set_chain(0, chain);

  const size_t tone = SECONDS(rate, 0.5);
  signal_sine(tone, rate, 61.0, 12000.0);
  process(s_in, tone);

  /* Two seconds of silence: a tail first, then exact zeros. */
  const size_t gap = SECONDS(rate, 2);
  memset(s_out, 0, gap * 4);
  process(s_out, gap);
  size_t last = 0;
  for (size_t i = 0; i < gap; i++) {
    if (s_out[2 * i] != 0 || s_out[2 * i + 1] != 0) {
      last = i;
    }
  }
  printf("  tail rang out for %.0f ms, then silence\n",
         (double)last * 1000.0 / rate);
  CHECK(last > 0, "no tail: the silence was not filtered");
  CHECK(last < gap - SECONDS(rate, 0.5), "still ringing %.0f ms in",
        (double)last * 1000.0 / rate);

  /* The next audio must match a chain started from rest. */
  const size_t frames = SECONDS(rate, 0.5);
  signal_mix(frames, rate, 4);
  memcpy(s_out, s_in, frames * 4);
  process(s_out, frames);
  double pre = pow(10.0, audio_eq_get_preamp_db() / 20.0);
  ref_t r;
  ref_init(&r, chain, rate);
  double emax = 0;
  for (size_t i = 0; i < frames; i++) {
    double y = clip16(ref_step(&r, s_in[2 * i] * pre));
    emax = fmax(emax, fabs(s_out[2 * i] - y));
  }
  printf("  next audio within %.2f LSB of a fresh start\n", emax);
  CHECK(emax < 3.0, "resumed %.1f LSB off a fresh start", emax);
}

static void test_ganged_and_rejects(void) {
  printf("unganged chains are independent; unstable custom is rejected\n");
  tas58xx_bq_t chain[AUDIO_EQ_SLOTS], flat[AUDIO_EQ_SLOTS];
  chain_flat(flat);
  chain_flat(chain);
  chain[0] = peak(1000.0f, 1.0f, -6.0f);
  reset(48000);
  audio_eq_set_ganged(false);
  audio_eq_set_chain(0, chain);
  audio_eq_set_chain(1, flat);
  signal_mix(SECONDS(48000, 0.5), 48000, 3);
  memcpy(s_out, s_in, sizeof(s_out));
  process(s_out, SECONDS(48000, 0.5));
  int right_same = 1, left_same = 1;
  for (size_t i = 0; i < SECONDS(48000, 0.5); i++) {
    right_same &= s_out[2 * i + 1] == s_in[2 * i + 1];
    left_same &= s_out[2 * i] == s_in[2 * i];
  }
  CHECK(right_same && !left_same, "unganged: left %s, right %s",
        left_same ? "untouched" : "filtered",
        right_same ? "untouched" : "filtered");

  tas58xx_bq_t bad[AUDIO_EQ_SLOTS];
  chain_flat(bad);
  bad[0].type = TAS58XX_BQ_CUSTOM;
  const float poles_outside[5] = {1.0f, 0.0f, 0.0f, 2.1f, -1.2f};
  memcpy(bad[0].coeff, poles_outside, sizeof(poles_outside));
  CHECK(audio_eq_set_chain(0, bad) == ESP_ERR_INVALID_ARG,
        "unstable custom accepted");
}

int main(void) {
  CHECK(audio_eq_init() == ESP_OK, "init failed");
  test_flat_is_bit_exact();
  test_matches_reference();
  test_preamp_covers_peak();
  test_rate_follows_clock();
  test_edits_keep_state();
  test_levels_glide();
  test_silence_rests();
  test_ganged_and_rejects();
  if (failures) {
    printf("%d check(s) failed\n", failures);
    return 1;
  }
  printf("all passed\n");
  return 0;
}
