// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "audio_eq.h"

#include "settings.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <inttypes.h>
#include <math.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "audio_eq"

#define CFG_PATH    "/spiffs/eq/sw_eq.cfg"
#define CFG_TMP     "/spiffs/eq/sw_eq.tmp"
#define CFG_MAGIC   0x51455753u /* "SWEQ" */
#define CFG_VERSION 1u

/* Log-spaced points at which each channel's response is evaluated to find
 * its peak, for the anti-clipping preamp. A narrow peak can fall between
 * them, so each section's resonance is probed as well, and the highest point
 * found is then refined PEAK_REFINE steps to either side. */
#define PEAK_GRID_POINTS 256
#define PEAK_REFINE      8
/* Floor for that preamp, reached only by custom coefficients whose response
 * runs off to infinity. */
#define PREAMP_MIN_DB (-100.0f)

/* The rates the output actually switches between (AirPlay and most USB and
 * Sendspin sources), designed whenever the model changes so a clock change
 * only has to pick one up. Anything else, e.g. Bluetooth at 32 kHz, is
 * designed when the clock gets there. */
static const uint32_t k_cached_rates[] = {44100, 48000};
#define CACHED_RATES (sizeof(k_cached_rates) / sizeof(k_cached_rates[0]))

/* Input gain changes (preamp, trim, mute) glide rather than step, like the
 * software volume in audio_output.c: ~5 ms time constant, snapped to the
 * target once within -100 dB of it. */
#define GAIN_GLIDE 0.00390625f /* 1/256 per frame */
#define GAIN_SNAP  1e-5f

/* Filter state below this, in 16-bit LSB, can no longer move the rounded
 * output. On silent input it is cleared, and a chain whose state is all
 * clear is at rest: silence in is silence out, with nothing to compute. */
#define REST_LEVEL 1e-3f

/* Stored chains. The header lets a build with different limits refuse the
 * file rather than read it crooked. */
typedef struct {
  uint32_t magic;
  uint32_t version;
  uint8_t channels;
  uint8_t slots;
  uint8_t ganged;
  uint8_t pad;
  tas58xx_bq_t bq[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
} cfg_file_t;

/* Transfer function of one section: {b0, b1, b2, a1, a2} with a0 == 1. */
typedef struct {
  double b0, b1, b2, a1, a2;
} biquad_t;

/* |H|^2 of one section as polynomials in phi = sin^2(w/2):
 *   (n0 + n1 phi + n2 phi^2) / (d0 + d1 phi + d2 phi^2)
 * Unlike the cos/sin form this does not cancel near DC, so it holds up in
 * float, and costs one sin per frequency rather than four trig calls. */
typedef struct {
  float n0, n1, n2;
  float d0, d1, d2;
  float f_res; /* frequency of the pole pair, 0 for real poles */
} mag_poly_t;

/* One section as run on the audio path: a trapezoidal state-variable filter
 * (Simper, "SvfLinearTrapOptimised2"), converted from the designed biquad.
 * Same transfer function, but its state stays well scaled at low corner
 * frequencies, where a float32 direct-form biquad adds several LSB of
 * rounding noise. */
typedef struct {
  float a1, a2, a3; /* integrator coefficients */
  float m0, m1, m2; /* output mix of input, band-pass and low-pass */
} svf_t;

typedef struct {
  bool active; /* false: leave the buffer untouched */
  uint8_t stages[AUDIO_EQ_CHANNELS];
  /* The chain slot each stage came from, so a section keeps its state when
   * the ones around it come and go. */
  uint8_t slot[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
  float in_gain[AUDIO_EQ_CHANNELS]; /* preamp x trim x mute */
  svf_t svf[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
} eq_config_t;

typedef struct {
  uint32_t rate;
  float preamp_db;
  eq_config_t cfg;
} eq_design_t;

/* Buffer indices of the triple buffer below, and the flag marking the middle
 * one as not yet picked up. */
#define TB_INDEX 0x3
#define TB_FRESH 0x4

/* Everything off the per-sample path, in PSRAM. */
typedef struct {
  tas58xx_bq_t chain[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
  eq_design_t cache[CACHED_RATES];
  mag_poly_t mag[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS]; /* design() scratch */
  /* Hand-over to the writer. The designer fills tb[s_tb_back] and swaps it
   * into the middle (s_tb_mid); the writer swaps its own buffer back for
   * it. Neither side ever waits on the other or touches a buffer the other
   * holds. */
  eq_config_t tb[3];
} eq_model_t;

/* Model, owned by whoever holds s_mutex (web server, audio tasks on a clock
 * change). */
static SemaphoreHandle_t s_mutex;
static eq_model_t *s_model;
static bool s_ganged = true;
static float s_trim_db[AUDIO_EQ_CHANNELS];
static bool s_mute[AUDIO_EQ_CHANNELS];
static uint32_t s_rate = CONFIG_OUTPUT_SAMPLE_RATE_HZ;
static float s_preamp_db;
static int s_tb_back = 0;

static _Atomic int s_tb_mid = 1;

/* Writer side, touched only by the task writing to I2S: the design it is
 * running (in internal RAM, as it is read every sample), the integrator
 * state per channel and stage, and where each input gain has glided to. */
static int s_tb_front = 2;
static bool s_primed;
static eq_config_t s_live;
static float s_ic1[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
static float s_ic2[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
static float s_gain[AUDIO_EQ_CHANNELS] = {1.0f, 1.0f};
static bool s_resting;

/* ---------- design ---------- */

static biquad_t design_biquad(const tas58xx_bq_t *bq, double fs) {
  double c[5];
  tas58xx_bq_design(bq, fs, c);
  /* The designer emits the denominator already negated, as the TAS wants. */
  biquad_t out = {c[0], c[1], c[2], -c[3], -c[4]};
  return out;
}

static bool biquad_is_unity(const biquad_t *b) {
  return fabs(b->b0 - 1.0) < 1e-9 && fabs(b->b1) < 1e-9 && fabs(b->b2) < 1e-9 &&
         fabs(b->a1) < 1e-9 && fabs(b->a2) < 1e-9;
}

/*
 * Rewrite a digital biquad as the SVF above. Undoing the bilinear transform
 * with p = (1 - z^-1) / (1 + z^-1) turns the denominator into
 *   (1 - a1 + a2) p^2 + 2 (1 - a2) p + (1 + a1 + a2)
 * which, matched against the SVF's g^2 (s^2 + k s + 1) with p = g s, gives
 * g and k; the numerator likewise yields the output mix. Both p^2 and p^0
 * terms are positive exactly when the poles are inside the unit circle, so
 * this fails only for unstable or marginal sections.
 */
static bool biquad_to_svf(const biquad_t *b, svf_t *out) {
  double c = 1.0 - b->a1 + b->a2;
  double d = 1.0 + b->a1 + b->a2;
  if (!(c > 0.0) || !(d > 0.0) || !(fabs(b->a2) < 1.0)) {
    return false;
  }
  double g = sqrt(d / c);
  double k = (2.0 - 2.0 * b->a2) / (c * g);
  double n2 = (b->b0 - b->b1 + b->b2) / c;
  double n1 = (2.0 * b->b0 - 2.0 * b->b2) / c;
  double n0 = (b->b0 + b->b1 + b->b2) / c;

  double a1 = 1.0 / (1.0 + g * (g + k));
  double a2 = g * a1;
  out->a1 = (float)a1;
  out->a2 = (float)a2;
  out->a3 = (float)(g * a2);
  out->m0 = (float)n2;
  out->m1 = (float)(n1 / g - n2 * k);
  out->m2 = (float)(n0 / (g * g) - n2);
  return true;
}

/* The combinations are formed in double, where they cancel harmlessly. */
static mag_poly_t biquad_mag_poly(const biquad_t *b, double fs) {
  const double a0 = 1.0;
  double ns = b->b0 + b->b1 + b->b2;
  double ds = a0 + b->a1 + b->a2;
  mag_poly_t m = {
      (float)(ns * ns),
      (float)(-4.0 * (b->b0 * b->b1 + 4.0 * b->b0 * b->b2 + b->b1 * b->b2)),
      (float)(16.0 * b->b0 * b->b2),
      (float)(ds * ds),
      (float)(-4.0 * (a0 * b->a1 + 4.0 * a0 * b->a2 + b->a1 * b->a2)),
      (float)(16.0 * a0 * b->a2),
      0.0f,
  };
  /* Poles at r e^(+-j theta): a1 = -2 r cos(theta), a2 = r^2. */
  if (b->a2 > 0.0 && b->a1 * b->a1 < 4.0 * b->a2) {
    double c = -b->a1 / (2.0 * sqrt(b->a2));
    m.f_res = (float)(acos(c) * fs / (2.0 * M_PI));
  }
  return m;
}

/* |H|^2 of a whole chain at frequency f. */
static float chain_mag2(const mag_poly_t *mag, int stages, float f, float fs) {
  float s = sinf((float)M_PI * f / fs);
  float phi = s * s;
  float mag2 = 1.0f;
  for (int n = 0; n < stages; n++) {
    mag2 *= (mag[n].n0 + phi * (mag[n].n1 + phi * mag[n].n2)) /
            (mag[n].d0 + phi * (mag[n].d1 + phi * mag[n].d2));
  }
  return mag2;
}

/* Highest |H|^2 of a chain between 20 Hz and f_hi. */
static float chain_peak(const mag_poly_t *mag, int stages, float fs,
                        float f_hi) {
  const float step = powf(f_hi / 20.0f, 1.0f / (PEAK_GRID_POINTS - 1));
  float peak = 0.0f;
  float peak_f = 20.0f;
  float f = 20.0f;
  for (int p = 0; p < PEAK_GRID_POINTS + stages; p++) {
    if (p >= PEAK_GRID_POINTS) {
      f = mag[p - PEAK_GRID_POINTS].f_res;
      if (!(f >= 20.0f && f <= f_hi)) {
        continue;
      }
    }
    float mag2 = chain_mag2(mag, stages, f, fs);
    if (mag2 > peak) {
      peak = mag2;
      peak_f = f;
    }
    f *= step;
  }
  const float fine = powf(step, 1.0f / PEAK_REFINE);
  for (int dir = -1; dir <= 1; dir += 2) {
    f = peak_f;
    for (int k = 1; k < PEAK_REFINE; k++) {
      f = dir > 0 ? f * fine : f / fine;
      float mag2 = chain_mag2(mag, stages, fminf(fmaxf(f, 20.0f), f_hi), fs);
      if (mag2 > peak) {
        peak = mag2;
      }
    }
  }
  return peak;
}

/* Overlapping boosts add up, so a channel's peak can exceed any single
 * section's gain. Find the louder channel's peak, trim included, and return
 * the attenuation (dB, <= 0) that pulls it down to 0 dBFS. Pulling both
 * channels down by the same amount keeps the balance. */
static float preamp_for(const eq_config_t *cfg, uint32_t rate) {
  const float fs = (float)rate;
  const float f_hi = fs / 2.0f < 20000.0f ? fs / 2.0f * 0.99f : 20000.0f;
  float peak_db = -INFINITY;

  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    if (s_mute[ch]) {
      continue;
    }
    float peak = cfg->stages[ch] > 0
                     ? chain_peak(s_model->mag[ch], cfg->stages[ch], fs, f_hi)
                     : 1.0f;
    float db = 10.0f * log10f(peak) + s_trim_db[ch];
    if (db > peak_db) {
      peak_db = db;
    }
  }
  if (!(peak_db > 0.0f)) {
    return 0.0f; /* nothing boosts past 0 dBFS, or every output is muted */
  }
  return fmaxf(-peak_db, PREAMP_MIN_DB);
}

/* Design both channels of the current model at @p rate into @p cfg, and
 * return the preamp that went into it. Caller holds s_mutex. */
static float design(uint32_t rate, eq_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  const double fs = (double)rate;
  bool any_filter = false;

  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    const tas58xx_bq_t *chain = s_model->chain[s_ganged ? 0 : ch];
    for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
      if (chain[i].type == TAS58XX_BQ_BYPASS) {
        continue;
      }
      biquad_t b = design_biquad(&chain[i], fs);
      if (biquad_is_unity(&b)) {
        continue; /* e.g. a 0 dB peak: nothing to run */
      }
      int n = cfg->stages[ch];
      if (!biquad_to_svf(&b, &cfg->svf[ch][n])) {
        ESP_LOGW(TAG, "ch %d slot %d is unstable at %" PRIu32 " Hz, bypassed",
                 ch, i, rate);
        continue;
      }
      cfg->slot[ch][n] = (uint8_t)i;
      s_model->mag[ch][n] = biquad_mag_poly(&b, fs);
      cfg->stages[ch] = (uint8_t)(n + 1);
      any_filter = true;
    }
  }

  const float pre_db = preamp_for(cfg, rate);
  bool unity_gain = true;
  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    float db = pre_db + s_trim_db[ch];
    cfg->in_gain[ch] = s_mute[ch] ? 0.0f : powf(10.0f, db / 20.0f);
    if (s_mute[ch] || db != 0.0f) {
      unity_gain = false;
    }
  }
  cfg->active = any_filter || !unity_gain;
  return pre_db;
}

/* Hand the design for s_rate to the writer, from the cache when it holds
 * that rate. Caller holds s_mutex. */
static void publish(void) {
  eq_config_t *back = &s_model->tb[s_tb_back];
  const eq_design_t *hit = NULL;
  for (size_t i = 0; i < CACHED_RATES; i++) {
    if (s_model->cache[i].rate == s_rate) {
      hit = &s_model->cache[i];
    }
  }
  if (hit != NULL) {
    memcpy(back, &hit->cfg, sizeof(*back));
    s_preamp_db = hit->preamp_db;
  } else {
    s_preamp_db = design(s_rate, back);
  }
  /* Integer formatting only: float printf alone costs ~1 KB of stack, and
   * this runs on the audio tasks. */
  ESP_LOGD(TAG, "%" PRIu32 " Hz: %d + %d sections, preamp -%d.%d dB", s_rate,
           back->stages[0], back->stages[1],
           (int)(-s_preamp_db * 10.0f + 0.5f) / 10,
           (int)(-s_preamp_db * 10.0f + 0.5f) % 10);

  /* Whatever was in the middle is ours now: either the writer has already
   * swapped it for the buffer it was running, or it never saw it. */
  s_tb_back = atomic_exchange(&s_tb_mid, s_tb_back | TB_FRESH) & TB_INDEX;
}

/* The model changed: redesign every cached rate, then publish. Caller holds
 * s_mutex. */
static void redesign(void) {
  for (size_t i = 0; i < CACHED_RATES; i++) {
    eq_design_t *d = &s_model->cache[i];
    d->rate = k_cached_rates[i];
    d->preamp_db = design(d->rate, &d->cfg);
  }
  publish();
}

/* ---------- persistence ---------- */

static void chains_default(void) {
  s_ganged = true;
  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
      tas58xx_bq_init_bypass(&s_model->chain[ch][i]);
    }
  }
}

/* Load the committed chains; false leaves the model alone. */
static bool chains_load(void) {
  FILE *f = fopen(CFG_PATH, "rb");
  if (!f) {
    return false;
  }
  cfg_file_t *cfg = calloc(1, sizeof(*cfg));
  if (!cfg) {
    fclose(f);
    return false;
  }
  size_t n = fread(cfg, 1, sizeof(*cfg), f);
  fclose(f);

  bool ok = n == sizeof(*cfg) && cfg->magic == CFG_MAGIC &&
            cfg->version == CFG_VERSION && cfg->channels == AUDIO_EQ_CHANNELS &&
            cfg->slots == AUDIO_EQ_SLOTS;
  for (int ch = 0; ok && ch < AUDIO_EQ_CHANNELS; ch++) {
    for (int i = 0; ok && i < AUDIO_EQ_SLOTS; i++) {
      ok = tas58xx_bq_validate(&cfg->bq[ch][i], NULL);
    }
  }
  if (ok) {
    memcpy(s_model->chain, cfg->bq, sizeof(s_model->chain));
    s_ganged = cfg->ganged != 0;
  } else {
    ESP_LOGW(TAG, "ignoring %s (%u bytes)", CFG_PATH, (unsigned)n);
  }
  free(cfg);
  return ok;
}

static void levels_save(void) {
  float gain[SETTINGS_AMP_OUTPUTS] = {0};
  uint8_t mute[SETTINGS_AMP_OUTPUTS] = {0};
  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    gain[ch] = s_trim_db[ch];
    mute[ch] = s_mute[ch];
  }
  settings_set_amp_gain(gain);
  settings_set_amp_mute(mute);
}

static void levels_load(void) {
  float gain[SETTINGS_AMP_OUTPUTS];
  uint8_t mute[SETTINGS_AMP_OUTPUTS];
  if (settings_get_amp_gain(gain) == ESP_OK) {
    for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
      s_trim_db[ch] =
          fminf(fmaxf(gain[ch], AUDIO_EQ_TRIM_MIN_DB), AUDIO_EQ_TRIM_MAX_DB);
    }
  }
  if (settings_get_amp_mute(mute) == ESP_OK) {
    for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
      s_mute[ch] = mute[ch] != 0;
    }
  }
}

/* ---------- public API ---------- */

esp_err_t audio_eq_init(void) {
  if (s_mutex != NULL) {
    return ESP_OK;
  }
  s_model = heap_caps_calloc(1, sizeof(*s_model),
                             MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (s_model == NULL) {
    return ESP_ERR_NO_MEM;
  }
  s_mutex = xSemaphoreCreateMutex();
  if (s_mutex == NULL) {
    heap_caps_free(s_model);
    s_model = NULL;
    return ESP_ERR_NO_MEM;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  chains_default();
  if (chains_load()) {
    ESP_LOGI(TAG, "loaded %s", CFG_PATH);
  }
  levels_load();
  redesign();
  xSemaphoreGive(s_mutex);
  return ESP_OK;
}

void audio_eq_set_rate(uint32_t sample_rate_hz) {
  if (s_mutex == NULL || sample_rate_hz == 0) {
    return;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (sample_rate_hz != s_rate) {
    s_rate = sample_rate_hz;
    publish();
  }
  xSemaphoreGive(s_mutex);
}

uint32_t audio_eq_get_rate(void) {
  return s_rate;
}

static inline int16_t to_int16(float v) {
  if (v >= 32767.0f) {
    return 32767;
  }
  if (v <= -32768.0f) {
    return -32768;
  }
  /* Round to nearest without a libm call per sample: offset into positive
   * range, where truncation is floor. Exact for integer input, so a flat
   * chain at unity gain gives the samples back unchanged. */
  return (int16_t)((int32_t)(v + 32768.5f) - 32768);
}

/* Take over a new design without restarting the filters. A section that
 * carries on, retuned or not, keeps its state, which the SVF tolerates; only
 * one that was not running before starts from rest. */
static void adopt(const eq_config_t *next) {
  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    float ic1[AUDIO_EQ_SLOTS] = {0};
    float ic2[AUDIO_EQ_SLOTS] = {0};
    bool running[AUDIO_EQ_SLOTS] = {false};
    for (int n = 0; n < s_live.stages[ch]; n++) {
      const int slot = s_live.slot[ch][n];
      ic1[slot] = s_ic1[ch][n];
      ic2[slot] = s_ic2[ch][n];
      running[slot] = true;
    }
    for (int n = 0; n < next->stages[ch]; n++) {
      const int slot = next->slot[ch][n];
      s_ic1[ch][n] = running[slot] ? ic1[slot] : 0.0f;
      s_ic2[ch][n] = running[slot] ? ic2[slot] : 0.0f;
    }
  }
  memcpy(&s_live, next, sizeof(s_live));
  s_resting = false;
  if (!s_primed) {
    /* Nothing has played through the old gains yet. */
    for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
      s_gain[ch] = s_live.in_gain[ch];
    }
    s_primed = true;
  }
}

static bool is_silent(const int16_t *buf, size_t frames) {
  for (size_t i = 0; i < frames * 2; i++) {
    if (buf[i] != 0) {
      return false;
    }
  }
  return true;
}

void audio_eq_process(int16_t *buf, size_t frames) {
  if (atomic_load_explicit(&s_tb_mid, memory_order_relaxed) & TB_FRESH) {
    s_tb_front = atomic_exchange(&s_tb_mid, s_tb_front) & TB_INDEX;
    adopt(&s_model->tb[s_tb_front]);
  }
  if (!s_live.active && s_gain[0] == 1.0f && s_gain[1] == 1.0f) {
    return; /* flat, and done gliding: bit-exact passthrough */
  }
  /* Sources keep writing silence while idle; once the tails have died away
   * there is nothing left to filter. */
  const bool silent = is_silent(buf, frames);
  if (silent && s_resting && s_gain[0] == s_live.in_gain[0] &&
      s_gain[1] == s_live.in_gain[1]) {
    return;
  }
  bool resting = silent;

  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    const int stages = s_live.stages[ch];
    const float target = s_live.in_gain[ch];
    const svf_t *f = s_live.svf[ch];
    float *ic1 = s_ic1[ch];
    float *ic2 = s_ic2[ch];
    float gain = s_gain[ch];

    for (size_t i = 0; i < frames; i++) {
      if (gain != target) {
        gain += (target - gain) * GAIN_GLIDE;
        if (fabsf(target - gain) < GAIN_SNAP) {
          gain = target;
        }
      }
      float x = (float)buf[i * 2 + ch] * gain;
      for (int s = 0; s < stages; s++) {
        float v3 = x - ic2[s];
        float v1 = f[s].a1 * ic1[s] + f[s].a2 * v3;
        float v2 = ic2[s] + f[s].a2 * ic1[s] + f[s].a3 * v3;
        ic1[s] = 2.0f * v1 - ic1[s];
        ic2[s] = 2.0f * v2 - ic2[s];
        x = f[s].m0 * x + f[s].m1 * v1 + f[s].m2 * v2;
      }
      buf[i * 2 + ch] = to_int16(x);
    }
    s_gain[ch] = gain;

    /* Decaying tails would otherwise sink into denormals, and in silence
     * are cleared as soon as they stop mattering. */
    const float clear_below = silent ? REST_LEVEL : 1e-15f;
    for (int s = 0; s < stages; s++) {
      if (fabsf(ic1[s]) < clear_below) {
        ic1[s] = 0.0f;
      }
      if (fabsf(ic2[s]) < clear_below) {
        ic2[s] = 0.0f;
      }
      resting = resting && ic1[s] == 0.0f && ic2[s] == 0.0f;
    }
  }
  s_resting = resting;
}

bool audio_eq_get_chain(int ch, tas58xx_bq_t out[AUDIO_EQ_SLOTS]) {
  if (s_mutex == NULL || !out || ch < 0 || ch >= AUDIO_EQ_CHANNELS) {
    return false;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  memcpy(out, s_model->chain[ch], sizeof(s_model->chain[ch]));
  xSemaphoreGive(s_mutex);
  return true;
}

esp_err_t audio_eq_set_chain(int ch, const tas58xx_bq_t in[AUDIO_EQ_SLOTS]) {
  if (s_mutex == NULL || !in || ch < 0 || ch >= AUDIO_EQ_CHANNELS) {
    return ESP_ERR_INVALID_ARG;
  }
  for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
    const char *why = NULL;
    if (!tas58xx_bq_validate(&in[i], &why)) {
      ESP_LOGW(TAG, "ch %d slot %d rejected: %s", ch, i, why ? why : "?");
      return ESP_ERR_INVALID_ARG;
    }
    /* Only raw coefficients can describe an unstable filter, and those do
     * not depend on the rate. */
    if (in[i].type == TAS58XX_BQ_CUSTOM) {
      biquad_t b = design_biquad(&in[i], (double)s_rate);
      svf_t unused;
      if (!biquad_is_unity(&b) && !biquad_to_svf(&b, &unused)) {
        ESP_LOGW(TAG, "ch %d slot %d rejected: unstable", ch, i);
        return ESP_ERR_INVALID_ARG;
      }
    }
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  memcpy(s_model->chain[ch], in, sizeof(s_model->chain[ch]));
  redesign();
  xSemaphoreGive(s_mutex);
  return ESP_OK;
}

void audio_eq_set_ganged(bool ganged) {
  if (s_mutex == NULL) {
    return;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (ganged != s_ganged) {
    s_ganged = ganged;
    redesign();
  }
  xSemaphoreGive(s_mutex);
}

bool audio_eq_get_ganged(void) {
  return s_ganged;
}

esp_err_t audio_eq_commit(void) {
  if (s_mutex == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  cfg_file_t *cfg = calloc(1, sizeof(*cfg));
  if (!cfg) {
    return ESP_ERR_NO_MEM;
  }
  cfg->magic = CFG_MAGIC;
  cfg->version = CFG_VERSION;
  cfg->channels = AUDIO_EQ_CHANNELS;
  cfg->slots = AUDIO_EQ_SLOTS;
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  cfg->ganged = s_ganged ? 1 : 0;
  memcpy(cfg->bq, s_model->chain, sizeof(cfg->bq));
  xSemaphoreGive(s_mutex);

  /* Written to one side and renamed, so a reset mid-write leaves the
   * previous tuning intact rather than a truncated file. */
  esp_err_t err = ESP_OK;
  FILE *f = fopen(CFG_TMP, "wb");
  if (!f) {
    ESP_LOGE(TAG, "cannot open %s for writing", CFG_TMP);
    err = ESP_FAIL;
  } else {
    size_t n = fwrite(cfg, 1, sizeof(*cfg), f);
    if (fclose(f) != 0 || n != sizeof(*cfg)) {
      ESP_LOGE(TAG, "short write to %s", CFG_TMP);
      remove(CFG_TMP);
      err = ESP_FAIL;
    } else {
      remove(CFG_PATH);
      if (rename(CFG_TMP, CFG_PATH) != 0) {
        ESP_LOGE(TAG, "cannot rename %s to %s", CFG_TMP, CFG_PATH);
        remove(CFG_TMP);
        err = ESP_FAIL;
      } else {
        ESP_LOGI(TAG, "committed to %s", CFG_PATH);
      }
    }
  }
  free(cfg);
  return err;
}

esp_err_t audio_eq_revert(void) {
  if (s_mutex == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  chains_default();
  chains_load();
  redesign();
  xSemaphoreGive(s_mutex);
  return ESP_OK;
}

void audio_eq_set_trim_db(int ch, float db) {
  if (s_mutex == NULL || ch < 0 || ch >= AUDIO_EQ_CHANNELS) {
    return;
  }
  db = fminf(fmaxf(db, AUDIO_EQ_TRIM_MIN_DB), AUDIO_EQ_TRIM_MAX_DB);
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (db != s_trim_db[ch]) {
    s_trim_db[ch] = db;
    redesign();
    levels_save();
  }
  xSemaphoreGive(s_mutex);
}

float audio_eq_get_trim_db(int ch) {
  return (ch >= 0 && ch < AUDIO_EQ_CHANNELS) ? s_trim_db[ch] : 0.0f;
}

void audio_eq_set_mute(int ch, bool mute) {
  if (s_mutex == NULL || ch < 0 || ch >= AUDIO_EQ_CHANNELS) {
    return;
  }
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (mute != s_mute[ch]) {
    s_mute[ch] = mute;
    redesign();
    levels_save();
  }
  xSemaphoreGive(s_mutex);
}

bool audio_eq_get_mute(int ch) {
  return ch >= 0 && ch < AUDIO_EQ_CHANNELS && s_mute[ch];
}

float audio_eq_get_preamp_db(void) {
  return s_preamp_db;
}
