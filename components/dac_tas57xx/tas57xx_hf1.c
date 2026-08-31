#include "tas57xx_hf1.h"

#include <math.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "tas57xx_hf1";

/** Coefficient RAM slot holding the harmonic generator's drive scalar. */
#define HF1_PBE_HARMONIC_WORD 151
/** First word of the effect-intensity shelf, stored denominator-first. */
#define HF1_PBE_EFFECT_WORD 157
#define HF1_PBE_MIX_WORD    209
/** Reciprocal of the energy estimator's averaging window, in samples. */
#define HF1_ENERGY_WINDOW_WORD 145
/** DBE crossfade: lower threshold, then the reciprocal of the span. */
#define HF1_DBE_MIX_WORD 143
/** Bandpass the energy estimator listens through. */
#define HF1_SENSING_BAND_WORD 146
/** Compander band mixer gains, low first; the flow ships the mid at -1. */
#define HF1_DRC_MIX_WORD 0
/** Compander detectors: 3 bands x (energy, attack, decay), each a word pair. */
#define HF1_DRC_TIMING_WORD 5
/** Compander curve: 3 region slopes, then the 2 thresholds splitting them. */
#define HF1_DRC_CURVE_WORD 23
/** Output limiter threshold, stored with a 1/2 headroom pad. */
#define HF1_SMOOTH_CLIP_WORD 251
/** Flow-internal volume trim, distinct from the part's volume registers. */
#define HF1_FINE_VOLUME_WORD 255

#define Q23_ONE 8388607.0f

static const int hf1_eq_slots[TAS57XX_HF1_EQ_BANDS] = {83,  88,  93,  98,  103,
                                                       108, 113, 118, 123, 128};

static const int hf1_dbe_eq_slots[TAS57XX_HF1_DBE_EQ_BANDS] = {177, 182};
static const int hf1_dbe_ll_eq_slots[TAS57XX_HF1_DBE_EQ_BANDS] = {133, 138};

/** Compander band-split slots, in the order the config lists them. */
static const int hf1_drc_cross_slots[TAS57XX_HF1_DRC_CROSS_SECTIONS] = {
    189, /* low  */
    199, /* mid A */
    204, /* mid B */
    194, /* high */
};

/**
 * The bass enhancer derives its whole extraction network from the single HPF
 * corner in the tuning GUI. Ratios and Qs are fitted from PurePath Console
 * captures at 80/100/120 Hz and reproduce them to within 3 LSB of 2^23; they
 * are not the textbook Butterworth values, so do not "correct" them.
 */
static const struct {
  int word;
  tas57xx_bq_type_t type;
  tas57xx_bq_subtype_t subtype;
  float ratio;
  float q;
} hf1_pbe_extract[] = {
    {152, TAS57XX_BQ_HIGHPASS, TAS57XX_BQ_SUB_VARIABLE_Q_2, 0.19420f, 0.5693f},
    {162, TAS57XX_BQ_LOWPASS, TAS57XX_BQ_SUB_VARIABLE_Q_2, 0.59992f, 0.7054f},
    {167, TAS57XX_BQ_LOWPASS, TAS57XX_BQ_SUB_VARIABLE_Q_2, 1.20198f, 0.9994f},
    {172, TAS57XX_BQ_LOWPASS, TAS57XX_BQ_SUB_BUTTERWORTH_1, 1.20270f, 1.0f},
};

/**
 * Effect intensity selects a shelf whose pole pair and real zero both track the
 * HPF corner. There are only five settings, so the design parameters are
 * tabulated rather than derived; each row reproduces the captured coefficients
 * to better than 0.0001 dB.
 */
static const struct {
  float pole_ratio;
  float pole_q;
  float zero_ratio;
} hf1_pbe_effect[TAS57XX_HF1_PBE_EFFECT_MAX] = {
    {0.18901f, 0.5231f, 0.26710f}, {0.46708f, 1.1324f, 0.66942f},
    {0.48703f, 1.4195f, 0.90321f}, {0.49383f, 1.6511f, 1.08794f},
    {0.49600f, 1.8494f, 1.24322f},
};

static int32_t hf1_q23(float v) {
  float s = v * Q23_ONE;
  if (s > Q23_ONE) {
    s = Q23_ONE;
  } else if (s < -Q23_ONE - 1.0f) {
    s = -Q23_ONE - 1.0f;
  }
  return (int32_t)lrintf(s);
}

/** The compander block scales unity to 2^23, not the 2^23-1 used elsewhere. */
static int32_t hf1_q23_unit(float v) {
  float s = v * 8388608.0f;
  if (s > 8388607.0f) {
    s = 8388607.0f;
  } else if (s < -8388608.0f) {
    s = -8388608.0f;
  }
  return (int32_t)lrintf(s);
}

/** Store a direct-form biquad in the denominator-first layout the PBE uses. */
static void hf1_pack_den_first(float b0, float b1, float b2, float a1, float a2,
                               int32_t out[TAS57XX_BQ_WORDS]) {
  out[0] = hf1_q23(-a1 / 2.0f);
  out[1] = hf1_q23(-a2);
  out[2] = hf1_q23(b0 / 2.0f);
  out[3] = hf1_q23(b1 / 4.0f);
  out[4] = hf1_q23(b2 / 2.0f);
}

static esp_err_t hf1_write_pbe_harmonic(const tas57xx_cram_sink_t *sink,
                                        int harmonic) {
  /* 0 mutes outright; 1-100 maps linearly onto -49.5 .. 0 dB in 0.5 dB steps.
   */
  int32_t word = harmonic <= 0
                     ? 0
                     : hf1_q23(powf(10.0f, (0.5f * harmonic - 50.0f) / 20.0f));
  return tas57xx_cram_write(sink, HF1_PBE_HARMONIC_WORD, &word, 1);
}

static esp_err_t hf1_write_pbe_effect(const tas57xx_cram_sink_t *sink,
                                      int effect, float hpf_hz,
                                      uint32_t sample_rate_hz) {
  const float fs = (float)sample_rate_hz;
  const int idx = effect - TAS57XX_HF1_PBE_EFFECT_MIN;
  const float w =
      2.0f * (float)M_PI * hf1_pbe_effect[idx].pole_ratio * hpf_hz / fs;
  const float alpha = sinf(w) / (2.0f * hf1_pbe_effect[idx].pole_q);
  const float a0 = 1.0f + alpha;

  /* One zero pinned at DC, one real zero tracking the corner. */
  const float b0 = 1.0f / a0;
  const float b2 = b0 * expf(-2.0f * (float)M_PI *
                             hf1_pbe_effect[idx].zero_ratio * hpf_hz / fs);

  int32_t c[TAS57XX_BQ_WORDS];
  hf1_pack_den_first(b0, -(b0 + b2), b2, -2.0f * cosf(w) / a0,
                     (1.0f - alpha) / a0, c);
  return tas57xx_cram_write(sink, HF1_PBE_EFFECT_WORD, c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf1_set_eq_band(const tas57xx_cram_sink_t *sink, int band,
                                  const tas57xx_bq_t *bq,
                                  uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF1_EQ_BANDS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  float makeup = tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  if (makeup < -0.01f) {
    ESP_LOGD(TAG, "band %d needs %.2f dB of make-up gain", band, -makeup);
  }
  return tas57xx_cram_write(sink, hf1_eq_slots[band], c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf1_set_pbe(const tas57xx_cram_sink_t *sink,
                              const tas57xx_hf1_pbe_t *pbe,
                              uint32_t sample_rate_hz) {
  if (!pbe || pbe->hpf_hz < TAS57XX_HF1_PBE_HPF_MIN_HZ ||
      pbe->hpf_hz > TAS57XX_HF1_PBE_HPF_MAX_HZ || pbe->harmonic < 0 ||
      pbe->harmonic > TAS57XX_HF1_PBE_HARMONIC_MAX ||
      pbe->effect < TAS57XX_HF1_PBE_EFFECT_MIN ||
      pbe->effect > TAS57XX_HF1_PBE_EFFECT_MAX) {
    return ESP_ERR_INVALID_ARG;
  }
  for (size_t i = 0; i < sizeof(hf1_pbe_extract) / sizeof(hf1_pbe_extract[0]);
       i++) {
    tas57xx_bq_t bq = {
        .type = hf1_pbe_extract[i].type,
        .subtype = hf1_pbe_extract[i].subtype,
        .freq_hz = pbe->hpf_hz * hf1_pbe_extract[i].ratio,
        .q = hf1_pbe_extract[i].q,
        .gain_db = 0.0f,
    };
    int32_t c[TAS57XX_BQ_WORDS];
    tas57xx_bq_pack(&bq, sample_rate_hz, TAS57XX_BQ_DEN_FIRST, c);
    esp_err_t err =
        tas57xx_cram_write(sink, hf1_pbe_extract[i].word, c, TAS57XX_BQ_WORDS);
    if (err != ESP_OK) {
      return err;
    }
  }
  esp_err_t err =
      hf1_write_pbe_effect(sink, pbe->effect, pbe->hpf_hz, sample_rate_hz);
  if (err != ESP_OK) {
    return err;
  }
  err = hf1_write_pbe_harmonic(sink, pbe->harmonic);
  if (err != ESP_OK) {
    return err;
  }
  ESP_LOGD(TAG, "PBE: hpf %.1f Hz, harmonic %d, effect %d", pbe->hpf_hz,
           pbe->harmonic, pbe->effect);
  return ESP_OK;
}

esp_err_t tas57xx_hf1_set_pbe_enabled(const tas57xx_cram_sink_t *sink,
                                      bool enabled) {
  // A crossfade, not a flag: 209 carries the processed path, 210 the dry one.
  int32_t w[2] = {hf1_q23_unit(enabled ? 1.0f : 0.0f),
                  hf1_q23_unit(enabled ? 0.0f : 1.0f)};
  return tas57xx_cram_write(sink, HF1_PBE_MIX_WORD, w, 2);
}

esp_err_t tas57xx_hf1_set_dbe_hl_eq_band(const tas57xx_cram_sink_t *sink,
                                         int band, const tas57xx_bq_t *bq,
                                         uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF1_DBE_EQ_BANDS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, hf1_dbe_eq_slots[band], c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf1_set_dbe_ll_eq_band(const tas57xx_cram_sink_t *sink,
                                         int band, const tas57xx_bq_t *bq,
                                         uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF1_DBE_EQ_BANDS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, hf1_dbe_ll_eq_slots[band], c,
                            TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf1_set_sensing_band(const tas57xx_cram_sink_t *sink,
                                       float lower_hz, float upper_hz,
                                       uint32_t sample_rate_hz) {
  if (lower_hz < 10.0f || upper_hz <= lower_hz ||
      upper_hz > (float)sample_rate_hz / 2.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  const float centre = sqrtf(lower_hz * upper_hz);
  tas57xx_bq_t bq = {
      .type = TAS57XX_BQ_BANDPASS,
      .freq_hz = centre,
      .q = centre / (upper_hz - lower_hz),
      .gain_db = 0.0f,
  };
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(&bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, HF1_SENSING_BAND_WORD, c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf1_set_energy_window(const tas57xx_cram_sink_t *sink,
                                        float window_ms,
                                        uint32_t sample_rate_hz) {
  if (window_ms < 1.0f || window_ms > 1000.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t word = hf1_q23(1000.0f / (window_ms * (float)sample_rate_hz));
  return tas57xx_cram_write(sink, HF1_ENERGY_WINDOW_WORD, &word, 1);
}

esp_err_t tas57xx_hf1_set_drc_crossover(
    const tas57xx_cram_sink_t *sink,
    const tas57xx_bq_t sections[TAS57XX_HF1_DRC_CROSS_SECTIONS],
    uint32_t sample_rate_hz) {
  if (!sections) {
    return ESP_ERR_INVALID_ARG;
  }
  for (int i = 0; i < TAS57XX_HF1_DRC_CROSS_SECTIONS; i++) {
    int32_t c[TAS57XX_BQ_WORDS];
    tas57xx_bq_pack(&sections[i], sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
    esp_err_t err =
        tas57xx_cram_write(sink, hf1_drc_cross_slots[i], c, TAS57XX_BQ_WORDS);
    if (err != ESP_OK) {
      return err;
    }
  }
  return ESP_OK;
}

esp_err_t tas57xx_hf1_set_drc_mix(const tas57xx_cram_sink_t *sink,
                                  const float gain[TAS57XX_HF1_DRC_BANDS]) {
  if (!gain) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w[TAS57XX_HF1_DRC_BANDS];
  for (int i = 0; i < TAS57XX_HF1_DRC_BANDS; i++) {
    if (!(gain[i] >= TAS57XX_HF1_DRC_MIX_MIN &&
          gain[i] <= TAS57XX_HF1_DRC_MIX_MAX)) {
      return ESP_ERR_INVALID_ARG;
    }
    w[i] = hf1_q23(gain[i]);
  }
  return tas57xx_cram_write(sink, HF1_DRC_MIX_WORD, w, TAS57XX_HF1_DRC_BANDS);
}

/**
 * Detector coefficients are one-pole smoothers stored as the pair (1-a, a),
 * with unity at 2^23 rather than the 2^23-1 used for filter coefficients.
 * Attack and decay are specified as a settling time of three time constants;
 * the energy window is a single one.
 */
static void hf1_time_pair(float ms, int constants, uint32_t sample_rate_hz,
                          int32_t out[2]) {
  const float n = (float)constants * 1000.0f / ((float)sample_rate_hz * ms);
  int32_t c = (int32_t)lrintf((1.0f - expf(-n)) * 8388608.0f);
  if (c < 1) {
    c = 1;
  } else if (c > 0x7FFFFF) {
    c = 0x7FFFFF;
  }
  out[0] = c;
  out[1] = 0x800000 - c;
}

esp_err_t tas57xx_hf1_set_drc_timing(const tas57xx_cram_sink_t *sink, int band,
                                     const tas57xx_hf1_drc_timing_t *timing,
                                     uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF1_DRC_BANDS || !timing) {
    return ESP_ERR_INVALID_ARG;
  }
  const float ms[3] = {timing->energy_ms, timing->attack_ms, timing->decay_ms};
  for (int i = 0; i < 3; i++) {
    if (ms[i] < TAS57XX_HF1_DRC_TIME_MIN_MS ||
        ms[i] > TAS57XX_HF1_DRC_TIME_MAX_MS) {
      return ESP_ERR_INVALID_ARG;
    }
  }
  int32_t w[6];
  hf1_time_pair(ms[0], 1, sample_rate_hz, &w[0]);
  hf1_time_pair(ms[1], 3, sample_rate_hz, &w[2]);
  hf1_time_pair(ms[2], 3, sample_rate_hz, &w[4]);
  return tas57xx_cram_write(sink, HF1_DRC_TIMING_WORD + band * 6, w, 6);
}

/**
 * The level metric the curve works in is dB/128, so thresholds are stored
 * negated and scaled. Slopes are stored as a quarter of the deviation from
 * unity gain, which leaves room for the full 0.2 to 5.0 ratio range.
 */
esp_err_t tas57xx_hf1_set_drc_curve(
    const tas57xx_cram_sink_t *sink,
    const tas57xx_hf1_drc_region_t regions[TAS57XX_HF1_DRC_REGIONS],
    float thresh1_db, float thresh2_db) {
  if (!regions || thresh1_db < -120.0f || thresh2_db > 0.0f ||
      thresh2_db <= thresh1_db) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w[TAS57XX_HF1_DRC_REGIONS + 2];
  for (int i = 0; i < TAS57XX_HF1_DRC_REGIONS; i++) {
    const float ratio = regions[i].ratio;
    if (ratio < TAS57XX_HF1_DRC_RATIO_MIN ||
        ratio > TAS57XX_HF1_DRC_RATIO_MAX) {
      return ESP_ERR_INVALID_ARG;
    }
    const float slope =
        regions[i].mode == TAS57XX_HF1_DRC_EXPAND ? ratio : 1.0f / ratio;
    w[i] = hf1_q23_unit((slope - 1.0f) / 4.0f);
  }
  w[TAS57XX_HF1_DRC_REGIONS] = hf1_q23_unit(-thresh1_db / 128.0f);
  w[TAS57XX_HF1_DRC_REGIONS + 1] = hf1_q23_unit(-thresh2_db / 128.0f);
  return tas57xx_cram_write(sink, HF1_DRC_CURVE_WORD, w,
                            TAS57XX_HF1_DRC_REGIONS + 2);
}

esp_err_t tas57xx_hf1_set_smooth_clip(const tas57xx_cram_sink_t *sink,
                                      float threshold_db) {
  if (threshold_db < -78.0f || threshold_db > 0.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  const float t = powf(10.0f, threshold_db / 20.0f);
  /* The threshold and its reciprocal, padded by 1/2 and 2^-13. */
  int32_t w[2] = {hf1_q23(t / 2.0f), hf1_q23(0.0001220703125f / t)};
  return tas57xx_cram_write(sink, HF1_SMOOTH_CLIP_WORD, w, 2);
}

esp_err_t tas57xx_hf1_set_fine_volume(const tas57xx_cram_sink_t *sink,
                                      float gain_db) {
  if (gain_db < TAS57XX_HF1_FINE_VOL_MIN_DB ||
      gain_db > TAS57XX_HF1_FINE_VOL_MAX_DB) {
    return ESP_ERR_INVALID_ARG;
  }
  /* Padded by 1/2, the same way the smooth-clip threshold is. */
  int32_t w = hf1_q23(powf(10.0f, gain_db / 20.0f) / 2.0f);
  return tas57xx_cram_write(sink, HF1_FINE_VOLUME_WORD, &w, 1);
}

esp_err_t tas57xx_hf1_set_dbe_mix(const tas57xx_cram_sink_t *sink,
                                  float lower_db, float upper_db) {
  if (lower_db < -60.0f || lower_db > -10.0f || upper_db < -24.0f ||
      upper_db > 0.0f || upper_db - lower_db < 3.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  /* The two thresholds reach the mixer at different offsets: 5 dB and 4 dB,
   * the same pair HF3 uses. Measured from captures entered as -31/-10, which
   * store exactly -36 and -14 dBFS. */
  const float lower = powf(10.0f, (lower_db - 5.0f) / 20.0f);
  const float scale =
      0.03125f / (powf(10.0f, (upper_db - 4.0f) / 20.0f) - lower);
  if (scale > 1.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w[2] = {hf1_q23(-lower), hf1_q23(scale)};
  return tas57xx_cram_write(sink, HF1_DBE_MIX_WORD, w, 2);
}

void tas57xx_hf1_defaults(tas57xx_hf1_config_t *cfg) {
  if (!cfg) {
    return;
  }
  memset(cfg, 0, sizeof(*cfg));
  cfg->magic = TAS57XX_HF1_CONFIG_MAGIC;
  cfg->version = TAS57XX_HF1_CONFIG_VERSION;
  cfg->sample_rate_hz = 44100;

  for (int i = 0; i < TAS57XX_HF1_EQ_BANDS; i++) {
    cfg->eq[i].type = TAS57XX_BQ_BYPASS;
    cfg->eq[i].subtype = TAS57XX_BQ_SUB_BUTTERWORTH_2;
    cfg->eq[i].freq_hz = 1000.0f;
    cfg->eq[i].q = 0.707f;
  }
  for (int i = 0; i < TAS57XX_HF1_DBE_EQ_BANDS; i++) {
    cfg->dbe_high[i].type = TAS57XX_BQ_BYPASS;
    cfg->dbe_high[i].subtype = TAS57XX_BQ_SUB_BUTTERWORTH_2;
    cfg->dbe_high[i].freq_hz = 1000.0f;
    cfg->dbe_high[i].q = 0.707f;
    cfg->dbe_low[i] = cfg->dbe_high[i];
  }

  cfg->pbe.hpf_hz = 80.0f;
  cfg->pbe.harmonic = 0;
  cfg->pbe.effect = 3;
  cfg->pbe_enabled = true;

  cfg->dbe_lower_db = -40.0f;
  cfg->dbe_upper_db = -20.0f;
  cfg->sense_lower_hz = 50.0f;
  cfg->sense_upper_hz = 200.0f;
  cfg->sense_window_ms = 100.0f;

  /* Complementary Linkwitz-Riley at the band edges SLAU577A 12.5.3 asks for
   * (low below 300 Hz, mid to 5 kHz, high above): with the mid inverted by the
   * mixer this sums back to flat. */
  const tas57xx_bq_t cross[TAS57XX_HF1_DRC_CROSS_SECTIONS] = {
      {.type = TAS57XX_BQ_LOWPASS,
       .subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2,
       .freq_hz = 300.0f,
       .q = 0.5f},
      {.type = TAS57XX_BQ_LOWPASS,
       .subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2,
       .freq_hz = 5000.0f,
       .q = 0.5f},
      {.type = TAS57XX_BQ_HIGHPASS,
       .subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2,
       .freq_hz = 300.0f,
       .q = 0.5f},
      {.type = TAS57XX_BQ_HIGHPASS,
       .subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2,
       .freq_hz = 5000.0f,
       .q = 0.5f},
  };
  memcpy(cfg->drc_cross, cross, sizeof(cross));
  cfg->drc_mix[TAS57XX_HF1_DRC_LOW] = 1.0f;
  cfg->drc_mix[TAS57XX_HF1_DRC_MID] = -1.0f;
  cfg->drc_mix[TAS57XX_HF1_DRC_HIGH] = 1.0f;
  /* SLAU577A Table 3, "fast" column, against each band's lowest frequency:
   * energy 5/fmin, attack 2/fmin, decay 10/fmin, with fmin 20 Hz, 300 Hz and
   * 5 kHz. */
  const tas57xx_hf1_drc_timing_t timing[TAS57XX_HF1_DRC_BANDS] = {
      {250.0f, 100.0f, 500.0f},
      {16.7f, 6.7f, 33.3f},
      {1.0f, 0.4f, 2.0f},
  };
  memcpy(cfg->drc_timing, timing, sizeof(timing));
  /* SLAU577A 12.5.1 soft power limit: 1:1 until a little under the rated
   * level, a mild ratio to it, then as hard a one as this flow can express
   * (TI asks for 25:1 or more; the coefficient stops at 5:1). Full scale is
   * assumed to be the rated level, which is only true at maximum volume. */
  cfg->drc_region[0].mode = TAS57XX_HF1_DRC_COMPRESS;
  cfg->drc_region[0].ratio = 1.0f;
  cfg->drc_region[1].mode = TAS57XX_HF1_DRC_COMPRESS;
  cfg->drc_region[1].ratio = 2.0f;
  cfg->drc_region[2].mode = TAS57XX_HF1_DRC_COMPRESS;
  cfg->drc_region[2].ratio = 5.0f;
  cfg->drc_thresh1_db = -2.0f;
  cfg->drc_thresh2_db = -1.0f;

  cfg->smooth_clip_db = 0.0f;
  cfg->fine_volume_db = 0.0f;
}

/** Keep the first failure but let the rest of the chain be programmed. */
static void hf1_keep(esp_err_t *first, esp_err_t err, const char *what) {
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "%s rejected: %s", what, esp_err_to_name(err));
    if (*first == ESP_OK) {
      *first = err;
    }
  }
}

esp_err_t tas57xx_hf1_validate(const tas57xx_hf1_config_t *cfg) {
  tas57xx_cram_sink_t sink = {.dry_run = true};
  return tas57xx_hf1_apply(&sink, cfg);
}

/* ---- reading a tuning back out of a flow image ------------------------ */

/**
 * 0x800000 is a legitimate -1.0: it is what PPC2 emits for a fully inverted
 * mixer. Scaling by Q23_ONE overshoots that one code, so clamp instead of
 * handing back a value the writers would reject as out of range.
 */
static float hf1_unq23(int32_t w) {
  float v = (float)w / Q23_ONE;
  return v < -1.0f ? -1.0f : v;
}
static float hf1_unq23_unit(int32_t w) {
  return (float)w / 8388608.0f;
}

static void hf1_read_bq(const uint8_t *img, size_t size, int word,
                        uint32_t sample_rate_hz, tas57xx_bq_t *bq) {
  int32_t s[TAS57XX_BQ_WORDS];
  if (tas57xx_cram_read_image(img, size, word, s, TAS57XX_BQ_WORDS) == ESP_OK) {
    tas57xx_bq_unpack(s, TAS57XX_BQ_NUM_FIRST, sample_rate_hz, bq);
  }
}

/** Invert the one-pole smoother back to a time constant in milliseconds. */
static float hf1_read_time(int32_t w, int constants, uint32_t sample_rate_hz) {
  const float y = hf1_unq23_unit(w);
  if (!(y > 0.0f) || y >= 1.0f) {
    return 0.0f;
  }
  const float n = -log1pf(-y);
  return n > 0.0f ? (float)constants * 1000.0f / ((float)sample_rate_hz * n)
                  : 0.0f;
}

/**
 * The bass enhancer's corner is carried by every section it drives, so it is
 * read from the extraction high-pass, whose alpha gives the design frequency
 * directly. Effect intensity is then whichever tabulated pole ratio the shelf
 * lands nearest.
 */
static void hf1_read_pbe(const uint8_t *img, size_t size,
                         uint32_t sample_rate_hz, tas57xx_hf1_config_t *cfg) {
  const float fs = (float)sample_rate_hz;
  int32_t s[TAS57XX_BQ_WORDS];

  if (tas57xx_cram_read_image(img, size, hf1_pbe_extract[0].word, s,
                              TAS57XX_BQ_WORDS) == ESP_OK) {
    const float a2 = -hf1_unq23(s[1]);
    const float alpha = (1.0f + a2) != 0.0f ? (1.0f - a2) / (1.0f + a2) : 0.0f;
    const float arg = 2.0f * hf1_pbe_extract[0].q * alpha;
    if (arg > 0.0f && arg < 1.0f) {
      const float f0 = asinf(arg) * fs / (2.0f * (float)M_PI);
      /* The extraction ratios are fitted, not exact, so the inverse lands a
       * few hundredths of a Hz off a corner that was entered as a whole
       * number. Round to where the tuner would recognise it. */
      cfg->pbe.hpf_hz = roundf(f0 / hf1_pbe_extract[0].ratio * 10.0f) / 10.0f;
    }
  }

  if (tas57xx_cram_read_image(img, size, HF1_PBE_EFFECT_WORD, s,
                              TAS57XX_BQ_WORDS) == ESP_OK &&
      cfg->pbe.hpf_hz > 0.0f) {
    const float a1 = -2.0f * hf1_unq23(s[0]);
    const float a2 = -hf1_unq23(s[1]);
    float cw = (1.0f + a2) != 0.0f ? -a1 / (1.0f + a2) : 1.0f;
    if (cw > 1.0f) {
      cw = 1.0f;
    } else if (cw < -1.0f) {
      cw = -1.0f;
    }
    const float ratio = acosf(cw) * fs / (2.0f * (float)M_PI) / cfg->pbe.hpf_hz;
    float best = 1e9f;
    for (int i = 0; i < TAS57XX_HF1_PBE_EFFECT_MAX; i++) {
      const float d = fabsf(hf1_pbe_effect[i].pole_ratio - ratio);
      if (d < best) {
        best = d;
        cfg->pbe.effect = i + TAS57XX_HF1_PBE_EFFECT_MIN;
      }
    }
  }

  int32_t w;
  if (tas57xx_cram_read_image(img, size, HF1_PBE_HARMONIC_WORD, &w, 1) ==
      ESP_OK) {
    const float v = hf1_unq23(w);
    int h = v > 0.0f ? (int)lrintf((20.0f * log10f(v) + 50.0f) / 0.5f) : 0;
    if (h < 0) {
      h = 0;
    } else if (h > TAS57XX_HF1_PBE_HARMONIC_MAX) {
      h = TAS57XX_HF1_PBE_HARMONIC_MAX;
    }
    cfg->pbe.harmonic = h;
  }
  if (tas57xx_cram_read_image(img, size, HF1_PBE_MIX_WORD, &w, 1) == ESP_OK) {
    cfg->pbe_enabled = hf1_unq23_unit(w) >= 0.5f;
  }
}

esp_err_t tas57xx_hf1_read(const uint8_t *img, size_t size,
                           uint32_t sample_rate_hz, tas57xx_hf1_config_t *cfg) {
  if (!img || !cfg || size < 2) {
    return ESP_ERR_INVALID_ARG;
  }
  tas57xx_hf1_defaults(cfg);
  cfg->sample_rate_hz = sample_rate_hz;

  for (int i = 0; i < TAS57XX_HF1_EQ_BANDS; i++) {
    hf1_read_bq(img, size, hf1_eq_slots[i], sample_rate_hz, &cfg->eq[i]);
  }
  for (int i = 0; i < TAS57XX_HF1_DBE_EQ_BANDS; i++) {
    hf1_read_bq(img, size, hf1_dbe_eq_slots[i], sample_rate_hz,
                &cfg->dbe_high[i]);
    hf1_read_bq(img, size, hf1_dbe_ll_eq_slots[i], sample_rate_hz,
                &cfg->dbe_low[i]);
  }
  for (int i = 0; i < TAS57XX_HF1_DRC_CROSS_SECTIONS; i++) {
    hf1_read_bq(img, size, hf1_drc_cross_slots[i], sample_rate_hz,
                &cfg->drc_cross[i]);
  }

  hf1_read_pbe(img, size, sample_rate_hz, cfg);

  int32_t w[6];
  if (tas57xx_cram_read_image(img, size, HF1_DBE_MIX_WORD, w, 2) == ESP_OK) {
    const float lower = -hf1_unq23(w[0]);
    const float scale = hf1_unq23(w[1]);
    if (lower > 0.0f && scale > 0.0f) {
      cfg->dbe_lower_db = 20.0f * log10f(lower) + 5.0f;
      cfg->dbe_upper_db = 20.0f * log10f(lower + 0.03125f / scale) + 4.0f;
    }
  }

  /* Unlike HF3's first-order sensing filter, this one is a bandpass, so both
   * edges come back: the pole pair gives the geometric centre and Q, which the
   * encoder built from exactly those two numbers. */
  if (tas57xx_cram_read_image(img, size, HF1_SENSING_BAND_WORD, w,
                              TAS57XX_BQ_WORDS) == ESP_OK) {
    tas57xx_bq_t band;
    tas57xx_bq_unpack(w, TAS57XX_BQ_NUM_FIRST, sample_rate_hz, &band);
    if (band.freq_hz > 0.0f && band.q > 0.0f) {
      const float inv = 1.0f / (2.0f * band.q);
      cfg->sense_lower_hz = band.freq_hz * (sqrtf(inv * inv + 1.0f) - inv);
      cfg->sense_upper_hz = cfg->sense_lower_hz + band.freq_hz / band.q;
    }
  }

  int32_t one;
  if (tas57xx_cram_read_image(img, size, HF1_ENERGY_WINDOW_WORD, &one, 1) ==
      ESP_OK) {
    const float v = hf1_unq23(one);
    if (v > 0.0f) {
      cfg->sense_window_ms = 1000.0f / (v * (float)sample_rate_hz);
    }
  }

  if (tas57xx_cram_read_image(img, size, HF1_DRC_MIX_WORD, w,
                              TAS57XX_HF1_DRC_BANDS) == ESP_OK) {
    for (int i = 0; i < TAS57XX_HF1_DRC_BANDS; i++) {
      cfg->drc_mix[i] = hf1_unq23(w[i]);
    }
  }

  for (int band = 0; band < TAS57XX_HF1_DRC_BANDS; band++) {
    if (tas57xx_cram_read_image(img, size, HF1_DRC_TIMING_WORD + band * 6, w,
                                6) != ESP_OK) {
      continue;
    }
    const float t[3] = {hf1_read_time(w[0], 1, sample_rate_hz),
                        hf1_read_time(w[2], 3, sample_rate_hz),
                        hf1_read_time(w[4], 3, sample_rate_hz)};
    if (t[0] > 0.0f) {
      cfg->drc_timing[band].energy_ms = t[0];
    }
    if (t[1] > 0.0f) {
      cfg->drc_timing[band].attack_ms = t[1];
    }
    if (t[2] > 0.0f) {
      cfg->drc_timing[band].decay_ms = t[2];
    }
  }

  if (tas57xx_cram_read_image(img, size, HF1_DRC_CURVE_WORD, w,
                              TAS57XX_HF1_DRC_REGIONS + 2) == ESP_OK) {
    for (int i = 0; i < TAS57XX_HF1_DRC_REGIONS; i++) {
      const float slope = 4.0f * hf1_unq23_unit(w[i]) + 1.0f;
      if (slope > 1.0f) {
        cfg->drc_region[i].mode = TAS57XX_HF1_DRC_EXPAND;
        cfg->drc_region[i].ratio = slope;
      } else if (slope > 0.0f) {
        cfg->drc_region[i].mode = TAS57XX_HF1_DRC_COMPRESS;
        cfg->drc_region[i].ratio = 1.0f / slope;
      }
    }
    cfg->drc_thresh1_db = -128.0f * hf1_unq23_unit(w[TAS57XX_HF1_DRC_REGIONS]);
    cfg->drc_thresh2_db =
        -128.0f * hf1_unq23_unit(w[TAS57XX_HF1_DRC_REGIONS + 1]);
  }

  if (tas57xx_cram_read_image(img, size, HF1_SMOOTH_CLIP_WORD, w, 2) ==
      ESP_OK) {
    const float t = 2.0f * hf1_unq23(w[0]);
    // Rounding can put an untouched limiter a hair above 0 dB, which apply()
    // would then refuse.
    if (t > 0.0f) {
      const float db = 20.0f * log10f(t);
      cfg->smooth_clip_db = db > 0.0f ? 0.0f : (db < -78.0f ? -78.0f : db);
    }
  }
  if (tas57xx_cram_read_image(img, size, HF1_FINE_VOLUME_WORD, &one, 1) ==
      ESP_OK) {
    const float g = 2.0f * hf1_unq23(one);
    if (g > 0.0f) {
      const float db = 20.0f * log10f(g);
      cfg->fine_volume_db =
          db > TAS57XX_HF1_FINE_VOL_MAX_DB
              ? TAS57XX_HF1_FINE_VOL_MAX_DB
              : (db < TAS57XX_HF1_FINE_VOL_MIN_DB ? TAS57XX_HF1_FINE_VOL_MIN_DB
                                                  : db);
    }
  }
  return ESP_OK;
}

esp_err_t tas57xx_hf1_apply(tas57xx_cram_sink_t *sink,
                            const tas57xx_hf1_config_t *cfg) {
  if (!sink || !cfg) {
    return ESP_ERR_INVALID_ARG;
  }
  if (cfg->magic != TAS57XX_HF1_CONFIG_MAGIC ||
      cfg->version != TAS57XX_HF1_CONFIG_VERSION) {
    return ESP_ERR_INVALID_VERSION;
  }
  const uint32_t fs = cfg->sample_rate_hz;
  esp_err_t first = tas57xx_cram_begin(sink);
  if (first != ESP_OK) {
    return first;
  }

  for (int i = 0; i < TAS57XX_HF1_EQ_BANDS; i++) {
    hf1_keep(&first, tas57xx_hf1_set_eq_band(sink, i, &cfg->eq[i], fs), "EQ");
  }
  hf1_keep(&first, tas57xx_hf1_set_pbe(sink, &cfg->pbe, fs), "PBE");
  hf1_keep(&first, tas57xx_hf1_set_pbe_enabled(sink, cfg->pbe_enabled),
           "PBE enable");

  for (int i = 0; i < TAS57XX_HF1_DBE_EQ_BANDS; i++) {
    hf1_keep(&first,
             tas57xx_hf1_set_dbe_hl_eq_band(sink, i, &cfg->dbe_high[i], fs),
             "DBE high EQ");
    hf1_keep(&first,
             tas57xx_hf1_set_dbe_ll_eq_band(sink, i, &cfg->dbe_low[i], fs),
             "DBE low EQ");
  }
  hf1_keep(&first,
           tas57xx_hf1_set_dbe_mix(sink, cfg->dbe_lower_db, cfg->dbe_upper_db),
           "DBE mix");
  hf1_keep(&first,
           tas57xx_hf1_set_sensing_band(sink, cfg->sense_lower_hz,
                                        cfg->sense_upper_hz, fs),
           "sensing band");
  hf1_keep(&first,
           tas57xx_hf1_set_energy_window(sink, cfg->sense_window_ms, fs),
           "energy window");

  hf1_keep(&first, tas57xx_hf1_set_drc_crossover(sink, cfg->drc_cross, fs),
           "DRC crossover");
  hf1_keep(&first, tas57xx_hf1_set_drc_mix(sink, cfg->drc_mix), "DRC mix");
  for (int i = 0; i < TAS57XX_HF1_DRC_BANDS; i++) {
    hf1_keep(&first,
             tas57xx_hf1_set_drc_timing(sink, i, &cfg->drc_timing[i], fs),
             "DRC timing");
  }
  hf1_keep(&first,
           tas57xx_hf1_set_drc_curve(sink, cfg->drc_region, cfg->drc_thresh1_db,
                                     cfg->drc_thresh2_db),
           "DRC curve");

  hf1_keep(&first, tas57xx_hf1_set_smooth_clip(sink, cfg->smooth_clip_db),
           "smooth clip");
  hf1_keep(&first, tas57xx_hf1_set_fine_volume(sink, cfg->fine_volume_db),
           "fine volume");

  // A half-written tuning is worse than none: one swap, or nothing.
  if (first != ESP_OK) {
    tas57xx_cram_abort(sink);
    return first;
  }
  return tas57xx_cram_commit(sink);
}
