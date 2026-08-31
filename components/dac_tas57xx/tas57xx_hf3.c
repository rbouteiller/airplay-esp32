#include "tas57xx_hf3.h"

#include <math.h>
#include <string.h>

#include "esp_log.h"

static const char *TAG = "tas57xx_hf3";

/** Coefficient RAM slot holding the harmonic generator's drive scalar. */
#define HF3_PBE_HARMONIC_WORD 2
/** First word of the effect-intensity shelf, stored denominator-first. */
#define HF3_PBE_EFFECT_WORD 8
/** Bypass crossfade around the bass enhancer: dry gain, then wet. */
#define HF3_PBE_MIX_WORD 227
/** Compander band splits: the low band's low-pass, then the high band's
 *  high-pass. The mid band is whatever those two leave behind. */
#define HF3_DRC_SPLIT_LOW_WORD  28
#define HF3_DRC_SPLIT_HIGH_WORD 33
/** Mixer gains for the low and mid bands; the high band is fixed at unity, and
 *  the flow ships the mid at -1, which is what makes the split recombine
 *  flat. */
#define HF3_DRC_MIX_LOW_WORD 38
#define HF3_DRC_MIX_MID_WORD 39
/** DBE crossfade: lower threshold, then the reciprocal of the span. */
#define HF3_DBE_MIX_WORD 69
/** Reciprocal of the energy estimator's averaging window, in samples. */
#define HF3_ENERGY_WINDOW_WORD 71
/** High-pass the energy estimator listens through. */
#define HF3_SENSING_BAND_WORD 98
/** Compander detectors: 3 bands x (energy, attack, decay), each a word pair. */
#define HF3_DRC_TIMING_WORD 118
/** Compander curve: 3 region slopes, then the 2 thresholds splitting them. */
#define HF3_DRC_CURVE_WORD 136
/** Five fixed delay taps for the mid/high way, longest first. */
#define HF3_DELAY_WORD 196
/** Output limiter threshold, stored with a 1/2 headroom pad. */
#define HF3_SMOOTH_CLIP_WORD 251

#define Q23_ONE 8388607.0f

/** Crossover slot, then the four tunable sections, for each way. */
static const int hf3_way_cross_slots[TAS57XX_HF3_WAYS] = {43, 72};
static const int hf3_way_eq_slots[TAS57XX_HF3_WAYS][TAS57XX_HF3_EQ_BANDS] = {
    {48, 53, 58, 63},
    {77, 82, 87, 92},
};
/** Input mixer gain pair, left then right, for each way. */
static const int hf3_way_mix_slots[TAS57XX_HF3_WAYS] = {206, 201};

static const int hf3_dbe_hl_slots[TAS57XX_HF3_DBE_HL_BANDS] = {108, 113};
static const int hf3_dbe_ll_slots[TAS57XX_HF3_DBE_LL_BANDS] = {212, 217, 222};

/**
 * The bass enhancer is HF1's block relocated by -149. Fitted from captures at
 * 60, 70 and 180 Hz by recovering alpha from a2, which pins the ratio/Q product
 * to five figures; the split between the two is far weaker, so where a
 * textbook alignment sits inside the noise it is used.
 *
 * The extraction network turns out to be a Butterworth 2 at 0.6014 of the
 * corner feeding a Butterworth 3 at exactly twice that, which is why LP2 and
 * LP3 share a frequency. Do not "tidy" these into round numbers.
 */
static const struct {
  int word;
  tas57xx_bq_type_t type;
  tas57xx_bq_subtype_t subtype;
  float ratio;
  float q;
} hf3_pbe_extract[] = {
    {3, TAS57XX_BQ_HIGHPASS, TAS57XX_BQ_SUB_VARIABLE_Q_2, 0.19420f, 0.569207f},
    {13, TAS57XX_BQ_LOWPASS, TAS57XX_BQ_SUB_VARIABLE_Q_2, 0.6013585f,
     0.7071237f},
    {18, TAS57XX_BQ_LOWPASS, TAS57XX_BQ_SUB_VARIABLE_Q_2, 1.202717f, 1.0f},
    {23, TAS57XX_BQ_LOWPASS, TAS57XX_BQ_SUB_BUTTERWORTH_1, 1.202717f, 1.0f},
};

/**
 * Effect intensity selects a shelf whose pole pair and real zero both track the
 * HPF corner. There are only five settings, so the design parameters are
 * tabulated rather than derived.
 */
static const struct {
  float pole_ratio;
  float pole_q;
  float zero_ratio;
} hf3_pbe_effect[TAS57XX_HF3_PBE_EFFECT_MAX] = {
    {0.18901f, 0.5230727f, 0.267172f}, {0.46708f, 1.1324f, 0.66942f},
    {0.48703f, 1.4195f, 0.90321f},     {0.49383f, 1.6511f, 1.08794f},
    {0.49600f, 1.8494f, 1.24322f},
};

static int32_t hf3_q23(float v) {
  float s = v * Q23_ONE;
  if (s > Q23_ONE) {
    s = Q23_ONE;
  } else if (s < -Q23_ONE - 1.0f) {
    s = -Q23_ONE - 1.0f;
  }
  return (int32_t)lrintf(s);
}

/**
 * Gains and detector coefficients scale unity to 2^23, not the 2^23-1 filter
 * coefficients use. Only a non-dyadic value tells the two apart: the captured
 * 0.707 band gain is round(0.707 * 2^23), one LSB above the other convention.
 */
static int32_t hf3_q23_unit(float v) {
  float s = v * 8388608.0f;
  if (s > Q23_ONE) {
    s = Q23_ONE;
  } else if (s < -Q23_ONE) {
    s = -Q23_ONE;
  }
  return (int32_t)lrintf(s);
}

/** Store a direct-form biquad in the denominator-first layout the PBE uses. */
static void hf3_pack_den_first(float b0, float b1, float b2, float a1, float a2,
                               int32_t out[TAS57XX_BQ_WORDS]) {
  out[0] = hf3_q23(-a1 / 2.0f);
  out[1] = hf3_q23(-a2);
  out[2] = hf3_q23(b0 / 2.0f);
  out[3] = hf3_q23(b1 / 4.0f);
  out[4] = hf3_q23(b2 / 2.0f);
}

/**
 * Detector coefficients are one-pole smoothers stored as the pair (a, 1-a).
 * Attack and decay are specified as a settling time of three time constants;
 * the energy window is a single one.
 *
 * Every useful time constant is far longer than a sample, so the exponent is
 * small and 1 - exp(-n) loses most of its significant digits to cancellation.
 * expm1 keeps them, which is worth a whole LSB here.
 */
static int32_t hf3_smoother(float ms, int constants, uint32_t sample_rate_hz) {
  const float n = (float)constants * 1000.0f / ((float)sample_rate_hz * ms);
  int32_t c = (int32_t)lrintf(-expm1f(-n) * 8388608.0f);
  if (c < 1) {
    c = 1;
  } else if (c > 0x7FFFFF) {
    c = 0x7FFFFF;
  }
  return c;
}

static void hf3_time_pair(float ms, int constants, uint32_t sample_rate_hz,
                          int32_t out[2]) {
  out[0] = hf3_smoother(ms, constants, sample_rate_hz);
  out[1] = 0x800000 - out[0];
}

static esp_err_t hf3_write_pbe_harmonic(const tas57xx_cram_sink_t *sink,
                                        int harmonic) {
  /* 0 mutes outright; 1-100 maps linearly onto -49.5 .. 0 dB in 0.5 dB steps.
   */
  int32_t word = harmonic <= 0
                     ? 0
                     : hf3_q23(powf(10.0f, (0.5f * harmonic - 50.0f) / 20.0f));
  return tas57xx_cram_write(sink, HF3_PBE_HARMONIC_WORD, &word, 1);
}

static esp_err_t hf3_write_pbe_effect(const tas57xx_cram_sink_t *sink,
                                      int effect, float hpf_hz,
                                      uint32_t sample_rate_hz) {
  const float fs = (float)sample_rate_hz;
  const int idx = effect - TAS57XX_HF3_PBE_EFFECT_MIN;
  const float w =
      2.0f * (float)M_PI * hf3_pbe_effect[idx].pole_ratio * hpf_hz / fs;
  const float alpha = sinf(w) / (2.0f * hf3_pbe_effect[idx].pole_q);
  const float a0 = 1.0f + alpha;

  /* One zero pinned at DC, one real zero tracking the corner. The numerator
   * carries the same (1+cos w)/2 scaling a high-pass would; leaving it out
   * costs 50 LSB by 70 Hz and grows with the square of the corner. */
  const float b0 = (1.0f + cosf(w)) / (2.0f * a0);
  const float b2 = b0 * expf(-2.0f * (float)M_PI *
                             hf3_pbe_effect[idx].zero_ratio * hpf_hz / fs);

  int32_t c[TAS57XX_BQ_WORDS];
  hf3_pack_den_first(b0, -(b0 + b2), b2, -2.0f * cosf(w) / a0,
                     (1.0f - alpha) / a0, c);
  return tas57xx_cram_write(sink, HF3_PBE_EFFECT_WORD, c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_way_input(const tas57xx_cram_sink_t *sink, int way,
                                    const float gain[2]) {
  if (way < 0 || way >= TAS57XX_HF3_WAYS || !gain) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w[2];
  for (int i = 0; i < 2; i++) {
    if (!(gain[i] >= -1.0f && gain[i] <= 1.0f)) {
      return ESP_ERR_INVALID_ARG;
    }
    w[i] = hf3_q23_unit(gain[i]);
  }
  return tas57xx_cram_write(sink, hf3_way_mix_slots[way], w, 2);
}

esp_err_t tas57xx_hf3_set_way_crossover(const tas57xx_cram_sink_t *sink,
                                        int way, const tas57xx_bq_t *bq,
                                        uint32_t sample_rate_hz) {
  if (way < 0 || way >= TAS57XX_HF3_WAYS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, hf3_way_cross_slots[way], c,
                            TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_way_eq_band(const tas57xx_cram_sink_t *sink, int way,
                                      int band, const tas57xx_bq_t *bq,
                                      uint32_t sample_rate_hz) {
  if (way < 0 || way >= TAS57XX_HF3_WAYS || band < 0 ||
      band >= TAS57XX_HF3_EQ_BANDS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  float makeup = tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  if (makeup < -0.01f) {
    ESP_LOGD(TAG, "way %d band %d needs %.2f dB of make-up gain", way, band,
             -makeup);
  }
  return tas57xx_cram_write(sink, hf3_way_eq_slots[way][band], c,
                            TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_high_delay(const tas57xx_cram_sink_t *sink,
                                     int samples) {
  if (samples < 0 || samples > TAS57XX_HF3_DELAY_MAX ||
      samples % TAS57XX_HF3_DELAY_STEP != 0) {
    return ESP_ERR_INVALID_ARG;
  }
  /* One tap of five is selected by putting unity in its word; the taps run
   * longest first, so the slot counts down from the maximum. */
  const int slot = (TAS57XX_HF3_DELAY_MAX - samples) / TAS57XX_HF3_DELAY_STEP;
  int32_t w[5] = {0};
  w[slot] = hf3_q23_unit(1.0f);
  return tas57xx_cram_write(sink, HF3_DELAY_WORD, w, 5);
}

esp_err_t tas57xx_hf3_set_pbe(const tas57xx_cram_sink_t *sink,
                              const tas57xx_hf3_pbe_t *pbe,
                              uint32_t sample_rate_hz) {
  if (!pbe || pbe->hpf_hz < TAS57XX_HF3_PBE_HPF_MIN_HZ ||
      pbe->hpf_hz > TAS57XX_HF3_PBE_HPF_MAX_HZ || pbe->harmonic < 0 ||
      pbe->harmonic > TAS57XX_HF3_PBE_HARMONIC_MAX ||
      pbe->effect < TAS57XX_HF3_PBE_EFFECT_MIN ||
      pbe->effect > TAS57XX_HF3_PBE_EFFECT_MAX) {
    return ESP_ERR_INVALID_ARG;
  }
  for (size_t i = 0; i < sizeof(hf3_pbe_extract) / sizeof(hf3_pbe_extract[0]);
       i++) {
    tas57xx_bq_t bq = {
        .type = hf3_pbe_extract[i].type,
        .subtype = hf3_pbe_extract[i].subtype,
        .freq_hz = pbe->hpf_hz * hf3_pbe_extract[i].ratio,
        .q = hf3_pbe_extract[i].q,
        .gain_db = 0.0f,
    };
    int32_t c[TAS57XX_BQ_WORDS];
    tas57xx_bq_pack(&bq, sample_rate_hz, TAS57XX_BQ_DEN_FIRST, c);
    esp_err_t err =
        tas57xx_cram_write(sink, hf3_pbe_extract[i].word, c, TAS57XX_BQ_WORDS);
    if (err != ESP_OK) {
      return err;
    }
  }
  esp_err_t err =
      hf3_write_pbe_effect(sink, pbe->effect, pbe->hpf_hz, sample_rate_hz);
  if (err != ESP_OK) {
    return err;
  }
  return hf3_write_pbe_harmonic(sink, pbe->harmonic);
}

esp_err_t tas57xx_hf3_set_pbe_enabled(const tas57xx_cram_sink_t *sink,
                                      bool enabled) {
  // A crossfade, not a flag: 227 carries the processed path, 228 the dry one.
  int32_t w[2] = {hf3_q23_unit(enabled ? 1.0f : 0.0f),
                  hf3_q23_unit(enabled ? 0.0f : 1.0f)};
  return tas57xx_cram_write(sink, HF3_PBE_MIX_WORD, w, 2);
}

esp_err_t tas57xx_hf3_set_dbe_hl_eq_band(const tas57xx_cram_sink_t *sink,
                                         int band, const tas57xx_bq_t *bq,
                                         uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF3_DBE_HL_BANDS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, hf3_dbe_hl_slots[band], c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_dbe_ll_eq_band(const tas57xx_cram_sink_t *sink,
                                         int band, const tas57xx_bq_t *bq,
                                         uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF3_DBE_LL_BANDS || !bq) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, hf3_dbe_ll_slots[band], c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_dbe_mix(const tas57xx_cram_sink_t *sink,
                                  float lower_db, float upper_db) {
  /* The two thresholds reach the mixer at different offsets: 5 dB and 4 dB.
   * Confirmed against a capture whose PPC2 fields read -40 and -15, which
   * stores exactly -45 and -19 dBFS. HF1's flow uses 4 dB for BOTH — that is
   * a single-point measurement there too, so do not unify them blind. */
  const float lower = powf(10.0f, (lower_db - 5.0f) / 20.0f);
  const float span = powf(10.0f, (upper_db - 4.0f) / 20.0f) - lower;
  if (upper_db <= lower_db || span < 0.03125f) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w[2] = {hf3_q23(-lower), hf3_q23(0.03125f / span)};
  return tas57xx_cram_write(sink, HF3_DBE_MIX_WORD, w, 2);
}

esp_err_t tas57xx_hf3_set_sensing_band(const tas57xx_cram_sink_t *sink,
                                       float lower_hz, float upper_hz,
                                       uint32_t sample_rate_hz) {
  if (lower_hz < 10.0f || upper_hz <= lower_hz ||
      upper_hz > (float)sample_rate_hz / 2.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  /* Only the arithmetic centre is stored, truncated to a whole Hz, and only as
   * a high-pass — the tool keeps no record of the band's width. */
  tas57xx_bq_t bq = {
      .type = TAS57XX_BQ_HIGHPASS,
      .subtype = TAS57XX_BQ_SUB_BUTTERWORTH_1,
      .freq_hz = floorf((lower_hz + upper_hz) / 2.0f),
      .q = 1.0f,
  };
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(&bq, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, HF3_SENSING_BAND_WORD, c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_energy_window(const tas57xx_cram_sink_t *sink,
                                        float window_ms,
                                        uint32_t sample_rate_hz) {
  if (window_ms < 1.0f || window_ms > 1000.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t word = hf3_smoother(window_ms, 1, sample_rate_hz);
  return tas57xx_cram_write(sink, HF3_ENERGY_WINDOW_WORD, &word, 1);
}

esp_err_t tas57xx_hf3_set_drc_timing(const tas57xx_cram_sink_t *sink, int band,
                                     const tas57xx_hf3_drc_timing_t *timing,
                                     uint32_t sample_rate_hz) {
  if (band < 0 || band >= TAS57XX_HF3_DRC_BANDS || !timing) {
    return ESP_ERR_INVALID_ARG;
  }
  const float ms[3] = {timing->energy_ms, timing->attack_ms, timing->decay_ms};
  for (int i = 0; i < 3; i++) {
    if (ms[i] < TAS57XX_HF3_DRC_TIME_MIN_MS ||
        ms[i] > TAS57XX_HF3_DRC_TIME_MAX_MS) {
      return ESP_ERR_INVALID_ARG;
    }
  }
  int32_t w[6];
  hf3_time_pair(ms[0], 1, sample_rate_hz, &w[0]);
  hf3_time_pair(ms[1], 3, sample_rate_hz, &w[2]);
  hf3_time_pair(ms[2], 3, sample_rate_hz, &w[4]);
  return tas57xx_cram_write(sink, HF3_DRC_TIMING_WORD + band * 6, w, 6);
}

esp_err_t tas57xx_hf3_set_drc_split(const tas57xx_cram_sink_t *sink,
                                    const tas57xx_bq_t *low,
                                    const tas57xx_bq_t *high,
                                    uint32_t sample_rate_hz) {
  if (!low || !high) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t c[TAS57XX_BQ_WORDS];
  tas57xx_bq_pack(low, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  esp_err_t err =
      tas57xx_cram_write(sink, HF3_DRC_SPLIT_LOW_WORD, c, TAS57XX_BQ_WORDS);
  if (err != ESP_OK) {
    return err;
  }
  tas57xx_bq_pack(high, sample_rate_hz, TAS57XX_BQ_NUM_FIRST, c);
  return tas57xx_cram_write(sink, HF3_DRC_SPLIT_HIGH_WORD, c, TAS57XX_BQ_WORDS);
}

esp_err_t tas57xx_hf3_set_drc_mix(const tas57xx_cram_sink_t *sink, float low,
                                  float mid) {
  if (!(low >= TAS57XX_HF3_DRC_MIX_MIN && low <= TAS57XX_HF3_DRC_MIX_MAX) ||
      !(mid >= TAS57XX_HF3_DRC_MIX_MIN && mid <= TAS57XX_HF3_DRC_MIX_MAX)) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w = hf3_q23_unit(low);
  esp_err_t err = tas57xx_cram_write(sink, HF3_DRC_MIX_LOW_WORD, &w, 1);
  if (err != ESP_OK) {
    return err;
  }
  w = hf3_q23_unit(mid);
  return tas57xx_cram_write(sink, HF3_DRC_MIX_MID_WORD, &w, 1);
}

/**
 * The level metric the curve works in is dB/128, so thresholds are stored
 * negated and scaled. Slopes are stored as a quarter of the deviation from
 * unity gain, which leaves room for the full 0.2 to 5.0 ratio range.
 */
esp_err_t tas57xx_hf3_set_drc_curve(
    const tas57xx_cram_sink_t *sink,
    const tas57xx_hf3_drc_region_t regions[TAS57XX_HF3_DRC_REGIONS],
    float thresh1_db, float thresh2_db) {
  if (!regions || thresh1_db < -120.0f || thresh2_db > 0.0f ||
      thresh2_db <= thresh1_db) {
    return ESP_ERR_INVALID_ARG;
  }
  int32_t w[TAS57XX_HF3_DRC_REGIONS + 2];
  for (int i = 0; i < TAS57XX_HF3_DRC_REGIONS; i++) {
    const float ratio = regions[i].ratio;
    if (ratio < TAS57XX_HF3_DRC_RATIO_MIN ||
        ratio > TAS57XX_HF3_DRC_RATIO_MAX) {
      return ESP_ERR_INVALID_ARG;
    }
    const float slope =
        regions[i].mode == TAS57XX_HF3_DRC_EXPAND ? ratio : 1.0f / ratio;
    w[i] = hf3_q23_unit((slope - 1.0f) / 4.0f);
  }
  w[TAS57XX_HF3_DRC_REGIONS] = hf3_q23_unit(-thresh1_db / 128.0f);
  w[TAS57XX_HF3_DRC_REGIONS + 1] = hf3_q23_unit(-thresh2_db / 128.0f);
  return tas57xx_cram_write(sink, HF3_DRC_CURVE_WORD, w,
                            TAS57XX_HF3_DRC_REGIONS + 2);
}

esp_err_t tas57xx_hf3_set_smooth_clip(const tas57xx_cram_sink_t *sink,
                                      float threshold_db) {
  if (threshold_db < -78.0f || threshold_db > 0.0f) {
    return ESP_ERR_INVALID_ARG;
  }
  const float t = powf(10.0f, threshold_db / 20.0f);
  /* The threshold and its reciprocal, padded by 1/2 and 2^-13. */
  int32_t w[2] = {hf3_q23_unit(t / 2.0f), hf3_q23_unit(1.0f / (t * 8192.0f))};
  return tas57xx_cram_write(sink, HF3_SMOOTH_CLIP_WORD, w, 2);
}

bool tas57xx_hf3_config_migrate(tas57xx_hf3_config_t *cfg) {
  if (cfg == NULL || cfg->magic != TAS57XX_HF3_CONFIG_MAGIC ||
      cfg->version != 2u) {
    return false;
  }
  const tas57xx_bq_t was_first = cfg->drc_split_low;
  cfg->drc_split_low = cfg->drc_split_high;
  cfg->drc_split_high = was_first;
  cfg->version = TAS57XX_HF3_CONFIG_VERSION;
  return true;
}

void tas57xx_hf3_defaults(tas57xx_hf3_config_t *cfg) {
  if (!cfg) {
    return;
  }
  memset(cfg, 0, sizeof(*cfg));
  cfg->magic = TAS57XX_HF3_CONFIG_MAGIC;
  cfg->version = TAS57XX_HF3_CONFIG_VERSION;
  cfg->sample_rate_hz = 44100;

  /* Both ways take the same mono sum; a bi-amped pair drives one speaker. */
  for (int w = 0; w < TAS57XX_HF3_WAYS; w++) {
    cfg->mix[w][0] = 0.5f;
    cfg->mix[w][1] = 0.5f;
    for (int b = 0; b < TAS57XX_HF3_EQ_BANDS; b++) {
      cfg->eq[w][b].type = TAS57XX_BQ_BYPASS;
    }
  }
  cfg->high_delay_samples = 0;

  cfg->crossover[TAS57XX_HF3_WAY_LOW].type = TAS57XX_BQ_LOWPASS;
  cfg->crossover[TAS57XX_HF3_WAY_LOW].subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2;
  cfg->crossover[TAS57XX_HF3_WAY_LOW].freq_hz = 1000.0f;
  cfg->crossover[TAS57XX_HF3_WAY_LOW].q = 0.5f;
  cfg->crossover[TAS57XX_HF3_WAY_HIGH].type = TAS57XX_BQ_HIGHPASS;
  cfg->crossover[TAS57XX_HF3_WAY_HIGH].subtype =
      TAS57XX_BQ_SUB_LINKWITZ_RILEY_2;
  cfg->crossover[TAS57XX_HF3_WAY_HIGH].freq_hz = 1000.0f;
  cfg->crossover[TAS57XX_HF3_WAY_HIGH].q = 0.5f;

  cfg->pbe.hpf_hz = 180.0f;
  cfg->pbe.harmonic = 0;
  cfg->pbe.effect = 1;
  cfg->pbe_enabled = true;

  for (int i = 0; i < TAS57XX_HF3_DBE_HL_BANDS; i++) {
    cfg->dbe_high[i].type = TAS57XX_BQ_BYPASS;
  }
  for (int i = 0; i < TAS57XX_HF3_DBE_LL_BANDS; i++) {
    cfg->dbe_low[i].type = TAS57XX_BQ_BYPASS;
  }
  cfg->dbe_lower_db = -30.0f;
  cfg->dbe_upper_db = -10.0f;
  cfg->sense_lower_hz = 40.0f;
  cfg->sense_upper_hz = 160.0f;
  cfg->sense_window_ms = 100.0f;

  /* Complementary Linkwitz-Riley pair sharing a corner, which is what makes
   * the three bands sum back to unity. The mid band is the leftover, so it
   * comes out as a band-pass peaking at that same corner: move the two edges
   * apart and the mid widens into a real band. */
  cfg->drc_split_low.type = TAS57XX_BQ_LOWPASS;
  cfg->drc_split_low.subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2;
  cfg->drc_split_low.freq_hz = 5000.0f;
  cfg->drc_split_low.q = 0.5f;
  cfg->drc_split_high.type = TAS57XX_BQ_HIGHPASS;
  cfg->drc_split_high.subtype = TAS57XX_BQ_SUB_LINKWITZ_RILEY_2;
  cfg->drc_split_high.freq_hz = 5000.0f;
  cfg->drc_split_high.q = 0.5f;
  cfg->drc_mix_low = 1.0f;
  cfg->drc_mix_mid = -1.0f;

  const tas57xx_hf3_drc_timing_t timing[TAS57XX_HF3_DRC_BANDS] = {
      {100.0f, 50.0f, 150.0f},
      {40.0f, 20.0f, 60.0f},
      {5.0f, 2.5f, 7.5f},
  };
  memcpy(cfg->drc_timing, timing, sizeof(timing));

  for (int i = 0; i < TAS57XX_HF3_DRC_REGIONS; i++) {
    cfg->drc_region[i].mode = TAS57XX_HF3_DRC_COMPRESS;
    cfg->drc_region[i].ratio = 1.0f;
  }
  cfg->drc_thresh1_db = -80.0f;
  cfg->drc_thresh2_db = -20.0f;

  cfg->smooth_clip_db = 0.0f;
}

/** Keep the first failure but let the rest of the chain be programmed. */
static void hf3_keep(esp_err_t *first, esp_err_t err, const char *what) {
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "%s rejected: %s", what, esp_err_to_name(err));
    if (*first == ESP_OK) {
      *first = err;
    }
  }
}

esp_err_t tas57xx_hf3_validate(const tas57xx_hf3_config_t *cfg) {
  tas57xx_cram_sink_t sink = {.dry_run = true};
  return tas57xx_hf3_apply(&sink, cfg);
}

/* ---- reading a tuning back out of a flow image ------------------------ */

/**
 * 0x800000 is a legitimate -1.0: it is what PPC2 emits for a fully inverted
 * mixer. Scaling by Q23_ONE overshoots that one code, so clamp instead of
 * handing back a value the writers would reject as out of range.
 */
static float hf3_unq23(int32_t w) {
  float v = (float)w / Q23_ONE;
  return v < -1.0f ? -1.0f : v;
}
static float hf3_unq23_unit(int32_t w) {
  return (float)w / 8388608.0f;
}

/**
 * Recover a biquad from a slot in the flow image.
 */
static void hf3_read_bq(const uint8_t *img, size_t size, int word,
                        uint32_t sample_rate_hz, tas57xx_bq_t *bq) {
  int32_t s[TAS57XX_BQ_WORDS];
  if (tas57xx_cram_read_image(img, size, word, s, TAS57XX_BQ_WORDS) != ESP_OK) {
    return;
  }
  tas57xx_bq_unpack(s, TAS57XX_BQ_NUM_FIRST, sample_rate_hz, bq);
}

/** Invert the one-pole smoother back to a time constant in milliseconds. */
static float hf3_read_time(int32_t w, int constants, uint32_t sample_rate_hz) {
  const float y = hf3_unq23_unit(w);
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
static void hf3_read_pbe(const uint8_t *img, size_t size,
                         uint32_t sample_rate_hz, tas57xx_hf3_config_t *cfg) {
  const float fs = (float)sample_rate_hz;
  int32_t s[TAS57XX_BQ_WORDS];

  if (tas57xx_cram_read_image(img, size, hf3_pbe_extract[0].word, s,
                              TAS57XX_BQ_WORDS) == ESP_OK) {
    const float a2 = -hf3_unq23(s[1]);
    const float alpha = (1.0f + a2) != 0.0f ? (1.0f - a2) / (1.0f + a2) : 0.0f;
    const float arg = 2.0f * hf3_pbe_extract[0].q * alpha;
    if (arg > 0.0f && arg < 1.0f) {
      const float f0 = asinf(arg) * fs / (2.0f * (float)M_PI);
      /* The extraction ratios are fitted, not exact, so the inverse lands a
       * few hundredths of a Hz off a corner that was entered as a whole
       * number. Round to where the tuner would recognise it. */
      cfg->pbe.hpf_hz = roundf(f0 / hf3_pbe_extract[0].ratio * 10.0f) / 10.0f;
    }
  }

  if (tas57xx_cram_read_image(img, size, HF3_PBE_EFFECT_WORD, s,
                              TAS57XX_BQ_WORDS) == ESP_OK &&
      cfg->pbe.hpf_hz > 0.0f) {
    const float a1 = -2.0f * hf3_unq23(s[0]);
    const float a2 = -hf3_unq23(s[1]);
    float cw = (1.0f + a2) != 0.0f ? -a1 / (1.0f + a2) : 1.0f;
    if (cw > 1.0f) {
      cw = 1.0f;
    } else if (cw < -1.0f) {
      cw = -1.0f;
    }
    const float ratio = acosf(cw) * fs / (2.0f * (float)M_PI) / cfg->pbe.hpf_hz;
    float best = 1e9f;
    for (int i = 0; i < TAS57XX_HF3_PBE_EFFECT_MAX; i++) {
      const float d = fabsf(hf3_pbe_effect[i].pole_ratio - ratio);
      if (d < best) {
        best = d;
        cfg->pbe.effect = i + TAS57XX_HF3_PBE_EFFECT_MIN;
      }
    }
  }

  int32_t w;
  if (tas57xx_cram_read_image(img, size, HF3_PBE_HARMONIC_WORD, &w, 1) ==
      ESP_OK) {
    const float v = hf3_unq23(w);
    cfg->pbe.harmonic =
        v > 0.0f ? (int)lrintf((20.0f * log10f(v) + 50.0f) / 0.5f) : 0;
    if (cfg->pbe.harmonic < 0) {
      cfg->pbe.harmonic = 0;
    } else if (cfg->pbe.harmonic > TAS57XX_HF3_PBE_HARMONIC_MAX) {
      cfg->pbe.harmonic = TAS57XX_HF3_PBE_HARMONIC_MAX;
    }
  }
  if (tas57xx_cram_read_image(img, size, HF3_PBE_MIX_WORD, &w, 1) == ESP_OK) {
    cfg->pbe_enabled = hf3_unq23_unit(w) >= 0.5f;
  }
}

esp_err_t tas57xx_hf3_read(const uint8_t *img, size_t size,
                           uint32_t sample_rate_hz, tas57xx_hf3_config_t *cfg) {
  if (!img || !cfg || size < 2) {
    return ESP_ERR_INVALID_ARG;
  }
  tas57xx_hf3_defaults(cfg);
  cfg->sample_rate_hz = sample_rate_hz;

  int32_t w[6];
  for (int way = 0; way < TAS57XX_HF3_WAYS; way++) {
    hf3_read_bq(img, size, hf3_way_cross_slots[way], sample_rate_hz,
                &cfg->crossover[way]);
    for (int b = 0; b < TAS57XX_HF3_EQ_BANDS; b++) {
      hf3_read_bq(img, size, hf3_way_eq_slots[way][b], sample_rate_hz,
                  &cfg->eq[way][b]);
    }
    if (tas57xx_cram_read_image(img, size, hf3_way_mix_slots[way], w, 2) ==
        ESP_OK) {
      cfg->mix[way][0] = hf3_unq23_unit(w[0]);
      cfg->mix[way][1] = hf3_unq23_unit(w[1]);
    }
  }

  if (tas57xx_cram_read_image(img, size, HF3_DELAY_WORD, w, 5) == ESP_OK) {
    for (int i = 0; i < 5; i++) {
      if (hf3_unq23_unit(w[i]) > 0.5f) {
        cfg->high_delay_samples =
            TAS57XX_HF3_DELAY_MAX - i * TAS57XX_HF3_DELAY_STEP;
        break;
      }
    }
  }

  hf3_read_pbe(img, size, sample_rate_hz, cfg);

  for (int i = 0; i < TAS57XX_HF3_DBE_HL_BANDS; i++) {
    hf3_read_bq(img, size, hf3_dbe_hl_slots[i], sample_rate_hz,
                &cfg->dbe_high[i]);
  }
  for (int i = 0; i < TAS57XX_HF3_DBE_LL_BANDS; i++) {
    hf3_read_bq(img, size, hf3_dbe_ll_slots[i], sample_rate_hz,
                &cfg->dbe_low[i]);
  }

  if (tas57xx_cram_read_image(img, size, HF3_DBE_MIX_WORD, w, 2) == ESP_OK) {
    const float lower = -hf3_unq23(w[0]);
    const float scale = hf3_unq23(w[1]);
    if (lower > 0.0f && scale > 0.0f) {
      cfg->dbe_lower_db = 20.0f * log10f(lower) + 5.0f;
      cfg->dbe_upper_db = 20.0f * log10f(lower + 0.03125f / scale) + 4.0f;
    }
  }

  /* Only the band's centre survives the encoding, so the recovered pair keeps
   * the width it had and moves to sit around it. */
  {
    int32_t s[TAS57XX_BQ_WORDS];
    if (tas57xx_cram_read_image(img, size, HF3_SENSING_BAND_WORD, s,
                                TAS57XX_BQ_WORDS) == ESP_OK) {
      const float a1 = -2.0f * hf3_unq23(s[3]);
      // The stored centre was floored to a whole Hz on the way in, so round
      // back to one or re-encoding drops it by another Hz.
      const float centre = floorf((float)sample_rate_hz / (float)M_PI *
                                      atanf((1.0f + a1) / (1.0f - a1)) +
                                  0.5f);
      if (centre > 0.0f) {
        const float half = (cfg->sense_upper_hz - cfg->sense_lower_hz) / 2.0f;
        cfg->sense_lower_hz = centre - half > 10.0f ? centre - half : 10.0f;
        cfg->sense_upper_hz = cfg->sense_lower_hz + 2.0f * half;
      }
    }
  }

  int32_t one;
  if (tas57xx_cram_read_image(img, size, HF3_ENERGY_WINDOW_WORD, &one, 1) ==
      ESP_OK) {
    const float ms = hf3_read_time(one, 1, sample_rate_hz);
    if (ms > 0.0f) {
      cfg->sense_window_ms = ms;
    }
  }

  hf3_read_bq(img, size, HF3_DRC_SPLIT_LOW_WORD, sample_rate_hz,
              &cfg->drc_split_low);
  hf3_read_bq(img, size, HF3_DRC_SPLIT_HIGH_WORD, sample_rate_hz,
              &cfg->drc_split_high);
  if (tas57xx_cram_read_image(img, size, HF3_DRC_MIX_LOW_WORD, w, 2) ==
      ESP_OK) {
    cfg->drc_mix_low = hf3_unq23_unit(w[0]);
    cfg->drc_mix_mid = hf3_unq23_unit(w[1]);
  }

  for (int band = 0; band < TAS57XX_HF3_DRC_BANDS; band++) {
    if (tas57xx_cram_read_image(img, size, HF3_DRC_TIMING_WORD + band * 6, w,
                                6) != ESP_OK) {
      continue;
    }
    const float e = hf3_read_time(w[0], 1, sample_rate_hz);
    const float a = hf3_read_time(w[2], 3, sample_rate_hz);
    const float d = hf3_read_time(w[4], 3, sample_rate_hz);
    if (e > 0.0f) {
      cfg->drc_timing[band].energy_ms = e;
    }
    if (a > 0.0f) {
      cfg->drc_timing[band].attack_ms = a;
    }
    if (d > 0.0f) {
      cfg->drc_timing[band].decay_ms = d;
    }
  }

  if (tas57xx_cram_read_image(img, size, HF3_DRC_CURVE_WORD, w,
                              TAS57XX_HF3_DRC_REGIONS + 2) == ESP_OK) {
    for (int i = 0; i < TAS57XX_HF3_DRC_REGIONS; i++) {
      const float slope = 4.0f * hf3_unq23_unit(w[i]) + 1.0f;
      if (slope > 1.0f) {
        cfg->drc_region[i].mode = TAS57XX_HF3_DRC_EXPAND;
        cfg->drc_region[i].ratio = slope;
      } else if (slope > 0.0f) {
        cfg->drc_region[i].mode = TAS57XX_HF3_DRC_COMPRESS;
        cfg->drc_region[i].ratio = 1.0f / slope;
      }
    }
    cfg->drc_thresh1_db = -128.0f * hf3_unq23_unit(w[TAS57XX_HF3_DRC_REGIONS]);
    cfg->drc_thresh2_db =
        -128.0f * hf3_unq23_unit(w[TAS57XX_HF3_DRC_REGIONS + 1]);
  }

  if (tas57xx_cram_read_image(img, size, HF3_SMOOTH_CLIP_WORD, w, 2) ==
      ESP_OK) {
    const float t = 2.0f * hf3_unq23_unit(w[0]);
    // Rounding can put an untouched limiter a hair above 0 dB, which apply()
    // would then refuse.
    if (t > 0.0f) {
      const float db = 20.0f * log10f(t);
      cfg->smooth_clip_db = db > 0.0f ? 0.0f : (db < -78.0f ? -78.0f : db);
    }
  }
  return ESP_OK;
}

esp_err_t tas57xx_hf3_apply(tas57xx_cram_sink_t *sink,
                            const tas57xx_hf3_config_t *cfg) {
  if (!sink || !cfg) {
    return ESP_ERR_INVALID_ARG;
  }
  if (cfg->magic != TAS57XX_HF3_CONFIG_MAGIC ||
      cfg->version != TAS57XX_HF3_CONFIG_VERSION) {
    return ESP_ERR_INVALID_VERSION;
  }
  const uint32_t fs = cfg->sample_rate_hz;
  esp_err_t first = tas57xx_cram_begin(sink);
  if (first != ESP_OK) {
    return first;
  }

  for (int w = 0; w < TAS57XX_HF3_WAYS; w++) {
    hf3_keep(&first, tas57xx_hf3_set_way_input(sink, w, cfg->mix[w]),
             "way input");
    hf3_keep(&first,
             tas57xx_hf3_set_way_crossover(sink, w, &cfg->crossover[w], fs),
             "crossover");
    for (int b = 0; b < TAS57XX_HF3_EQ_BANDS; b++) {
      hf3_keep(&first,
               tas57xx_hf3_set_way_eq_band(sink, w, b, &cfg->eq[w][b], fs),
               "way EQ");
    }
  }
  hf3_keep(&first, tas57xx_hf3_set_high_delay(sink, cfg->high_delay_samples),
           "delay");

  hf3_keep(&first, tas57xx_hf3_set_pbe(sink, &cfg->pbe, fs), "PBE");
  hf3_keep(&first, tas57xx_hf3_set_pbe_enabled(sink, cfg->pbe_enabled),
           "PBE bypass");

  for (int i = 0; i < TAS57XX_HF3_DBE_HL_BANDS; i++) {
    hf3_keep(&first,
             tas57xx_hf3_set_dbe_hl_eq_band(sink, i, &cfg->dbe_high[i], fs),
             "DBE high EQ");
  }
  for (int i = 0; i < TAS57XX_HF3_DBE_LL_BANDS; i++) {
    hf3_keep(&first,
             tas57xx_hf3_set_dbe_ll_eq_band(sink, i, &cfg->dbe_low[i], fs),
             "DBE low EQ");
  }
  hf3_keep(&first,
           tas57xx_hf3_set_dbe_mix(sink, cfg->dbe_lower_db, cfg->dbe_upper_db),
           "DBE mix");
  hf3_keep(&first,
           tas57xx_hf3_set_sensing_band(sink, cfg->sense_lower_hz,
                                        cfg->sense_upper_hz, fs),
           "sensing band");
  hf3_keep(&first,
           tas57xx_hf3_set_energy_window(sink, cfg->sense_window_ms, fs),
           "energy window");

  hf3_keep(&first,
           tas57xx_hf3_set_drc_split(sink, &cfg->drc_split_low,
                                     &cfg->drc_split_high, fs),
           "DRC split");
  hf3_keep(&first,
           tas57xx_hf3_set_drc_mix(sink, cfg->drc_mix_low, cfg->drc_mix_mid),
           "DRC mix");
  for (int i = 0; i < TAS57XX_HF3_DRC_BANDS; i++) {
    hf3_keep(&first,
             tas57xx_hf3_set_drc_timing(sink, i, &cfg->drc_timing[i], fs),
             "DRC timing");
  }
  hf3_keep(&first,
           tas57xx_hf3_set_drc_curve(sink, cfg->drc_region, cfg->drc_thresh1_db,
                                     cfg->drc_thresh2_db),
           "DRC curve");

  hf3_keep(&first, tas57xx_hf3_set_smooth_clip(sink, cfg->smooth_clip_db),
           "smooth clip");

  // A half-written tuning is worse than none: one swap, or nothing.
  if (first != ESP_OK) {
    tas57xx_cram_abort(sink);
    return first;
  }
  return tas57xx_cram_commit(sink);
}
