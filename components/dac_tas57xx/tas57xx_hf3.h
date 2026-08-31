/**
 * HybridFlow 3 (bi-amp) parameter map for the TAS5754M.
 *
 * The flow splits the input into a low way and a mid/high way. Each way has
 * its own input mixer and a chain of five biquads whose first section is the
 * crossover. The low way then carries the bass enhancer, the dynamic bass
 * enhancer and the three-band compander; the mid/high way carries a delay to
 * time-align the tweeter.
 *
 * Slot addresses are specific to this flow — nothing in the .bin identifies
 * which flow is loaded, so these are only valid once HF3 has been downloaded.
 */
#pragma once

#include "tas57xx_cram.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TAS57XX_HF3_WAYS     2
#define TAS57XX_HF3_EQ_BANDS 4

enum {
  TAS57XX_HF3_WAY_LOW = 0, /**< woofer, ahead of the PBE/DBE/compander */
  TAS57XX_HF3_WAY_HIGH,    /**< mid+tweeter, ahead of the delay */
};

/**
 * Set a way's input mixer. The two gains are applied to left and right, so
 * (0.5, 0.5) is mono, (1, 0) is left only, and negating both inverts polarity.
 */
esp_err_t tas57xx_hf3_set_way_input(const tas57xx_cram_sink_t *sink, int way,
                                    const float gain[2]);

/** Program a way's crossover, the first section of its five-biquad chain. */
esp_err_t tas57xx_hf3_set_way_crossover(const tas57xx_cram_sink_t *sink,
                                        int way, const tas57xx_bq_t *bq,
                                        uint32_t sample_rate_hz);

/** Program one of the four tunable sections following a way's crossover. */
esp_err_t tas57xx_hf3_set_way_eq_band(const tas57xx_cram_sink_t *sink, int way,
                                      int band, const tas57xx_bq_t *bq,
                                      uint32_t sample_rate_hz);

#define TAS57XX_HF3_DELAY_STEP 4
#define TAS57XX_HF3_DELAY_MAX  16

/**
 * Delay the mid/high way, in samples. The flow holds five fixed taps rather
 * than a variable line, so only multiples of four up to sixteen exist — about
 * 363 us, or 12 cm of path difference, at 44.1 kHz.
 */
esp_err_t tas57xx_hf3_set_high_delay(const tas57xx_cram_sink_t *sink,
                                     int samples);

#define TAS57XX_HF3_PBE_HPF_MIN_HZ   50.0f
#define TAS57XX_HF3_PBE_HPF_MAX_HZ   300.0f
#define TAS57XX_HF3_PBE_HARMONIC_MAX 100
#define TAS57XX_HF3_PBE_EFFECT_MIN   1
#define TAS57XX_HF3_PBE_EFFECT_MAX   5

/** Psychoacoustic bass enhancer settings, matching the PurePath Console pane.
 */
typedef struct {
  float hpf_hz; /**< extraction corner, 50-300 Hz */
  int harmonic; /**< harmonic intensity, 0-100 (0 mutes the generator) */
  int effect;   /**< effect intensity, 1-5 */
} tas57xx_hf3_pbe_t;

/**
 * Retune the whole bass enhancer. The effect shelf is derived from the HPF
 * corner as well as the intensity, so all of it is written together to stop
 * the two from drifting out of step.
 */
esp_err_t tas57xx_hf3_set_pbe(const tas57xx_cram_sink_t *sink,
                              const tas57xx_hf3_pbe_t *pbe,
                              uint32_t sample_rate_hz);

/** Route the low way through the bass enhancer, or straight past it. */
esp_err_t tas57xx_hf3_set_pbe_enabled(const tas57xx_cram_sink_t *sink,
                                      bool enabled);

#define TAS57XX_HF3_DBE_HL_BANDS 2
#define TAS57XX_HF3_DBE_LL_BANDS 3

/** Program one band of the DBE's high-level (loud path) EQ. */
esp_err_t tas57xx_hf3_set_dbe_hl_eq_band(const tas57xx_cram_sink_t *sink,
                                         int band, const tas57xx_bq_t *bq,
                                         uint32_t sample_rate_hz);

/** Program one band of the DBE's low-level (quiet path) EQ. */
esp_err_t tas57xx_hf3_set_dbe_ll_eq_band(const tas57xx_cram_sink_t *sink,
                                         int band, const tas57xx_bq_t *bq,
                                         uint32_t sample_rate_hz);

/**
 * Set the levels the DBE crossfades between, in dBFS. The pair is stored as a
 * threshold and a reciprocal span, so very narrow ranges are not representable
 * and are rejected.
 *
 * Note the two thresholds reach the mixer at different offsets — 5 dB below
 * the entered value for the lower, 4 dB for the upper. Both were measured from
 * captures that moved one threshold at a time.
 */
esp_err_t tas57xx_hf3_set_dbe_mix(const tas57xx_cram_sink_t *sink,
                                  float lower_db, float upper_db);

/**
 * Set the band the DBE energy estimator listens to.
 *
 * Unlike HF1, which centres a bandpass on the geometric mean, this flow stores
 * a single first-order high-pass cornered at the ARITHMETIC mean of the two
 * boundaries, truncated to a whole Hz. That is what PurePath Console emits.
 */
esp_err_t tas57xx_hf3_set_sensing_band(const tas57xx_cram_sink_t *sink,
                                       float lower_hz, float upper_hz,
                                       uint32_t sample_rate_hz);

/** Set the energy estimator's averaging window in milliseconds. */
esp_err_t tas57xx_hf3_set_energy_window(const tas57xx_cram_sink_t *sink,
                                        float window_ms,
                                        uint32_t sample_rate_hz);

#define TAS57XX_HF3_DRC_BANDS 3

#define TAS57XX_HF3_DRC_TIME_MIN_MS 0.1f
#define TAS57XX_HF3_DRC_TIME_MAX_MS 10000.0f

enum {
  TAS57XX_HF3_DRC_LOW = 0,
  TAS57XX_HF3_DRC_MID,
  TAS57XX_HF3_DRC_HIGH,
};

/** One compander band's detector timing, in milliseconds. */
typedef struct {
  float energy_ms; /**< level-estimator averaging window */
  float attack_ms;
  float decay_ms;
} tas57xx_hf3_drc_timing_t;

/** Set one compander band's detector timing. */
esp_err_t tas57xx_hf3_set_drc_timing(const tas57xx_cram_sink_t *sink, int band,
                                     const tas57xx_hf3_drc_timing_t *timing,
                                     uint32_t sample_rate_hz);

/**
 * Set the compander's band-split filters.
 *
 * Only two exist: a low-pass feeding the low band and a high-pass feeding the
 * high band. The mid band is whatever the two leave behind, which is why it has
 * no filter of its own.
 */
esp_err_t tas57xx_hf3_set_drc_split(const tas57xx_cram_sink_t *sink,
                                    const tas57xx_bq_t *low,
                                    const tas57xx_bq_t *high,
                                    uint32_t sample_rate_hz);

#define TAS57XX_HF3_DRC_MIX_MIN -1.0f
#define TAS57XX_HF3_DRC_MIX_MAX 1.0f

/**
 * Set the gains that sum the companded low and mid bands back in.
 *
 * The high band has no gain of its own and is always summed at unity. The flow
 * ships the mid at -1: that inversion is what makes the default complementary
 * split recombine flat, so changing it without also rethinking the split will
 * not sum flat.
 */
esp_err_t tas57xx_hf3_set_drc_mix(const tas57xx_cram_sink_t *sink, float low,
                                  float mid);

#define TAS57XX_HF3_DRC_REGIONS   3
#define TAS57XX_HF3_DRC_RATIO_MIN 0.2f
#define TAS57XX_HF3_DRC_RATIO_MAX 5.0f

enum {
  TAS57XX_HF3_DRC_COMPRESS = 0,
  TAS57XX_HF3_DRC_EXPAND,
};

/** One segment of the compander's piecewise-linear transfer curve. */
typedef struct {
  int mode;    /**< TAS57XX_HF3_DRC_COMPRESS or _EXPAND */
  float ratio; /**< 0.2 to 5.0; 1.0 leaves the segment flat either way */
} tas57xx_hf3_drc_region_t;

/**
 * Set the compander transfer curve: three regions bottom-up, split by two
 * level thresholds.
 */
esp_err_t tas57xx_hf3_set_drc_curve(
    const tas57xx_cram_sink_t *sink,
    const tas57xx_hf3_drc_region_t regions[TAS57XX_HF3_DRC_REGIONS],
    float thresh1_db, float thresh2_db);

/** Set the output smooth-clip threshold, -78..0 dBFS. */
esp_err_t tas57xx_hf3_set_smooth_clip(const tas57xx_cram_sink_t *sink,
                                      float threshold_db);

#define TAS57XX_HF3_CONFIG_MAGIC   0x48463345u /* "HF3E" */
#define TAS57XX_HF3_CONFIG_VERSION 3u

/**
 * Every tunable parameter of the flow, in one blob.
 *
 * Coefficient RAM cannot be read back while the DSP is running, so this struct
 * — not the device — is the source of truth for what the current tuning is.
 */
typedef struct {
  uint32_t magic;
  uint32_t version;
  uint32_t sample_rate_hz; /**< rate the flow was designed for */

  float mix[TAS57XX_HF3_WAYS][2]; /**< left and right gain, per way */
  int high_delay_samples;

  tas57xx_bq_t crossover[TAS57XX_HF3_WAYS];
  tas57xx_bq_t eq[TAS57XX_HF3_WAYS][TAS57XX_HF3_EQ_BANDS];

  tas57xx_hf3_pbe_t pbe;
  bool pbe_enabled;

  tas57xx_bq_t dbe_high[TAS57XX_HF3_DBE_HL_BANDS];
  tas57xx_bq_t dbe_low[TAS57XX_HF3_DBE_LL_BANDS];
  float dbe_lower_db;
  float dbe_upper_db;
  float sense_lower_hz;
  float sense_upper_hz;
  float sense_window_ms;

  /* The compander has three bands but only two filters: the low band is what
   * the low-pass passes, the high band what the high-pass passes, and the mid
   * is the input less those two. Only the low and mid gains are stored; the
   * high band is summed at unity. */
  tas57xx_bq_t drc_split_low;
  tas57xx_bq_t drc_split_high;
  float drc_mix_low;
  float drc_mix_mid;
  tas57xx_hf3_drc_timing_t drc_timing[TAS57XX_HF3_DRC_BANDS];
  tas57xx_hf3_drc_region_t drc_region[TAS57XX_HF3_DRC_REGIONS];
  float drc_thresh1_db;
  float drc_thresh2_db;

  float smooth_clip_db;
} tas57xx_hf3_config_t;

/**
 * Bring a saved config forward to the current version, in place.
 *
 * Version 2 held the two split biquads in the opposite order, so swapping them
 * is what keeps the amplifier doing the same thing. Returns false, leaving the
 * config untouched, when there is nothing to bring forward.
 */
bool tas57xx_hf3_config_migrate(tas57xx_hf3_config_t *cfg);

/**
 * Fill in the tuning the stock flow ships with: a 1 kHz Linkwitz-Riley 2
 * crossover, flat EQ, bass enhancer bypassed and the compander pass-through.
 */
void tas57xx_hf3_defaults(tas57xx_hf3_config_t *cfg);

/**
 * Range-check a whole config without writing anything, so a tuning cannot be
 * stored while the DSP is asleep and only turn out to be invalid later.
 */
esp_err_t tas57xx_hf3_validate(const tas57xx_hf3_config_t *cfg);

/**
 * Recover the tuning a flow image is carrying, so the editor can open on what
 * the speaker is actually running rather than on a set of defaults.
 *
 * Biquads come back as TAS57XX_BQ_CUSTOM: the response is exact, but the shape
 * they were designed as is not stored and cannot be inferred. The sensing
 * band's width and the sample rate are likewise absent from the image, so both
 * are taken from cfg's defaults.
 */
esp_err_t tas57xx_hf3_read(const uint8_t *img, size_t size,
                           uint32_t sample_rate_hz, tas57xx_hf3_config_t *cfg);

/**
 * Write a whole tuning to a live device or into a flow image.
 *
 * Carries on past a rejected section so one bad parameter cannot leave the
 * chain half-programmed; the first error seen is returned at the end.
 */
esp_err_t tas57xx_hf3_apply(tas57xx_cram_sink_t *sink,
                            const tas57xx_hf3_config_t *cfg);

#ifdef __cplusplus
}
#endif
