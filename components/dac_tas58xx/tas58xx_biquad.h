#pragma once

/**
 * Biquad filter models for the TAS58xx on-chip DSP.
 *
 * The coefficient formulas are those used by TI PurePath Console 3, so a
 * filter dialled in here matches what PPC3 would have computed for the same
 * settings. Designs are evaluated at runtime against the live I2S sample
 * rate rather than baked at one rate.
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

/** Biquad slots in each channel's EQ chain. */
#define TAS58XX_BQ_SLOTS 15

/** Bytes in one packed coefficient block (5 coefficients x 4 bytes). */
#define TAS58XX_BQ_COEFF_BYTES 20

/** Filter shapes, mirroring the PurePath Console 3 filter list. */
typedef enum {
  TAS58XX_BQ_BYPASS = 0,   /**< all-pass: unity, the slot does nothing */
  TAS58XX_BQ_PEAKING_Q,    /**< "Equalizer (Q Factor)" */
  TAS58XX_BQ_PEAKING_BW,   /**< "Equalizer (Bandwidth)", bandwidth in Hz */
  TAS58XX_BQ_BASS_SHELF,   /**< "Bass Shelf" */
  TAS58XX_BQ_TREBLE_SHELF, /**< "Treble Shelf" */
  TAS58XX_BQ_LOWPASS,      /**< "Low Pass-*", alignment in .sub */
  TAS58XX_BQ_HIGHPASS,     /**< "High Pass-*", alignment in .sub */
  TAS58XX_BQ_BANDPASS,     /**< "Band Pass", bandwidth in Hz */
  TAS58XX_BQ_NOTCH,        /**< "Notch", bandwidth in Hz */
  TAS58XX_BQ_PHASE_SHIFT,  /**< "Phase Shift", bandwidth in Hz */
  TAS58XX_BQ_CUSTOM,       /**< raw coefficients in .coeff */
  TAS58XX_BQ_TYPE_COUNT,
} tas58xx_bq_type_t;

/** Alignment of a low- or high-pass section. */
typedef enum {
  TAS58XX_BQ_SUB_BUTTERWORTH_1 = 0, /**< 1st order, -6 dB/oct */
  TAS58XX_BQ_SUB_BUTTERWORTH_2,     /**< Q = 1/sqrt(2) */
  TAS58XX_BQ_SUB_BESSEL_2,          /**< Q = 1/sqrt(3) */
  TAS58XX_BQ_SUB_LINKWITZ_RILEY_2,  /**< Q = 0.5, -6 dB at the corner */
  TAS58XX_BQ_SUB_VARIABLE_Q_2,      /**< Q taken from the .q field */
  TAS58XX_BQ_SUB_CHEBYSHEV_2,       /**< ripple taken from .ripple_db */
  TAS58XX_BQ_SUB_COUNT,
} tas58xx_bq_sub_t;

/** One configurable biquad section. */
typedef struct {
  uint8_t type;       /**< tas58xx_bq_type_t */
  uint8_t sub;        /**< tas58xx_bq_sub_t, low/high pass only */
  uint8_t invert;     /**< flip polarity: negates the numerator */
  uint8_t reserved;   /**< keeps the struct 4-byte aligned on flash */
  float freq_hz;      /**< corner or centre frequency */
  float q;            /**< Q, where the shape uses one */
  float bandwidth_hz; /**< bandwidth, where the shape uses one */
  float gain_db;      /**< boost or cut, where the shape uses one */
  float ripple_db;    /**< Chebyshev passband ripple */
  float coeff[5];     /**< {b0, b1, b2, -a1, -a2} for CUSTOM */
} tas58xx_bq_t;

/** Limits accepted by tas58xx_bq_design(). */
#define TAS58XX_BQ_GAIN_MIN_DB   (-20.0f)
#define TAS58XX_BQ_GAIN_MAX_DB   (20.0f)
#define TAS58XX_BQ_Q_MIN         (0.1f)
#define TAS58XX_BQ_Q_MAX         (20.0f)
#define TAS58XX_BQ_RIPPLE_MIN_DB (0.1f)
#define TAS58XX_BQ_RIPPLE_MAX_DB (3.0f)

/** A slot that passes audio through untouched. */
void tas58xx_bq_init_bypass(tas58xx_bq_t *bq);

/**
 * Compute the five device coefficients for @p bq at @p sample_rate_hz.
 *
 * @p out receives {b0, b1, b2, -a1, -a2} — the denominator terms are already
 * negated, which is both what PPC3 emits and what the part expects.
 * Out-of-range settings are clamped rather than rejected, so the result is
 * always a stable filter.
 */
void tas58xx_bq_design(const tas58xx_bq_t *bq, double sample_rate_hz,
                       double out[5]);

/**
 * Pack designed coefficients into the part's 5.27 big-endian layout.
 * Values outside the representable range are saturated.
 */
void tas58xx_bq_pack(const double coeff[5],
                     uint8_t out[TAS58XX_BQ_COEFF_BYTES]);

/**
 * Recover a section from a packed coefficient block.
 *
 * The shape that produced the block is not stored with it, so anything other
 * than a pass-through comes back as TAS58XX_BQ_CUSTOM.
 */
void tas58xx_bq_unpack(const uint8_t in[TAS58XX_BQ_COEFF_BYTES],
                       tas58xx_bq_t *bq);

/** Design and pack in one step. */
void tas58xx_bq_design_packed(const tas58xx_bq_t *bq, double sample_rate_hz,
                              uint8_t out[TAS58XX_BQ_COEFF_BYTES]);

/** True when @p bq is structurally valid; @p why is optional. */
bool tas58xx_bq_validate(const tas58xx_bq_t *bq, const char **why);
