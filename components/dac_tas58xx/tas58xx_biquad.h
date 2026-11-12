// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

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
 * The rate a TAS5805M's biquads run at, for audio arriving at @p i2s_rate_hz.
 *
 * Its ROM process flow puts a sample-rate converter ahead of the EQ, which
 * takes every input to 96 kHz, or to 88.2 kHz for the 44.1 kHz family (TI
 * SLOA263A, Process Flow 1). A section designed at the I2S rate therefore
 * plays an octave high at 48 kHz, so the part's sections are designed here.
 */
double tas5805m_dsp_rate(double i2s_rate_hz);

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
 * tas58xx_bq_design() for the part: a section whose coefficients would not
 * fit its 5.27 words comes out as a pass-through, keeping only its polarity,
 * since saturated it would play a different filter altogether.
 */
void tas58xx_bq_design_chip(const tas58xx_bq_t *bq, double sample_rate_hz,
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

/** tas58xx_bq_design_chip() and pack in one step. */
void tas58xx_bq_design_packed(const tas58xx_bq_t *bq, double sample_rate_hz,
                              uint8_t out[TAS58XX_BQ_COEFF_BYTES]);

/**
 * Highest point of a chain's magnitude response, in dB, between 10 Hz and the
 * lower of 20 kHz and 0.45 of @p sample_rate_hz: how far the chain lifts a
 * full-scale tone above full scale. @p coeff holds @p count sections already
 * designed with tas58xx_bq_design() at that rate. @p at_hz, if given,
 * receives where the peak is. An empty chain is flat, 0 dB.
 *
 * Evaluated in single precision, which is cheap enough to run on every edit:
 * each section's terms are formed in double and only then rounded, so the
 * low corners that need double precision to design lose nothing here.
 */
float tas58xx_bq_chain_peak_db(const double (*coeff)[5], int count,
                               double sample_rate_hz, float *at_hz);

/** True when @p bq is structurally valid; @p why is optional. */
bool tas58xx_bq_validate(const tas58xx_bq_t *bq, const char **why);

/**
 * Whether @p bq's coefficients fit the part's 5.27 words at every rate a
 * chain is designed for: 44.1 and 48 kHz on a TAS5825M, 88.2 and 96 kHz
 * behind a TAS5805M's converter. Past 16 a word saturates and the part plays
 * a different filter altogether; a treble shelf boosted beyond about 18 dB
 * with its corner below a few kHz is what gets there.
 */
bool tas58xx_bq_fits(const tas58xx_bq_t *bq);
