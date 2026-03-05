#pragma once

/**
 * 15-band parametric EQ using TAS5825M on-chip biquad filters.
 *
 * Coefficient addresses and band parameters match the mrtoy-me/esphome-tas58xx
 * reference implementation (Book 0xAA, TAS5825M ROM Mode 1).
 *
 * Band   Center (Hz)   Q
 *  0        20        2.0
 *  1        31.5      2.0
 *  2        50        1.5
 *  3        80        1.5
 *  4       125        1.0
 *  5       200        1.0
 *  6       315        0.9
 *  7       500        0.9
 *  8       800        0.8
 *  9      1250        0.8
 * 10      2000        0.7
 * 11      3150        0.7
 * 12      5000        0.6
 * 13      8000        0.6
 * 14     16000        0.5
 *
 * Requires dac_init() to have been called first.
 */

#include "esp_err.h"
#include <stdbool.h>

/** Number of EQ bands (one per on-chip biquad) */
#define TAS58XX_EQ_BANDS 15

/** Gain limits per band (dB) — matches reference ±15 dB range */
#define TAS58XX_EQ_MAX_GAIN_DB 15.0f
#define TAS58XX_EQ_MIN_GAIN_DB (-15.0f)

/**
 * Enable or disable the on-chip parametric EQ.
 * Must be called after the DAC enters PLAY state to take effect.
 * When disabled, all biquads are bypassed (flat response).
 *
 * @param enable  true to enable EQ processing, false to bypass
 * @return ESP_OK on success
 */
esp_err_t tas58xx_eq_enable(bool enable);

/**
 * Set gain for a single EQ band.
 * Uses pre-computed coefficient lookup tables for integer dB gains.
 * Coefficients are written immediately; both L and R channels are set.
 *
 * @param band     Band index 0–14
 * @param gain_db  Gain in dB (rounded to nearest integer, clamped to ±15 dB)
 * @return ESP_OK on success
 */
esp_err_t tas58xx_eq_set_band(int band, float gain_db);

/**
 * Set all 15 EQ bands in one call.
 *
 * @param gains_db  Array of TAS58XX_EQ_BANDS gain values in dB
 * @return ESP_OK on success, or the first error encountered
 */
esp_err_t tas58xx_eq_set_all(const float gains_db[TAS58XX_EQ_BANDS]);

/**
 * Reset all bands to flat (0 dB gain) and enable EQ.
 */
esp_err_t tas58xx_eq_flat(void);

/**
 * Return the center frequency (Hz) of the given band.
 *
 * @param band  Band index 0–14
 * @return Center frequency in Hz, or 0.0f if index is invalid
 */
float tas58xx_eq_get_center_freq(int band);

/**
 * Read back biquad coefficients at the expected RAM addresses and log
 * whether they match the default (flat) pattern.  Useful for verifying
 * that the coefficient address table is correct for this device.
 *
 * @return ESP_OK if all addresses look valid
 */
esp_err_t tas58xx_eq_verify_addresses(void);
