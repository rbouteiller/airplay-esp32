/**
 * TAS57xx miniDSP coefficient RAM access and biquad design.
 *
 * A HybridFlow's tunable parameters all live in coefficient RAM, which stays
 * writable while the flow runs. This module owns the addressing, the fixed
 * point convention and the double-buffer commit; the flow-specific slot maps
 * live elsewhere.
 */
#pragma once

#include "esp_err.h"
#include "driver/i2c_master.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Coefficient RAM holds 30 words per page across pages 0x2C-0x34 (bank A).
#define TAS57XX_CRAM_WORDS_PER_PAGE 30
#define TAS57XX_CRAM_PAGES          9
#define TAS57XX_CRAM_WORD_COUNT \
  (TAS57XX_CRAM_WORDS_PER_PAGE * TAS57XX_CRAM_PAGES)

// A biquad occupies 5 consecutive words: b0, b1, b2, a1, a2.
#define TAS57XX_BQ_WORDS 5

// Limits PurePath Console imposes on a tunable section. Shelves have no Q at
// all in its UI; capping ours keeps a shelf from overshooting into a peak.
#define TAS57XX_BQ_GAIN_MIN_DB (-15.0f)
#define TAS57XX_BQ_GAIN_MAX_DB (12.0f)
#define TAS57XX_BQ_SHELF_Q_MAX (1.0f)

/** Filter shapes a HybridFlow biquad slot can be programmed to. */
typedef enum {
  // PurePath Console lists this as "All pass". It is unity, not a phase
  // shifting section — TAS57XX_BQ_PHASE_* are the real all-pass filters.
  TAS57XX_BQ_BYPASS = 0,
  // "EQ". Its Q is measured 3 dB back from the peak rather than at the
  // half-gain points, so it is neither RBJ's Q nor the one REW reports.
  TAS57XX_BQ_PEAKING,
  TAS57XX_BQ_PEAKING_BW, // "EQ", parameterised by bandwidth in octaves
  TAS57XX_BQ_LOW_SHELF,  // "Bass shelf"
  TAS57XX_BQ_HIGH_SHELF, // "Treble shelf"
  TAS57XX_BQ_LOWPASS,    // subtype picks the order and Q
  TAS57XX_BQ_HIGHPASS,   // subtype picks the order and Q
  TAS57XX_BQ_BANDPASS,
  TAS57XX_BQ_NOTCH,   // bandwidth in Hz
  TAS57XX_BQ_PHASE_1, // 1st order all-pass
  TAS57XX_BQ_PHASE_2, // 2nd order all-pass, bandwidth in octaves
  TAS57XX_BQ_CUSTOM,  // coefficients entered directly
  TAS57XX_BQ_TYPE_MAX,
} tas57xx_bq_type_t;

/**
 * Alignment of a low-pass or high-pass section, which is really just a choice
 * of Q. Variable Q is zero so that a section built without naming a subtype
 * keeps using the Q it was given.
 *
 * Butterworth and Linkwitz-Riley are confirmed against PurePath Console
 * captures; Bessel and Chebyshev are the textbook values and are unverified.
 */
typedef enum {
  TAS57XX_BQ_SUB_VARIABLE_Q_2 = 0,
  TAS57XX_BQ_SUB_BUTTERWORTH_1,
  TAS57XX_BQ_SUB_BUTTERWORTH_2,
  TAS57XX_BQ_SUB_BESSEL_2,
  TAS57XX_BQ_SUB_CHEBYSHEV_2,
  TAS57XX_BQ_SUB_LINKWITZ_RILEY_2,
  TAS57XX_BQ_SUB_MAX,
} tas57xx_bq_subtype_t;

typedef struct {
  tas57xx_bq_type_t type;
  tas57xx_bq_subtype_t subtype; // low-pass and high-pass only
  float freq_hz;
  float q;       // octaves for the bandwidth types, Hz for the notch
  float gain_db; // peaking and shelves only
  float coeff[TAS57XX_BQ_WORDS]; // TAS57XX_BQ_CUSTOM: b0, b1, b2, a1, a2
} tas57xx_bq_t;

/**
 * Word order and scaling of a biquad slot. A flow uses both: the EQ chain is
 * numerator first, the bass enhancer's own sections are denominator first and
 * carry an extra factor of two of headroom in the numerator.
 */
typedef enum {
  TAS57XX_BQ_NUM_FIRST = 0, // b0, b1/2, b2, -a1/2, -a2
  TAS57XX_BQ_DEN_FIRST,     // -a1/2, -a2, b0/2, b1/4, b2/2
} tas57xx_bq_layout_t;

/**
 * Design a biquad and pack it for coefficient RAM.
 *
 * Returns the attenuation (dB, <= 0) that had to be applied to keep the
 * numerator in range. Any boost needs that much make-up gain downstream, which
 * is how PurePath Console itself realises a boost.
 */
float tas57xx_bq_pack(const tas57xx_bq_t *bq, uint32_t sample_rate_hz,
                      tas57xx_bq_layout_t layout,
                      int32_t out[TAS57XX_BQ_WORDS]);

/** Coefficients for a slot that should pass audio through untouched. */
void tas57xx_bq_unity(tas57xx_bq_layout_t layout,
                      int32_t out[TAS57XX_BQ_WORDS]);

/**
 * Recover a biquad from packed coefficients.
 *
 * Comes back as TAS57XX_BQ_CUSTOM: a peaking filter and a shelf that happens
 * to match it store the same five numbers, so the shape a section was designed
 * as is not recoverable. The response is exact, and freq_hz and q are solved
 * from the pole pair so there is still something meaningful to show.
 */
void tas57xx_bq_unpack(const int32_t c[TAS57XX_BQ_WORDS],
                       tas57xx_bq_layout_t layout, uint32_t sample_rate_hz,
                       tas57xx_bq_t *bq);

/**
 * Map a coefficient RAM word index onto its page and register address.
 * Returns false if the index is outside bank A.
 */
bool tas57xx_cram_addr(int word, uint8_t *page, uint8_t *reg);

/**
 * Where coefficient writes are directed.
 *
 * A live device takes them over I2C and hears the change immediately. A flow
 * image takes them by rewriting the bytes the download would have sent, so the
 * tuning survives the next download instead of being overwritten by it.
 * Exactly one of the two must be set, unless dry_run discards them entirely.
 */
typedef struct tas57xx_cram_batch tas57xx_cram_batch_t;

typedef struct {
  i2c_master_dev_handle_t handle;
  uint8_t *image;
  size_t image_size;
  bool dry_run;                /**< run the checks, write nothing */
  tas57xx_cram_batch_t *batch; // set by tas57xx_cram_begin()
} tas57xx_cram_sink_t;

/**
 * Collect subsequent writes instead of committing each one.
 *
 * The DSP runs from one of two coefficient banks and a write is only made
 * permanent by requesting a swap, so every commit costs a swap. Swapping once
 * per parameter leaves the two banks disagreeing part-way through a retune,
 * which can momentarily assemble a biquad out of coefficients from two
 * different filters — audibly, an unstable one. PurePath Console writes every
 * changed word, swaps once, then writes them all again; this does the same.
 *
 * Has no effect on an image sink beyond deferring the patching.
 */
esp_err_t tas57xx_cram_begin(tas57xx_cram_sink_t *sink);

/** Commit everything staged since tas57xx_cram_begin() and end the batch. */
esp_err_t tas57xx_cram_commit(tas57xx_cram_sink_t *sink);

/** Abandon a batch without writing anything. */
void tas57xx_cram_abort(tas57xx_cram_sink_t *sink);

/**
 * Write words into coefficient RAM.
 *
 * Inside a batch this only stages them. Otherwise it commits immediately: on a
 * live device the burst is split at page boundaries and written twice with a
 * bank swap in between, leaving the device on page 0; on a flow image every
 * copy of the affected words is rewritten, in both banks.
 */
esp_err_t tas57xx_cram_write(const tas57xx_cram_sink_t *sink, int word,
                             const int32_t *words, int count);

/**
 * Read words back out of a flow image.
 *
 * A flow may write a slot more than once and carries both banks, so the last
 * copy wins — that is what the DSP is left running. Returns ESP_ERR_NOT_FOUND
 * if any requested word is absent from the image.
 */
esp_err_t tas57xx_cram_read_image(const uint8_t *img, size_t size, int word,
                                  int32_t *out, int count);

#ifdef __cplusplus
}
#endif
