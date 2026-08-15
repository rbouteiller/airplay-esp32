#pragma once

#include "dac.h"

/**
 * TAS57xx DAC driver ops — register with dac_register() before calling
 * dac_init().
 */
extern const dac_ops_t dac_tas57xx_ops;

/** Sub level-trim limits (dB), relative to the master volume. */
#define TAS57XX_SUB_OFFSET_MIN_DB (-15.0f)
#define TAS57XX_SUB_OFFSET_MAX_DB (15.0f)

/**
 * Set the sub (index > 0) volume offset in dB, relative to the master volume.
 * Positive raises the bass level, negative lowers it. Clamped to
 * [TAS57XX_SUB_OFFSET_MIN_DB, TAS57XX_SUB_OFFSET_MAX_DB]. Safe to call before
 * dac_init(); the value is applied on the next volume update.
 */
void dac_tas57xx_set_sub_offset_db(float offset_db);

/** Get the current sub volume offset in dB. */
float dac_tas57xx_get_sub_offset_db(void);

/** Which input channel a bi-amp hybrid flow's mixer feeds both ways from. */
typedef enum {
  TAS57XX_INPUT_MIX = 0, /**< (L+R)/2 */
  TAS57XX_INPUT_LEFT,
  TAS57XX_INPUT_RIGHT,
} tas57xx_input_src_t;

/**
 * True when a running hybrid flow carries a recognised bi-amp input mixer, and
 * so makes the channel selection itself. False for any other flow — a sub
 * low-pass or a full-range EQ uses that coefficient RAM for something else.
 */
bool dac_tas57xx_has_input_mix(void);

/**
 * Select the input channel a bi-amp hybrid flow mixes down to. Ignored by any
 * device whose flow has no input mixer. The flow's two outputs are crossover
 * ways rather than left and right, so this replaces the software channel
 * selection rather than adding to it. Safe to call before dac_init(); the
 * value is re-applied after every flow download.
 */
void dac_tas57xx_set_input_source(tas57xx_input_src_t src);

/** Get the input channel a bi-amp hybrid flow is mixing down to. */
tas57xx_input_src_t dac_tas57xx_get_input_source(void);

/** Number of TAS57xx amplifiers detected. 0 before dac_init(). */
int dac_tas57xx_get_device_count(void);

/**
 * Read and log the read-only status registers of every detected amplifier:
 * power state, output short detection, auto-mute, analogue mute and the
 * SPK_MUTE pin decoder. Useful on boards where SPK_FAULT is not wired to the
 * ESP32. Safe to call before dac_init() (logs a warning and returns).
 */
void dac_tas57xx_log_status(void);
