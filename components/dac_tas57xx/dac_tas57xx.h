#pragma once

#include "dac.h"
#include "tas57xx_hf1.h"
#include "tas57xx_hf3.h"

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

/** The part's two amplifier outputs. Index 0 is A, which the EVM feeds from
 *  the right input channel, and index 1 is B, fed from the left. */
#define TAS57XX_CHANNELS 2

/** Per-channel trim limits (dB), relative to the master volume. Cut only, so
 *  no trim can push a channel past the ceiling the master sets. */
#define TAS57XX_CH_TRIM_MIN_DB (-20.0f)
#define TAS57XX_CH_TRIM_MAX_DB (0.0f)

/**
 * Trim one amplifier channel relative to the master volume, for balance or,
 * on a bi-amp speaker, for the level between woofer and tweeter. Clamped to
 * [TAS57XX_CH_TRIM_MIN_DB, TAS57XX_CH_TRIM_MAX_DB]. Safe to call before
 * dac_init(); the value is applied on the next volume update.
 */
void dac_tas57xx_set_channel_trim_db(int ch, float trim_db);

/** Get one channel's trim in dB. */
float dac_tas57xx_get_channel_trim_db(int ch);

/**
 * Silence one channel, for comparing the two against each other. This is not
 * persisted, so it clears on reboot.
 */
void dac_tas57xx_set_channel_mute(int ch, bool mute);

/** True while the channel is silenced. */
bool dac_tas57xx_get_channel_mute(int ch);

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

/**
 * True when a full-range flow is loaded and its tuning can be edited. HF1 and
 * HF3 map coefficient RAM differently, so at most one is ever available — the
 * bi-amp input mixer is what tells them apart.
 */
bool dac_tas57xx_hf1_available(void);

/** Read the current HF1 tuning. */
esp_err_t dac_tas57xx_hf1_get(tas57xx_hf1_config_t *cfg);

/**
 * Apply a tuning to the running DSP without persisting it. Reverted by the
 * next reboot or flow download, so it is safe to audition anything.
 */
esp_err_t dac_tas57xx_hf1_set(const tas57xx_hf1_config_t *cfg);

/**
 * Bake the current tuning into the flow image and write it back to SPIFFS.
 * A flow download rewrites all of coefficient RAM, so this is what makes a
 * tuning outlast one.
 */
esp_err_t dac_tas57xx_hf1_commit(void);

/** Reload the committed flow from SPIFFS and re-download it, dropping any
 * uncommitted tuning. */
esp_err_t dac_tas57xx_hf1_revert(void);

/* ---- Flow selection --------------------------------------------------- */

/** The rate the base flows are chosen for. */
uint32_t dac_tas57xx_flow_sample_rate(void);

/** 1 or 3 for the flow currently loaded, 0 when there is none. */
int dac_tas57xx_active_flow(void);

/** True when a base flow for this type exists in SPIFFS at the current rate. */
bool dac_tas57xx_flow_base_available(int flow);

/**
 * Install the base flow for `flow` (1 or 3) and re-download it, then re-apply
 * that flow's saved tuning if there is one. Bi-amp and stereo drive the two
 * amplifier outputs completely differently, so callers must confirm the
 * speaker is wired for it first.
 *
 * Flow 0 removes the working flow instead, leaving the part on its ROM stereo
 * program. That is the only setting a TAS57xx without a usable HybridFlow can
 * run, and it discards nothing but the flow file - the saved tunings stay.
 */
esp_err_t dac_tas57xx_select_flow(int flow);

/** True when a bi-amp flow is loaded and its tuning can be edited. */
bool dac_tas57xx_hf3_available(void);

/** Read the current HF3 tuning. */
esp_err_t dac_tas57xx_hf3_get(tas57xx_hf3_config_t *cfg);

/** Audition an HF3 tuning on the running DSP without persisting it. */
esp_err_t dac_tas57xx_hf3_set(const tas57xx_hf3_config_t *cfg);

/** Bake the current HF3 tuning into the flow image and write it to SPIFFS. */
esp_err_t dac_tas57xx_hf3_commit(void);

/** Reload the committed bi-amp flow, dropping any uncommitted tuning. */
esp_err_t dac_tas57xx_hf3_revert(void);
