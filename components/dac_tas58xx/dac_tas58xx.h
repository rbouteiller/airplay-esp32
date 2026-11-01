// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "dac.h"
#include "tas58xx_biquad.h"

/**
 * TAS58xx (TAS5825M) DAC driver ops — register with dac_register() before
 * calling dac_init().
 */
extern const dac_ops_t dac_tas58xx_ops;

/**
 * Per-output level trim limits (dB). Applied in the DSP input mixer, ahead of
 * the biquads, so it only ever attenuates and cannot cost EQ headroom.
 */
#define TAS58XX_GAIN_MIN_DB (-40.0f)
#define TAS58XX_GAIN_MAX_DB (0.0f)

/**
 * Set the level of one output (0 = A, 1 = B) of one amplifier, relative to the
 * master volume, so drivers of differing sensitivity can be matched — a
 * bridged sub against the satellites, say. Clamped to
 * [TAS58XX_GAIN_MIN_DB, TAS58XX_GAIN_MAX_DB]. Safe to call before dac_init().
 */
esp_err_t dac_tas58xx_set_gain_db(int dev, int ch, float gain_db);

/** Get one output's level in dB. Returns 0 for an unknown index. */
float dac_tas58xx_get_gain_db(int dev, int ch);

/** Silence one output without disturbing its level setting. */
esp_err_t dac_tas58xx_set_ch_mute(int dev, int ch, bool mute);

/** Whether one output is muted. */
bool dac_tas58xx_get_ch_mute(int dev, int ch);

/**
 * Number of TAS58xx chips found on the I2C bus. Returns 0 before dac_init();
 * >1 means the board is a dual-DAC variant.
 */
int dac_tas58xx_get_device_count(void);

/**
 * Whether the primary amplifier is bridged (PBTL) mono rather than a stereo
 * pair. This describes how the board is wired and nothing more: it selects the
 * bridged output stage and sums L+R into that chip. On a dual-DAC board any
 * crossover between the two amplifiers is expressed as ordinary biquad
 * sections, not as a mode.
 */
bool dac_tas58xx_get_first_pbtl(void);

/** The wiring the primary chip was actually brought up in. */
bool dac_tas58xx_get_active_first_pbtl(void);

/**
 * Set whether the primary amplifier is bridged. PBTL is a control-port setting
 * that can only be changed while the output stage is idle, so the new value is
 * stored and applied by the next dac_init() — the caller must restart.
 */
void dac_tas58xx_set_first_pbtl(bool pbtl);

/**
 * Whether the second amplifier on a dual-DAC board is bridged (PBTL) mono
 * rather than a stereo pair. This describes how the board is wired and
 * nothing more: it selects the bridged output stage and sums L+R into that
 * chip. Any crossover between the two amplifiers is expressed as ordinary
 * biquad sections, not as a mode.
 */
bool dac_tas58xx_get_second_pbtl(void);

/** The wiring the chips were actually brought up in. */
bool dac_tas58xx_get_active_second_pbtl(void);

/**
 * Set whether the second amplifier is bridged. PBTL is a control-port setting
 * that can only be changed while the output stage is idle, so the new value is
 * stored and applied by the next dac_init() — the caller must restart.
 */
void dac_tas58xx_set_second_pbtl(bool pbtl);

/** Whether an amplifier is driving a bridged (PBTL) mono output right now. */
bool dac_tas58xx_is_pbtl(int dev);

/**
 * The analog gain at which digital full scale swings the output as far as
 * @p supply_mv lets it before it clips, in 0.5 dB steps and at most 0 dB.
 * Below about 5.2 V it is under TAS58XX_ANALOG_GAIN_MIN_DB.
 */
float dac_tas58xx_clean_db(int supply_mv);

/** Quietest digital gain dac_tas58xx_set_full_volume_db() takes. */
#define TAS58XX_FULL_VOLUME_MIN_DB (-30.0f)

/**
 * Set the digital gain AirPlay's full volume maps to, in dB, rounded to
 * 0.5 dB and held to TAS58XX_FULL_VOLUME_MIN_DB..0. 0 dB until set. Safe
 * before dac_init().
 */
void dac_tas58xx_set_full_volume_db(float db);
float dac_tas58xx_get_full_volume_db(void);

/** Deepest analog gain dac_tas58xx_set_analog_gain_db() takes. */
#define TAS58XX_ANALOG_GAIN_MIN_DB (-15.5f)

/**
 * Set the amplifier's analog gain by hand, in dB, rounded to 0.5 dB and held
 * to TAS58XX_ANALOG_GAIN_MIN_DB..0, and stop it following the supply. The
 * digital gain does not follow it. Safe before dac_init().
 */
void dac_tas58xx_set_analog_gain_db(float db);
/** The analog gain playing, set by hand or following the supply. */
float dac_tas58xx_get_analog_gain_db(void);

/**
 * Have the analog gain match the supply (dac_tas58xx_clean_db()), held to
 * TAS58XX_ANALOG_GAIN_MIN_DB, or CONFIG_TAS58XX_ANALOG_GAIN_UNKNOWN_SUPPLY
 * while the supply is unknown; or go back to the one set by hand. On until
 * turned off. Safe before dac_init().
 */
void dac_tas58xx_set_analog_auto(bool on);
bool dac_tas58xx_get_analog_auto(void);

/**
 * Tell the driver the amplifier's supply in mV, or 0 if it is not known.
 * Safe before dac_init(), and from the USB-PD trigger's supply callback.
 */
void dac_tas58xx_set_supply_mv(int supply_mv);
int dac_tas58xx_get_supply_mv(void);

/**
 * Whether an amplifier can route its inputs at all. Routing is a process-flow
 * change, which only a TAS5825M has: a TAS5805M plays the pair as it comes.
 */
bool dac_tas58xx_can_route(int dev);

/**
 * Which of the incoming stereo channels an amplifier plays. A bridged (PBTL)
 * amplifier drives one output from one channel of the pair, so it has to be
 * fed a summed or single-channel routing rather than TAS58XX_MIX_STEREO,
 * unless it cannot route at all: then it plays the left channel.
 */
typedef enum {
  TAS58XX_MIX_STEREO = 0, /* L -> output A, R -> output B */
  TAS58XX_MIX_MONO,       /* (L+R)/2 -> both outputs */
  TAS58XX_MIX_LEFT,       /* L -> both outputs */
  TAS58XX_MIX_RIGHT,      /* R -> both outputs */
  TAS58XX_MIX_COUNT,
} tas58xx_mix_t;

/**
 * Set one amplifier's input routing. Applied immediately if the chip is
 * playing, and re-applied on the next PLAY transition either way. Safe to
 * call before dac_init(), which is how a stored setting is restored.
 *
 * An amplifier that cannot route (dac_tas58xx_can_route()) is refused
 * anything but TAS58XX_MIX_STEREO with ESP_ERR_NOT_SUPPORTED, and nothing is
 * stored. Before dac_init() the part is not known yet, so dac_init() drops
 * such a routing instead.
 */
esp_err_t dac_tas58xx_set_mix(int dev, tas58xx_mix_t mix);

/** Get one amplifier's input routing. */
tas58xx_mix_t dac_tas58xx_get_mix(int dev);

/**
 * Hand one amplifier's input routing to the software EQ, which applies it
 * ahead of its filters (as the DSP applies it ahead of its EQ), and pass the
 * pair through the chip's mixer unrouted. The per-output levels and mutes
 * stay in the chip. Refused, returning false, while a PPC3 dump's routing is
 * in force, since that is part of the dump's tuning.
 *
 * @return whether the software EQ now owns the routing
 */
bool dac_tas58xx_set_soft_routing(int dev, bool on);

/** Whether the software side routes one amplifier's input. */
bool dac_tas58xx_get_soft_routing(int dev);
/** Whether dac_tas58xx_set_soft_routing() would be accepted. */
bool dac_tas58xx_can_soft_route(int dev);

/* ---------- Fault reporting ---------- */

/**
 * Name every latched fault across all amplifiers into buf, which is left
 * empty when nothing is latched.
 *
 * Returns true only for a fault worth muting for. A clock fault on its own is
 * not one: it says the I2S clocks stopped, which is what happens at the end of
 * every track, and the FAULTZ line cannot tell the two apart on its own.
 */
bool dac_tas58xx_fault_report(char *buf, size_t len);

/** Drop the latched faults so FAULTZ releases. */
void dac_tas58xx_fault_clear(void);

/* ---------- Fully parametric biquad chain ----------
 *
 * Each amplifier runs a 15-section biquad chain per channel, and this chain is
 * the only writer of the chip's coefficient RAM. Crossovers, shelves and room
 * correction are all just sections in it.
 */

/** Channels per amplifier: 0 = left/CH1, 1 = right/CH2. */
#define TAS58XX_BQ_CHANNELS 2

/** Read one channel's chain. Returns false for an out-of-range index. */
bool dac_tas58xx_bq_get(int dev, int ch, tas58xx_bq_t out[TAS58XX_BQ_SLOTS]);

/** Replace one channel's chain and push it to the hardware. */
esp_err_t dac_tas58xx_bq_set(int dev, int ch,
                             const tas58xx_bq_t in[TAS58XX_BQ_SLOTS]);

/**
 * Gang the two channels of an amplifier: the left chain drives both, and the
 * right chain is left untouched so un-ganging restores it.
 */
void dac_tas58xx_bq_set_ganged(int dev, bool ganged);
bool dac_tas58xx_bq_get_ganged(int dev);

/** Sample rate the primary amplifier's chain is designed against. */
uint32_t dac_tas58xx_bq_sample_rate(void);

/**
 * Sample rate one amplifier's chain is designed against. Amplifiers sharing
 * an I2S bus can have different DSP rates. An unknown index uses the I2S rate.
 */
uint32_t dac_tas58xx_bq_device_sample_rate(int dev);

/** Write the current chains to SPIFFS so they survive a reboot. */
esp_err_t dac_tas58xx_bq_commit(void);

/** Reload the chains from SPIFFS, discarding uncommitted edits. */
esp_err_t dac_tas58xx_bq_revert(void);

/** Reset every chain to bypass, in memory and on the hardware. */
esp_err_t dac_tas58xx_bq_reset(void);

/** One channel's sections as designed, next to what the chip holds. */
typedef struct {
  uint8_t expected[TAS58XX_BQ_SLOTS][TAS58XX_BQ_COEFF_BYTES];
  uint8_t actual[TAS58XX_BQ_SLOTS][TAS58XX_BQ_COEFF_BYTES];
  uint8_t ctrl2;           /**< DEVICE_CTRL2 at the read: power state, mute */
  bool eq_bypassed;        /**< EQ block bypassed, so none of it plays */
  uint32_t design_rate_hz; /**< rate the sections are designed for */
} tas58xx_bq_readback_t;

/**
 * Read one channel's sections back out of the chip's coefficient RAM, with
 * the blocks the chain should have written there, to check that the designs
 * reach the part intact. The chain is rewritten whenever the amplifier
 * enters PLAY, so read while audio is playing: a part that has slept since
 * may hold anything.
 */
esp_err_t dac_tas58xx_bq_readback(int dev, int ch, tas58xx_bq_readback_t *out);

/**
 * A TAS5805M's automatic gain limiter and full-scale clipper as the chip
 * holds them: raw words from book 0x8C, Process Flow 1 (TI SLOA263A,
 * Table 5). The driver writes none of them, so they show the part's own
 * state.
 */
typedef struct {
  int32_t agl_release;   /**< 1.31 */
  int32_t agl_attack;    /**< 1.31 */
  int32_t agl_threshold; /**< 1.31, linear */
  int32_t agl_enable;    /**< 1.31, non-zero = on */
  int32_t agl_alpha;     /**< 1.31, energy time constant */
  int32_t agl_omega;     /**< 1.31 */
  int32_t thd_boost;     /**< 9.23, gain into the clip at full scale */
  int32_t fine_vol[2];   /**< 2.30, left and right gain after it */
} tas58xx_limit_readback_t;

/** Read a TAS5805M's limiter and clipper; ESP_ERR_NOT_SUPPORTED on others. */
esp_err_t dac_tas58xx_limit_readback(int dev, tas58xx_limit_readback_t *out);

/**
 * Write every section as a pass-through while keeping the chains, so the
 * software EQ can play them instead and the two can be compared by ear. The
 * chains, their API and auto gain are unchanged; only what reaches the
 * chip's coefficient RAM is. Not saved here; safe before dac_init(), so a
 * saved choice can be set before the chains are first written.
 */
void dac_tas58xx_bq_set_flat(bool flat);
bool dac_tas58xx_bq_get_flat(void);

/**
 * Raise the volume by @p db (>= 0) on top of the digital gain, to give back
 * what an EQ ahead of the amplifier takes off before its filters. It moves
 * the register in 0.5 dB steps, so a level that is not a multiple of 0.5 dB
 * is not returned exactly.
 */
void dac_tas58xx_set_makeup_db(float db);

/**
 * Called after the chains, their ganging or the sample rate change, from
 * the task that changed them (the web server, or an audio task on a new
 * rate). One listener; NULL removes it.
 */
void dac_tas58xx_set_eq_listener(void (*listener)(void));

/**
 * Whether PBTL mode on the primary amplifier is forced by configuration.
 * Returns true if CONFIG_TAS58XX_FORCE_PBTL is enabled, which means
 * the PBTL setting cannot be changed from the web UI.
 */
bool dac_tas58xx_is_first_pbtl_forced(void);
