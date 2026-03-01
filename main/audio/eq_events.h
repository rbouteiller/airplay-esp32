#pragma once

/**
 * EQ event system — Observer pattern for equalizer state changes.
 *
 * Decouples the web interface, NVS persistence, and DAC driver so each
 * can react to EQ changes independently.  Mirrors the RTSP event pattern.
 *
 * Compile-time gated: only available when CONFIG_DAC_TAS58XX is set.
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef CONFIG_DAC_TAS58XX
#include "dac_tas58xx_eq.h"
#else
/* Provide the constant even when EQ hardware isn't present so that
   data structures compile cleanly.  The event system simply won't
   be active. */
#define TAS58XX_EQ_BANDS 15
#endif

/** Maximum number of EQ event listeners */
#define EQ_MAX_LISTENERS 4

/* ------------------------------------------------------------------ */
/*  Event types                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
  /** A single band's gain changed.  data->band_changed is valid. */
  EQ_EVENT_BAND_CHANGED,

  /** All 15 bands were set at once (bulk update / preset load).
   *  data->all_bands is valid. */
  EQ_EVENT_ALL_BANDS_SET,

  /** All bands reset to 0 dB (flat).  No extra data needed. */
  EQ_EVENT_FLAT,
} eq_event_t;

/* ------------------------------------------------------------------ */
/*  Event data                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
  int band;      /**< 0–14 */
  float gain_db; /**< new gain in dB */
} eq_band_changed_t;

typedef struct {
  float gains_db[TAS58XX_EQ_BANDS]; /**< all 15 gains */
} eq_all_bands_t;

typedef union {
  eq_band_changed_t band_changed; /**< EQ_EVENT_BAND_CHANGED */
  eq_all_bands_t all_bands;       /**< EQ_EVENT_ALL_BANDS_SET */
} eq_event_data_t;

/* ------------------------------------------------------------------ */
/*  Callback signature                                                 */
/* ------------------------------------------------------------------ */

/**
 * EQ event callback.
 * @param event     Which event fired
 * @param data      Event-specific payload (NULL for EQ_EVENT_FLAT)
 * @param user_data Pointer registered with eq_events_register()
 */
typedef void (*eq_event_callback_t)(eq_event_t event,
                                    const eq_event_data_t *data,
                                    void *user_data);

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

/**
 * Register a listener for EQ events.
 * @return 0 on success, -1 if max listeners reached or callback is NULL
 */
int eq_events_register(eq_event_callback_t callback, void *user_data);

/**
 * Unregister a previously registered listener.
 */
void eq_events_unregister(eq_event_callback_t callback);

/**
 * Emit an EQ event to all registered listeners.
 * @param event  The event type
 * @param data   Event payload (may be NULL for EQ_EVENT_FLAT)
 */
void eq_events_emit(eq_event_t event, const eq_event_data_t *data);
