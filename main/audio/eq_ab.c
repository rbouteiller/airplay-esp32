// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "eq_ab.h"

#include "audio_eq.h"
#include "dac_tas58xx.h"

#include "settings.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>

#define TAG "eq_ab"

/* The amplifier's volume moves in 0.5 dB steps, so the software EQ's preamp
 * is kept to them and given back exactly. */
#define VOLUME_STEP_DB 0.5f

/* Created by eq_ab_init(), before the driver can call back. */
static SemaphoreHandle_t s_mutex;
static bool s_on;

/* What the software EQ holds, so a call that changes nothing redesigns
 * nothing: the rate change that calls back runs on an audio task. */
static tas58xx_bq_t s_held[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
static bool s_held_ganged;
static bool s_held_valid;

bool eq_ab_available(void) {
  return dac_tas58xx_get_device_count() == 1;
}

bool eq_ab_get(void) {
  return s_on;
}

/* Hand the software EQ the amplifier's chains, or flat ones when off.
 * Caller holds s_mutex. */
static void mirror_locked(void) {
  tas58xx_bq_t chain[AUDIO_EQ_CHANNELS][AUDIO_EQ_SLOTS];
  bool ganged = true;
  if (s_on) {
    /* Bridged, the chip plays its left path, which is the left chain. */
    ganged = dac_tas58xx_is_pbtl(0) || dac_tas58xx_bq_get_ganged(0);
    for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
      dac_tas58xx_bq_get(0, ch, chain[ch]);
    }
    /* The chip routes ahead of its EQ and the software EQ plays ahead of
     * the chip, so two different chains on a summed routing differ. */
    if (!ganged && dac_tas58xx_get_mix(0) != TAS58XX_MIX_STEREO) {
      ESP_LOGW(TAG, "per-channel chains on a summed routing: software side "
                    "filters before the mix, the DSP after it");
    }
  } else {
    for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
      for (int i = 0; i < AUDIO_EQ_SLOTS; i++) {
        tas58xx_bq_init_bypass(&chain[ch][i]);
      }
    }
  }
  /* tas58xx_bq_t has no padding. Equal floats with different bytes (-0 and
   * 0) only cost a redesign. */
  if (s_held_valid && ganged == s_held_ganged &&
      // NOLINTNEXTLINE(bugprone-suspicious-memory-comparison)
      memcmp(chain, s_held, sizeof(chain)) == 0) {
    return;
  }
  audio_eq_set_ganged(ganged);
  for (int ch = 0; ch < AUDIO_EQ_CHANNELS; ch++) {
    if (audio_eq_set_chain(ch, chain[ch]) != ESP_OK) {
      ESP_LOGW(TAG, "software EQ refused chain %d", ch);
    }
  }
  memcpy(s_held, chain, sizeof(s_held));
  s_held_ganged = ganged;
  s_held_valid = true;
}

static void makeup_locked(void) {
  dac_tas58xx_set_makeup_db(s_on ? -audio_eq_get_preamp_db() : 0.0f);
}

/* The driver's listener: the chains, ganging or rate moved, or the driver
 * has just loaded them. */
static void follow(void) {
  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (s_on && !eq_ab_available()) {
    /* Saved on a board that turned out to have a second amplifier. */
    s_on = false;
    dac_tas58xx_bq_set_flat(false);
  }
  if (s_on) {
    mirror_locked();
    makeup_locked();
  }
  xSemaphoreGive(s_mutex);
}

esp_err_t eq_ab_init(void) {
  esp_err_t err = audio_eq_init_blank(VOLUME_STEP_DB);
  if (err != ESP_OK) {
    return err;
  }
  s_mutex = xSemaphoreCreateMutex();
  if (s_mutex == NULL) {
    return ESP_ERR_NO_MEM;
  }
  /* The amplifiers are not probed yet, so the chains reach the software EQ
   * when the driver has loaded them and calls back. Set flat now, the
   * amplifier never plays them first. */
  s_on = settings_get_software_eq_ab();
  if (s_on) {
    dac_tas58xx_bq_set_flat(true);
  }
  dac_tas58xx_set_eq_listener(follow);
  return ESP_OK;
}

esp_err_t eq_ab_set(bool software) {
  if (s_mutex == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!eq_ab_available()) {
    return ESP_ERR_NOT_SUPPORTED;
  }

  xSemaphoreTake(s_mutex, portMAX_DELAY);
  if (software != s_on) {
    s_on = software;
    /* Each way round, the level drops before the EQ moves and comes back
     * after, so the change never plays the boosts twice at full level. */
    if (software) {
      mirror_locked();
      dac_tas58xx_bq_set_flat(true);
      makeup_locked();
    } else {
      makeup_locked();
      dac_tas58xx_bq_set_flat(false);
      mirror_locked();
    }
    ESP_LOGI(TAG, "EQ now plays on the %s (preamp %.1f dB)",
             software ? "ESP32" : "amplifier's DSP",
             (double)audio_eq_get_preamp_db());
    settings_set_software_eq_ab(software);
  }
  xSemaphoreGive(s_mutex);
  return ESP_OK;
}
