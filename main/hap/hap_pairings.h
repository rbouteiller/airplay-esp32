// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/**
 * Persistent HomeKit controller pairings and accessory configuration.
 *
 * A controller pairing is what a non-transient pair-setup (M5/M6) or a
 * /pair-add leaves behind: the controller's pairing identifier, its Ed25519
 * long-term public key and its permissions. pair-verify looks the controller up
 * here to check its signature; /pair-list reports the set.
 *
 * The HomeKit access-control state that the Home app sends in POST /configure
 * lives here too, because it is meaningless without the pairings and is
 * cleared with them.
 *
 * Everything is in one NVS blob in its own namespace, mirrored in RAM and
 * guarded by a mutex: two RTSP connection tasks and the web server all reach
 * it.
 */

// HAP pairing identifiers are UUID strings (36 bytes) in practice; leave room.
#define HAP_PAIRING_ID_MAX 64
// The HAP specification requires at least 16.
#define HAP_PAIRINGS_MAX 16

#define HAP_PERM_USER  0x00
#define HAP_PERM_ADMIN 0x01

typedef struct {
  uint8_t id_len;
  uint8_t perms;
  uint8_t ltpk[32];
  char id[HAP_PAIRING_ID_MAX];
} hap_pairing_t;

/**
 * Load the store from NVS. Safe to call more than once.
 */
esp_err_t hap_pairings_init(void);

/**
 * Add a controller, or update the permissions of one already present.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG for a bad identifier,
 *         ESP_ERR_INVALID_STATE if the identifier is paired with a different
 *         key, ESP_ERR_NO_MEM if the store is full, or an NVS error.
 */
esp_err_t hap_pairings_add(const uint8_t *id, size_t id_len,
                           const uint8_t ltpk[32], uint8_t perms);

/**
 * As hap_pairings_add(), but a controller already present takes the new key
 * instead of being refused. For pair-setup, where the controller has just
 * proved the setup code: one that was reset comes back with a new key under
 * the same identifier.
 */
esp_err_t hap_pairings_put(const uint8_t *id, size_t id_len,
                           const uint8_t ltpk[32], uint8_t perms);

/**
 * Store a controller for a session that proved the setup code: the Home app
 * adding the speaker to a home.
 *
 * Unless joining, or another setup-code session stored a pairing in the last
 * five minutes, this starts a new pairing set: every other pairing is
 * forgotten, so a home the speaker was removed from while offline loses its
 * rights and its slots. That holds even when this controller is already
 * stored, because the same iPhone is usually the first one added to the next
 * home too. Within the window, or when joining, it is added as by
 * hap_pairings_put(): another connection of the same setup, or a retry.
 * The window is kept in RAM only. The HomeKit configuration is kept either
 * way, since the Home app may send /configure first.
 *
 * @param joining The session has already claimed; never start over.
 * @return As hap_pairings_put()
 */
esp_err_t hap_pairings_claim(const uint8_t *id, size_t id_len,
                             const uint8_t ltpk[32], uint8_t perms,
                             bool joining);

/**
 * Look a controller up by its pairing identifier.
 * @param ltpk Receives the long-term public key (may be NULL)
 * @param perms Receives the permissions (may be NULL)
 * @return true if found
 */
bool hap_pairings_find(const uint8_t *id, size_t id_len, uint8_t ltpk[32],
                       uint8_t *perms);

/**
 * Remove a controller. Removing the last admin removes every pairing and
 * turns HomeKit access control off: the accessory is unpaired, as the HAP
 * specification requires.
 * @return ESP_OK, ESP_ERR_NOT_FOUND, or an NVS error
 */
esp_err_t hap_pairings_remove(const uint8_t *id, size_t id_len);

/** Number of stored controllers. */
size_t hap_pairings_count(void);

/** Number of stored controllers with the admin bit. */
size_t hap_pairings_admin_count(void);

/**
 * Copy up to max pairings into out.
 * @return Number copied
 */
size_t hap_pairings_snapshot(hap_pairing_t *out, size_t max);

/**
 * Forget every pairing and the HomeKit configuration. Nothing changes in RAM
 * unless the erase reached flash.
 */
esp_err_t hap_pairings_clear(void);

/** Whether the Home app has turned on HomeKit access control. */
bool hap_homekit_access_control(void);

/**
 * Access control level from the Home app's "Allow Speaker & TV Access":
 * 0 everyone, 1 anyone on the same network, 2 only people sharing this home.
 * Stored and advertised; not enforced.
 */
uint8_t hap_homekit_acl(void);

/**
 * Store the HomeKit configuration from POST /configure. On a failed flash
 * write the previous configuration stays in effect and the error is returned.
 */
esp_err_t hap_homekit_set_config(bool access_control, uint8_t acl);

/**
 * Register a function to call (outside the lock) whenever anything that is
 * advertised changes: access control, its level, or being paired at all.
 */
void hap_pairings_set_change_cb(void (*cb)(void));
