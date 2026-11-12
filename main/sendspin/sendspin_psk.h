// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "sendspin_noise.h"

/**
 * @file sendspin_psk.h
 * @brief The pre-shared keys a Sendspin handshake can be keyed with.
 *
 * Every connection is a `KKpsk2` handshake, and which PSK goes into it is
 * what decides whether the session is authenticated.  The server names its
 * choice by `psk_id` in the message 1 payload and the client answers with the
 * matching key, so the client's job is to hold a set of candidates and look
 * one up:
 *
 *   - the **Sentinel**, a constant published in the specification.  A session
 *     keyed with it is *unpaired*: encrypted and replay-protected, but with
 *     neither peer's identity proven.
 *   - the **pairing PSK**, drawn from the CSPRNG once per device and never
 *     rotated by the client itself.  It authenticates the one handshake in
 *     which the device is adopted, and is handed to the operator out of band
 *     as a pairing token.
 *   - a **long-term PSK** per paired server, delivered by the client at the
 *     end of that pairing and used for every session with it afterwards.
 *
 * The pairing PSK is long-lived and pairs the device with any number of
 * servers, so it is a standing credential: anyone holding the token can adopt
 * the device.  Long-term PSKs are per-server and are what actually
 * authenticate day-to-day sessions.
 */

#define SENDSPIN_PSK_LEN    SENDSPIN_NOISE_KEY_LEN
#define SENDSPIN_PSK_ID_LEN SENDSPIN_NOISE_PSK_ID_LEN

/** Longest pairing token: "SP:" + version + 103 base32 characters. */
#define SENDSPIN_PSK_TOKEN_LEN 107

/** How many servers the device can stay paired with at once. */
#define SENDSPIN_PSK_MAX_RECORDS 4

/** The static PIN is exactly 8 decimal digits; no other length is legal. */
#define SENDSPIN_PSK_PIN_LEN 8

/** Which candidate a handshake matched. */
typedef enum {
  SENDSPIN_PSK_SENTINEL,  /**< Unpaired: the session proves no identity. */
  SENDSPIN_PSK_PAIRING,   /**< Only valid for a pairing activity. */
  SENDSPIN_PSK_LONG_TERM, /**< A paired server. */
} sendspin_psk_kind_t;

/**
 * Load the pairing PSK and the pairing records, generating the pairing PSK on
 * first boot.  Call once, after the client identity is known: the identity is
 * half of the pairing token.
 */
esp_err_t sendspin_psk_init(const uint8_t client_pub[SENDSPIN_PSK_LEN]);

/**
 * Find the PSK the server named.
 *
 * Returns NULL when no candidate matches, which the specification's Sentinel
 * Fallback says to answer with the Sentinel anyway so the server sees a
 * credential mismatch rather than a silent hang.
 */
const uint8_t *sendspin_psk_lookup(const char *psk_id,
                                   sendspin_psk_kind_t *kind_out);

/**
 * The version-0 pairing token: `client_key || pairing_psk`, base32-encoded.
 * This is the string the operator hands to a server to adopt the device.
 */
const char *sendspin_psk_token(void);

/**
 * The device's static pairing PIN: 8 decimal digits, generated once and kept
 * across reboots.  An operator reads it off the device's own page and types
 * it into the server, which proves knowledge of it through a PAKE.
 */
const char *sendspin_psk_static_pin(void);

/** Draw a fresh long-term PSK for a pairing about to be finalized. */
void sendspin_psk_generate(uint8_t psk[SENDSPIN_PSK_LEN]);

/**
 * Persist a pairing record.  Re-pairing a server replaces its record; when
 * the table is full the oldest is dropped.
 */
esp_err_t sendspin_psk_add_record(const char *server_id,
                                  const uint8_t psk[SENDSPIN_PSK_LEN]);

/** How many servers the device is currently paired with. */
size_t sendspin_psk_record_count(void);

/** Forget every pairing record. The pairing PSK itself is left alone. */
esp_err_t sendspin_psk_forget_all(void);
