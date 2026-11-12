// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/**
 * @file sendspin_cpace.h
 * @brief CPACE-X25519-SHA512, the PAKE behind Sendspin's PIN pairing.
 *
 * CPace turns a short shared secret -- here an 8-digit PIN -- into a strong
 * session key without ever putting the PIN on the wire, and without letting an
 * eavesdropper or an active attacker test more than one guess per attempt.
 * That last property is what makes a PIN safe to use at all.
 *
 * The password is hashed to a curve point which becomes the group generator,
 * so both sides only agree on a shared secret if they started from the same
 * PIN.  Sendspin runs it with the server as initiator and the client as
 * responder, then both sides exchange confirmation tags before either trusts
 * the result.
 *
 * Interoperability is byte-exact or nothing: every length prefix is LEB128 and
 * a single wrong one yields a silent mismatch rather than an error.  This is a
 * port of the `cpace` Python package that the reference server uses, and is
 * checked against it by a host-side interop test rather than by inspection.
 */

#define SENDSPIN_CPACE_SHARE_LEN 32
#define SENDSPIN_CPACE_TAG_LEN   64
#define SENDSPIN_CPACE_ISK_LEN   64
#define SENDSPIN_CPACE_SID_MAX   64
#define SENDSPIN_CPACE_AD_MAX    16

typedef enum {
  SENDSPIN_CPACE_INITIATOR, /**< The server. */
  SENDSPIN_CPACE_RESPONDER, /**< This client. */
} sendspin_cpace_role_t;

typedef struct {
  sendspin_cpace_role_t role;
  uint8_t sid[SENDSPIN_CPACE_SID_MAX];
  size_t sid_len;
  uint8_t ad[SENDSPIN_CPACE_AD_MAX];
  size_t ad_len;
  uint8_t peer_ad[SENDSPIN_CPACE_AD_MAX];
  size_t peer_ad_len;
  uint8_t scalar[32];
  uint8_t public_share[SENDSPIN_CPACE_SHARE_LEN];
  uint8_t peer_share[SENDSPIN_CPACE_SHARE_LEN];
  uint8_t isk[SENDSPIN_CPACE_ISK_LEN];
  uint8_t mac_key[64];
  bool started;
  bool derived;
} sendspin_cpace_t;

/**
 * Sample a scalar and compute this side's public share.
 *
 * Fails if the PIN hashes to a low-order generator, which would make every
 * share the identity.  @p prs is the PIN as ASCII; @p ad is this side's
 * associated data ("client" for us).
 */
esp_err_t sendspin_cpace_start(sendspin_cpace_t *cp, sendspin_cpace_role_t role,
                               const uint8_t *prs, size_t prs_len,
                               const uint8_t *sid, size_t sid_len,
                               const uint8_t *ad, size_t ad_len);

/**
 * Ingest the peer's share, deriving the ISK and the confirmation MAC key.
 * Single-use; fails on a low-order share.
 */
esp_err_t sendspin_cpace_derive(sendspin_cpace_t *cp,
                                const uint8_t peer_share[32],
                                const uint8_t *peer_ad, size_t peer_ad_len);

/** This side's confirmation tag. */
esp_err_t sendspin_cpace_tag(const sendspin_cpace_t *cp,
                             uint8_t out[SENDSPIN_CPACE_TAG_LEN]);

/** Whether the peer's tag proves it knew the same PIN. */
bool sendspin_cpace_verify(const sendspin_cpace_t *cp,
                           const uint8_t peer_tag[SENDSPIN_CPACE_TAG_LEN]);

/** The intermediate session key; run it through a KDF before use. */
const uint8_t *sendspin_cpace_isk(const sendspin_cpace_t *cp);

void sendspin_cpace_reset(sendspin_cpace_t *cp);
