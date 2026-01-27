#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * SRP-6a implementation for HomeKit/AirPlay pair-setup
 * Uses 3072-bit prime N and SHA-512
 */

// SRP parameter sizes
#define SRP_PRIME_BITS        3072
#define SRP_PRIME_BYTES       (SRP_PRIME_BITS / 8) // 384 bytes
#define SRP_SALT_BYTES        16
#define SRP_PROOF_BYTES       64
#define SRP_SESSION_KEY_BYTES 64 // SHA-512 output

// SRP session context
typedef struct srp_session {
  uint8_t salt[SRP_SALT_BYTES];
  uint8_t server_public_key[SRP_PRIME_BYTES]; // B
  uint8_t server_secret[SRP_PRIME_BYTES];     // b
  uint8_t client_public_key[SRP_PRIME_BYTES]; // A
  uint8_t session_key[SRP_SESSION_KEY_BYTES]; // K
  size_t session_key_len;
  uint8_t proof_m1[SRP_SESSION_KEY_BYTES]; // Client proof
  uint8_t proof_m2[SRP_SESSION_KEY_BYTES]; // Server proof
  int state;
  bool verified;
} srp_session_t;

/**
 * Create a new SRP session
 */
srp_session_t *srp_session_create(void);

/**
 * Free an SRP session
 */
void srp_session_free(srp_session_t *session);

/**
 * Start SRP session (generate salt and server public key B)
 * For transient pairing, username="Pair-Setup" and password="3939"
 *
 * @param session SRP session
 * @param username Username (typically "Pair-Setup")
 * @param password Password (typically "3939" for transient)
 * @return ESP_OK on success
 */
esp_err_t srp_start(srp_session_t *session, const char *username,
                    const char *password);

/**
 * Get salt for M2 response
 */
const uint8_t *srp_get_salt(srp_session_t *session);

/**
 * Get server public key B for M2 response
 * @param len Output: length of public key
 */
const uint8_t *srp_get_public_key(srp_session_t *session, size_t *len);

/**
 * Process client's public key A and proof M1 from M3
 * Verifies client's proof and generates server proof M2
 *
 * @param session SRP session
 * @param client_public_key Client's public key A
 * @param client_pk_len Length of client public key
 * @param client_proof Client's proof M1
 * @param proof_len Length of proof
 * @return ESP_OK if verification succeeds
 */
esp_err_t srp_verify_client(srp_session_t *session,
                            const uint8_t *client_public_key,
                            size_t client_pk_len, const uint8_t *client_proof,
                            size_t proof_len);

/**
 * Get server proof M2 for M4 response
 */
const uint8_t *srp_get_proof(srp_session_t *session);

/**
 * Get session key K after successful verification
 * This key is used to encrypt M5/M6 messages
 */
const uint8_t *srp_get_session_key(srp_session_t *session, size_t *len);
