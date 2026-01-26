#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * HAP (HomeKit Accessory Protocol) implementation for AirPlay 2
 * Handles pair-verify for transient pairing
 */

// Key sizes
#define HAP_ED25519_PUBLIC_KEY_SIZE  32
#define HAP_ED25519_SECRET_KEY_SIZE  64
#define HAP_X25519_KEY_SIZE          32
#define HAP_CHACHA20_KEY_SIZE        32
#define HAP_CHACHA20_NONCE_SIZE      12
#define HAP_POLY1305_TAG_SIZE        16

// Forward declaration
struct srp_session;

// Session state
typedef struct {
    // Device long-term Ed25519 keypair
    uint8_t device_public_key[HAP_ED25519_PUBLIC_KEY_SIZE];
    uint8_t device_secret_key[HAP_ED25519_SECRET_KEY_SIZE];

    // Ephemeral X25519 keypair for this session
    uint8_t session_public_key[HAP_X25519_KEY_SIZE];
    uint8_t session_secret_key[HAP_X25519_KEY_SIZE];

    // Client's ephemeral public key
    uint8_t client_public_key[HAP_X25519_KEY_SIZE];

    // Shared secret from X25519
    uint8_t shared_secret[HAP_X25519_KEY_SIZE];

    // Derived session keys
    uint8_t encrypt_key[HAP_CHACHA20_KEY_SIZE];
    uint8_t decrypt_key[HAP_CHACHA20_KEY_SIZE];

    // Encryption nonces (counters)
    uint64_t encrypt_nonce;
    uint64_t decrypt_nonce;

    // Session state
    int pair_verify_state;
    int pair_setup_state;
    bool pair_setup_transient;
    bool session_established;

    // SRP session for pair-setup
    struct srp_session *srp;
} hap_session_t;

/**
 * Initialize HAP module
 * Generates or loads device Ed25519 keypair from NVS
 */
esp_err_t hap_init(void);

/**
 * Get device's Ed25519 public key (for mDNS pk field)
 */
const uint8_t *hap_get_public_key(void);

/**
 * Create a new HAP session for a client connection
 */
hap_session_t *hap_session_create(void);

/**
 * Free a HAP session
 */
void hap_session_free(hap_session_t *session);

/**
 * Handle pair-verify M1 message from client
 * @param session HAP session
 * @param input Input TLV data from client
 * @param input_len Length of input
 * @param output Output buffer for M2 response
 * @param output_capacity Capacity of output buffer
 * @param output_len Actual length of output
 * @return ESP_OK on success
 */
esp_err_t hap_pair_verify_m1(hap_session_t *session,
                             const uint8_t *input, size_t input_len,
                             uint8_t *output, size_t output_capacity, size_t *output_len);

/**
 * Handle pair-verify M3 message from client
 * @param session HAP session
 * @param input Input TLV data from client
 * @param input_len Length of input
 * @param output Output buffer for M4 response
 * @param output_capacity Capacity of output buffer
 * @param output_len Actual length of output
 * @return ESP_OK on success, session keys are derived
 */
esp_err_t hap_pair_verify_m3(hap_session_t *session,
                             const uint8_t *input, size_t input_len,
                             uint8_t *output, size_t output_capacity, size_t *output_len);

/**
 * Handle AirPlay 2 raw (non-TLV) pair-verify M1
 * Used when iOS sends raw 68-byte format instead of TLV
 */
esp_err_t hap_pair_verify_m1_raw(hap_session_t *session,
                                  const uint8_t *input, size_t input_len,
                                  uint8_t *output, size_t output_capacity, size_t *output_len);

/**
 * Handle AirPlay 2 raw (non-TLV) pair-verify M3
 */
esp_err_t hap_pair_verify_m3_raw(hap_session_t *session,
                                  const uint8_t *input, size_t input_len,
                                  uint8_t *output, size_t output_capacity, size_t *output_len);

/**
 * Encrypt data using session keys
 * @param session HAP session (must be established)
 * @param plaintext Input data
 * @param plaintext_len Length of input
 * @param ciphertext Output buffer (must have room for plaintext_len + 16 tag)
 * @param ciphertext_len Actual output length
 * @return ESP_OK on success
 */
esp_err_t hap_encrypt(hap_session_t *session,
                      const uint8_t *plaintext, size_t plaintext_len,
                      uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt data using session keys
 * @param session HAP session (must be established)
 * @param ciphertext Input data (includes 16 byte tag)
 * @param ciphertext_len Length of input
 * @param plaintext Output buffer
 * @param plaintext_len Actual output length
 * @return ESP_OK on success, ESP_ERR_INVALID_STATE if auth fails
 */
esp_err_t hap_decrypt(hap_session_t *session,
                      const uint8_t *ciphertext, size_t ciphertext_len,
                      uint8_t *plaintext, size_t *plaintext_len);

/**
 * Derive audio encryption key from pair-verify shared secret
 * Uses HKDF-SHA512 with AirPlay 2 audio-specific parameters
 * @param session HAP session (must be established)
 * @param audio_key Output buffer for audio key
 * @param key_len Length of audio key to generate (typically 16 or 32 bytes)
 * @return ESP_OK on success
 */
esp_err_t hap_derive_audio_key(hap_session_t *session, uint8_t *audio_key, size_t key_len);

/**
 * Handle pair-setup M1 (client initiates SRP)
 * @param session HAP session
 * @param input Input TLV (method, state, flags)
 * @param input_len Length of input
 * @param output Output buffer for M2 (salt, public key)
 * @param output_capacity Capacity of output buffer
 * @param output_len Actual output length
 * @return ESP_OK on success
 */
esp_err_t hap_pair_setup_m1(hap_session_t *session,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_capacity, size_t *output_len);

/**
 * Handle pair-setup M3 (client sends A and proof)
 * @param session HAP session
 * @param input Input TLV (public key, proof)
 * @param input_len Length of input
 * @param output Output buffer for M4 (server proof)
 * @param output_capacity Capacity of output buffer
 * @param output_len Actual output length
 * @return ESP_OK on success
 */
esp_err_t hap_pair_setup_m3(hap_session_t *session,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_capacity, size_t *output_len);

/**
 * Handle pair-setup M5 (client sends encrypted data)
 * @param session HAP session
 * @param input Input TLV (encrypted data)
 * @param input_len Length of input
 * @param output Output buffer for M6 (encrypted response)
 * @param output_capacity Capacity of output buffer
 * @param output_len Actual output length
 * @return ESP_OK on success
 */
esp_err_t hap_pair_setup_m5(hap_session_t *session,
                            const uint8_t *input, size_t input_len,
                            uint8_t *output, size_t output_capacity, size_t *output_len);
