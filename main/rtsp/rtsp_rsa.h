#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * AirPlay v1 RSA operations using the well-known AirPlay private key.
 * Uses mbedtls for RSA (libsodium does not support RSA).
 *
 * Two operations:
 * 1. Apple-Challenge: sign with RSA PKCS1 v1.5 (private encrypt)
 * 2. AES key decrypt: RSA OAEP-SHA1 (private decrypt of rsaaeskey)
 */

/**
 * Seed the RNG and parse the private key.
 *
 * Optional: every entry point does this lazily. Call it up front to keep the
 * cost off the RTSP task, where it lands in the middle of the OPTIONS response
 * a sender is waiting on.
 *
 * @return 0 on success, -1 on failure
 */
int rsa_init(void);

/**
 * Build the Apple-Challenge response.
 *
 * Decodes the base64 challenge, appends our IP + MAC, pads to 32 bytes,
 * signs with RSA PKCS1 v1.5, and returns the base64-encoded response
 * (no trailing '=' padding).
 *
 * @param challenge_b64  Base64-encoded Apple-Challenge header value
 * @param ip_addr        Our IPv4 address in network byte order
 * @param mac            Our 6-byte MAC address
 * @param out_b64        Output buffer for base64-encoded response
 * @param out_b64_size   Size of output buffer (256 bytes is sufficient)
 * @return 0 on success, -1 on failure
 */
int rsa_apple_challenge_response(const char *challenge_b64, uint32_t ip_addr,
                                 const uint8_t mac[6], char *out_b64,
                                 size_t out_b64_size);

/**
 * Decrypt an RSA-encrypted AES key from ANNOUNCE SDP.
 *
 * The key is base64-encoded, RSA OAEP-SHA1 encrypted with the
 * well-known AirPlay public key. We decrypt with the private key.
 *
 * @param encrypted_b64  Base64-encoded RSA-encrypted AES key
 * @param out_key        Output buffer for decrypted AES key (16 bytes)
 * @param out_key_size   Size of output buffer
 * @param out_key_len    Actual decrypted key length
 * @return 0 on success, -1 on failure
 */
int rsa_decrypt_aes_key(const char *encrypted_b64, uint8_t *out_key,
                        size_t out_key_size, size_t *out_key_len);
