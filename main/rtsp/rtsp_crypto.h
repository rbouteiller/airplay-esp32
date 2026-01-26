#pragma once

#include <stddef.h>
#include <stdint.h>

#include "rtsp_conn.h"

/**
 * RTSP Encrypted Communication
 * Handles ChaCha20-Poly1305 encrypted frame read/write
 */

// Maximum size of an encrypted block
#define RTSP_ENCRYPTED_BLOCK_MAX 0x400

/**
 * Read and decrypt a block from socket
 * Format: [2-byte length (little-endian)][encrypted data + 16-byte tag]
 *
 * @param socket Client socket
 * @param conn Connection state (must have hap_session and encrypted_mode)
 * @param buffer Output buffer for decrypted data
 * @param buffer_size Size of output buffer
 * @return Decrypted length on success, -1 on error
 */
int rtsp_crypto_read_block(int socket, rtsp_conn_t *conn,
                           uint8_t *buffer, size_t buffer_size);

/**
 * Encrypt and write data to socket
 * Splits into multiple blocks if needed (max RTSP_ENCRYPTED_BLOCK_MAX each)
 * Format: [2-byte length (little-endian)][encrypted data + 16-byte tag]
 *
 * @param socket Client socket
 * @param conn Connection state (must have hap_session and encrypted_mode)
 * @param data Data to encrypt and send
 * @param data_len Length of data
 * @return 0 on success, -1 on error
 */
int rtsp_crypto_write_frame(int socket, rtsp_conn_t *conn,
                            const uint8_t *data, size_t data_len);
