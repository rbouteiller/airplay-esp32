#pragma once

#include <stddef.h>
#include <stdint.h>

/**
 * FairPlay handshake handling for AirPlay 2
 * Contains pre-computed static response tables
 */

#define FP_REPLY_SIZE        142
#define FP_HEADER_SIZE       12
#define FP_SETUP2_SUFFIX_LEN 20

/**
 * Handle FairPlay setup request
 * @param body Request body from POST /fp-setup
 * @param body_len Length of request body
 * @param response Output buffer for response (caller must free if *response !=
 * NULL)
 * @param response_len Output: length of response
 * @return 0 on success, -1 on error
 */
int rtsp_fairplay_handle(const uint8_t *body, size_t body_len,
                         uint8_t **response, size_t *response_len);
