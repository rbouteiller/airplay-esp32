#pragma once

#include <stddef.h>
#include <stdint.h>

#include "rtsp_conn.h"
#include "rtsp_message.h"

/**
 * RTSP Method Handler Dispatch Table
 * Inspired by shairport-sync's method_handlers pattern
 */

// Key bits:
//   Bit 38: SupportsCoreUtilsPairingAndEncryption
//   Bit 46: SupportsHKPairingAndAccessControl
//   Bit 48: SupportsTransientPairing
#define AIRPLAY_FEATURES_HI 0x1C340
#define AIRPLAY_FEATURES_LO 0x405C4A00

// Audio buffer size for buffered streams (type 103)
#define AP2_AUDIO_BUFFER_SIZE (1 * 1024 * 1024)

// Include for audio_format_t
#include "audio_receiver.h"

/**
 * Codec registry entry
 */
typedef struct {
  const char *name; // Codec name: "ALAC", "AAC", "OPUS"
  int64_t type_id;  // bplist "ct" value (2=ALAC, 4=AAC, 8=AAC-ELD)
} rtsp_codec_t;

/**
 * Configure audio format from codec type ID
 * Looks up codec in registry and calls its configure function.
 * @param type_id Codec type from bplist "ct" field
 * @param fmt Audio format struct to configure
 * @param sample_rate Sample rate from bplist
 * @param samples_per_frame Samples per frame from bplist
 * @return true if codec found and configured, false otherwise
 */
bool rtsp_codec_configure(int64_t type_id, audio_format_t *fmt,
                          int64_t sample_rate, int64_t samples_per_frame);

/**
 * Handler function type
 */
typedef void (*rtsp_handler_fn)(int socket, rtsp_conn_t *conn,
                                const rtsp_request_t *req,
                                const uint8_t *raw_request, size_t raw_len);

/**
 * Method handler entry
 */
typedef struct {
  const char *method;
  rtsp_handler_fn handler;
} rtsp_method_handler_t;

/**
 * Dispatch RTSP request to appropriate handler
 * @param socket Client socket
 * @param conn Connection state
 * @param raw_request Raw request data
 * @param raw_len Length of raw request
 * @return 0 on success, -1 on error
 */
int rtsp_dispatch(int socket, rtsp_conn_t *conn, const uint8_t *raw_request,
                  size_t raw_len);

/**
 * Get device ID string (MAC address format)
 * @param device_id Output buffer (at least 18 bytes)
 * @param len Buffer size
 */
void rtsp_get_device_id(char *device_id, size_t len);

// Event port task management
void rtsp_start_event_port_task(int listen_socket);
void rtsp_stop_event_port_task(void);
