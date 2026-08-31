#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Immutable metadata carried with one compressed audio access unit from
 * ingress through decrypt/decode.  Keeping the epoch beside the RTP timestamp
 * closes the gap where a seek/flush can occur after a packet passes the RTP
 * gate but before its decoder work completes. */
typedef struct {
  uint32_t epoch;
  uint32_t rtp_timestamp;
  const uint8_t *payload;
  size_t payload_len;
  /* Sampled at ingress, where the block counters are coherent: by the time the
   * decode worker reaches this packet the reader has already counted the ones
   * behind it, so the worker cannot re-derive whether this is a priming frame
   * that must be silenced. */
  bool prime_mute;
} audio_encoded_packet_t;
