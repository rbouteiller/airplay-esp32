#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "audio_receiver.h"

/* Stream timing state.
 *
 * This used to be a playout engine as well: audio_timing_read() pulled frames
 * off the sorted buffer, gated them on an early/late window, drained stale
 * ones and ran a position servo.  Playback now lives in audio_scheduler.c,
 * which computes position from the RTP-addressed timeline instead of
 * discovering it, so what is left here is the state the RTSP layer sets and
 * the engine reads: the sender's anchor, the latency figures advertised in
 * SETUP, and the deferred-flush handshake. */
typedef struct {
  uint32_t output_latency_us;
  bool playing;
  bool anchor_valid;
  uint64_t anchor_network_time_ns;
  uint32_t anchor_rtp_time;
  int64_t anchor_local_time_ns;
  bool ptp_locked;
  // Stream playout latency in samples, added to every frame's scheduled
  // play time.  Realtime streams (type 96): the anchor maps RTP onto the
  // sender's source timeline and playout happens latencyMin samples later
  // (11025 = 250 ms unless SETUP says otherwise).  Buffered streams
  // (type 103): 0 — the anchor is the play time.  Set at stream SETUP;
  // survives audio_timing_reset() because it is stream configuration, not
  // playback state.
  uint32_t playout_latency_samples;
  // Deferred flush (AirPlay 2 FLUSHBUFFERED with flushFromSeq present):
  // keep playing until a frame with rtp_timestamp >= flush_until_ts arrives,
  // then bulk-flush and start fresh.  Written by the RTSP task, read by the
  // DMA callback task.  Aligned 32-bit + bool — atomic on Xtensa without a
  // mutex (write flush_until_ts first, arm bool second; read bool first).
  bool deferred_flush_pending;
  uint32_t flush_until_ts;
} audio_timing_t;

void audio_timing_init(audio_timing_t *timing);
void audio_timing_reset(audio_timing_t *timing);
void audio_timing_set_output_latency(audio_timing_t *timing,
                                     uint32_t latency_us);
uint32_t audio_timing_get_output_latency(const audio_timing_t *timing);
uint32_t audio_timing_get_hardware_latency(void);
// Total end-to-end latency (output target + HW DMA + fixed pipeline delay).
//
// DIAGNOSTIC ONLY — do NOT wire this into outputLatencyMicros.
// rtsp_handlers.c deliberately advertises 0 for both inputLatencyMicros and
// outputLatencyMicros because compute_early_us() already compensates for the
// hardware and pipeline delay internally; advertising a non-zero value makes
// the sender adjust its anchor as well and the delay is applied twice.
// shairport-sync likewise advertises no audioLatencies.
//
// Note also that this figure does not include the sender-driven pre-buffer
// actually sitting in the jitter buffer during playback (frequently 1.5 s+),
// so it is not the true end-to-end delay either. Use it for logging and
// introspection, not for protocol negotiation.
uint32_t audio_timing_get_advertised_latency(const audio_timing_t *timing);
// Set the stream playout latency (samples).  See playout_latency_samples.
void audio_timing_set_playout_latency(audio_timing_t *timing,
                                      uint32_t latency_samples);
void audio_timing_set_anchor(audio_timing_t *timing,
                             const audio_format_t *format, uint64_t clock_id,
                             uint64_t network_time_ns, uint32_t rtp_time);
void audio_timing_set_playing(audio_timing_t *timing, bool playing);

// Consume a pending deferred flush if `timestamp` has reached the boundary.
// Returns true exactly once per armed flush and stores the boundary in
// *flush_until_ts.  Applied by the decode task as the frames go past.
bool audio_timing_take_deferred_flush(audio_timing_t *timing,
                                      uint32_t timestamp,
                                      uint32_t *flush_until_ts);
