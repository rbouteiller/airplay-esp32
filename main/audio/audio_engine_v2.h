#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "audio_clock_map.h"
#include "audio_epoch.h"
#include "audio_receiver.h"
#include "audio_scheduler.h"
#include "audio_timeline.h"

typedef struct {
  audio_epoch_t epoch;
  audio_timeline_t timeline;
  audio_clock_map_t clock_map;
  audio_scheduler_t scheduler;
  audio_format_t format;
  bool initialized;
  bool playing;
  uint64_t blocks_inserted;
  uint64_t blocks_rejected;
  uint64_t concealed_samples;
  int64_t last_status_log_us;
  uint64_t conceal_events;
  /* Conceal activity since the last status log, so the render path never has
   * to format a message itself. */
  uint64_t conceal_events_logged;
  uint32_t drift_servo_trims_logged;
  uint32_t last_conceal_gap_rtp;

  /* Per-epoch ingress/decode diagnostics. Atomic increments are used because
   * buffered RX, decoder worker and audio output run on different tasks. */
  uint64_t diag_rx_packets;
  uint64_t diag_gate_drops;
  uint64_t diag_enqueue_ok;
  uint64_t diag_enqueue_retries;
  uint64_t diag_queue_drops;
  uint64_t diag_dequeued;
  uint64_t diag_epoch_drops;
  uint64_t diag_decode_ok;
  uint64_t diag_decode_fail;
  uint64_t diag_pcm_inserted;

  /* One-shot startup watchdog. Armed by a valid anchor and cleared as soon
   * as the scheduler reaches PLAYING. It is diagnostic only and never changes
   * scheduler, timeline, RTP gate, decoder, or I2S behavior. */
  bool start_watchdog_armed;
  int64_t start_watchdog_anchor_us;
  uint32_t start_watchdog_epoch;
  uint32_t start_watchdog_anchor_rtp;

  /* Short publication gate shared by epoch changes and PCM insertion. */
  portMUX_TYPE publish_lock;
} audio_engine_v2_t;

esp_err_t audio_engine_v2_init(audio_engine_v2_t *engine,
                               const audio_format_t *format,
                               uint32_t frame_samples, uint16_t capacity);
void audio_engine_v2_deinit(audio_engine_v2_t *engine);
uint32_t audio_engine_v2_begin_epoch(audio_engine_v2_t *engine, int64_t now_us);
void audio_engine_v2_set_format(audio_engine_v2_t *engine,
                                const audio_format_t *format);
/* Switch codecs on the shared slot pool.  Discards anything held, so call it
 * at stream start, before PCM for the new stream arrives. */
bool audio_engine_v2_set_frame_samples(audio_engine_v2_t *engine,
                                       uint32_t frame_samples);
bool audio_engine_v2_set_anchor(audio_engine_v2_t *engine, uint32_t anchor_rtp,
                                uint64_t anchor_network_ns,
                                int64_t playout_offset_ns);
// Invalidate the current clock map without discarding buffered PCM. Used when
// an anchor is known but the matching network clock has not locked yet.
void audio_engine_v2_wait_for_anchor(audio_engine_v2_t *engine, int64_t now_us);
void audio_engine_v2_set_playing(audio_engine_v2_t *engine, bool playing);
bool audio_engine_v2_is_nearly_full(audio_engine_v2_t *engine);

/* AirPlay 2 deferred FLUSHBUFFERED.  Drops buffered PCM from `flush_rtp`
 * onwards while leaving earlier audio, the epoch and the clock map intact, so
 * the outgoing track plays out to the boundary and the replacement content
 * continues on the same timeline without waiting for a new anchor. */
size_t audio_engine_v2_deferred_flush(audio_engine_v2_t *engine, uint32_t epoch,
                                      uint32_t flush_rtp);

bool audio_engine_v2_push_pcm(audio_engine_v2_t *engine, uint32_t epoch,
                              uint32_t first_rtp, const int16_t *pcm,
                              size_t samples, uint8_t channels);

/* Buffered streams must never discard a decoded packet merely because the PCM
 * timeline is temporarily full.  This variant blocks until the consumer frees
 * a slot, aborting immediately if the stream epoch changes.  timeout_ms is a
 * hard bound: an unbounded wait would leave the decode task unresponsive to
 * teardown while a paused scheduler holds the timeline full. */
bool audio_engine_v2_push_pcm_wait(audio_engine_v2_t *engine, uint32_t epoch,
                                   uint32_t first_rtp, const int16_t *pcm,
                                   size_t samples, uint8_t channels,
                                   uint32_t timeout_ms);

size_t audio_engine_v2_render(audio_engine_v2_t *engine,
                              int64_t output_network_ns, int16_t *out,
                              size_t samples);
