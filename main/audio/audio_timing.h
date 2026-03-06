#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "audio_buffer.h"
#include "audio_receiver.h"
#include "audio_stream.h"

typedef struct {
  uint32_t output_latency_us;
  uint32_t target_buffer_frames;
  uint32_t nominal_frame_samples;
  bool playout_started;
  bool playing;
  bool anchor_valid;
  uint64_t anchor_network_time_ns;
  uint32_t anchor_rtp_time;
  int64_t anchor_local_time_ns;
  int64_t ready_time_us; // When buffer became ready (0 = not ready yet)
  bool ptp_locked;
  uint8_t *pending_frame;
  size_t pending_frame_len;
  size_t pending_frame_capacity;
  bool pending_valid;
  // Early-frame guard: counts consecutive early frames to detect a stuck
  // anchor. Reset whenever a new anchor is set or a late/on-time frame is
  // played.
  int consecutive_early_frames;
  // Late-frame guard: counts consecutive individually-late frames.  When this
  // exceeds MAX_CONSECUTIVE_LATE the whole buffer is considered stale (e.g.
  // after a track skip where the anchor network_time has already passed) and a
  // bulk flush is triggered instead of draining frame-by-frame.
  int consecutive_late_frames;
  // Post-seek/skip flag: set by audio_receiver_seek_flush() via
  // audio_timing_t so that audio_timing_read plays frames immediately rather
  // than silencing them during the phone's pre-buffer window (which can be
  // several seconds).  Cleared automatically after POST_FLUSH_TIMEOUT_US of
  // real-time playback so normal timing re-engages and frames are held until
  // their scheduled play point.
  bool post_flush;
  int64_t post_flush_start_us; // esp_timer_get_time() when post_flush began
  // Deferred flush (AirPlay 2 FLUSHBUFFERED with flushFromSeq present):
  // keep playing until a frame with rtp_timestamp >= flush_until_ts arrives,
  // then bulk-flush and start fresh.  Written by the RTSP task, read by the
  // DMA callback task.  Aligned 32-bit + bool — atomic on Xtensa without a
  // mutex (write flush_until_ts first, arm bool second; read bool first).
  bool deferred_flush_pending;
  uint32_t flush_until_ts;
} audio_timing_t;

void audio_timing_init(audio_timing_t *timing, size_t pending_capacity);
void audio_timing_reset(audio_timing_t *timing);
void audio_timing_set_format(audio_timing_t *timing,
                             const audio_format_t *format);
void audio_timing_set_output_latency(audio_timing_t *timing,
                                     const audio_format_t *format,
                                     uint32_t latency_us);
uint32_t audio_timing_get_output_latency(const audio_timing_t *timing);
uint32_t audio_timing_get_hardware_latency(void);
void audio_timing_set_anchor(audio_timing_t *timing,
                             const audio_format_t *format, uint64_t clock_id,
                             uint64_t network_time_ns, uint32_t rtp_time);
void audio_timing_set_playing(audio_timing_t *timing, bool playing);
size_t audio_timing_read(audio_timing_t *timing, audio_buffer_t *buffer,
                         const audio_stream_t *stream, audio_stats_t *stats,
                         int16_t *out, size_t samples);
