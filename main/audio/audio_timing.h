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
  uint32_t frame_counter;      // For subtle timing adjustments (1 in N frames)
  int64_t drift_accumulator;   // Accumulated drift in microseconds
  uint32_t drift_frame_count;  // Frames counted for drift calculation
} audio_timing_t;

void audio_timing_init(audio_timing_t *timing, size_t pending_capacity);
void audio_timing_reset(audio_timing_t *timing);
void audio_timing_set_format(audio_timing_t *timing,
                             const audio_format_t *format);
void audio_timing_set_output_latency(audio_timing_t *timing,
                                     const audio_format_t *format,
                                     uint32_t latency_us);
uint32_t audio_timing_get_output_latency(const audio_timing_t *timing);
void audio_timing_set_anchor(audio_timing_t *timing,
                             const audio_format_t *format, uint64_t clock_id,
                             uint64_t network_time_ns, uint32_t rtp_time);
void audio_timing_set_playing(audio_timing_t *timing, bool playing);
size_t audio_timing_read(audio_timing_t *timing, audio_buffer_t *buffer,
                         const audio_stream_t *stream, audio_stats_t *stats,
                         int16_t *out, size_t samples);
