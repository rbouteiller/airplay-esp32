#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lwip/sockets.h"

#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "audio_buffer.h"
#include "audio_decode_worker.h"
#include "audio_decoder.h"
#include "audio_engine_v2.h"
#include "audio_packet.h"
#include "audio_receiver.h"
#include "audio_stream.h"
#include "audio_timing.h"

#define MAX_RTP_PACKET_SIZE 2048

/* Task stacks and ordinary malloc() need byte-addressable internal RAM.
 * MALLOC_CAP_INTERNAL on its own also counts the leftover IRAM that is added
 * to the heap, which is 32-bit access only, so it reports headroom no stack
 * can ever use. */
#define AUDIO_DRAM_CAPS (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)

typedef struct audio_receiver_state {
  audio_stream_t *stream;
  audio_stream_t *realtime_stream;
  audio_stream_t *buffered_stream;

  audio_decoder_t *decoder;
  audio_buffer_t buffer;
  audio_timing_t timing;

  // AirPlay 2 buffered path only.  Realtime (AirPlay 1) keeps using
  // buffer + timing above; the two are mutually exclusive at runtime.
  //
  // The engine owns ~790 KB of PSRAM, so it is created lazily on the first
  // buffered SETUP and then kept: tearing it down would race the playback
  // task that calls audio_engine_v2_render() on every I2S refill, and a
  // device that only ever serves AirPlay 1 never pays for it.
  audio_engine_v2_t engine_v2;
  bool engine_v2_ready;
  audio_decode_worker_t *decode_worker;
  // Serialises the stateful AAC decoder between the decode worker task and
  // audio_receiver_set_format()/stop(), which destroy and recreate it.
  SemaphoreHandle_t decoder_mutex;

  // AAC RTP continuity diagnostic for the buffered path: consecutive frames
  // must advance by exactly AUDIO_TIMELINE_FRAME_SAMPLES.
  uint32_t aac_diag_epoch;
  uint32_t aac_diag_last_rtp;
  bool aac_diag_rtp_valid;

  // Last SETRATEANCHORTIME, kept in the sender's PTP domain so it can be
  // re-armed once the PTP clock locks.  An anchor that arrives while the
  // offset is still 0 maps to a wrapped RTP position and must not be used.
  bool engine_v2_anchor_pending;
  // Which clock the anchor above is expressed in, taken from the timeline ID
  // the sender supplied.  PTP and NTP are unrelated absolute timelines, so
  // reading the offset from the other one puts the anchor decades away.
  bool engine_v2_anchor_uses_ptp;
  uint32_t engine_v2_anchor_rtp;
  uint64_t engine_v2_anchor_network_ns;
  int64_t engine_v2_playout_offset_ns;

  audio_stats_t stats;

  int data_socket;
  int control_socket;
  TaskHandle_t task_handle;
  TaskHandle_t control_task_handle;
  uint16_t data_port;
  uint16_t control_port;

  int buffered_listen_socket;
  int buffered_client_socket;
  uint16_t buffered_port;
  TaskHandle_t buffered_task_handle;
  uint8_t *buffered_recv_buffer;

  uint8_t *decrypt_buffer;
  size_t decrypt_buffer_size;

  uint64_t blocks_read;
  uint64_t blocks_read_in_sequence;

  // NACK retransmission support
  struct sockaddr_in client_control_addr; // Client's control address for NACKs
  bool retransmit_enabled;                // True when client address is set
  int64_t last_resend_error_time_us;      // Backoff timer on sendto failure
  bool rtp_sequence_valid;
  uint16_t resend_window_first;
  uint64_t resend_missing_mask;
  int64_t resend_last_request_time_us;

  // Post-seek RTP gates: together they form a window [discard_before_rtp,
  // discard_above_rtp] around the new anchor.  Frames outside the window are
  // discarded in audio_stream_process_frame before they enter the ring buffer,
  // preventing the stale-frame / repeated-bulk-flush loop.
  //
  //   discard_before_rtp — drop frames with RTP < anchor (forward-seek stale)
  //   discard_above_rtp  — drop frames with RTP > anchor+10s (backward-seek
  //                        stale, e.g. seek-to-start where old pre-buffer
  //                        frames have much higher RTP than the new anchor)
  //
  // Both are always armed together; whichever direction the seek went, one
  // gate fires and the other is harmless.  Each self-disarms on the first
  // frame that passes it (FIFO TCP order guarantees stale frames drain first).
  // Written by the RTSP task, read by the TCP buffered task — uint32_t write
  // is atomic on Xtensa; arm bool last so reader never sees stale threshold.
  uint32_t discard_before_rtp;
  bool discard_before_rtp_valid;
  uint32_t discard_above_rtp;
  bool discard_above_rtp_valid;
  // Set by audio_receiver_seek_flush() to ensure the gates are armed on the
  // next SETRATEANCHORTIME even when the buffer was already empty (forward
  // seek: flush empties buffer before anchor arrives, so seek detection in
  // set_anchor_time would otherwise find no oldest_rtp and skip arming).
  bool arm_gate_on_next_anchor;
  // Set by audio_receiver_seek_flush() to reject ALL incoming frames until
  // the next SETRATEANCHORTIME provides a valid anchor.  Without this, stale
  // TCP data (from the old track still draining the socket buffer) fills the
  // ring buffer between FLUSHBUFFERED and the anchor, causing a second flush
  // and doubling the startup delay.
  bool discard_all_until_anchor;

  // Snapshot of the expected RTP position taken the moment the sender signals
  // PAUSE (SETRATEANCHORTIME rate=0).  Path B in audio_receiver_set_anchor_time
  // uses this as the reference when comparing the new anchor on RESUME, so
  // that a long pause does not make the wall-clock-elapsed estimate overshoot
  // by (pause_duration × sample_rate) and false-trigger a seek flush.
  // Cleared on flush/reset and consumed after one use.
  uint32_t paused_rtp;
  bool paused_rtp_valid;
} audio_receiver_state_t;

// Lightweight RTP gate used by the buffered TCP task before decrypt/decode.
// Returns false for frames that belong to the pre-seek/old-track backlog.
bool audio_stream_accept_timestamp(audio_receiver_state_t *state,
                                   uint32_t timestamp);

// Decode and queue a frame whose timestamp has already passed the RTP gate.
bool audio_stream_process_accepted_frame(audio_receiver_state_t *state,
                                         uint32_t timestamp,
                                         const uint8_t *audio_data,
                                         size_t audio_len);

// True when the next decoded AAC frame is a post-seek/resume priming frame and
// must be silenced.  Read where the block counters are advanced, because the
// buffered path advances them on the TCP reader and decodes elsewhere.
bool audio_stream_aac_prime_mute_wanted(const audio_receiver_state_t *state);

// Buffered path: decode one encoded access unit and publish the PCM into the
// engine timeline.  Runs on the decode worker task.
bool audio_stream_decode_encoded_packet(audio_receiver_state_t *state,
                                        const audio_encoded_packet_t *packet);

// Convenience entry point for realtime paths: gate, then decode and queue.
bool audio_stream_process_frame(audio_receiver_state_t *state,
                                uint32_t timestamp, const uint8_t *audio_data,
                                size_t audio_len);

static inline audio_receiver_state_t *
audio_stream_state(audio_stream_t *stream) {
  return (audio_receiver_state_t *)stream->ctx;
}
