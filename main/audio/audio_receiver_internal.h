#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lwip/sockets.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "audio_buffer.h"
#include "audio_decoder.h"
#include "audio_receiver.h"
#include "audio_stream.h"
#include "audio_timing.h"

#define MAX_RTP_PACKET_SIZE 2048

typedef struct {
  audio_stream_t *stream;
  audio_stream_t *realtime_stream;
  audio_stream_t *buffered_stream;

  audio_decoder_t *decoder;
  audio_buffer_t buffer;
  audio_timing_t timing;

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
} audio_receiver_state_t;

bool audio_stream_process_frame(audio_receiver_state_t *state,
                                uint32_t timestamp, const uint8_t *audio_data,
                                size_t audio_len);

static inline audio_receiver_state_t *
audio_stream_state(audio_stream_t *stream) {
  return (audio_receiver_state_t *)stream->ctx;
}
