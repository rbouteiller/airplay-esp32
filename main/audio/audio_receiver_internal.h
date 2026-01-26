#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
} audio_receiver_state_t;

bool audio_stream_process_frame(audio_receiver_state_t *state,
                                uint32_t timestamp, const uint8_t *audio_data,
                                size_t audio_len);

static inline audio_receiver_state_t *audio_stream_state(audio_stream_t *stream) {
  return (audio_receiver_state_t *)stream->ctx;
}
