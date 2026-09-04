#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "audio_packet.h"

typedef struct audio_decode_worker audio_decode_worker_t;
struct audio_receiver_state;

esp_err_t audio_decode_worker_create(struct audio_receiver_state *state,
                                     audio_decode_worker_t **out_worker);
void audio_decode_worker_destroy(audio_decode_worker_t *worker);

typedef enum {
  AUDIO_DECODE_ENQUEUE_OK = 0,
  AUDIO_DECODE_ENQUEUE_RETRY,
  AUDIO_DECODE_ENQUEUE_DROP,
} audio_decode_enqueue_result_t;

audio_decode_enqueue_result_t
audio_decode_worker_enqueue(audio_decode_worker_t *worker,
                            const audio_encoded_packet_t *packet,
                            uint32_t timeout_ms);
void audio_decode_worker_discard_pending(audio_decode_worker_t *worker);
size_t audio_decode_worker_pending(const audio_decode_worker_t *worker);
bool audio_decode_worker_is_nearly_full(const audio_decode_worker_t *worker);
