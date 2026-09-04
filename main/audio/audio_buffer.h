#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* Scratch space shared by the ALAC and AAC decoders.
 *
 * This module used to own a 1000-slot PCM ring in PSRAM as well, sorted by RTP
 * timestamp and consumed from the front.  Playback now runs entirely off the
 * RTP-addressed timeline in audio_timeline.c, which stores decoded audio
 * itself, so all that is left here is the staging area a decoder writes into
 * before its PCM is pushed to the timeline. */

#define AUDIO_MAX_CHANNELS     2
#define AUDIO_BYTES_PER_SAMPLE 2
/* Large enough for any frame either codec produces (AAC is 1024, ALAC 352). */
#define MAX_SAMPLES_PER_FRAME 4096

typedef struct {
  int16_t *decode_buffer;
  size_t decode_capacity_samples;
} audio_buffer_t;

esp_err_t audio_buffer_init(audio_buffer_t *buffer);
void audio_buffer_deinit(audio_buffer_t *buffer);
int16_t *audio_buffer_get_decode_buffer(audio_buffer_t *buffer,
                                        size_t *capacity_samples);
