#include <stdlib.h>
#include <string.h>

#include "audio_stream.h"

#include "audio_buffer.h"
#include "audio_decoder.h"
#include "audio_receiver_internal.h"

extern const audio_stream_ops_t audio_stream_realtime_ops;
extern const audio_stream_ops_t audio_stream_buffered_ops;

static bool apply_aac_transient_mute(audio_receiver_state_t *state,
                                     int16_t *buffer, size_t samples,
                                     int channels) {
  if (!audio_decoder_is_aac(state->decoder)) {
    return false;
  }

  if ((state->blocks_read_in_sequence <= 2) &&
      (state->blocks_read_in_sequence != state->blocks_read)) {
    memset(buffer, 0, samples * channels * sizeof(int16_t));
    return true;
  }

  return false;
}

bool audio_stream_process_frame(audio_receiver_state_t *state,
                                uint32_t timestamp, const uint8_t *audio_data,
                                size_t audio_len) {
  if (!state || !state->decoder) {
    return false;
  }

  size_t capacity_samples = 0;
  int16_t *decode_buffer =
      audio_buffer_get_decode_buffer(&state->buffer, &capacity_samples);
  if (!decode_buffer || capacity_samples == 0) {
    return false;
  }

  audio_decode_info_t info = {0};
  int decoded_samples =
      audio_decoder_decode(state->decoder, audio_data, audio_len, decode_buffer,
                           capacity_samples, &info);
  if (decoded_samples <= 0) {
    return false;
  }

  int channels =
      info.channels > 0 ? info.channels : state->stream->format.channels;
  if (channels <= 0) {
    channels = 2;
  }

  apply_aac_transient_mute(state, decode_buffer, (size_t)decoded_samples,
                           channels);

  return audio_buffer_queue_decoded(&state->buffer, &state->stats, timestamp,
                                    decode_buffer, (size_t)decoded_samples,
                                    channels);
}

audio_stream_t *audio_stream_create_realtime(void) {
  audio_stream_t *stream = calloc(1, sizeof(*stream));
  if (!stream) {
    return NULL;
  }

  stream->ops = &audio_stream_realtime_ops;
  stream->type = AUDIO_STREAM_REALTIME;
  return stream;
}

audio_stream_t *audio_stream_create_buffered(void) {
  audio_stream_t *stream = calloc(1, sizeof(*stream));
  if (!stream) {
    return NULL;
  }

  stream->ops = &audio_stream_buffered_ops;
  stream->type = AUDIO_STREAM_BUFFERED;
  return stream;
}

void audio_stream_destroy(audio_stream_t *stream) {
  if (!stream) {
    return;
  }

  if (stream->ops && stream->ops->destroy) {
    stream->ops->destroy(stream);
    return;
  }

  free(stream);
}

bool audio_stream_uses_buffer(audio_stream_type_t type) {
  return type == AUDIO_STREAM_BUFFERED;
}
