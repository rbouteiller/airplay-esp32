#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "audio_stream.h"

#include "esp_log.h"

#include "audio_buffer.h"
#include "audio_decoder.h"
#include "audio_receiver_internal.h"

// Upper bound on how long a decoded frame waits for timeline space.  Sized to
// outlast a full drain of the ring (~4.5 s of PCM): a gapless track change can
// shift RTP phase mid-epoch, and the timeline can only adopt the new phase once
// the outgoing track has played out.  Waiting that long keeps the incoming
// track intact; past it the packet is dropped so the decode task stays
// responsive to teardown.  Flush and teardown break the wait early by bumping
// the epoch, so this bound is only reached when the sender really is ahead.
#define AUDIO_DECODE_PUSH_TIMEOUT_MS 6000U

static const char *TAG = "audio_stream";

extern const audio_stream_ops_t audio_stream_realtime_ops;
extern const audio_stream_ops_t audio_stream_buffered_ops;

// The first frames after a resume or seek come out of the AAC decoder with the
// tail of the previous track still in its overlap buffers, so they are
// silenced.  A fresh start needs no priming, which is what the second test
// picks out: only a restart leaves the in-sequence count behind the total.
//
// Sampled where the counters are advanced, which for the buffered path is the
// TCP reader rather than the decode worker.
bool audio_stream_aac_prime_mute_wanted(const audio_receiver_state_t *state) {
  return state && (state->blocks_read_in_sequence <= 2) &&
         (state->blocks_read_in_sequence != state->blocks_read);
}

static bool apply_aac_transient_mute(audio_receiver_state_t *state, bool wanted,
                                     int16_t *buffer, size_t samples,
                                     int channels) {
  if (!wanted || !audio_decoder_is_aac(state->decoder)) {
    return false;
  }

  memset(buffer, 0, samples * channels * sizeof(int16_t));
  return true;
}

bool audio_stream_accept_timestamp(audio_receiver_state_t *state,
                                   uint32_t timestamp) {
  if (!state) {
    return false;
  }

  // Blanket gate: reject everything between seek_flush and the next anchor.
  // Deliberately checked before decrypt/decode in the buffered TCP task so
  // old-track backlog is drained from the socket without decoder CPU or PCM
  // ring use.
  if (state->discard_all_until_anchor) {
    return false;
  }

  // Post-seek RTP window gate: discard frames outside [discard_before_rtp,
  // discard_above_rtp].  The TCP socket buffer can hold many seconds of
  // pre-seek audio; both gates together handle both seek directions:
  //   discard_before_rtp — forward seek: stale frames have lower RTP
  //   discard_above_rtp  — backward seek: stale frames have much higher RTP
  // Each self-disarms on the first frame that passes it.
  if (state->discard_before_rtp_valid) {
    if ((int32_t)(timestamp - state->discard_before_rtp) < 0) {
      return false; // below lower bound — forward-seek stale frame
    }
    state->discard_before_rtp_valid = false;
  }
  if (state->discard_above_rtp_valid) {
    if ((int32_t)(timestamp - state->discard_above_rtp) > 0) {
      return false; // above upper bound — backward-seek stale frame
    }
    state->discard_above_rtp_valid = false;
  }

  return true;
}

// Read-only variant of the RTP gate used for the post-decode re-check.  Unlike
// audio_stream_accept_timestamp() it does NOT disarm the window gates on a
// passing frame — disarming is the job of the ordered pre-decode pass.  If a
// concurrent seek armed a window gate while this frame was mid-decode and the
// frame happens to fall inside the new window, disarming here would clear the
// gate and let subsequent stale TCP backlog through.  This check only reports
// whether the frame must be dropped.
static bool timestamp_is_gated(const audio_receiver_state_t *state,
                               uint32_t timestamp) {
  if (state->discard_all_until_anchor) {
    return true;
  }
  if (state->discard_before_rtp_valid &&
      (int32_t)(timestamp - state->discard_before_rtp) < 0) {
    return true;
  }
  if (state->discard_above_rtp_valid &&
      (int32_t)(timestamp - state->discard_above_rtp) > 0) {
    return true;
  }
  return false;
}

// Split a decoded packet across timeline blocks, so a sender whose packet
// length differs from the SDP frame length still lands somewhere.
static bool audio_stream_push_timeline_pcm(audio_receiver_state_t *state,
                                           uint32_t timestamp,
                                           const int16_t *pcm, size_t samples,
                                           int channels) {
  const size_t frame_samples = state->engine_v2.timeline.frame_samples;
  const uint32_t epoch = audio_epoch_get(&state->engine_v2.epoch);
  bool pushed = false;

  for (size_t offset = 0; offset < samples; offset += frame_samples) {
    size_t chunk = samples - offset;
    if (chunk > frame_samples) {
      chunk = frame_samples;
    }
    // Must not block: this runs on the UDP rx task, which drops packets while
    // it is not reading the socket.
    if (audio_engine_v2_push_pcm(
            &state->engine_v2, epoch, timestamp + (uint32_t)offset,
            &pcm[offset * (size_t)channels], chunk, (uint8_t)channels)) {
      pushed = true;
    }
  }
  return pushed;
}

bool audio_stream_process_accepted_frame(audio_receiver_state_t *state,
                                         uint32_t timestamp,
                                         const uint8_t *audio_data,
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

  apply_aac_transient_mute(state, audio_stream_aac_prime_mute_wanted(state),
                           decode_buffer, (size_t)decoded_samples, channels);

  // Re-check the gates after decode.  A concurrent seek/anchor flush (RTSP
  // task) can set discard_all_until_anchor OR arm the RTP window gates
  // (discard_before_rtp / discard_above_rtp, Path B) and flush the ring while
  // this frame was being decrypted/decoded.  Use the read-only predicate so a
  // stale mid-flight frame is dropped without disarming a gate a concurrent
  // seek just armed (which would let later backlog through).
  if (timestamp_is_gated(state, timestamp)) {
    return false;
  }

  // Deferred FLUSHBUFFERED boundary, as the buffered decode path applies it.
  // audio_timing_read() used to own this for the realtime stream; the check
  // has to live wherever the PCM is queued now.
  uint32_t flush_until_ts = 0;
  if (audio_timing_take_deferred_flush(&state->timing, timestamp,
                                       &flush_until_ts)) {
    (void)audio_engine_v2_deferred_flush(
        &state->engine_v2, audio_epoch_get(&state->engine_v2.epoch),
        flush_until_ts);
    state->blocks_read_in_sequence = 0;
  }

  state->stats.packets_decoded++;
  return audio_stream_push_timeline_pcm(state, timestamp, decode_buffer,
                                        (size_t)decoded_samples, channels);
}

bool audio_stream_process_frame(audio_receiver_state_t *state,
                                uint32_t timestamp, const uint8_t *audio_data,
                                size_t audio_len) {
  if (!audio_stream_accept_timestamp(state, timestamp)) {
    return false;
  }
  return audio_stream_process_accepted_frame(state, timestamp, audio_data,
                                             audio_len);
}

bool audio_stream_decode_encoded_packet(audio_receiver_state_t *state,
                                        const audio_encoded_packet_t *packet) {
  if (!state || !packet || !packet->payload || packet->payload_len == 0) {
    return false;
  }

  // The decoder is destroyed and recreated by audio_receiver_set_format() on
  // the RTSP task, so the worker must hold the mutex across the whole decode.
  if (!state->decoder_mutex ||
      xSemaphoreTake(state->decoder_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
    return false;
  }

  if (!state->decoder || !state->engine_v2_ready ||
      !audio_epoch_matches(&state->engine_v2.epoch, packet->epoch)) {
    xSemaphoreGive(state->decoder_mutex);
    return false;
  }

  // Shared scratch with the realtime path.  Only one of the two stream types
  // is ever active, so there is no contention for it.
  size_t capacity_samples = 0;
  int16_t *decode_buffer =
      audio_buffer_get_decode_buffer(&state->buffer, &capacity_samples);
  if (!decode_buffer || capacity_samples == 0) {
    xSemaphoreGive(state->decoder_mutex);
    return false;
  }

  audio_decode_info_t info = {0};
  const int decoded_samples =
      audio_decoder_decode(state->decoder, packet->payload, packet->payload_len,
                           decode_buffer, capacity_samples, &info);
  if (decoded_samples <= 0) {
    (void)__atomic_add_fetch(&state->engine_v2.diag_decode_fail, 1U,
                             __ATOMIC_RELAXED);
    xSemaphoreGive(state->decoder_mutex);
    return false;
  }

  int channels =
      info.channels > 0 ? info.channels : state->stream->format.channels;
  if (channels <= 0) {
    channels = 2;
  }

  apply_aac_transient_mute(state, packet->prime_mute, decode_buffer,
                           (size_t)decoded_samples, channels);
  xSemaphoreGive(state->decoder_mutex);

  (void)__atomic_add_fetch(&state->engine_v2.diag_decode_ok, 1U,
                           __ATOMIC_RELAXED);

  // Decoded frames must advance by exactly one timeline frame.  A break means a
  // packet was lost or reordered, which the timeline will show as a hole.
  const uint32_t frame_samples = state->engine_v2.timeline.frame_samples;
  if (state->aac_diag_rtp_valid && state->aac_diag_epoch == packet->epoch) {
    const int32_t delta =
        (int32_t)(packet->rtp_timestamp - state->aac_diag_last_rtp);
    if (delta != (int32_t)frame_samples) {
      ESP_LOGW(TAG,
               "RTP step %" PRId32 " at rtp=%" PRIu32 " (expected %" PRIu32 ")",
               delta, packet->rtp_timestamp, frame_samples);
    }
  }
  state->aac_diag_epoch = packet->epoch;
  state->aac_diag_last_rtp = packet->rtp_timestamp;
  state->aac_diag_rtp_valid = true;

  // Deferred FLUSHBUFFERED boundary: cut the timeline here so this packet and
  // its successors replace the tail of the outgoing track.  Applied before the
  // push so the freed slots are immediately reusable.
  uint32_t flush_until_ts = 0;
  if (audio_timing_take_deferred_flush(&state->timing, packet->rtp_timestamp,
                                       &flush_until_ts)) {
    (void)audio_engine_v2_deferred_flush(&state->engine_v2, packet->epoch,
                                         flush_until_ts);
    state->blocks_read_in_sequence = 0;
  }

  // Re-check the gates: a concurrent seek can have armed them while this
  // frame was in the decoder.
  if (timestamp_is_gated(state, packet->rtp_timestamp)) {
    return false;
  }

  if (!audio_engine_v2_push_pcm_wait(&state->engine_v2, packet->epoch,
                                     packet->rtp_timestamp, decode_buffer,
                                     (size_t)decoded_samples, (uint8_t)channels,
                                     AUDIO_DECODE_PUSH_TIMEOUT_MS)) {
    return false;
  }

  // The arrival was already counted by the TCP reader that enqueued it; this
  // path owns the decode side of the tally.
  state->stats.packets_decoded++;
  return true;
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
