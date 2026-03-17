#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "audio_receiver.h"

#include "esp_heap_caps.h"
#include "esp_log.h"

#include "audio_buffer.h"
#include "audio_decoder.h"
#include "audio_output.h"
#include "audio_receiver_internal.h"
#include "audio_stream.h"
#include "audio_timing.h"
#include "ptp_clock.h"

#define DEFAULT_SAMPLE_RATE     44100
#define DEFAULT_CHANNELS        2
#define DEFAULT_BITS_PER_SAMPLE 16
#define DEFAULT_FRAME_SIZE      352
#define DECRYPT_BUFFER_SIZE     8192

static const char *TAG = "audio_recv";

static audio_receiver_state_t receiver = {0};

static void audio_receiver_reset_stats(void) {
  memset(&receiver.stats, 0, sizeof(receiver.stats));
}

static void audio_receiver_reset_blocks(void) {
  receiver.blocks_read = 0;
  receiver.blocks_read_in_sequence = 0;
}

static void audio_receiver_copy_stream_state(audio_stream_t *dst,
                                             const audio_stream_t *src) {
  if (!dst || !src) {
    return;
  }

  dst->format = src->format;
  dst->encrypt = src->encrypt;
}

esp_err_t audio_receiver_init(void) {
  if (receiver.buffer.pool) {
    return ESP_OK;
  }

  receiver.realtime_stream = audio_stream_create_realtime();
  if (receiver.realtime_stream) {
    receiver.realtime_stream->ctx = &receiver;
  }
  receiver.buffered_stream = audio_stream_create_buffered();
  if (receiver.buffered_stream) {
    receiver.buffered_stream->ctx = &receiver;
  }
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    ESP_LOGE(TAG, "Failed to allocate audio streams");
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return ESP_ERR_NO_MEM;
  }

  receiver.stream = receiver.realtime_stream;

  audio_format_t default_format = {0};
  strcpy(default_format.codec, "AppleLossless");
  default_format.sample_rate = DEFAULT_SAMPLE_RATE;
  default_format.channels = DEFAULT_CHANNELS;
  default_format.bits_per_sample = DEFAULT_BITS_PER_SAMPLE;
  default_format.frame_size = DEFAULT_FRAME_SIZE;

  receiver.realtime_stream->format = default_format;
  receiver.buffered_stream->format = default_format;

  esp_err_t err = audio_buffer_init(&receiver.buffer);
  if (err != ESP_OK) {
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return err;
  }

  receiver.decrypt_buffer_size = DECRYPT_BUFFER_SIZE;
#ifdef CONFIG_SPIRAM
  receiver.decrypt_buffer = heap_caps_malloc(
      receiver.decrypt_buffer_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
  if (!receiver.decrypt_buffer) {
    receiver.decrypt_buffer = malloc(receiver.decrypt_buffer_size);
  }
  if (!receiver.decrypt_buffer) {
    ESP_LOGE(TAG, "Failed to allocate decrypt buffer");
    audio_buffer_deinit(&receiver.buffer);
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return ESP_ERR_NO_MEM;
  }

  size_t pending_capacity =
      sizeof(audio_frame_header_t) +
      ((size_t)MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS * sizeof(int16_t));
  audio_timing_init(&receiver.timing, pending_capacity);
  audio_timing_set_format(&receiver.timing, &receiver.stream->format);

  receiver.buffered_listen_socket = -1;
  receiver.buffered_client_socket = -1;

  audio_receiver_reset_blocks();

  return ESP_OK;
}

void audio_receiver_set_format(const audio_format_t *format) {
  if (!format) {
    return;
  }
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    return;
  }

  receiver.realtime_stream->format = *format;
  receiver.buffered_stream->format = *format;

  audio_decoder_destroy(receiver.decoder);
  receiver.decoder = NULL;

  audio_decoder_config_t cfg = {.format = *format};
  receiver.decoder = audio_decoder_create(&cfg);
  if (!receiver.decoder) {
    ESP_LOGW(TAG, "Decoder not initialized for codec: %s", format->codec);
  }

  audio_timing_set_format(&receiver.timing, format);
  audio_output_set_source_rate(format->sample_rate);
}

void audio_receiver_set_encryption(const audio_encrypt_t *encrypt) {
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    return;
  }
  if (encrypt) {
    receiver.realtime_stream->encrypt = *encrypt;
    receiver.buffered_stream->encrypt = *encrypt;
  } else {
    memset(&receiver.realtime_stream->encrypt, 0,
           sizeof(receiver.realtime_stream->encrypt));
    memset(&receiver.buffered_stream->encrypt, 0,
           sizeof(receiver.buffered_stream->encrypt));
  }
}

void audio_receiver_set_output_latency_us(uint32_t latency_us) {
  if (!receiver.stream) {
    return;
  }
  audio_timing_set_output_latency(&receiver.timing, &receiver.stream->format,
                                  latency_us);
}

uint32_t audio_receiver_get_output_latency_us(void) {
  return audio_timing_get_output_latency(&receiver.timing);
}

uint32_t audio_receiver_get_hardware_latency_us(void) {
  return audio_timing_get_hardware_latency();
}

void audio_receiver_set_anchor_time(uint64_t clock_id, uint64_t network_time_ns,
                                    uint32_t rtp_time) {
  if (!receiver.stream) {
    return;
  }

  // Detect a seek where the buffer content is far displaced from the new
  // anchor position.  Threshold is 5 seconds of samples — large enough to
  // clear normal pre-buffer depth after a pause (typically 1-3 s), but
  // small enough to catch any real seek (which displaces by the full delta
  // from the current song position).  Both directions are checked:
  //   rtp_ahead > threshold  → backward seek (buffer ahead of new anchor)
  //   rtp_ahead < -threshold → forward seek (buffer behind new anchor)
  // Long-pause resume where the anchor advances over the pre-buffer is
  // handled by the bulk-flush path in audio_timing_read, but catching it
  // here avoids even the first DMA callback of silence.
  // Window size for the upper RTP gate: 10 s of samples.  Large enough that
  // a normal 2-4 s pre-buffer passes, but small enough to reject stale frames
  // left in the TCP socket buffer after a backward seek (which are 60+ s ahead
  // of the new anchor when seeking back to near the start of a track).
  int sample_rate = receiver.stream->format.sample_rate;
  if (sample_rate <= 0) {
    sample_rate = 44100;
  }
  const uint32_t gate_window = (uint32_t)(10 * sample_rate);

  uint32_t oldest_rtp = 0;
  if (audio_buffer_oldest_timestamp(&receiver.buffer, &oldest_rtp)) {
    int32_t rtp_ahead = (int32_t)(oldest_rtp - rtp_time);
    int32_t flush_threshold = 5 * sample_rate; // 5 seconds of samples
    int32_t abs_ahead = rtp_ahead < 0 ? -rtp_ahead : rtp_ahead;
    if (abs_ahead > flush_threshold) {
      ESP_LOGI(TAG,
               "Seek detected: oldest_rtp=%lu, new anchor rtp=%lu, "
               "delta=%ld samples (%.1f s) — flushing stale buffer",
               (unsigned long)oldest_rtp, (unsigned long)rtp_time,
               (long)rtp_ahead, (float)rtp_ahead / sample_rate);
      audio_buffer_flush(&receiver.buffer);
      receiver.timing.playout_started = false;
      receiver.timing.pending_valid = false;
      receiver.timing.pending_frame_len = 0;
      receiver.timing.ready_time_us = 0;
      receiver.blocks_read_in_sequence = 0;
      // Arm both RTP gates so the TCP task discards stale frames at decode
      // time rather than letting them fill the ring buffer and trigger repeated
      // bulk-flushes in the DMA callback.
      // discard_before_rtp catches forward-seek stale frames (RTP < anchor).
      // discard_above_rtp catches backward-seek stale frames (RTP >> anchor).
      receiver.discard_before_rtp = rtp_time;
      receiver.discard_before_rtp_valid = true;
      receiver.discard_above_rtp = rtp_time + gate_window;
      receiver.discard_above_rtp_valid = true;
      receiver.arm_gate_on_next_anchor = false; // already handled
    }
  }

  // Forward-seek path: seek_flush empties the buffer before the anchor
  // arrives, so the oldest_rtp check above never fires. arm_gate_on_next_anchor
  // was set by seek_flush to ensure we still arm both gates here.
  if (receiver.arm_gate_on_next_anchor) {
    receiver.arm_gate_on_next_anchor = false;
    receiver.discard_before_rtp = rtp_time;
    receiver.discard_before_rtp_valid = true;
    receiver.discard_above_rtp = rtp_time + gate_window;
    receiver.discard_above_rtp_valid = true;
    ESP_LOGI(TAG,
             "RTP gates armed on anchor: discard_before=%lu discard_above=%lu",
             (unsigned long)rtp_time, (unsigned long)(rtp_time + gate_window));
  }

  audio_timing_set_anchor(&receiver.timing, &receiver.stream->format, clock_id,
                          network_time_ns, rtp_time);
}

void audio_receiver_set_playing(bool playing) {
  audio_timing_set_playing(&receiver.timing, playing);
  if (!playing) {
    receiver.blocks_read_in_sequence = 0;
  }
}

void audio_receiver_reset_timing(void) {
  audio_timing_reset(&receiver.timing);
}

bool audio_receiver_is_playing(void) {
  return receiver.timing.playing;
}

void audio_receiver_set_stream_type(audio_stream_type_t type) {
  if (!receiver.realtime_stream || !receiver.buffered_stream) {
    return;
  }
  audio_stream_t *target = receiver.realtime_stream;
  if (type == AUDIO_STREAM_BUFFERED) {
    target = receiver.buffered_stream;
  }

  if (!target) {
    return;
  }

  if (receiver.stream != target) {
    if (receiver.stream) {
      audio_receiver_copy_stream_state(target, receiver.stream);
      if (receiver.stream->running && receiver.stream->ops &&
          receiver.stream->ops->stop) {
        receiver.stream->ops->stop(receiver.stream);
      }
    }
    receiver.stream = target;
  }

  receiver.stream->type = type;
}

esp_err_t audio_receiver_start(uint16_t data_port, uint16_t control_port) {
  audio_receiver_set_stream_type(AUDIO_STREAM_REALTIME);

  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->start) {
    return ESP_FAIL;
  }

  // Always stop and restart fresh
  if (receiver.stream->running) {
    receiver.stream->ops->stop(receiver.stream);
  }

  receiver.data_port = data_port;
  receiver.control_port = control_port;

  // Starting a stream resets all timing state (including pause tracking)
  audio_receiver_reset_stats();
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);

  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  return receiver.stream->ops->start(receiver.stream, data_port);
}

esp_err_t audio_receiver_start_buffered(uint16_t tcp_port) {
  audio_receiver_set_stream_type(AUDIO_STREAM_BUFFERED);

  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->start) {
    return ESP_FAIL;
  }

  // Buffered streams use a fixed port, no need to restart if running
  if (receiver.stream->running) {
    return ESP_OK;
  }

  // Starting a stream resets all timing state (including pause tracking)
  audio_receiver_reset_stats();
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);

  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  return receiver.stream->ops->start(receiver.stream, tcp_port);
}

esp_err_t audio_receiver_start_stream(uint16_t data_port, uint16_t control_port,
                                      uint16_t tcp_port) {
  if (!receiver.stream) {
    return ESP_FAIL;
  }
  if (receiver.stream->type == AUDIO_STREAM_BUFFERED) {
    return audio_receiver_start_buffered(tcp_port);
  }

  return audio_receiver_start(data_port, control_port);
}

uint16_t audio_receiver_get_stream_port(void) {
  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->get_port) {
    return 0;
  }

  return receiver.stream->ops->get_port(receiver.stream);
}

void audio_receiver_set_client_control(uint32_t client_ip,
                                       uint16_t client_control_port) {
  if (client_ip == 0 || client_control_port == 0) {
    receiver.retransmit_enabled = false;
    return;
  }
  memset(&receiver.client_control_addr, 0,
         sizeof(receiver.client_control_addr));
  receiver.client_control_addr.sin_family = AF_INET;
  receiver.client_control_addr.sin_addr.s_addr = client_ip;
  receiver.client_control_addr.sin_port = htons(client_control_port);
  receiver.retransmit_enabled = true;
  receiver.last_resend_error_time_us = 0;
  ESP_LOGI(TAG, "NACK retransmission enabled, client control port %u",
           client_control_port);
}

void audio_receiver_stop(void) {
  if (receiver.realtime_stream && receiver.realtime_stream->ops &&
      receiver.realtime_stream->ops->stop) {
    receiver.realtime_stream->ops->stop(receiver.realtime_stream);
  }

  if (receiver.buffered_stream && receiver.buffered_stream->ops &&
      receiver.buffered_stream->ops->stop) {
    receiver.buffered_stream->ops->stop(receiver.buffered_stream);
  }

  audio_decoder_destroy(receiver.decoder);
  receiver.decoder = NULL;

  if (receiver.realtime_stream) {
    memset(&receiver.realtime_stream->encrypt, 0,
           sizeof(receiver.realtime_stream->encrypt));
  }
  if (receiver.buffered_stream) {
    memset(&receiver.buffered_stream->encrypt, 0,
           sizeof(receiver.buffered_stream->encrypt));
  }

  receiver.retransmit_enabled = false;
  memset(&receiver.client_control_addr, 0,
         sizeof(receiver.client_control_addr));

  audio_receiver_flush();
}

void audio_receiver_stop_buffered_only(void) {
  if (receiver.buffered_stream && receiver.buffered_stream->ops &&
      receiver.buffered_stream->ops->stop) {
    receiver.buffered_stream->ops->stop(receiver.buffered_stream);
  }
}

void audio_receiver_get_stats(audio_stats_t *stats) {
  if (!stats) {
    return;
  }
  memcpy(stats, &receiver.stats, sizeof(receiver.stats));
}

size_t audio_receiver_read(int16_t *buffer, size_t samples) {
  if (!receiver.buffer.pool || !buffer || samples == 0) {
    return 0;
  }

  return audio_timing_read(&receiver.timing, &receiver.buffer, receiver.stream,
                           &receiver.stats, buffer, samples);
}

bool audio_receiver_has_data(void) {
  int buffered_frames = audio_buffer_get_frame_count(&receiver.buffer);
  return buffered_frames > 0 || receiver.timing.pending_valid;
}

void audio_receiver_flush(void) {
  // Flush is an explicit reset — clear all timing state including pause
  // tracking.  The sender will provide fresh anchor times after flush.
  // Also disarm any pending deferred flush so it does not fire on the
  // next track's frames.
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);

  receiver.discard_before_rtp_valid = false;
  receiver.discard_above_rtp_valid = false;
  receiver.arm_gate_on_next_anchor = false;
  receiver.blocks_read_in_sequence = 1;
}

void audio_receiver_seek_flush(void) {
  // Mid-stream seek flush (FLUSH / immediate FLUSHBUFFERED).  Like
  // audio_receiver_flush() but sets timing.post_flush so audio_timing_read
  // plays frames immediately after the seek instead of silencing them while
  // the anchor's pre-buffer window (several seconds) elapses.
  // Also disarms any pending deferred flush (audio_timing_reset clears it).
  audio_receiver_flush();
  receiver.timing.post_flush = true;
  receiver.timing.post_flush_start_us = 0; // will be set on first frame
  // Request that the RTP gate be armed as soon as the next anchor arrives.
  // This covers the forward-seek case where the buffer is already empty by
  // the time SETRATEANCHORTIME arrives, so the seek-detection heuristic
  // (which needs oldest_rtp from the buffer) would otherwise miss arming it.
  receiver.arm_gate_on_next_anchor = true;
}

void audio_receiver_set_deferred_flush(uint32_t flush_until_ts) {
  if (!receiver.stream) {
    return;
  }
  // Write flush_until_ts before arming the flag so audio_timing_read never
  // sees deferred_flush_pending=true with a stale timestamp.
  receiver.timing.flush_until_ts = flush_until_ts;
  receiver.timing.deferred_flush_pending = true;
  ESP_LOGI(TAG, "Deferred flush armed: flush_until_ts=%" PRIu32,
           flush_until_ts);
}

void audio_receiver_pause(void) {
  // Stop the consumer.  The receiver tasks keep running so the audio buffer
  // continues to fill with pre-buffered audio — TCP back-pressure naturally
  // throttles the sender.  On resume the phone sends a fresh
  // SETRATEANCHORTIME anchor that re-aligns the buffered frames to the
  // correct wall-clock position; no flush or offset compensation is needed.
  audio_timing_set_playing(&receiver.timing, false);
  receiver.blocks_read_in_sequence = 0;
}

uint16_t audio_receiver_get_buffered_port(void) {
  return receiver.buffered_port;
}
