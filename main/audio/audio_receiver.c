#include <stdlib.h>
#include <string.h>

#include "audio_receiver.h"

#include "esp_log.h"

#include "audio_buffer.h"
#include "audio_decoder.h"
#include "audio_receiver_internal.h"
#include "audio_stream.h"
#include "audio_timing.h"
#include "ptp_clock.h"

#define DEFAULT_SAMPLE_RATE 44100
#define DEFAULT_CHANNELS 2
#define DEFAULT_BITS_PER_SAMPLE 16
#define DEFAULT_FRAME_SIZE 352
#define DECRYPT_BUFFER_SIZE 8192

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
  if (receiver.buffer.ring) {
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
  receiver.decrypt_buffer = malloc(receiver.decrypt_buffer_size);
  if (!receiver.decrypt_buffer) {
    ESP_LOGE(TAG, "Failed to allocate decrypt buffer");
    audio_buffer_deinit(&receiver.buffer);
    audio_stream_destroy(receiver.realtime_stream);
    audio_stream_destroy(receiver.buffered_stream);
    receiver.realtime_stream = NULL;
    receiver.buffered_stream = NULL;
    return ESP_ERR_NO_MEM;
  }

  size_t pending_capacity = sizeof(audio_frame_header_t) +
                            (MAX_SAMPLES_PER_FRAME * AUDIO_MAX_CHANNELS *
                             sizeof(int16_t));
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

void audio_receiver_set_anchor_time(uint64_t clock_id, uint64_t network_time_ns,
                                    uint32_t rtp_time) {
  if (!receiver.stream) {
    return;
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

  if (receiver.stream && receiver.stream->running) {
    ESP_LOGI(TAG, "Audio receiver already running, continuing");
    return ESP_OK;
  }

  receiver.data_port = data_port;
  receiver.control_port = control_port;

  audio_receiver_reset_stats();
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);
  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->start) {
    return ESP_FAIL;
  }

  return receiver.stream->ops->start(receiver.stream, data_port);
}

esp_err_t audio_receiver_start_buffered(uint16_t tcp_port) {
  audio_receiver_set_stream_type(AUDIO_STREAM_BUFFERED);

  if (receiver.stream && receiver.stream->running) {
    ESP_LOGI(TAG, "Buffered audio already running, continuing");
    return ESP_OK;
  }

  audio_receiver_reset_stats();
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);
  receiver.timing.ptp_locked = ptp_clock_is_locked();
  audio_receiver_reset_blocks();

  if (!receiver.stream || !receiver.stream->ops ||
      !receiver.stream->ops->start) {
    return ESP_FAIL;
  }

  return receiver.stream->ops->start(receiver.stream, tcp_port);
}

esp_err_t audio_receiver_start_stream(uint16_t data_port,
                                      uint16_t control_port,
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
  if (!receiver.buffer.ring || !buffer || samples == 0) {
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
  audio_buffer_flush(&receiver.buffer);
  audio_timing_reset(&receiver.timing);

  receiver.blocks_read_in_sequence = 1;
}

uint16_t audio_receiver_get_buffered_port(void) {
  return receiver.buffered_port;
}
