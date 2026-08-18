#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* AP2 buffered AAC-only audio receiver. */
typedef struct {
  char codec[32];
  int sample_rate;
  int channels;
  int bits_per_sample;
  int frame_size; /* observed AP2 AAC path: 1024 PCM frames/AU */
} audio_format_t;

typedef enum {
  AUDIO_ENCRYPT_NONE = 0,
  AUDIO_ENCRYPT_AES_CBC,
  AUDIO_ENCRYPT_CHACHA20_POLY1305
} audio_encrypt_type_t;

typedef struct {
  audio_encrypt_type_t type;
  uint8_t key[32];
  uint8_t iv[16];
  size_t key_len;
} audio_encrypt_t;

typedef struct {
  uint32_t packets_received;
  uint32_t packets_decoded;
  uint32_t packets_dropped;
  uint32_t decrypt_errors;
  uint32_t buffer_underruns;
  uint32_t buffer_overruns;
  uint32_t late_frames;
  uint16_t last_seq;
  uint32_t last_timestamp;
} audio_stats_t;

typedef enum {
  AUDIO_STREAM_NONE = 0,
  AUDIO_STREAM_REALTIME = 96,  /* retained only so RTSP can reject it cleanly */
  AUDIO_STREAM_BUFFERED = 103  /* supported AP2 TCP AAC path */
} audio_stream_type_t;

esp_err_t audio_receiver_init(void);
void audio_receiver_set_format(const audio_format_t *format);
void audio_receiver_set_encryption(const audio_encrypt_t *encrypt);
void audio_receiver_set_stream_type(audio_stream_type_t type);

esp_err_t audio_receiver_start(uint16_t data_port, uint16_t control_port);
esp_err_t audio_receiver_start_stream(uint16_t data_port, uint16_t control_port,
                                      uint16_t tcp_port);
esp_err_t audio_receiver_start_buffered(uint16_t tcp_port);
void audio_receiver_stop(void);
void audio_receiver_stop_buffered_only(void);
uint16_t audio_receiver_get_stream_port(void);
uint16_t audio_receiver_get_buffered_port(void);

void audio_receiver_get_stats(audio_stats_t *stats);

/* Software output volume. Q15: 0=mute, 32768=0 dB/full scale. */
void audio_receiver_set_volume_q15(int32_t volume_q15);
int32_t audio_receiver_get_volume_q15(void);

/* Compatibility read APIs; V8 uses the internal RTP-addressed playout task. */
size_t audio_receiver_read(int16_t *buffer, size_t samples);
bool audio_receiver_has_data(void);

/* Timeline/generation control. These invalidate old PCM in O(1), no scan. */
void audio_receiver_flush(void);
void audio_receiver_seek_flush(void);
void audio_receiver_set_deferred_flush(uint32_t flush_until_ts);
void audio_receiver_pause(void);
void audio_receiver_set_playing(bool playing);
bool audio_receiver_is_playing(void);
void audio_receiver_reset_timing(void);

void audio_receiver_set_anchor_time(uint64_t clock_id, uint64_t network_time_ns,
                                    uint32_t rtp_time);
void audio_receiver_set_client_control(uint32_t client_ip,
                                       uint16_t client_control_port);

/* RTSP compatibility: buffered AP2 uses zero extra playout latency here. */
void audio_receiver_set_playout_latency_samples(uint32_t latency_samples);
void audio_receiver_set_output_latency_us(uint32_t latency_us);
uint32_t audio_receiver_get_output_latency_us(void);
uint32_t audio_receiver_get_hardware_latency_us(void);
uint32_t audio_receiver_get_advertised_latency_us(void);
