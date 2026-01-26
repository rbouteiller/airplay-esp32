#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Audio receiver for AirPlay RTP streams
 * Handles UDP packet reception and audio decoding
 */

// Audio format info from ANNOUNCE SDP
typedef struct {
  char codec[32];      // "AppleLossless", "AAC", etc.
  int sample_rate;     // 44100, 48000, etc.
  int channels;        // 1 or 2
  int bits_per_sample; // 16, 24
  int frame_size;      // Samples per frame (ALAC: 352)

  // ALAC-specific config (from fmtp line)
  uint32_t max_samples_per_frame;
  uint8_t sample_size;
  uint8_t rice_history_mult;
  uint8_t rice_initial_history;
  uint8_t rice_limit;
  uint8_t num_channels;
  uint16_t max_run;
  uint32_t max_coded_frame_size;
  uint32_t avg_bit_rate;
  uint32_t sample_rate_config;
} audio_format_t;

// Audio encryption types
typedef enum {
  AUDIO_ENCRYPT_NONE = 0,
  AUDIO_ENCRYPT_AES_CBC,
  AUDIO_ENCRYPT_CHACHA20_POLY1305
} audio_encrypt_type_t;

// Audio encryption configuration
typedef struct {
  audio_encrypt_type_t type;
  uint8_t key[32]; // AES-128 uses 16, ChaCha20 uses 32
  uint8_t iv[16];  // AES-CBC IV
  size_t key_len;
} audio_encrypt_t;

// Audio buffer statistics
typedef struct {
  uint32_t packets_received;
  uint32_t packets_decoded;
  uint32_t packets_dropped;
  uint32_t decrypt_errors;
  uint32_t buffer_underruns;
  uint16_t last_seq;
  uint32_t last_timestamp;
} audio_stats_t;

/**
 * Initialize audio receiver
 */
esp_err_t audio_receiver_init(void);

/**
 * Set audio format from ANNOUNCE SDP
 */
void audio_receiver_set_format(const audio_format_t *format);

/**
 * Set encryption parameters for RTP decryption
 */
void audio_receiver_set_encryption(const audio_encrypt_t *encrypt);

/**
 * Start receiving audio on specified port
 */
esp_err_t audio_receiver_start(uint16_t data_port, uint16_t control_port);

/**
 * Start the active stream type using the provided ports.
 */
esp_err_t audio_receiver_start_stream(uint16_t data_port, uint16_t control_port,
                                      uint16_t tcp_port);

/**
 * Stop receiving audio
 */
void audio_receiver_stop(void);

/**
 * Get audio statistics
 */
void audio_receiver_get_stats(audio_stats_t *stats);

/**
 * Read decoded PCM samples from buffer
 * @param buffer Output buffer for PCM samples (interleaved stereo, 16-bit)
 * @param samples Maximum number of samples to read (per channel)
 * @return Number of samples actually read
 */
size_t audio_receiver_read(int16_t *buffer, size_t samples);

/**
 * Check if audio data is available
 */
bool audio_receiver_has_data(void);

/**
 * Flush audio buffer
 */
void audio_receiver_flush(void);

/**
 * Set advertised/target output latency in microseconds.
 */
void audio_receiver_set_output_latency_us(uint32_t latency_us);

/**
 * Get current output latency in microseconds.
 */
uint32_t audio_receiver_get_output_latency_us(void);

/**
 * Provide anchor timing information from SETRATEANCHORTIME.
 * @param clock_id PTP clock ID (networkTimeTimelineID)
 * @param network_time_ns Anchor time in nanoseconds (PTP timeline)
 * @param rtp_time RTP timestamp for the anchor
 */
void audio_receiver_set_anchor_time(uint64_t clock_id, uint64_t network_time_ns,
                                    uint32_t rtp_time);

/**
 * Enable or pause playout scheduling.
 */
void audio_receiver_set_playing(bool playing);

/**
 * Stream types for AirPlay 2
 */
typedef enum {
  AUDIO_STREAM_NONE = 0,
  AUDIO_STREAM_REALTIME = 96, // UDP, ALAC
  AUDIO_STREAM_BUFFERED = 103 // TCP, AAC-ELD
} audio_stream_type_t;

/**
 * Start buffered audio receiver (type=103) on TCP port
 * @param tcp_port Port to listen on for TCP connections
 * @return ESP_OK on success
 */
esp_err_t audio_receiver_start_buffered(uint16_t tcp_port);

/**
 * Get the active stream port (data or buffered).
 */
uint16_t audio_receiver_get_stream_port(void);

/**
 * Get the TCP port for buffered audio (after start_buffered)
 */
uint16_t audio_receiver_get_buffered_port(void);

/**
 * Stop only the buffered receiver but keep playing buffered data
 * Used when TEARDOWN with streams array is received (sender done sending)
 */
void audio_receiver_stop_buffered_only(void);

/**
 * Set the stream type (realtime vs buffered)
 */
void audio_receiver_set_stream_type(audio_stream_type_t type);
