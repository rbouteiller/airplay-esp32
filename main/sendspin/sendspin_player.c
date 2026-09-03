#include "sendspin_player.h"

#include <inttypes.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "audio_engine_v2.h"
#include "audio_output.h"
#include "audio_receiver.h"
#include "decoder/impl/esp_flac_dec.h"
#include "esp_audio_dec.h"
#ifdef CONFIG_SENDSPIN_OPUS
#include "decoder/impl/esp_opus_dec.h"
#endif

static const char *TAG = "sendspin_pl";

#ifdef CONFIG_SENDSPIN_OPUS
#define SENDSPIN_HAS_OPUS 1
#else
#define SENDSPIN_HAS_OPUS 0
#endif

/* Timeline block length. Shorter than the AAC block the AirPlay path uses:
 * Sendspin chunks are timestamped individually and can be as short as 15 ms,
 * so a finer block keeps the re-cut below cheap and bounds how much audio a
 * partial block holds back at the end of a stream. */
#define SENDSPIN_FRAME_SAMPLES 512U

/* Reported to the server as min_buffer_ms. It has to clear the engine's
 * 180 ms preroll with room for the chunk period on top, or the server aims
 * its lead time at a buffer depth the scheduler will not start from. */
#define SENDSPIN_MIN_BUFFER_MS 300U

#define SENDSPIN_STATUS_PERIOD_US 10000000LL

/* Scratch for one decoded chunk. The protocol caps a chunk at 150 ms and
 * libFLAC blocks are 4096 samples, so this is several times either. */
#define SENDSPIN_DECODE_FRAMES 8192U

static audio_engine_v2_t s_engine;
static bool s_engine_ready = false;
static const sendspin_time_t *s_clock = NULL;

static bool s_streaming = false;
/* Set while the render hook is inside the engine. stream_end() runs on the
 * WebSocket task and has to know that the playback task is not, before it
 * resets the scheduler underneath it. */
static bool s_rendering = false;
static uint32_t s_epoch = 0;
static uint32_t s_sample_rate = 44100;
static uint8_t s_src_channels = 2;
static uint8_t s_bit_depth = 16;
static uint8_t s_bytes_per_frame = 4;

/* Chunk timestamps are absolute server microseconds; the clock map wants RTP
 * sample numbers. Anchor on the first chunk of the stream and derive every
 * later chunk from its own timestamp, so a gap in the stream lands at the
 * right place instead of being packed against the previous chunk. */
static bool s_anchor_valid = false;
static int64_t s_anchor_server_us = 0;
static uint32_t s_anchor_rtp = 0;

/* Partial block waiting to be pushed. Blocks must start on a multiple of
 * frame_samples from the timeline's base, so chunk boundaries cannot be
 * block boundaries and the tail of every chunk is carried here. */
static int16_t *s_fill = NULL;
static uint32_t s_fill_frames = 0;
static uint32_t s_block_rtp = 0;
static uint32_t s_next_rtp = 0;
/* Board time the last chunk was ingested, to tell a server that skipped from
 * one that was never given the chance to send. */
static int64_t s_last_ingest_us = 0;

static uint64_t s_chunks_received = 0;
static uint64_t s_chunks_dropped = 0;
static uint64_t s_frames_pushed = 0;
static int64_t s_last_status_us = 0;

static void *s_flac = NULL;
#ifdef CONFIG_SENDSPIN_OPUS
static void *s_opus = NULL;
#endif
static uint8_t *s_pcm = NULL;
static size_t s_pcm_size = 0;
static int32_t s_gap_tolerance = 44;

static size_t sendspin_player_read(int16_t *buffer, size_t samples);

uint32_t sendspin_player_buffer_capacity(void) {
  /* Bytes of *compressed* audio the server may keep queued on us. There is
   * only this one number and it goes out in client/init, before a codec has
   * been chosen, so it has to be safe for the most compressible one we
   * offer: bytes stop bounding *duration* once FLAC -- let alone Opus -- is
   * on the wire, and the server's own duration cap is 30 s, which is no help
   * at all. Quote a fixed budget rather than a share of the timeline, so
   * that deepening the timeline for Opus does not invite the server to run
   * proportionally further ahead of us. At 48 kHz this is ~0.5 s of PCM,
   * ~1 s of FLAC and several seconds of Opus, all of which the timeline can
   * hold. */
  return 96U * 1024U;
}

uint32_t sendspin_player_min_buffer_ms(void) {
  return SENDSPIN_MIN_BUFFER_MS;
}

esp_err_t sendspin_player_init(const sendspin_time_t *clock) {
  if (s_engine_ready) {
    return ESP_OK;
  }
  if (!clock) {
    return ESP_ERR_INVALID_ARG;
  }

  s_fill = heap_caps_calloc(SENDSPIN_FRAME_SAMPLES * 2U, sizeof(int16_t),
                            MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
  if (!s_fill) {
    return ESP_ERR_NO_MEM;
  }

  const audio_format_t format = {
      .codec = "pcm",
      .sample_rate = 44100,
      .channels = 2,
      .bits_per_sample = 16,
      .frame_size = (int)SENDSPIN_FRAME_SAMPLES,
  };
  esp_err_t err =
      audio_engine_v2_init(&s_engine, &format, SENDSPIN_FRAME_SAMPLES,
                           (uint16_t)CONFIG_SENDSPIN_TIMELINE_BLOCKS);
  if (err != ESP_OK) {
    free(s_fill);
    s_fill = NULL;
    return err;
  }

  s_clock = clock;
  s_engine_ready = true;
  ESP_LOGI(TAG, "timeline ready: %u blocks x %u frames (%u KB, %u ms)",
           (unsigned)CONFIG_SENDSPIN_TIMELINE_BLOCKS,
           (unsigned)SENDSPIN_FRAME_SAMPLES,
           (unsigned)(((uint32_t)CONFIG_SENDSPIN_TIMELINE_BLOCKS *
                       SENDSPIN_FRAME_SAMPLES * 2U * sizeof(int16_t)) /
                      1024U),
           (unsigned)((uint64_t)CONFIG_SENDSPIN_TIMELINE_BLOCKS *
                      SENDSPIN_FRAME_SAMPLES * 1000U / 44100U));
  return ESP_OK;
}

void sendspin_player_deinit(void) {
  if (!s_engine_ready) {
    return;
  }
  sendspin_player_stream_end();
  audio_engine_v2_deinit(&s_engine);
  free(s_fill);
  s_fill = NULL;
  s_engine_ready = false;
  s_clock = NULL;
}

bool sendspin_player_is_streaming(void) {
  return s_streaming;
}

/* ------------------------------------------------------------------ */
/*  Stream lifecycle                                                   */
/* ------------------------------------------------------------------ */

static void sendspin_player_reset_alignment(void) {
  s_anchor_valid = false;
  s_anchor_server_us = 0;
  s_anchor_rtp = 0;
  s_fill_frames = 0;
  s_block_rtp = 0;
  s_next_rtp = 0;
  s_last_ingest_us = 0;
}

static const char *sendspin_player_codec_name(sendspin_codec_t codec) {
  switch (codec) {
  case SENDSPIN_CODEC_FLAC:
    return "flac";
  case SENDSPIN_CODEC_OPUS:
    return "opus";
  case SENDSPIN_CODEC_PCM:
    return "pcm";
  default:
    return "?";
  }
}

static void sendspin_player_close_decoder(void) {
  if (s_flac) {
    esp_flac_dec_close(s_flac);
    s_flac = NULL;
  }
#ifdef CONFIG_SENDSPIN_OPUS
  if (s_opus) {
    esp_opus_dec_close(s_opus);
    s_opus = NULL;
  }
#endif
  free(s_pcm);
  s_pcm = NULL;
  s_pcm_size = 0;
}

/* Sized for 32-bit stereo so a wide stream cannot overrun it. */
static esp_err_t sendspin_player_alloc_pcm(void) {
  s_pcm_size = SENDSPIN_DECODE_FRAMES * 2U * 4U;
  s_pcm = heap_caps_malloc(s_pcm_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!s_pcm) {
    s_pcm = heap_caps_malloc(s_pcm_size, MALLOC_CAP_8BIT);
  }
  if (!s_pcm) {
    sendspin_player_close_decoder();
    return ESP_ERR_NO_MEM;
  }
  return ESP_OK;
}

static esp_err_t sendspin_player_open_flac(void) {
  if (esp_flac_dec_open(NULL, 0, &s_flac) != ESP_AUDIO_ERR_OK) {
    ESP_LOGE(TAG, "flac decoder would not open");
    return ESP_ERR_NO_MEM;
  }
  return sendspin_player_alloc_pcm();
}

#ifdef CONFIG_SENDSPIN_OPUS
static esp_err_t sendspin_player_open_opus(uint32_t sample_rate,
                                           uint8_t channels) {
  esp_opus_dec_cfg_t cfg = {
      .sample_rate = sample_rate,
      .channel = channels,
      /* The packet's own TOC byte carries the real duration; this only sizes
       * the decoder's output expectation, and INVALID means 60 ms. */
      .frame_duration = ESP_OPUS_DEC_FRAME_DURATION_INVALID,
      /* PyAV hands libopus's plain packets to the wire, with no length
       * prefix, so the decoder must not look for one. */
      .self_delimited = false,
  };
  if (esp_opus_dec_open(&cfg, sizeof(cfg), &s_opus) != ESP_AUDIO_ERR_OK) {
    ESP_LOGE(TAG, "opus decoder would not open");
    return ESP_ERR_NO_MEM;
  }
  return sendspin_player_alloc_pcm();
}
#endif

esp_err_t sendspin_player_stream_start(const sendspin_player_format_t *format) {
  if (!s_engine_ready || !format) {
    return ESP_ERR_INVALID_STATE;
  }
  if (format->codec == SENDSPIN_CODEC_OPUS && !SENDSPIN_HAS_OPUS) {
    ESP_LOGW(TAG, "opus is not enabled in this build");
    return ESP_ERR_NOT_SUPPORTED;
  }
  if (format->codec != SENDSPIN_CODEC_PCM &&
      format->codec != SENDSPIN_CODEC_FLAC &&
      format->codec != SENDSPIN_CODEC_OPUS) {
    ESP_LOGW(TAG, "only pcm, flac and opus are implemented in this build");
    return ESP_ERR_NOT_SUPPORTED;
  }
  if (format->channels < 1 || format->channels > 2 ||
      (format->bit_depth != 16 && format->bit_depth != 24) ||
      format->sample_rate < 8000 || format->sample_rate > 192000) {
    ESP_LOGW(TAG, "unsupported pcm format: %" PRIu32 " Hz, %u ch, %u bit",
             format->sample_rate, (unsigned)format->channels,
             (unsigned)format->bit_depth);
    return ESP_ERR_NOT_SUPPORTED;
  }

  s_sample_rate = format->sample_rate;
  s_src_channels = format->channels;
  s_bit_depth = format->bit_depth;
  s_bytes_per_frame =
      (uint8_t)((format->bit_depth / 8U) * (uint32_t)format->channels);

  sendspin_player_close_decoder();
  if (format->codec == SENDSPIN_CODEC_FLAC) {
    /* codec_header carries "fLaC" plus STREAMINFO, but esp_flac_dec decodes
     * bare frames and rejects it as a bad frame header; every frame header
     * repeats the rate, channels and depth anyway. */
    const esp_err_t err = sendspin_player_open_flac();
    if (err != ESP_OK) {
      return err;
    }
  } else if (format->codec == SENDSPIN_CODEC_OPUS) {
#ifdef CONFIG_SENDSPIN_OPUS
    const esp_err_t err =
        sendspin_player_open_opus(format->sample_rate, format->channels);
    if (err != ESP_OK) {
      return err;
    }
#endif
  }

  /* PCM chunk timestamps match the byte count to the sample, so a mismatch
   * there really is the server jumping. A codec's do not: the reference
   * encoder concatenates every packet one encode() call yields into a single
   * chunk but bills it for one block, so a chunk carries two blocks exactly
   * once, when the encoder's pipeline fills. Re-anchoring on that is an
   * audible stop in exchange for an inaudible offset. */
  s_gap_tolerance = format->codec == SENDSPIN_CODEC_PCM
                        ? (int32_t)(format->sample_rate / 1000U)
                        : (int32_t)(format->sample_rate / 5U);

  const audio_format_t engine_format = {
      .codec = "pcm",
      .sample_rate = (int)format->sample_rate,
      /* Mono is widened on the way in: the timeline slot is sized for two
       * channels regardless, and the output stage is stereo. */
      .channels = 2,
      .bits_per_sample = 16,
      .frame_size = (int)SENDSPIN_FRAME_SAMPLES,
  };
  audio_engine_v2_set_format(&s_engine, &engine_format);
  audio_output_set_source_rate((int)format->sample_rate);

  sendspin_player_reset_alignment();
  s_epoch = audio_engine_v2_begin_epoch(&s_engine, esp_timer_get_time());
  audio_engine_v2_wait_for_anchor(&s_engine, esp_timer_get_time());
  audio_engine_v2_set_playing(&s_engine, true);

  s_chunks_received = 0;
  s_chunks_dropped = 0;
  s_frames_pushed = 0;
  s_last_status_us = esp_timer_get_time();

  s_streaming = true;
  audio_output_set_source(sendspin_player_read);
  audio_output_start();

  ESP_LOGI(TAG, "stream start: %s, %" PRIu32 " Hz, %u ch, %u bit",
           sendspin_player_codec_name(format->codec), format->sample_rate,
           (unsigned)format->channels, (unsigned)format->bit_depth);
  return ESP_OK;
}

void sendspin_player_stream_clear(void) {
  if (!s_engine_ready) {
    return;
  }
  /* A seek invalidates the timestamp-to-RTP anchor as well as the content:
   * the next chunk restarts both. */
  sendspin_player_reset_alignment();
  if (s_flac) {
    esp_flac_dec_reset(s_flac);
  }
#ifdef CONFIG_SENDSPIN_OPUS
  if (s_opus) {
    esp_opus_dec_reset(s_opus);
  }
#endif
  s_epoch = audio_engine_v2_begin_epoch(&s_engine, esp_timer_get_time());
  audio_engine_v2_wait_for_anchor(&s_engine, esp_timer_get_time());
  audio_engine_v2_set_playing(&s_engine, s_streaming);
  ESP_LOGI(TAG, "stream clear");
}

void sendspin_player_stream_end(void) {
  if (!s_streaming) {
    return;
  }
  /* Drop the render hook and let the playback task drain before the engine is
   * quiesced, so it cannot observe a half-reset scheduler. */
  __atomic_store_n(&s_streaming, false, __ATOMIC_SEQ_CST);
  audio_output_set_source(NULL);
  /* A real stop on the I2S backend joins the playback task outright; the
   * others have no task to join, so wait out an in-flight render too. */
  audio_output_stop();
  for (int i = 0; i < 20 && __atomic_load_n(&s_rendering, __ATOMIC_SEQ_CST);
       i++) {
    vTaskDelay(pdMS_TO_TICKS(5));
  }
  audio_engine_v2_set_playing(&s_engine, false);
  sendspin_player_reset_alignment();
  s_epoch = audio_engine_v2_begin_epoch(&s_engine, esp_timer_get_time());
  sendspin_player_close_decoder();
  ESP_LOGI(TAG,
           "stream end: %" PRIu64 " chunks, %" PRIu64 " frames, %" PRIu64
           " dropped",
           s_chunks_received, s_frames_pushed, s_chunks_dropped);
}

/* ------------------------------------------------------------------ */
/*  Chunk ingest                                                       */
/* ------------------------------------------------------------------ */

static inline int16_t sendspin_sample_at(const uint8_t *p, uint8_t bit_depth) {
  if (bit_depth == 16) {
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
  }
  if (bit_depth == 32) {
    return (int16_t)((uint16_t)p[2] | ((uint16_t)p[3] << 8));
  }
  /* 24-bit little-endian packed, truncated to the engine's 16-bit slots. */
  return (int16_t)((uint16_t)p[1] | ((uint16_t)p[2] << 8));
}

/* Push the held block. Returns false if the timeline had no room, which is
 * the normal back-pressure signal and costs one block of audio. */
static bool sendspin_player_flush_block(void) {
  if (s_fill_frames == 0) {
    return true;
  }
  const bool ok = audio_engine_v2_push_pcm(&s_engine, s_epoch, s_block_rtp,
                                           s_fill, s_fill_frames, 2);
  if (ok) {
    s_frames_pushed += s_fill_frames;
  } else {
    s_chunks_dropped++;
  }
  s_block_rtp += SENDSPIN_FRAME_SAMPLES;
  s_fill_frames = 0;
  return ok;
}

/* Resume writing at a new RTP position after a hole. Blocks are only
 * addressable on a multiple of frame_samples from the timeline's base, so
 * the leading part-block is zero-filled rather than the position rounded. */
static void sendspin_player_skip_to(uint32_t rtp) {
  (void)sendspin_player_flush_block();
  const uint32_t phase = rtp % SENDSPIN_FRAME_SAMPLES;
  s_block_rtp = rtp - phase;
  s_fill_frames = phase;
  if (phase > 0) {
    memset(s_fill, 0, (size_t)phase * 2U * sizeof(int16_t));
  }
  s_next_rtp = rtp;
}

/* Decode one chunk into s_pcm. Returns the number of PCM bytes produced and
 * reports the decoded layout, which STREAMINFO may put at a wider bit depth
 * than stream/start advertised. */
static uint32_t sendspin_player_decode_flac(const uint8_t *data, size_t len,
                                            uint8_t *bits, uint8_t *channels) {
  uint32_t produced = 0;
  uint32_t offset = 0;
  while (offset < len && produced < s_pcm_size) {
    esp_audio_dec_in_raw_t raw = {.buffer = (uint8_t *)(data + offset),
                                  .len = (uint32_t)(len - offset),
                                  .consumed = 0,
                                  .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE};
    esp_audio_dec_out_frame_t frame = {.buffer = s_pcm + produced,
                                       .len = (uint32_t)(s_pcm_size - produced),
                                       .decoded_size = 0};
    esp_audio_dec_info_t info = {0};
    const esp_audio_err_t err =
        esp_flac_dec_decode(s_flac, &raw, &frame, &info);
    if (err != ESP_AUDIO_ERR_OK) {
      ESP_LOGW(TAG, "flac decode error %d (needed %" PRIu32 " bytes)", (int)err,
               frame.needed_size);
      esp_flac_dec_reset(s_flac);
      break;
    }
    if (raw.consumed == 0) {
      /* The decoder is holding a partial frame; nothing more to take from
       * this chunk. */
      break;
    }
    offset += raw.consumed;
    produced += frame.decoded_size;
    if (info.bits_per_sample > 0) {
      *bits = info.bits_per_sample;
    }
    if (info.channel > 0) {
      *channels = info.channel;
    }
  }
  return produced;
}

#ifdef CONFIG_SENDSPIN_OPUS
/* One chunk, one call: a non-self-delimited Opus packet carries no length, so
 * the decoder infers the last frame's size from the buffer it is handed.
 * Looping over a remainder the way the FLAC path does would hand it a
 * truncated packet, and there is no sync code to resynchronise on. */
static uint32_t sendspin_player_decode_opus(const uint8_t *data, size_t len,
                                            uint8_t *bits, uint8_t *channels) {
  esp_audio_dec_in_raw_t raw = {.buffer = (uint8_t *)data,
                                .len = (uint32_t)len,
                                .consumed = 0,
                                .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE};
  esp_audio_dec_out_frame_t frame = {
      .buffer = s_pcm, .len = (uint32_t)s_pcm_size, .decoded_size = 0};
  esp_audio_dec_info_t info = {0};
  const esp_audio_err_t err = esp_opus_dec_decode(s_opus, &raw, &frame, &info);
  if (err != ESP_AUDIO_ERR_OK) {
    ESP_LOGW(TAG, "opus decode error %d (needed %" PRIu32 " bytes)", (int)err,
             frame.needed_size);
    esp_opus_dec_reset(s_opus);
    return 0;
  }
  if (info.bits_per_sample > 0) {
    *bits = info.bits_per_sample;
  }
  if (info.channel > 0) {
    *channels = info.channel;
  }
  return frame.decoded_size;
}
#endif

/* Place already-decoded PCM on the timeline. Separate from the chunk entry
 * point because the re-anchor path replays it, and a FLAC frame can only be
 * decoded once. */
static void sendspin_player_ingest(int64_t timestamp_us, const uint8_t *pcm,
                                   uint32_t frames, uint8_t bit_depth,
                                   uint8_t channels) {
  if (frames == 0) {
    return;
  }

  const int64_t now_us = esp_timer_get_time();
  const int32_t since_ms =
      s_last_ingest_us ? (int32_t)((now_us - s_last_ingest_us) / 1000) : 0;
  s_last_ingest_us = now_us;

  if (!s_anchor_valid) {
    s_anchor_server_us = timestamp_us;
    s_anchor_rtp = 0;
    s_next_rtp = 0;
    s_block_rtp = 0;
    s_fill_frames = 0;
    s_anchor_valid = true;
    if (!audio_engine_v2_set_anchor(&s_engine, s_anchor_rtp,
                                    (uint64_t)(timestamp_us * 1000LL), 0)) {
      ESP_LOGW(TAG, "anchor rejected at ts=%" PRId64, timestamp_us);
      s_anchor_valid = false;
      return;
    }
    ESP_LOGI(TAG, "anchored at server ts=%" PRId64 " us", timestamp_us);
  } else {
    /* Where this chunk claims to sit, from its own timestamp. */
    const int64_t delta_us = timestamp_us - s_anchor_server_us;
    const int64_t chunk_rtp64 =
        (int64_t)s_anchor_rtp +
        ((delta_us * (int64_t)s_sample_rate) / 1000000LL);
    const int32_t gap = (int32_t)((uint32_t)chunk_rtp64 - s_next_rtp);

    /* Continuous audio lands within a sample of the running position; the
     * mismatch is only the microsecond quantisation of the timestamp. */
    if (gap > s_gap_tolerance) {
      /* Audio that never arrived. The anchor still maps server time onto RTP,
       * so the chunk belongs where its own timestamp puts it and the timeline
       * conceals the hole; re-anchoring would restart the epoch and mute the
       * DAC, which is far more audible than the hole itself. Anything too far
       * ahead for the timeline is refused block by block until the play
       * cursor reaches it, which needs no special case here. */
      ESP_LOGI(TAG,
               "hole of %" PRId32 " samples (%" PRId32
               " ms of that had no chunk at all)",
               gap, since_ms);
      sendspin_player_skip_to((uint32_t)chunk_rtp64);
    } else if (gap < -s_gap_tolerance) {
      /* The server moved its own playhead back, so RTP is no longer a
       * continuous function of server time and the map has to be rebuilt. */
      ESP_LOGI(TAG, "server rewound %" PRId32 " samples — re-anchoring", -gap);
      sendspin_player_reset_alignment();
      s_epoch = audio_engine_v2_begin_epoch(&s_engine, esp_timer_get_time());
      audio_engine_v2_wait_for_anchor(&s_engine, esp_timer_get_time());
      audio_engine_v2_set_playing(&s_engine, true);
      sendspin_player_ingest(timestamp_us, pcm, frames, bit_depth, channels);
      return;
    }
  }

  const uint8_t sample_bytes = (uint8_t)(bit_depth / 8U);
  const uint8_t stride = (uint8_t)(sample_bytes * channels);
  const uint8_t *p = pcm;
  for (uint32_t i = 0; i < frames; i++) {
    int16_t l = sendspin_sample_at(p, bit_depth);
    int16_t r = l; /* mono is widened by duplicating the sample */
    if (channels == 2) {
      r = sendspin_sample_at(p + sample_bytes, bit_depth);
    }
    p += stride;

    s_fill[s_fill_frames * 2U] = l;
    s_fill[(s_fill_frames * 2U) + 1U] = r;
    s_fill_frames++;
    if (s_fill_frames == SENDSPIN_FRAME_SAMPLES) {
      (void)sendspin_player_flush_block();
    }
  }

  s_next_rtp += frames;
  sendspin_player_log_status();
}

void sendspin_player_chunk(int64_t timestamp_us, const uint8_t *data,
                           size_t len) {
  if (!s_engine_ready || !s_streaming || !data || len == 0) {
    return;
  }
  s_chunks_received++;

  void *decoder = s_flac;
#ifdef CONFIG_SENDSPIN_OPUS
  if (!decoder) {
    decoder = s_opus;
  }
#endif
  if (!decoder) {
    if (len < s_bytes_per_frame) {
      return;
    }
    sendspin_player_ingest(timestamp_us, data,
                           (uint32_t)(len / s_bytes_per_frame), s_bit_depth,
                           s_src_channels);
    return;
  }

  uint8_t bits = s_bit_depth;
  uint8_t channels = s_src_channels;
  uint32_t bytes = 0;
  if (s_flac) {
    bytes = sendspin_player_decode_flac(data, len, &bits, &channels);
  }
#ifdef CONFIG_SENDSPIN_OPUS
  if (s_opus) {
    bytes = sendspin_player_decode_opus(data, len, &bits, &channels);
  }
#endif
  const uint32_t stride = (uint32_t)(bits / 8U) * (uint32_t)channels;
  if (bytes == 0 || stride == 0) {
    return;
  }
  sendspin_player_ingest(timestamp_us, s_pcm, bytes / stride, bits, channels);
}

/* ------------------------------------------------------------------ */
/*  Render                                                             */
/* ------------------------------------------------------------------ */

static size_t sendspin_player_read(int16_t *buffer, size_t samples) {
  if (!s_engine_ready || !buffer || samples == 0) {
    return 0;
  }

  /* Claim before testing s_streaming, which stream_end() clears before it
   * waits on this flag: whichever store lands first, the other side sees it. */
  __atomic_store_n(&s_rendering, true, __ATOMIC_SEQ_CST);
  if (!__atomic_load_n(&s_streaming, __ATOMIC_SEQ_CST)) {
    __atomic_store_n(&s_rendering, false, __ATOMIC_SEQ_CST);
    return 0;
  }

  const int64_t now_us = esp_timer_get_time();
  const int64_t playout_local_ns =
      audio_output_get_next_playout_time_ns(now_us);

  int64_t offset_ns = 0;
  if (!sendspin_time_offset_ns(s_clock, playout_local_ns / 1000LL,
                               &offset_ns)) {
    /* No usable clock estimate yet. Silence is the honest answer: the
     * scheduler cannot place this block on the server's timeline. */
    __atomic_store_n(&s_rendering, false, __ATOMIC_SEQ_CST);
    return 0;
  }

  const size_t rendered = audio_engine_v2_render(
      &s_engine, playout_local_ns + offset_ns, buffer, samples);
  __atomic_store_n(&s_rendering, false, __ATOMIC_SEQ_CST);
  return rendered;
}

/* ------------------------------------------------------------------ */
/*  Diagnostics                                                        */
/* ------------------------------------------------------------------ */

void sendspin_player_log_status(void) {
  if (!s_engine_ready) {
    return;
  }
  const int64_t now_us = esp_timer_get_time();
  if (now_us - s_last_status_us < SENDSPIN_STATUS_PERIOD_US) {
    return;
  }
  s_last_status_us = now_us;

  const size_t blocks = audio_timeline_count(&s_engine.timeline);
  ESP_LOGI(TAG,
           "%s buf=%u blk (%u ms) err=%" PRId32 " smp drift=%" PRId32
           " ppm rtt=%" PRId64 " us skew=%" PRId32 " ppm clk=%" PRIu32
           "/%" PRIu32 " drops=%" PRIu64,
           audio_scheduler_state_name(s_engine.scheduler.state),
           (unsigned)blocks,
           (unsigned)((uint64_t)blocks * SENDSPIN_FRAME_SAMPLES * 1000U /
                      (s_sample_rate ? s_sample_rate : 44100U)),
           s_engine.scheduler.playout_error_samples,
           s_engine.scheduler.estimated_drift_ppm,
           sendspin_time_best_rtt_us(s_clock), sendspin_time_skew_ppm(s_clock),
           s_clock->accepted, s_clock->rejected, s_chunks_dropped);
}
