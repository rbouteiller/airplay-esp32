#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "audio_decoder.h"

#include "esp_log.h"

#include "alac_magic_cookie.h"
#include "decoder/impl/esp_aac_dec.h"
#include "decoder/impl/esp_alac_dec.h"
#include "esp_audio_dec.h"

#define ADTS_HEADER_LEN 7
#define MAX_FALLBACK_CHANNELS 2

typedef enum {
  AUDIO_DECODER_NONE = 0,
  AUDIO_DECODER_PCM,
  AUDIO_DECODER_ALAC,
  AUDIO_DECODER_AAC
} audio_decoder_kind_t;

struct audio_decoder {
  audio_decoder_kind_t kind;
  audio_format_t format;
  void *alac_decoder;
  void *aac_decoder;
  uint8_t alac_magic_cookie[ALAC_MAGIC_COOKIE_SIZE];
  uint8_t *aac_frame_buffer;
  size_t aac_frame_buffer_size;
};

static const char *TAG = "audio_dec";

static bool codec_is_alac(const char *codec) {
  if (!codec) {
    return false;
  }
  return strcmp(codec, "AppleLossless") == 0 || strcmp(codec, "ALAC") == 0;
}

static bool codec_is_aac(const char *codec) {
  if (!codec) {
    return false;
  }
  return strstr(codec, "AAC") != NULL || strstr(codec, "aac") != NULL ||
         strstr(codec, "mpeg4-generic") != NULL;
}

static bool aac_has_adts_header(const uint8_t *data, size_t len) {
  return len >= 2 && data[0] == 0xFF && (data[1] & 0xF0) == 0xF0;
}

static void build_adts_header(uint8_t *header, size_t frame_len,
                              int sample_rate, int channels) {
  (void)sample_rate;
  (void)channels;

  int profile = 2;
  int freq_idx = 4;
  int chan_cfg = 2;
  int packet_len = (int)(frame_len + ADTS_HEADER_LEN);

  header[0] = 0xFF;
  header[1] = 0xF1;
  header[2] = ((profile - 1) << 6) + (freq_idx << 2) + (chan_cfg >> 2);
  header[3] = ((chan_cfg & 3) << 6) + (packet_len >> 11);
  header[4] = (packet_len & 0x7FF) >> 3;
  header[5] = ((packet_len & 7) << 5) + 0x1F;
  header[6] = 0xFC;
}

audio_decoder_t *audio_decoder_create(const audio_decoder_config_t *config) {
  if (!config) {
    return NULL;
  }

  audio_decoder_t *decoder = calloc(1, sizeof(*decoder));
  if (!decoder) {
    return NULL;
  }

  decoder->format = config->format;

  if (codec_is_alac(config->format.codec)) {
    decoder->kind = AUDIO_DECODER_ALAC;
    build_alac_magic_cookie(decoder->alac_magic_cookie, &config->format);

    esp_alac_dec_cfg_t alac_cfg = {
        .codec_spec_info = decoder->alac_magic_cookie,
        .spec_info_len = ALAC_MAGIC_COOKIE_SIZE};

    esp_audio_err_t err =
        esp_alac_dec_open(&alac_cfg, sizeof(alac_cfg),
                          &decoder->alac_decoder);
    if (err != ESP_AUDIO_ERR_OK) {
      ESP_LOGE(TAG, "Failed to open ALAC decoder: %d", err);
      decoder->alac_decoder = NULL;
      decoder->kind = AUDIO_DECODER_NONE;
    }
  } else if (codec_is_aac(config->format.codec)) {
    decoder->kind = AUDIO_DECODER_AAC;

    esp_aac_dec_cfg_t aac_cfg = ESP_AAC_DEC_CONFIG_DEFAULT();
    aac_cfg.sample_rate = config->format.sample_rate;
    aac_cfg.channel = config->format.channels;
    aac_cfg.bits_per_sample =
        config->format.bits_per_sample ? config->format.bits_per_sample : 16;
    aac_cfg.no_adts_header = false;
    aac_cfg.aac_plus_enable = false;

    esp_audio_err_t err = esp_aac_dec_open(&aac_cfg, sizeof(aac_cfg),
                                          &decoder->aac_decoder);
    if (err != ESP_AUDIO_ERR_OK) {
      ESP_LOGE(TAG, "Failed to open AAC decoder: %d", err);
      decoder->aac_decoder = NULL;
      decoder->kind = AUDIO_DECODER_NONE;
    }
  } else if (strcmp(config->format.codec, "L16") == 0 ||
             strcmp(config->format.codec, "PCM") == 0) {
    decoder->kind = AUDIO_DECODER_PCM;
  } else {
    decoder->kind = AUDIO_DECODER_NONE;
  }

  return decoder;
}

void audio_decoder_destroy(audio_decoder_t *decoder) {
  if (!decoder) {
    return;
  }

  if (decoder->alac_decoder) {
    esp_alac_dec_close(decoder->alac_decoder);
    decoder->alac_decoder = NULL;
  }

  if (decoder->aac_decoder) {
    esp_aac_dec_close(decoder->aac_decoder);
    decoder->aac_decoder = NULL;
  }

  if (decoder->aac_frame_buffer) {
    free(decoder->aac_frame_buffer);
    decoder->aac_frame_buffer = NULL;
    decoder->aac_frame_buffer_size = 0;
  }

  free(decoder);
}

int audio_decoder_decode(audio_decoder_t *decoder, const uint8_t *input,
                         size_t input_len, int16_t *output,
                         size_t output_capacity_samples,
                         audio_decode_info_t *info) {
  if (!decoder || !input || !output || output_capacity_samples == 0) {
    return -1;
  }

  int channels = decoder->format.channels;
  if (channels <= 0) {
    channels = MAX_FALLBACK_CHANNELS;
  }

  if (decoder->kind == AUDIO_DECODER_PCM) {
    size_t decoded_samples = input_len / (channels * sizeof(int16_t));
    if (decoded_samples > output_capacity_samples) {
      decoded_samples = output_capacity_samples;
    }

    const int16_t *src = (const int16_t *)input;
    for (size_t i = 0; i < decoded_samples * channels; i++) {
      output[i] = ntohs(src[i]);
    }

    if (info) {
      info->channels = channels;
    }
    return (int)decoded_samples;
  }

  if (decoder->kind == AUDIO_DECODER_ALAC) {
    if (!decoder->alac_decoder) {
      return -1;
    }

    esp_audio_dec_in_raw_t raw = {.buffer = (uint8_t *)input,
                                  .len = (uint32_t)input_len,
                                  .consumed = 0,
                                  .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE};
    esp_audio_dec_out_frame_t frame = {
        .buffer = (uint8_t *)output,
        .len = (uint32_t)(output_capacity_samples * channels *
                          sizeof(int16_t)),
        .decoded_size = 0};
    esp_audio_dec_info_t dec_info = {0};

    esp_audio_err_t err =
        esp_alac_dec_decode(decoder->alac_decoder, &raw, &frame, &dec_info);
    if (err != ESP_AUDIO_ERR_OK) {
      return -1;
    }

    int dec_channels =
        dec_info.channel > 0 ? dec_info.channel : channels;
    if (dec_channels <= 0) {
      dec_channels = MAX_FALLBACK_CHANNELS;
    }

    size_t decoded_samples =
        frame.decoded_size / (dec_channels * sizeof(int16_t));
    if (decoded_samples > output_capacity_samples) {
      decoded_samples = output_capacity_samples;
    }

    if (info) {
      info->channels = dec_channels;
    }
    return (int)decoded_samples;
  }

  if (decoder->kind == AUDIO_DECODER_AAC) {
    if (!decoder->aac_decoder) {
      return -1;
    }

    const uint8_t *decode_data = input;
    size_t decode_len = input_len;

    if (!aac_has_adts_header(input, input_len)) {
      size_t needed = input_len + ADTS_HEADER_LEN;
      if (!decoder->aac_frame_buffer ||
          decoder->aac_frame_buffer_size < needed) {
        uint8_t *new_buf = realloc(decoder->aac_frame_buffer, needed);
        if (!new_buf) {
          return -1;
        }
        decoder->aac_frame_buffer = new_buf;
        decoder->aac_frame_buffer_size = needed;
      }

      build_adts_header(decoder->aac_frame_buffer, input_len,
                        decoder->format.sample_rate, decoder->format.channels);
      memcpy(decoder->aac_frame_buffer + ADTS_HEADER_LEN, input, input_len);
      decode_data = decoder->aac_frame_buffer;
      decode_len = needed;
    }

    esp_audio_dec_in_raw_t raw = {.buffer = (uint8_t *)decode_data,
                                  .len = (uint32_t)decode_len,
                                  .consumed = 0,
                                  .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE};
    esp_audio_dec_out_frame_t frame = {
        .buffer = (uint8_t *)output,
        .len = (uint32_t)(output_capacity_samples * channels *
                          sizeof(int16_t)),
        .decoded_size = 0};
    esp_audio_dec_info_t dec_info = {0};

    esp_audio_err_t err =
        esp_aac_dec_decode(decoder->aac_decoder, &raw, &frame, &dec_info);
    if (err != ESP_AUDIO_ERR_OK) {
      return -1;
    }

    int dec_channels =
        dec_info.channel > 0 ? dec_info.channel : channels;
    if (dec_channels <= 0) {
      dec_channels = MAX_FALLBACK_CHANNELS;
    }

    size_t decoded_samples =
        frame.decoded_size / (dec_channels * sizeof(int16_t));
    if (decoded_samples > output_capacity_samples) {
      decoded_samples = output_capacity_samples;
    }

    if (info) {
      info->channels = dec_channels;
    }
    return (int)decoded_samples;
  }

  return -1;
}

bool audio_decoder_is_aac(const audio_decoder_t *decoder) {
  return decoder && decoder->kind == AUDIO_DECODER_AAC;
}

bool audio_decoder_is_alac(const audio_decoder_t *decoder) {
  return decoder && decoder->kind == AUDIO_DECODER_ALAC;
}
