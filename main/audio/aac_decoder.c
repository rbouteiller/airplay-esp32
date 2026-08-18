#include "aac_decoder.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "decoder/impl/esp_aac_dec.h"
#include "esp_audio_dec.h"
#include "esp_log.h"

#define ADTS_HEADER_LEN 7U
#define AAC_INPUT_MAX   8192U

struct aac_decoder {
  aac_decoder_config_t config;
  void *handle;
  uint8_t *adts_scratch;
  size_t adts_capacity;
};

static const char *TAG = "aac_dec_v1";

static int adts_frequency_index(int sample_rate) {
  static const int rates[] = {96000, 88200, 64000, 48000, 44100, 32000,
                              24000, 22050, 16000, 12000, 11025, 8000, 7350};
  for (int i = 0; i < (int)(sizeof(rates) / sizeof(rates[0])); ++i) {
    if (rates[i] == sample_rate) {
      return i;
    }
  }
  return 4; // AirPlay 2 path is 44.1 kHz in this project.
}

static bool has_adts(const uint8_t *data, size_t len) {
  return len >= 2U && data[0] == 0xffU && (data[1] & 0xf0U) == 0xf0U;
}

static void make_adts(uint8_t *h, size_t payload_len, int sample_rate,
                      int channels) {
  const int profile = 2; // AAC LC
  const int freq_idx = adts_frequency_index(sample_rate);
  const int chan_cfg = channels > 0 ? channels : 2;
  const int packet_len = (int)(payload_len + ADTS_HEADER_LEN);

  h[0] = 0xff;
  h[1] = 0xf1;
  h[2] = (uint8_t)(((profile - 1) << 6) | (freq_idx << 2) | (chan_cfg >> 2));
  h[3] = (uint8_t)(((chan_cfg & 3) << 6) | (packet_len >> 11));
  h[4] = (uint8_t)((packet_len & 0x7ff) >> 3);
  h[5] = (uint8_t)(((packet_len & 7) << 5) | 0x1f);
  h[6] = 0xfc;
}

static bool open_decoder(aac_decoder_t *d) {
  if (d->handle) {
    esp_aac_dec_close(d->handle);
    d->handle = NULL;
  }

  esp_aac_dec_cfg_t cfg = ESP_AAC_DEC_CONFIG_DEFAULT();
  cfg.sample_rate = d->config.sample_rate;
  cfg.channel = d->config.channels;
  cfg.bits_per_sample = d->config.bits_per_sample > 0 ? d->config.bits_per_sample : 16;
  cfg.no_adts_header = false;
  cfg.aac_plus_enable = false;

  esp_audio_err_t err = esp_aac_dec_open(&cfg, sizeof(cfg), &d->handle);
  if (err != ESP_AUDIO_ERR_OK) {
    ESP_LOGE(TAG, "esp_aac_dec_open failed: %d", err);
    d->handle = NULL;
    return false;
  }
  return true;
}

aac_decoder_t *aac_decoder_create(const aac_decoder_config_t *config) {
  if (!config || config->sample_rate <= 0 || config->channels <= 0) {
    return NULL;
  }

  aac_decoder_t *d = calloc(1, sizeof(*d));
  if (!d) {
    return NULL;
  }
  d->config = *config;
  d->adts_capacity = AAC_INPUT_MAX + ADTS_HEADER_LEN;
  d->adts_scratch = malloc(d->adts_capacity);
  if (!d->adts_scratch || !open_decoder(d)) {
    aac_decoder_destroy(d);
    return NULL;
  }
  return d;
}

void aac_decoder_destroy(aac_decoder_t *d) {
  if (!d) {
    return;
  }
  if (d->handle) {
    esp_aac_dec_close(d->handle);
  }
  free(d->adts_scratch);
  free(d);
}

int aac_decoder_decode(aac_decoder_t *d, const uint8_t *input,
                       size_t input_len, int16_t *output,
                       size_t output_capacity_frames,
                       aac_decode_info_t *info) {
  if (!d || !d->handle || !input || input_len == 0 || !output ||
      output_capacity_frames == 0) {
    return -1;
  }

  const uint8_t *decode_data = input;
  size_t decode_len = input_len;
  if (!has_adts(input, input_len)) {
    if (input_len + ADTS_HEADER_LEN > d->adts_capacity) {
      return -1;
    }
    make_adts(d->adts_scratch, input_len, d->config.sample_rate,
              d->config.channels);
    memcpy(d->adts_scratch + ADTS_HEADER_LEN, input, input_len);
    decode_data = d->adts_scratch;
    decode_len = input_len + ADTS_HEADER_LEN;
  }

  const int channels = d->config.channels > 0 ? d->config.channels : 2;
  esp_audio_dec_in_raw_t raw = {
      .buffer = (uint8_t *)decode_data,
      .len = (uint32_t)decode_len,
      .consumed = 0,
      .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE,
  };
  esp_audio_dec_out_frame_t frame = {
      .buffer = (uint8_t *)output,
      .len = (uint32_t)(output_capacity_frames * (size_t)channels * sizeof(int16_t)),
      .decoded_size = 0,
  };
  esp_audio_dec_info_t dec_info = {0};

  esp_audio_err_t err = esp_aac_dec_decode(d->handle, &raw, &frame, &dec_info);
  if (err != ESP_AUDIO_ERR_OK) {
    // A corrupt access unit can poison the codec state. Reset once here; the
    // caller simply drops this frame. This is an error path, not a hot-path log.
    ESP_LOGW(TAG, "decode error=%d; resetting AAC decoder", err);
    open_decoder(d);
    return -1;
  }

  int out_channels = dec_info.channel > 0 ? dec_info.channel : channels;
  if (out_channels <= 0) {
    out_channels = 2;
  }
  size_t frames = frame.decoded_size / ((size_t)out_channels * sizeof(int16_t));
  if (frames > output_capacity_frames) {
    frames = output_capacity_frames;
  }
  if (info) {
    info->channels = out_channels;
  }
  return (int)frames;
}
