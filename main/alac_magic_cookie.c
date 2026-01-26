#include "alac_magic_cookie.h"

#include <string.h>

// Build ALAC magic cookie (ALACSpecificConfig) from format parameters.
void build_alac_magic_cookie(uint8_t *cookie, const audio_format_t *fmt) {
  memset(cookie, 0, ALAC_MAGIC_COOKIE_SIZE);

  uint32_t frame_length = fmt->max_samples_per_frame
                          ? fmt->max_samples_per_frame
                          : (fmt->frame_size > 0 ? (uint32_t)fmt->frame_size
                                                 : 352);
  uint8_t compatible_version = 0;
  uint8_t bit_depth = fmt->sample_size
                      ? fmt->sample_size
                      : (fmt->bits_per_sample ? fmt->bits_per_sample : 16);
  uint8_t pb = fmt->rice_history_mult ? fmt->rice_history_mult : 40;
  uint8_t mb = fmt->rice_initial_history ? fmt->rice_initial_history : 10;
  uint8_t kb = fmt->rice_limit ? fmt->rice_limit : 14;
  uint8_t num_channels =
      fmt->num_channels ? fmt->num_channels : (fmt->channels ? fmt->channels : 2);
  uint16_t max_run = fmt->max_run ? fmt->max_run : 255;
  uint32_t max_frame_bytes =
      fmt->max_coded_frame_size ? fmt->max_coded_frame_size : 0;
  uint32_t avg_bit_rate = fmt->avg_bit_rate ? fmt->avg_bit_rate : 0;
  uint32_t sample_rate =
      fmt->sample_rate_config
          ? fmt->sample_rate_config
          : (fmt->sample_rate ? fmt->sample_rate : 44100);

  // ALACSpecificConfig structure (big-endian).
  cookie[0] = (frame_length >> 24) & 0xFF;
  cookie[1] = (frame_length >> 16) & 0xFF;
  cookie[2] = (frame_length >> 8) & 0xFF;
  cookie[3] = frame_length & 0xFF;
  cookie[4] = compatible_version;
  cookie[5] = bit_depth;
  cookie[6] = pb;
  cookie[7] = mb;
  cookie[8] = kb;
  cookie[9] = num_channels;
  cookie[10] = (max_run >> 8) & 0xFF;
  cookie[11] = max_run & 0xFF;
  cookie[12] = (max_frame_bytes >> 24) & 0xFF;
  cookie[13] = (max_frame_bytes >> 16) & 0xFF;
  cookie[14] = (max_frame_bytes >> 8) & 0xFF;
  cookie[15] = max_frame_bytes & 0xFF;
  cookie[16] = (avg_bit_rate >> 24) & 0xFF;
  cookie[17] = (avg_bit_rate >> 16) & 0xFF;
  cookie[18] = (avg_bit_rate >> 8) & 0xFF;
  cookie[19] = avg_bit_rate & 0xFF;
  cookie[20] = (sample_rate >> 24) & 0xFF;
  cookie[21] = (sample_rate >> 16) & 0xFF;
  cookie[22] = (sample_rate >> 8) & 0xFF;
  cookie[23] = sample_rate & 0xFF;
}
