/**
 * SPDIF audio output via I2S bit-banging on a single GPIO
 *
 * This uses the I2S peripheral in 32-bit stereo mode at 2x the sample rate
 * to produce a BMC (Biphase Mark Coded) SPDIF stream on the data-out pin.
 * Only the DO pin carries the actual SPDIF signal; BCK and WS are required
 * by the I2S peripheral but are not part of the SPDIF output.
 *
 * Based on the SPDIF implementation from squeezelite-esp32 by Sebastien and
 * Philippe G. (philippe_44@outlook.com), released under the MIT License.
 *
 * For coax SPDIF output, use this passive circuit:
 *
 *                     100nF
 *   GPIO ----210R------||---- coax SPDIF signal out
 *                 |
 *               110R
 *                 |
 *   GND  -------------------- coax signal ground
 */

#include "audio_output.h"

#include "audio_receiver.h"
#include "led.h"
#include "driver/i2s_std.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rtsp_server.h"
#include <stdlib.h>
#include <string.h>

#define TAG          "audio_spdif"
#define SAMPLE_RATE  44100
#define SPDIF_BLOCK  256
#define FRAME_SAMPLES 352

/* DMA buffer sizing — each audio frame becomes 4 × 32-bit words after BMC
 * encoding, so the I2S peripheral sees "pseudo-frames" at 2× the real rate
 * with 32-bit slot width.  450 pseudo-frames × 4 channels × 2 bytes = 3600
 * bytes per DMA buffer, which fits nicely in the 4092-byte hardware limit. */
#define DMA_BUF_FRAMES_SPDIF 450
#define DMA_BUF_COUNT_SPDIF  7

#define SPDIF_BCK_PIN  CONFIG_SPDIF_BCK_IO
#define SPDIF_WS_PIN   CONFIG_SPDIF_WS_IO
#define SPDIF_DO_PIN   CONFIG_SPDIF_DO_IO

#if CONFIG_FREERTOS_UNICORE
#define PLAYBACK_CORE 0
#else
#define PLAYBACK_CORE 1
#endif

/* ── SPDIF framing constants ───────────────────────────────────────────── */

#define PREAMBLE_B (0xE8) /* 11101000 – start of data block   */
#define PREAMBLE_M (0xE2) /* 11100010 – left channel (not BoB) */
#define PREAMBLE_W (0xE4) /* 11100100 – right channel          */

#define VUCP       ((uint32_t)0xCC << 24)
#define VUCP_MUTE  ((uint32_t)0xD4 << 24) /* set V=invalid to mute */

/* BMC (Biphase Mark Coding) lookup – maps each byte to its 16-bit encoded
 * form with LSB transmitted first. */
static const uint16_t spdif_bmclookup[256] = {
    0xcccc, 0x4ccc, 0x2ccc, 0xaccc, 0x34cc, 0xb4cc, 0xd4cc, 0x54cc,
    0x32cc, 0xb2cc, 0xd2cc, 0x52cc, 0xcacc, 0x4acc, 0x2acc, 0xaacc,
    0x334c, 0xb34c, 0xd34c, 0x534c, 0xcb4c, 0x4b4c, 0x2b4c, 0xab4c,
    0xcd4c, 0x4d4c, 0x2d4c, 0xad4c, 0x354c, 0xb54c, 0xd54c, 0x554c,
    0x332c, 0xb32c, 0xd32c, 0x532c, 0xcb2c, 0x4b2c, 0x2b2c, 0xab2c,
    0xcd2c, 0x4d2c, 0x2d2c, 0xad2c, 0x352c, 0xb52c, 0xd52c, 0x552c,
    0xccac, 0x4cac, 0x2cac, 0xacac, 0x34ac, 0xb4ac, 0xd4ac, 0x54ac,
    0x32ac, 0xb2ac, 0xd2ac, 0x52ac, 0xcaac, 0x4aac, 0x2aac, 0xaaac,
    0x3334, 0xb334, 0xd334, 0x5334, 0xcb34, 0x4b34, 0x2b34, 0xab34,
    0xcd34, 0x4d34, 0x2d34, 0xad34, 0x3534, 0xb534, 0xd534, 0x5534,
    0xccb4, 0x4cb4, 0x2cb4, 0xacb4, 0x34b4, 0xb4b4, 0xd4b4, 0x54b4,
    0x32b4, 0xb2b4, 0xd2b4, 0x52b4, 0xcab4, 0x4ab4, 0x2ab4, 0xaab4,
    0xccd4, 0x4cd4, 0x2cd4, 0xacd4, 0x34d4, 0xb4d4, 0xd4d4, 0x54d4,
    0x32d4, 0xb2d4, 0xd2d4, 0x52d4, 0xcad4, 0x4ad4, 0x2ad4, 0xaad4,
    0x3354, 0xb354, 0xd354, 0x5354, 0xcb54, 0x4b54, 0x2b54, 0xab54,
    0xcd54, 0x4d54, 0x2d54, 0xad54, 0x3554, 0xb554, 0xd554, 0x5554,
    0x3332, 0xb332, 0xd332, 0x5332, 0xcb32, 0x4b32, 0x2b32, 0xab32,
    0xcd32, 0x4d32, 0x2d32, 0xad32, 0x3532, 0xb532, 0xd532, 0x5532,
    0xccb2, 0x4cb2, 0x2cb2, 0xacb2, 0x34b2, 0xb4b2, 0xd4b2, 0x54b2,
    0x32b2, 0xb2b2, 0xd2b2, 0x52b2, 0xcab2, 0x4ab2, 0x2ab2, 0xaab2,
    0xccd2, 0x4cd2, 0x2cd2, 0xacd2, 0x34d2, 0xb4d2, 0xd4d2, 0x54d2,
    0x32d2, 0xb2d2, 0xd2d2, 0x52d2, 0xcad2, 0x4ad2, 0x2ad2, 0xaad2,
    0x3352, 0xb352, 0xd352, 0x5352, 0xcb52, 0x4b52, 0x2b52, 0xab52,
    0xcd52, 0x4d52, 0x2d52, 0xad52, 0x3552, 0xb552, 0xd552, 0x5552,
    0xccca, 0x4cca, 0x2cca, 0xacca, 0x34ca, 0xb4ca, 0xd4ca, 0x54ca,
    0x32ca, 0xb2ca, 0xd2ca, 0x52ca, 0xcaca, 0x4aca, 0x2aca, 0xaaca,
    0x334a, 0xb34a, 0xd34a, 0x534a, 0xcb4a, 0x4b4a, 0x2b4a, 0xab4a,
    0xcd4a, 0x4d4a, 0x2d4a, 0xad4a, 0x354a, 0xb54a, 0xd54a, 0x554a,
    0x332a, 0xb32a, 0xd32a, 0x532a, 0xcb2a, 0x4b2a, 0x2b2a, 0xab2a,
    0xcd2a, 0x4d2a, 0x2d2a, 0xad2a, 0x352a, 0xb52a, 0xd52a, 0x552a,
    0xccaa, 0x4caa, 0x2caa, 0xacaa, 0x34aa, 0xb4aa, 0xd4aa, 0x54aa,
    0x32aa, 0xb2aa, 0xd2aa, 0x52aa, 0xcaaa, 0x4aaa, 0x2aaa, 0xaaaa,
};

/* ── I2S handle ────────────────────────────────────────────────────────── */

static i2s_chan_handle_t tx_handle;

/* ── SPDIF state ───────────────────────────────────────────────────────── */

static uint8_t *spdif_buf;   /* SPDIF_BLOCK * 16 bytes, internal RAM      */
static size_t   spdif_count; /* frame counter within 192-frame SPDIF block */

/* ── Volume ────────────────────────────────────────────────────────────── */

static void apply_volume(int16_t *buf, size_t n) {
#ifndef DAC_CONTROLS_VOLUME
  int32_t vol = airplay_get_volume_q15();
  for (size_t i = 0; i < n; i++) {
    buf[i] = (int16_t)(((int32_t)buf[i] * vol) >> 15);
  }
#endif
}

/* ── SPDIF conversion ──────────────────────────────────────────────────
 *
 * SPDIF sub-frame layout (before BMC encoding, LSB to MSB):
 *   PPPP AAAA  SSSS SSSS  SSSS SSSS  SSSS VUCP
 *
 * After BMC encoding each bit becomes 2, so one sub-frame is 64 bits.
 * The trick is to start with a VUCP+preamble sequence so that the 16-bit
 * audio samples land on BMC word boundaries.
 *
 * Each stereo frame produces 4 × 32-bit words of output:
 *   [L_hi|L_lo]  [VUCP|preamble|L_aux]  [R_hi|R_lo]  [VUCP|preamble|R_aux]
 *
 * Input: interleaved 16-bit PCM (L, R, L, R …)
 * Output: 4 × uint32_t per frame
 */
static void IRAM_ATTR spdif_convert(int16_t *src, size_t frames, uint32_t *dst) {
  register uint16_t hi, lo, aux;
  size_t cnt = spdif_count;

  while (frames--) {
    /* ---- left channel ------------------------------------------------ */
    hi = spdif_bmclookup[(uint8_t)(*src >> 8)];
    lo = spdif_bmclookup[(uint8_t)*src++];

    /* differential encoding: invert if last preceding bit is 1 */
    lo ^= ~((int16_t)hi) >> 16;
    *dst++ = ((uint32_t)lo << 16) | hi;

    /* aux word = BMC of 0 (16-bit source has no extra bits) with parity */
    aux = 0xb333 ^ (((uint32_t)((int16_t)lo)) >> 17);

    /* VUCP + preamble: B at start of 192-frame block, M otherwise */
    if (++cnt > 191) {
      *dst++ = VUCP | ((uint32_t)PREAMBLE_B << 16) | aux;
      cnt = 0;
    } else {
      *dst++ = VUCP | ((uint32_t)PREAMBLE_M << 16) | aux;
    }

    /* ---- right channel ----------------------------------------------- */
    hi = spdif_bmclookup[(uint8_t)(*src >> 8)];
    lo = spdif_bmclookup[(uint8_t)*src++];
    lo ^= ~((int16_t)hi) >> 16;
    *dst++ = ((uint32_t)lo << 16) | hi;

    aux = 0xb333 ^ (((uint32_t)((int16_t)lo)) >> 17);
    *dst++ = VUCP | ((uint32_t)PREAMBLE_W << 16) | aux;
  }

  spdif_count = cnt;
}

/* ── Playback task ─────────────────────────────────────────────────────── */

static void playback_task(void *arg) {
  int16_t *pcm = malloc((size_t)(FRAME_SAMPLES + 1) * 2 * sizeof(int16_t));
  int16_t *silence = calloc((size_t)FRAME_SAMPLES * 2, sizeof(int16_t));
  if (!pcm || !silence) {
    ESP_LOGE(TAG, "Failed to allocate PCM buffers");
    free(pcm);
    free(silence);
    vTaskDelete(NULL);
    return;
  }

  size_t written;
  while (true) {
    size_t samples = audio_receiver_read(pcm, FRAME_SAMPLES + 1);
    if (samples > 0) {
      apply_volume(pcm, samples * 2);
      led_audio_feed(pcm, samples);

      /* Encode and send in SPDIF_BLOCK-sized chunks.
       * Each frame → 16 bytes of SPDIF data (4 × uint32_t). */
      size_t sent = 0;
      while (sent < samples) {
        size_t chunk = samples - sent;
        if (chunk > SPDIF_BLOCK) chunk = SPDIF_BLOCK;
        spdif_convert(pcm + sent * 2, chunk, (uint32_t *)spdif_buf);
        i2s_channel_write(tx_handle, spdif_buf, chunk * 16, &written,
                          portMAX_DELAY);
        sent += chunk;
      }
      taskYIELD();
    } else {
      led_audio_feed(silence, FRAME_SAMPLES);
      /* Send encoded silence */
      size_t sent = 0;
      while (sent < (size_t)FRAME_SAMPLES) {
        size_t chunk = FRAME_SAMPLES - sent;
        if (chunk > SPDIF_BLOCK) chunk = SPDIF_BLOCK;
        spdif_convert(silence + sent * 2, chunk, (uint32_t *)spdif_buf);
        i2s_channel_write(tx_handle, spdif_buf, chunk * 16, &written,
                          pdMS_TO_TICKS(10));
        sent += chunk;
      }
      vTaskDelay(1);
    }
  }
}

/* ── Public API ────────────────────────────────────────────────────────── */

esp_err_t audio_output_init(void) {
  ESP_LOGI(TAG, "Initialising SPDIF output on GPIO %d (bck=%d, ws=%d)",
           SPDIF_DO_PIN, SPDIF_BCK_PIN, SPDIF_WS_PIN);

  /* Allocate the SPDIF encode buffer in internal SRAM for speed —
   * the BMC conversion is called from IRAM and must access fast memory. */
  spdif_buf = heap_caps_malloc(SPDIF_BLOCK * 16, MALLOC_CAP_INTERNAL);
  if (!spdif_buf) {
    ESP_LOGE(TAG, "Failed to allocate SPDIF buffer (%d bytes)",
             SPDIF_BLOCK * 16);
    return ESP_ERR_NO_MEM;
  }
  spdif_count = 0;

  /* ── I2S channel ─────────────────────────────────────────────────── */
  i2s_chan_config_t chan_cfg =
      I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
  chan_cfg.dma_desc_num  = DMA_BUF_COUNT_SPDIF;
  chan_cfg.dma_frame_num = DMA_BUF_FRAMES_SPDIF;

  ESP_RETURN_ON_ERROR(i2s_new_channel(&chan_cfg, &tx_handle, NULL), TAG,
                      "channel create failed");

  /* SPDIF trick: run I2S at 2× sample rate with 32-bit slots.
   * Each real audio frame becomes two I2S "pseudo-frames" of 32-bit
   * stereo, carrying the BMC-encoded SPDIF bitstream on the DO pin. */
  i2s_std_config_t std_cfg = {
      .clk_cfg =
          I2S_STD_CLK_DEFAULT_CONFIG((uint32_t)SAMPLE_RATE * 2),
      .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(
          I2S_DATA_BIT_WIDTH_32BIT, I2S_SLOT_MODE_STEREO),
      .gpio_cfg =
          {
              .mclk = I2S_GPIO_UNUSED,
              .bclk = SPDIF_BCK_PIN,
              .ws   = SPDIF_WS_PIN,
              .dout = SPDIF_DO_PIN,
              .din  = I2S_GPIO_UNUSED,
          },
  };

  ESP_RETURN_ON_ERROR(i2s_channel_init_std_mode(tx_handle, &std_cfg), TAG,
                      "std mode init failed");
  ESP_RETURN_ON_ERROR(i2s_channel_enable(tx_handle), TAG,
                      "channel enable failed");

  ESP_LOGI(TAG, "SPDIF output ready  rate=%d×2  dma=%d×%d",
           SAMPLE_RATE, DMA_BUF_FRAMES_SPDIF, DMA_BUF_COUNT_SPDIF);
  return ESP_OK;
}

void audio_output_start(void) {
  xTaskCreatePinnedToCore(playback_task, "spdif_play", 4096, NULL, 7, NULL,
                          PLAYBACK_CORE);
}
