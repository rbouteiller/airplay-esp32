/**
 * SPDIF audio output via I2S bit-banging — amedes approach
 *
 * Based on the public-domain SPDIF implementation by amedes:
 *   https://github.com/amedes/esp_a2dp_sink_spdif
 *
 * The buffer is pre-filled with alternating M (left) / W (right) preambles.
 * Only the audio-data words (odd uint32_t indices) are written during
 * conversion.  The B (block-start) preamble is applied by XOR-flipping one
 * byte at the start of each half-block write — the XOR naturally toggles
 * between M and B every 96 stereo frames, placing B exactly once per
 * 192-frame SPDIF block.
 *
 * BCK and WS are not routed to any GPIO — only the DOUT pin carries the
 * SPDIF signal.  The internal I2S clock still runs, but no external
 * clocks are emitted.
 *
 * For coax SPDIF output, use this passive circuit:
 *
 *                     100nF
 * GPIO ----210R------||---- coax SPDIF signal out
 *               |
 *             110R
 *               |
 * GND  -------------------- coax signal ground
 */

#include "audio_output.h"

#include "audio_receiver.h"
#include "led.h"
#include "driver/i2s_std.h"
#include "esp_check.h"
#include "soc/soc_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rtsp_server.h"
#include <stdlib.h>
#include <string.h>

#define TAG           "audio_spdif"
#define SAMPLE_RATE   44100
#define FRAME_SAMPLES 352

#define SPDIF_DO_PIN CONFIG_SPDIF_DO_IO

#if CONFIG_FREERTOS_UNICORE
#define PLAYBACK_CORE 0
#else
#define PLAYBACK_CORE 1
#endif

/* ── SPDIF framing constants ──────────────────────────────────────────── */

#define I2S_BITS      32
#define I2S_CHANNELS  2
#define BMC_BITS      64 /* bits per SPDIF sub-frame after BMC */
#define BMC_FACTOR    (BMC_BITS / I2S_BITS) /* = 2 */
#define SPDIF_BLOCK   192 /* sub-frames per SPDIF block (L+R)  */
#define SPDIF_BUF_DIV 2   /* half-block buffering              */

/* DMA: one DMA buffer = one half-block = 96 stereo frames = 192 I2S
 * "pseudo-frames" of 32-bit stereo.  Size = 192 × 8 = 1536 bytes.      */
#define DMA_BUF_COUNT  2
#define DMA_BUF_FRAMES (SPDIF_BLOCK * BMC_BITS / I2S_BITS / SPDIF_BUF_DIV)

/* Encode buffer (uint32_t array) — one half-block                        */
#define SPDIF_BUF_BYTES \
  (SPDIF_BLOCK * (BMC_BITS / 8) * I2S_CHANNELS / SPDIF_BUF_DIV)
#define SPDIF_BUF_WORDS (SPDIF_BUF_BYTES / sizeof(uint32_t))

/* ── BMC preambles ─────────────────────────────────────────────────────── */

#define BMC_B      0x33173333U /* block start (B) */
#define BMC_M      0x331d3333U /* left channel (M) */
#define BMC_W      0x331b3333U /* right channel (W) */
#define BMC_MW_DIF (BMC_M ^ BMC_W)

/* Byte offset within the first preamble word where M↔B differs */
#define SYNC_OFFSET 2
#define SYNC_FLIP   ((BMC_B ^ BMC_M) >> (SYNC_OFFSET * 8))

/* ── BMC lookup table ──────────────────────────────────────────────────
 * 8-bit PCM → 16-bit BMC, LSb first, ending with a "1" level.          */

static const int16_t bmc_tab[256] = {
    0x3333, 0xb333, 0xd333, 0x5333, 0xcb33, 0x4b33, 0x2b33, 0xab33, 0xcd33,
    0x4d33, 0x2d33, 0xad33, 0x3533, 0xb533, 0xd533, 0x5533, 0xccb3, 0x4cb3,
    0x2cb3, 0xacb3, 0x34b3, 0xb4b3, 0xd4b3, 0x54b3, 0x32b3, 0xb2b3, 0xd2b3,
    0x52b3, 0xcab3, 0x4ab3, 0x2ab3, 0xaab3, 0xccd3, 0x4cd3, 0x2cd3, 0xacd3,
    0x34d3, 0xb4d3, 0xd4d3, 0x54d3, 0x32d3, 0xb2d3, 0xd2d3, 0x52d3, 0xcad3,
    0x4ad3, 0x2ad3, 0xaad3, 0x3353, 0xb353, 0xd353, 0x5353, 0xcb53, 0x4b53,
    0x2b53, 0xab53, 0xcd53, 0x4d53, 0x2d53, 0xad53, 0x3553, 0xb553, 0xd553,
    0x5553, 0xcccb, 0x4ccb, 0x2ccb, 0xaccb, 0x34cb, 0xb4cb, 0xd4cb, 0x54cb,
    0x32cb, 0xb2cb, 0xd2cb, 0x52cb, 0xcacb, 0x4acb, 0x2acb, 0xaacb, 0x334b,
    0xb34b, 0xd34b, 0x534b, 0xcb4b, 0x4b4b, 0x2b4b, 0xab4b, 0xcd4b, 0x4d4b,
    0x2d4b, 0xad4b, 0x354b, 0xb54b, 0xd54b, 0x554b, 0x332b, 0xb32b, 0xd32b,
    0x532b, 0xcb2b, 0x4b2b, 0x2b2b, 0xab2b, 0xcd2b, 0x4d2b, 0x2d2b, 0xad2b,
    0x352b, 0xb52b, 0xd52b, 0x552b, 0xccab, 0x4cab, 0x2cab, 0xacab, 0x34ab,
    0xb4ab, 0xd4ab, 0x54ab, 0x32ab, 0xb2ab, 0xd2ab, 0x52ab, 0xcaab, 0x4aab,
    0x2aab, 0xaaab, 0xcccd, 0x4ccd, 0x2ccd, 0xaccd, 0x34cd, 0xb4cd, 0xd4cd,
    0x54cd, 0x32cd, 0xb2cd, 0xd2cd, 0x52cd, 0xcacd, 0x4acd, 0x2acd, 0xaacd,
    0x334d, 0xb34d, 0xd34d, 0x534d, 0xcb4d, 0x4b4d, 0x2b4d, 0xab4d, 0xcd4d,
    0x4d4d, 0x2d4d, 0xad4d, 0x354d, 0xb54d, 0xd54d, 0x554d, 0x332d, 0xb32d,
    0xd32d, 0x532d, 0xcb2d, 0x4b2d, 0x2b2d, 0xab2d, 0xcd2d, 0x4d2d, 0x2d2d,
    0xad2d, 0x352d, 0xb52d, 0xd52d, 0x552d, 0xccad, 0x4cad, 0x2cad, 0xacad,
    0x34ad, 0xb4ad, 0xd4ad, 0x54ad, 0x32ad, 0xb2ad, 0xd2ad, 0x52ad, 0xcaad,
    0x4aad, 0x2aad, 0xaaad, 0x3335, 0xb335, 0xd335, 0x5335, 0xcb35, 0x4b35,
    0x2b35, 0xab35, 0xcd35, 0x4d35, 0x2d35, 0xad35, 0x3535, 0xb535, 0xd535,
    0x5535, 0xccb5, 0x4cb5, 0x2cb5, 0xacb5, 0x34b5, 0xb4b5, 0xd4b5, 0x54b5,
    0x32b5, 0xb2b5, 0xd2b5, 0x52b5, 0xcab5, 0x4ab5, 0x2ab5, 0xaab5, 0xccd5,
    0x4cd5, 0x2cd5, 0xacd5, 0x34d5, 0xb4d5, 0xd4d5, 0x54d5, 0x32d5, 0xb2d5,
    0xd2d5, 0x52d5, 0xcad5, 0x4ad5, 0x2ad5, 0xaad5, 0x3355, 0xb355, 0xd355,
    0x5355, 0xcb55, 0x4b55, 0x2b55, 0xab55, 0xcd55, 0x4d55, 0x2d55, 0xad55,
    0x3555, 0xb555, 0xd555, 0x5555,
};

/* ── I2S handle ────────────────────────────────────────────────────────── */

static i2s_chan_handle_t tx_handle;

/* ── SPDIF encode buffer and write pointer ─────────────────────────────── */

static uint32_t spdif_buf[SPDIF_BUF_WORDS];
static uint32_t *spdif_ptr;

/* ── Volume ────────────────────────────────────────────────────────────── */

static void apply_volume(int16_t *buf, size_t n) {
#ifndef DAC_CONTROLS_VOLUME
  int32_t vol = airplay_get_volume_q15();
  for (size_t i = 0; i < n; i++) {
    buf[i] = (int16_t)(((int32_t)buf[i] * vol) >> 15);
  }
#endif
}

/* ── SPDIF buffer init ─────────────────────────────────────────────────
 * Pre-fill even indices with alternating M / W preamble words.
 * Odd indices (audio data) will be overwritten during conversion.       */

static void spdif_buf_init(void) {
  uint32_t bmc_mw = BMC_W;
  for (int i = 0; i < (int)SPDIF_BUF_WORDS; i += 2) {
    spdif_buf[i] = (bmc_mw ^= BMC_MW_DIF);
  }
}

/* ── SPDIF write ───────────────────────────────────────────────────────
 * Convert interleaved 16-bit PCM to BMC and push to I2S when the
 * half-block buffer fills.
 *
 *   src  — pointer to interleaved 16-bit stereo PCM
 *   size — total byte count (frames × 2 ch × 2 bytes)                  */

static void spdif_write(const void *src, size_t size) {
  const uint8_t *p = src;

  while (p < (const uint8_t *)src + size) {
    /* Each 16-bit sample → one SPDIF sub-frame:
     *   bmc_tab[lo_byte] occupies upper 16 bits
     *   bmc_tab[hi_byte] occupies lower 16 bits
     *   XOR gives differential encoding
     *   << 1 >> 1 clears MSB (parity = 0)                              */
    *(spdif_ptr + 1) =
        (uint32_t)(((bmc_tab[*p] << 16) ^ bmc_tab[*(p + 1)]) << 1) >> 1;

    p += 2;
    spdif_ptr += 2; /* skip preamble word → next slot pair */

    /* Half-block complete → toggle B-preamble and flush to DMA          */
    if (spdif_ptr >= &spdif_buf[SPDIF_BUF_WORDS]) {
      size_t written;

      /* XOR toggles byte at SYNC_OFFSET between M and B preamble.
       * Because we always XOR, it alternates: B on even half-blocks,
       * M on odd ones → B appears once every 192 frames.               */
      ((uint8_t *)spdif_buf)[SYNC_OFFSET] ^= SYNC_FLIP;

      i2s_channel_write(tx_handle, spdif_buf, sizeof(spdif_buf), &written,
                        portMAX_DELAY);
      spdif_ptr = spdif_buf;
    }
  }
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

  while (true) {
    size_t samples = audio_receiver_read(pcm, FRAME_SAMPLES + 1);
    if (samples > 0) {
      apply_volume(pcm, samples * 2);
      led_audio_feed(pcm, samples);
      spdif_write(pcm, samples * 2 * sizeof(int16_t));
      taskYIELD();
    } else {
      led_audio_feed(silence, FRAME_SAMPLES);
      spdif_write(silence, (size_t)FRAME_SAMPLES * 2 * sizeof(int16_t));
      vTaskDelay(1);
    }
  }
}

/* ── Public API ────────────────────────────────────────────────────────── */

esp_err_t audio_output_init(void) {
  ESP_LOGI(TAG, "Initialising SPDIF output (amedes) on GPIO %d", SPDIF_DO_PIN);

  /* Pre-fill buffer with alternating M/W preambles */
  spdif_buf_init();
  spdif_ptr = spdif_buf;

  /* ── I2S channel ─────────────────────────────────────────────────── */
  i2s_chan_config_t chan_cfg =
      I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
  chan_cfg.dma_desc_num = DMA_BUF_COUNT;
  chan_cfg.dma_frame_num = DMA_BUF_FRAMES;

  ESP_RETURN_ON_ERROR(i2s_new_channel(&chan_cfg, &tx_handle, NULL), TAG,
                      "channel create failed");

  /* SPDIF: I2S at 2× sample rate, 32-bit stereo.
   * Only DOUT carries the SPDIF signal; BCK and WS are internal-only.
   * APLL provides exact audio-rate clocking (ESP32). */
  i2s_std_clk_config_t clk_cfg =
      I2S_STD_CLK_DEFAULT_CONFIG((uint32_t)SAMPLE_RATE * BMC_FACTOR);
#if SOC_I2S_SUPPORTS_APLL
  clk_cfg.clk_src = I2S_CLK_SRC_APLL;
#endif
  clk_cfg.mclk_multiple = I2S_MCLK_MULTIPLE_256;

  i2s_std_config_t std_cfg = {
      .clk_cfg = clk_cfg,
      .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_32BIT,
                                                      I2S_SLOT_MODE_STEREO),
      .gpio_cfg =
          {
              .mclk = I2S_GPIO_UNUSED,
              .bclk = I2S_GPIO_UNUSED,
              .ws = I2S_GPIO_UNUSED,
              .dout = SPDIF_DO_PIN,
              .din = I2S_GPIO_UNUSED,
          },
  };

  ESP_RETURN_ON_ERROR(i2s_channel_init_std_mode(tx_handle, &std_cfg), TAG,
                      "std mode init failed");
  ESP_RETURN_ON_ERROR(i2s_channel_enable(tx_handle), TAG,
                      "channel enable failed");

  /* Pre-fill DMA with SPDIF-encoded silence so the receiver can lock */
  {
    int16_t silence_pcm[SPDIF_BLOCK * 2];
    memset(silence_pcm, 0, sizeof(silence_pcm));
    for (int i = 0; i < DMA_BUF_COUNT; i++) {
      spdif_write(silence_pcm,
                  (size_t)(SPDIF_BLOCK / SPDIF_BUF_DIV) * 2 * sizeof(int16_t));
    }
  }

  ESP_LOGI(TAG, "SPDIF output ready  rate=%d×%d  dma=%d×%d", SAMPLE_RATE,
           BMC_FACTOR, DMA_BUF_FRAMES, DMA_BUF_COUNT);
  return ESP_OK;
}

void audio_output_start(void) {
  xTaskCreatePinnedToCore(playback_task, "spdif_play", 4096, NULL, 7, NULL,
                          PLAYBACK_CORE);
}
