#include "audio_output.h"

#include "audio_receiver.h"
#include "driver/i2s_std.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rtsp_server.h"

#include <stdlib.h>

#define TAG "audio_output"

#define I2S_BCK_PIN GPIO_NUM_5
#define I2S_LRCK_PIN GPIO_NUM_6
#define I2S_DOUT_PIN GPIO_NUM_7
#define SAMPLE_RATE 44100
#define FRAME_SAMPLES 352

#if CONFIG_FREERTOS_UNICORE
#define PLAYBACK_CORE 0
#else
#define PLAYBACK_CORE 1
#endif

static i2s_chan_handle_t tx_handle;

static void apply_volume(int16_t *buf, size_t n) {
  int32_t vol = airplay_get_volume_q15();
  for (size_t i = 0; i < n; i++) {
    buf[i] = (int16_t)(((int32_t)buf[i] * vol) >> 15);
  }
}

static void playback_task(void *arg) {
  int16_t *pcm = malloc((FRAME_SAMPLES + 1) * 2 * sizeof(int16_t));
  int16_t *silence = calloc(FRAME_SAMPLES * 2, sizeof(int16_t));
  if (!pcm || !silence) {
    ESP_LOGE(TAG, "Failed to allocate buffers");
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
      i2s_channel_write(tx_handle, pcm, samples * 4, &written, portMAX_DELAY);
      taskYIELD();
    } else {
      i2s_channel_write(tx_handle, silence, FRAME_SAMPLES * 4, &written,
                        pdMS_TO_TICKS(10));
      vTaskDelay(1);
    }
  }
}

esp_err_t audio_output_init(void) {
  i2s_chan_config_t chan_cfg =
      I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
  chan_cfg.dma_desc_num = 8;
  chan_cfg.dma_frame_num = 256;

  ESP_RETURN_ON_ERROR(i2s_new_channel(&chan_cfg, &tx_handle, NULL), TAG,
                      "channel create failed");

  i2s_std_config_t std_cfg = {
      .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(SAMPLE_RATE),
      .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT,
                                                      I2S_SLOT_MODE_STEREO),
      .gpio_cfg =
          {
              .mclk = I2S_GPIO_UNUSED,
              .bclk = I2S_BCK_PIN,
              .ws = I2S_LRCK_PIN,
              .dout = I2S_DOUT_PIN,
              .din = I2S_GPIO_UNUSED,
          },
  };

  ESP_RETURN_ON_ERROR(i2s_channel_init_std_mode(tx_handle, &std_cfg), TAG,
                      "std mode init failed");
  ESP_RETURN_ON_ERROR(i2s_channel_enable(tx_handle), TAG,
                      "channel enable failed");

  return ESP_OK;
}

void audio_output_start(void) {
  xTaskCreatePinnedToCore(playback_task, "audio_play", 4096, NULL, 7, NULL,
                          PLAYBACK_CORE);
}
