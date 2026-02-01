#include "audio_output.h"

#include "audio_receiver.h"
#include "driver/i2s_std.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "rtsp_server.h"

#include <stdlib.h>
#ifdef CONFIG_SQUEEZEAMP
#include "dac_tas57xx.h"
#define I2C_PORT_0 0
#else
// SIDE NOTE; providing power from GPIO pins is capped ~20mA.
#define I2S_GND_PIN GPIO_NUM_14
// #define I2S_VCC_PIN   GPIO_NUM_14
#endif

#define TAG          "audio_output"
#define I2S_BCK_PIN   CONFIG_I2S_BCK_IO
#define I2S_LRCK_PIN  CONFIG_I2S_WS_IO
#define I2S_DOUT_PIN  CONFIG_I2S_DO_IO
#define SAMPLE_RATE   44100
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
  int16_t *pcm = malloc((size_t)(FRAME_SAMPLES + 1) * 2 * sizeof(int16_t));
  int16_t *silence = calloc((size_t)FRAME_SAMPLES * 2, sizeof(int16_t));
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
      i2s_channel_write(tx_handle, silence, (size_t)FRAME_SAMPLES * 4, &written,
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
#ifdef CONFIG_SQUEEZEAMP
  esp_err_t err = ESP_OK;
  err = tas57xx_init(I2C_PORT_0, CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "Failed to initialize TAS57xx: %s", esp_err_to_name(err));
  };
#endif
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
#ifdef I2S_GND_PIN
  gpio_reset_pin(I2S_GND_PIN);
  gpio_set_direction(I2S_GND_PIN, GPIO_MODE_OUTPUT);
  gpio_set_level(I2S_GND_PIN, 0);
#endif
#ifdef I2S_VCC_PIN
  gpio_reset_pin(I2S_VCC_PIN);
  gpio_set_direction(I2S_VCC_PIN, GPIO_MODE_OUTPUT);
  gpio_set_level(I2S_VCC_PIN, 1);
#endif

  ESP_RETURN_ON_ERROR(i2s_channel_init_std_mode(tx_handle, &std_cfg), TAG,
                      "std mode init failed");
  ESP_RETURN_ON_ERROR(i2s_channel_enable(tx_handle), TAG,
                      "channel enable failed");

  return ESP_OK;
}

void audio_output_start(void) {
#ifdef CONFIG_SQUEEZEAMP
  tas57xx_set_power_mode(TAS57XX_AMP_ON);
  tas57xx_enable_speaker(true);
#endif
  xTaskCreatePinnedToCore(playback_task, "audio_play", 4096, NULL, 7, NULL,
                          PLAYBACK_CORE);
}
