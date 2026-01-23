#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/i2s_std.h"
#include "wifi.h"
#include "hap.h"
#include "mdns_airplay.h"
#include "rtsp_server.h"
#include "audio_receiver.h"

static const char *TAG = "airplay2";

#define I2S_BCK_PIN     GPIO_NUM_5
#define I2S_LRCK_PIN    GPIO_NUM_6
#define I2S_DOUT_PIN    GPIO_NUM_7
#define I2S_SAMPLE_RATE 44100
// Fixed output attenuation to prevent clipping (applied in addition to AirPlay volume)
#define OUTPUT_ATTENUATION_DB 20
#define OUTPUT_ATTENUATION_SCALE_Q15 3277  // 10^(-20/20) * 32768 = 0.1 * 32768
#if CONFIG_FREERTOS_UNICORE
#define AUDIO_TASK_CORE 0
#else
#define AUDIO_TASK_CORE 1
#endif

static i2s_chan_handle_t i2s_tx_handle = NULL;

static void apply_output_attenuation(int16_t *buffer, size_t samples)
{
    // Get current AirPlay volume (Q15: 0=mute, 32768=unity)
    int32_t airplay_vol = airplay_get_volume_q15();

    // Combined scale: (OUTPUT_ATTENUATION * AIRPLAY_VOL) / 32768
    // This gives us a Q15 result
    int32_t combined_scale = ((int32_t)OUTPUT_ATTENUATION_SCALE_Q15 * airplay_vol) >> 15;

    for (size_t i = 0; i < samples; i++) {
        int32_t scaled = (int32_t)buffer[i] * combined_scale;
        buffer[i] = (int16_t)(scaled >> 15);
    }
}

static esp_err_t i2s_init(void)
{
    i2s_chan_config_t chan_cfg = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
    chan_cfg.dma_desc_num = 8;
    chan_cfg.dma_frame_num = 256;

    esp_err_t ret = i2s_new_channel(&chan_cfg, &i2s_tx_handle, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create I2S channel: %d", ret);
        return ret;
    }

    i2s_std_config_t std_cfg = {
        .clk_cfg = I2S_STD_CLK_DEFAULT_CONFIG(I2S_SAMPLE_RATE),
        .slot_cfg = I2S_STD_PHILIPS_SLOT_DEFAULT_CONFIG(I2S_DATA_BIT_WIDTH_16BIT, I2S_SLOT_MODE_STEREO),
        .gpio_cfg = {
            .mclk = I2S_GPIO_UNUSED,
            .bclk = I2S_BCK_PIN,
            .ws = I2S_LRCK_PIN,
            .dout = I2S_DOUT_PIN,
            .din = I2S_GPIO_UNUSED,
            .invert_flags = {
                .mclk_inv = false,
                .bclk_inv = false,
                .ws_inv = false,
            },
        },
    };

    ret = i2s_channel_init_std_mode(i2s_tx_handle, &std_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to init I2S std mode: %d", ret);
        return ret;
    }

    ret = i2s_channel_enable(i2s_tx_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to enable I2S channel: %d", ret);
        return ret;
    }

    return ESP_OK;
}

static void audio_playback_task(void *pvParameters)
{

    const size_t SAMPLES_PER_READ = 352;
    int16_t *pcm_buffer = malloc(SAMPLES_PER_READ * 2 * sizeof(int16_t));
    if (!pcm_buffer) {
        ESP_LOGE(TAG, "Failed to allocate PCM buffer");
        vTaskDelete(NULL);
        return;
    }

    int16_t *silence = calloc(SAMPLES_PER_READ * 2, sizeof(int16_t));
    if (!silence) {
        free(pcm_buffer);
        vTaskDelete(NULL);
        return;
    }

    size_t bytes_written;
    uint32_t silence_count = 0;

    while (1) {
        // Try to read audio samples
        size_t samples = audio_receiver_read(pcm_buffer, SAMPLES_PER_READ);

        if (samples > 0) {
            apply_output_attenuation(pcm_buffer, samples * 2);
            size_t bytes = samples * 2 * sizeof(int16_t);
            i2s_channel_write(i2s_tx_handle, pcm_buffer, bytes, &bytes_written, portMAX_DELAY);
            silence_count = 0;
        } else {
            size_t bytes = SAMPLES_PER_READ * 2 * sizeof(int16_t);
            i2s_channel_write(i2s_tx_handle, silence, bytes, &bytes_written, pdMS_TO_TICKS(10));
            silence_count++;
            vTaskDelay(pdMS_TO_TICKS(5));
        }
    }

    free(pcm_buffer);
    free(silence);
    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta();
    wifi_wait_connected();
    ESP_ERROR_CHECK(hap_init());
    ESP_ERROR_CHECK(audio_receiver_init());
    ESP_ERROR_CHECK(i2s_init());

    xTaskCreatePinnedToCore(audio_playback_task, "audio_play", 4096, NULL, 7, NULL,
                            AUDIO_TASK_CORE);

    mdns_airplay_init();
    ESP_ERROR_CHECK(rtsp_server_start());

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
