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

// I2S configuration for ESP32-S3 - adjust pins for your DAC board
// Common DAC boards (PCM5102, MAX98357, etc.):
//   BCK/SCK/BCLK = Bit Clock
//   LRCK/WS      = Word Select (Left/Right Clock)
//   DIN/SD/DOUT  = Serial Data Out (from ESP32 to DAC)
#define I2S_BCK_PIN     GPIO_NUM_5   // BCK/SCK - Bit Clock
#define I2S_LRCK_PIN    GPIO_NUM_6   // LRCK/WS - Word Select
#define I2S_DOUT_PIN    GPIO_NUM_7   // DIN/DOUT - Data to DAC
#define I2S_SAMPLE_RATE 44100
#define OUTPUT_ATTENUATION_DB 20
#define OUTPUT_ATTENUATION_SCALE_Q15 3277  // -20 dB ~= 0.1 in Q1.15
#if CONFIG_FREERTOS_UNICORE
#define AUDIO_TASK_CORE 0
#else
#define AUDIO_TASK_CORE 1
#endif

static i2s_chan_handle_t i2s_tx_handle = NULL;

static void apply_output_attenuation(int16_t *buffer, size_t samples)
{
    for (size_t i = 0; i < samples; i++) {
        int32_t scaled = (int32_t)buffer[i] * OUTPUT_ATTENUATION_SCALE_Q15;
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

    ESP_LOGI(TAG, "I2S initialized: BCK=GPIO%d, LRCK=GPIO%d, DOUT=GPIO%d, %d Hz",
             I2S_BCK_PIN, I2S_LRCK_PIN, I2S_DOUT_PIN, I2S_SAMPLE_RATE);
    return ESP_OK;
}

// Audio playback task - reads from audio_receiver and sends to I2S
static void audio_playback_task(void *pvParameters)
{
    ESP_LOGI(TAG, "Audio playback task started");
    ESP_LOGI(TAG, "Output attenuation: -%d dB", OUTPUT_ATTENUATION_DB);

    // Buffer for PCM samples (352 samples/frame * 2 channels * 2 bytes = 1408 bytes)
    const size_t SAMPLES_PER_READ = 352;
    int16_t *pcm_buffer = malloc(SAMPLES_PER_READ * 2 * sizeof(int16_t));
    if (!pcm_buffer) {
        ESP_LOGE(TAG, "Failed to allocate PCM buffer");
        vTaskDelete(NULL);
        return;
    }

    // Silence buffer for when no audio is available
    int16_t *silence = calloc(SAMPLES_PER_READ * 2, sizeof(int16_t));
    if (!silence) {
        free(pcm_buffer);
        vTaskDelete(NULL);
        return;
    }

    size_t bytes_written;
    uint32_t samples_played = 0;

    bool first_audio = true;
    uint32_t silence_count = 0;

    while (1) {
        // Try to read audio samples
        size_t samples = audio_receiver_read(pcm_buffer, SAMPLES_PER_READ);

        if (samples > 0) {
            // Log first audio received
            if (first_audio) {
                ESP_LOGI(TAG, "First audio samples received: %zu samples", samples);
                first_audio = false;
            }

            apply_output_attenuation(pcm_buffer, samples * 2);

            // Write samples to I2S
            size_t bytes = samples * 2 * sizeof(int16_t);  // stereo, 16-bit
            i2s_channel_write(i2s_tx_handle, pcm_buffer, bytes, &bytes_written, portMAX_DELAY);
            samples_played += samples;
            silence_count = 0;

            // Log periodically (every ~5 seconds of audio)
            if (samples_played % (I2S_SAMPLE_RATE * 5) < SAMPLES_PER_READ) {
                ESP_LOGI(TAG, "Audio playing: %lu samples output", samples_played);
            }
        } else {
            // No audio available - send silence to keep I2S running
            size_t bytes = SAMPLES_PER_READ * 2 * sizeof(int16_t);
            i2s_channel_write(i2s_tx_handle, silence, bytes, &bytes_written, pdMS_TO_TICKS(10));
            silence_count++;

            // Log waiting state periodically
            if (silence_count == 100) {
                ESP_LOGI(TAG, "Waiting for audio data...");
            } else if (silence_count % 1000 == 0 && silence_count > 0) {
                ESP_LOGI(TAG, "Still waiting for audio (%lu silence frames)", silence_count);
            }

            vTaskDelay(pdMS_TO_TICKS(5));
        }
    }

    free(pcm_buffer);
    free(silence);
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "AirPlay 2 Receiver starting...");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize WiFi
    wifi_init_sta();

    // Wait for WiFi connection
    ESP_LOGI(TAG, "Waiting for WiFi connection...");
    wifi_wait_connected();

    // Initialize HAP (generates/loads Ed25519 keypair)
    ESP_LOGI(TAG, "Initializing HAP...");
    ESP_ERROR_CHECK(hap_init());

    // Initialize audio receiver
    ESP_LOGI(TAG, "Initializing audio receiver...");
    ESP_ERROR_CHECK(audio_receiver_init());

    // Initialize I2S for audio output
    ESP_LOGI(TAG, "Initializing I2S audio output...");
    ESP_ERROR_CHECK(i2s_init());

    // Start audio playback task
    xTaskCreatePinnedToCore(audio_playback_task, "audio_play", 4096, NULL, 7, NULL,
                            AUDIO_TASK_CORE);

    // Start mDNS AirPlay advertisement
    ESP_LOGI(TAG, "Starting mDNS AirPlay service...");
    mdns_airplay_init();

    // Start RTSP server for AirPlay connections
    ESP_LOGI(TAG, "Starting RTSP server on port 7000...");
    ESP_ERROR_CHECK(rtsp_server_start());

    ESP_LOGI(TAG, "AirPlay 2 Receiver ready!");
    ESP_LOGI(TAG, "Device should now appear in AirPlay menu on iOS devices");

    // Keep running
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
