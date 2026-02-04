/**
 * @file board.c
 * @brief ESP32-S3 Generic board HAL implementation
 *
 * Minimal HAL for generic ESP32-S3 dev boards with external I2S DAC.
 * No board-specific initialization required.
 */

#include "board.h"

#include "esp_log.h"

static const char TAG[] = "ESP32S3-Generic";

static const board_info_t s_board_info = {
    .name = "ESP32-S3 Generic",
    .description = "Generic ESP32-S3 dev board with external I2S DAC",
};

const board_info_t *board_get_info(void) {
    return &s_board_info;
}

esp_err_t board_init(void) {
    ESP_LOGI(TAG, "Generic board initialized (no board-specific init needed)");
    return ESP_OK;
}

esp_err_t board_deinit(void) {
    return ESP_OK;
}
