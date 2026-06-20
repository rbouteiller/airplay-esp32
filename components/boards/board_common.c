#include "board_common.h"

#include "esp_sleep.h"

/**
 * Weak default implementations of iot_board_*() functions.
 * Board-specific board.c files override these as needed.
 */

__attribute__((weak)) esp_err_t iot_board_init(void) {
  return ESP_OK;
}

__attribute__((weak)) esp_err_t iot_board_deinit(void) {
  return ESP_OK;
}

__attribute__((weak)) bool iot_board_is_init(void) {
  return false;
}

__attribute__((weak)) board_res_handle_t iot_board_get_handle(int id) {
  (void)id;
  return NULL;
}

__attribute__((weak)) const char *iot_board_get_info(void) {
  return "Unknown Board";
}

__attribute__((weak)) void iot_board_init_lvgl_resources(void) {
}

// Default: boards without a power latch enter deep sleep instead of cutting
// power. The Waveshare board overrides this to release its battery latch.
__attribute__((weak)) void board_power_off(void) {
  esp_deep_sleep_start();
}

// Default: no battery monitor. Boards with a battery override this.
__attribute__((weak)) bool board_battery_read(int *percent, bool *charging) {
  (void)percent;
  (void)charging;
  return false;
}
