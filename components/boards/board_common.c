#include "board_common.h"

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
