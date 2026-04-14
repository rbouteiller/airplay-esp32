#pragma once

#include "esp_err.h"
#include "driver/i2c_master.h"
#include <stdbool.h>
#include "board_utils.h"

typedef void *board_res_handle_t;

typedef enum {
  NULL_RESOURCE = 0,
  BOARD_I2C_DAC_ID,  ///< I2C master bus used by the DAC
  BOARD_I2C_DISP_ID, ///< I2C master bus used by the display
  BOARD_SPI_ETH_ID,  ///< SPI host used by the Ethernet controller
  BOARD_SPI_DISP_ID, ///< SPI host used by the display
} board_res_id_t;

/**
 * @brief Initialize board-specific hardware
 *
 * This function is called early during startup to initialize any
 * board-specific peripherals such as DACs, GPIOs, power management, etc.
 *
 * @return ESP_OK on success, or an error code on failure
 */
esp_err_t iot_board_init(void);

/**
 * @brief Deinitialize board-specific hardware
 *
 * This function is called during shutdown to clean up board-specific
 * resources.
 *
 * @return ESP_OK on success, or an error code on failure
 */
esp_err_t iot_board_deinit(void);

/**
 * @brief Check if board is initialized
 *
 * @return true if board is initialized, false otherwise
 */
bool iot_board_is_init(void);

/**
 * @brief Get a handle to a board resource
 *
 * @param id Resource identifier (from board_res_id_t)
 * @return Handle to the resource, or NULL if not available
 */
board_res_handle_t iot_board_get_handle(int id);

/**
 * @brief Get board information string
 *
 * @return Board name string (never NULL)
 */
const char *iot_board_get_info(void);
