/**
 * @file board.h
 * @brief Board Hardware Abstraction Layer (HAL) Interface
 *
 * All boards must implement these functions to provide a common interface
 * for board initialization and information retrieval.
 */

#pragma once

#include "esp_err.h"

/**
 * @brief Board information structure
 */
typedef struct {
    const char *name;        /**< Board name (e.g., "SqueezeAMP") */
    const char *description; /**< Board description */
} board_info_t;

/**
 * @brief Get board information
 *
 * @return Pointer to board_info_t structure (never NULL)
 */
const board_info_t *board_get_info(void);

/**
 * @brief Initialize board-specific hardware
 *
 * This function is called early during startup to initialize any
 * board-specific peripherals such as DACs, GPIOs, power management, etc.
 *
 * @return ESP_OK on success, or an error code on failure
 */
esp_err_t board_init(void);

/**
 * @brief Deinitialize board-specific hardware
 *
 * This function is called during shutdown to clean up board-specific
 * resources.
 *
 * @return ESP_OK on success, or an error code on failure
 */
esp_err_t board_deinit(void);
