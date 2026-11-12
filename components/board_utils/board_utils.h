// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "driver/i2c_master.h"
#include "esp_err.h"

/* ========== Common GPIO ISR service ========== */

/**
 * @brief Install the shared GPIO ISR service
 *
 * Safe to call multiple times — returns ESP_OK if already installed.
 * Board-specific init and the button driver both rely on this.
 *
 * @return ESP_OK on success
 */
esp_err_t board_gpio_isr_init(void);

/* ========== Common I2C bus helpers ========== */

/** Default I2C timeout in ms used by the helpers below. */
#define BOARD_I2C_TIMEOUT_MS 100

/**
 * @brief Add an I2C device to a master bus
 *
 * @param bus        Master bus handle
 * @param addr       7-bit device address
 * @param speed_hz   SCL clock speed in Hz
 * @param[out] dev   Resulting device handle
 * @return ESP_OK on success
 */
esp_err_t board_i2c_add_device(i2c_master_bus_handle_t bus, uint8_t addr,
                               uint32_t speed_hz, i2c_master_dev_handle_t *dev);

/**
 * @brief Remove an I2C device from the bus
 */
esp_err_t board_i2c_remove_device(i2c_master_dev_handle_t dev);

/**
 * @brief Write data to an I2C device register
 *
 * Prepends the register byte to @p data and transmits in a single
 * I2C transaction.
 *
 * @param dev   Device handle
 * @param reg   Register address
 * @param data  Payload bytes
 * @param len   Number of payload bytes
 * @return ESP_OK on success
 */
esp_err_t board_i2c_write(i2c_master_dev_handle_t dev, uint8_t reg,
                          const uint8_t *data, size_t len);

/**
 * @brief Write raw bytes to an I2C device (no register prefix)
 *
 * @param dev   Device handle
 * @param data  Payload bytes
 * @param len   Number of bytes
 * @return ESP_OK on success
 */
esp_err_t board_i2c_write_raw(i2c_master_dev_handle_t dev, const uint8_t *data,
                              size_t len);

/**
 * @brief Read data from an I2C device register
 *
 * Sends the single-byte register address, then reads @p len bytes.
 *
 * @param dev   Device handle
 * @param reg   Register address
 * @param data  Buffer to receive data
 * @param len   Number of bytes to read
 * @return ESP_OK on success
 */
esp_err_t board_i2c_read(i2c_master_dev_handle_t dev, uint8_t reg,
                         uint8_t *data, size_t len);
