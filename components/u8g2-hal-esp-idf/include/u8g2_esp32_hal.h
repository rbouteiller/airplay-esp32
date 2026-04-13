#ifndef U8G2_ESP32_HAL_H
#define U8G2_ESP32_HAL_H
/*
 * u8g2_esp32_hal.h
 *
 *  Created on: Feb 12, 2017
 *      Author: kolban
 */

#ifndef U8G2_ESP32_HAL_H_
#define U8G2_ESP32_HAL_H_
#include "u8g2.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"

#define U8G2_ESP32_HAL_UNDEFINED GPIO_NUM_NC

#if SOC_I2C_NUM > 1
#define I2C_MASTER_NUM I2C_NUM_1 //  I2C port number for master dev
#else
#define I2C_MASTER_NUM I2C_NUM_0 //  I2C port number for master dev
#endif

#define I2C_MASTER_TX_BUF_DISABLE 0     //  I2C master do not need buffer
#define I2C_MASTER_RX_BUF_DISABLE 0     //  I2C master do not need buffer
#define I2C_MASTER_FREQ_HZ        50000 //  I2C master clock frequency
#define ACK_CHECK_EN              0x1   //  I2C master will check ack from slave
#define ACK_CHECK_DIS             0x0 //  I2C master will not check ack from slave

/** @public
 * HAL configuration structure.
 */
typedef struct {
  union {
    /* SPI settings. */
    struct {
      /* GPIO num for clock. */
      gpio_num_t clk;
      /* GPIO num for SPI mosi. */
      gpio_num_t mosi;
      /* GPIO num for SPI slave/chip select. */
      gpio_num_t cs;
    } spi;
    /* I2C settings. */
    struct {
      /* GPIO num for I2C data. */
      gpio_num_t sda;
      /* GPIO num for I2C clock. */
      gpio_num_t scl;
    } i2c;
  } bus;
  /* GPIO num for reset. */
  gpio_num_t reset;
  /* GPIO num for DC. */
  gpio_num_t dc;
} u8g2_esp32_hal_t;

/**
 * Construct a default HAL configuration with all fields undefined.
 */
// clang-format off
#define U8G2_ESP32_HAL_DEFAULT                       \
  {.bus = {.spi = {.clk = U8G2_ESP32_HAL_UNDEFINED,  \
                   .mosi = U8G2_ESP32_HAL_UNDEFINED, \
                   .cs = U8G2_ESP32_HAL_UNDEFINED}}, \
   .reset = U8G2_ESP32_HAL_UNDEFINED,                \
   .dc = U8G2_ESP32_HAL_UNDEFINED}
// clang-format on

/**
 * Initialize the HAL with the given configuration.
 *
 * @see u8g2_esp32_hal_t
 * @see U8G2_ESP32_HAL_DEFAULT
 */
void u8g2_esp32_hal_init(u8g2_esp32_hal_t u8g2_esp32_hal_param);

/**
 * Supply a pre-initialised I2C master bus handle.
 * When set, u8g2_esp32_i2c_byte_cb will skip creating its own bus and use
 * this one instead.  Must be called after u8g2_esp32_hal_init().
 */
void u8g2_esp32_hal_set_i2c_bus(i2c_master_bus_handle_t bus);

/**
 * Supply a pre-initialised SPI host.
 * When set, u8g2_esp32_spi_byte_cb will skip calling spi_bus_initialize()
 * and will call spi_bus_add_device() on the provided host instead.
 * Must be called after u8g2_esp32_hal_init().
 */
void u8g2_esp32_hal_set_spi_host(spi_host_device_t host);

uint8_t u8g2_esp32_spi_byte_cb(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int,
                               void *arg_ptr);
uint8_t u8g2_esp32_i2c_byte_cb(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int,
                               void *arg_ptr);
uint8_t u8g2_esp32_gpio_and_delay_cb(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int,
                                     void *arg_ptr);
#endif /* U8G2_ESP32_HAL_H_ */

#endif