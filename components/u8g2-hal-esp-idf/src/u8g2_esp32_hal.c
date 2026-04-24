#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "u8g2_esp32_hal.h"

static const char *TAG = "u8g2_hal";
static const unsigned int I2C_TIMEOUT_MS = 1000;

static spi_device_handle_t handle_spi;  // SPI handle.
static i2c_master_bus_handle_t bus_i2c; // I2C bus handle.
static i2c_master_dev_handle_t dev_i2c; // I2C device handle.
static u8g2_esp32_hal_t u8g2_esp32_hal; // HAL state data.

#define I2C_BUFFER_SIZE 256
static uint8_t i2c_buffer[I2C_BUFFER_SIZE]; // I2C transmit buffer.
static size_t i2c_buf_idx;                  // Current index in I2C buffer.

// SPI host — defaults to SPI2_HOST; overridden by u8g2_esp32_hal_set_spi_host()
static spi_host_device_t s_spi_host = SPI2_HOST;
static bool s_spi_bus_external = false;

#undef ESP_ERROR_CHECK
#define ESP_ERROR_CHECK(x)                   \
  do {                                       \
    esp_err_t rc = (x);                      \
    if (rc != ESP_OK) {                      \
      ESP_LOGE("err", "esp_err_t = %d", rc); \
      assert(0 && #x);                       \
    }                                        \
  } while (0);

/*
 * Initialze the ESP32 HAL.
 */
void u8g2_esp32_hal_init(u8g2_esp32_hal_t u8g2_esp32_hal_param) {
  u8g2_esp32_hal = u8g2_esp32_hal_param;
  // Reset externally-supplied bus state so a fresh init works correctly
  bus_i2c = NULL;
  dev_i2c = NULL;
  s_spi_bus_external = false;
  s_spi_host = SPI2_HOST;
} // u8g2_esp32_hal_init

void u8g2_esp32_hal_set_i2c_bus(i2c_master_bus_handle_t bus) {
  bus_i2c = bus;
  dev_i2c = NULL;
}

void u8g2_esp32_hal_set_spi_host(spi_host_device_t host) {
  s_spi_host = host;
  s_spi_bus_external = true;
}

/*
 * HAL callback function as prescribed by the U8G2 library.  This callback is
 * invoked to handle SPI communications.
 */
uint8_t u8g2_esp32_spi_byte_cb(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int,
                               void *arg_ptr) {
  ESP_LOGD(TAG, "spi_byte_cb: Received a msg: %d, arg_int: %d, arg_ptr: %p",
           msg, arg_int, arg_ptr);
  switch (msg) {
  case U8X8_MSG_BYTE_SET_DC:
    if (u8g2_esp32_hal.dc != U8G2_ESP32_HAL_UNDEFINED) {
      gpio_set_level(u8g2_esp32_hal.dc, arg_int);
    }
    break;

  case U8X8_MSG_BYTE_INIT: {
    if (u8g2_esp32_hal.bus.spi.cs == U8G2_ESP32_HAL_UNDEFINED) {
      break;
    }

    if (!s_spi_bus_external) {
      // Caller wants us to own the SPI bus — initialise it now
      if (u8g2_esp32_hal.bus.spi.clk == U8G2_ESP32_HAL_UNDEFINED ||
          u8g2_esp32_hal.bus.spi.mosi == U8G2_ESP32_HAL_UNDEFINED) {
        break;
      }
      spi_bus_config_t bus_config = {0};
      bus_config.sclk_io_num = u8g2_esp32_hal.bus.spi.clk;
      bus_config.mosi_io_num = u8g2_esp32_hal.bus.spi.mosi;
      bus_config.miso_io_num = GPIO_NUM_NC;
      bus_config.quadwp_io_num = GPIO_NUM_NC;
      bus_config.quadhd_io_num = GPIO_NUM_NC;
      ESP_ERROR_CHECK(
          spi_bus_initialize(s_spi_host, &bus_config, SPI_DMA_CH_AUTO));
    }
    // else: caller pre-initialised the bus; just add our device to it

    spi_device_interface_config_t dev_config = {0};
    dev_config.address_bits = 0;
    dev_config.command_bits = 0;
    dev_config.dummy_bits = 0;
    dev_config.mode = 0;
    dev_config.duty_cycle_pos = 0;
    dev_config.cs_ena_posttrans = 0;
    dev_config.cs_ena_pretrans = 0;
    dev_config.clock_speed_hz = 8000000;
    dev_config.spics_io_num = u8g2_esp32_hal.bus.spi.cs;
    dev_config.flags = 0;
    dev_config.queue_size = 200;
    dev_config.pre_cb = NULL;
    dev_config.post_cb = NULL;
    ESP_ERROR_CHECK(spi_bus_add_device(s_spi_host, &dev_config, &handle_spi));

    break;
  }

  case U8X8_MSG_BYTE_SEND: {
    spi_transaction_t trans_desc = {0};
    trans_desc.addr = 0;
    trans_desc.cmd = 0;
    trans_desc.flags = 0;
    trans_desc.length = 8 * arg_int; // Number of bits NOT number of bytes.
    trans_desc.rxlength = 0;
    trans_desc.tx_buffer = arg_ptr;
    trans_desc.rx_buffer = NULL;
    // trans_desc.override_freq_hz = 0; // this param does not exist prior to
    // ESP-IDF 5.5.0 ESP_LOGI(TAG, "... Transmitting %d bytes.", arg_int);
    ESP_ERROR_CHECK(spi_device_transmit(handle_spi, &trans_desc));
    break;
  }
  }
  return 0;
} // u8g2_esp32_spi_byte_cb

/*
 * HAL callback function as prescribed by the U8G2 library.  This callback is
 * invoked to handle I2C communications.
 */
uint8_t u8g2_esp32_i2c_byte_cb(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int,
                               void *arg_ptr) {
  ESP_LOGD(TAG, "i2c_cb: Received a msg: %d, arg_int: %d, arg_ptr: %p", msg,
           arg_int, arg_ptr);

  switch (msg) {
  case U8X8_MSG_BYTE_SET_DC: {
    if (u8g2_esp32_hal.dc != U8G2_ESP32_HAL_UNDEFINED) {
      gpio_set_level(u8g2_esp32_hal.dc, arg_int);
    }
    break;
  }

  case U8X8_MSG_BYTE_INIT: {
    if (bus_i2c != NULL) {
      // Caller pre-supplied an I2C bus handle — nothing to initialise
      break;
    }
    if (u8g2_esp32_hal.bus.i2c.sda == U8G2_ESP32_HAL_UNDEFINED ||
        u8g2_esp32_hal.bus.i2c.scl == U8G2_ESP32_HAL_UNDEFINED) {
      break;
    }

    i2c_master_bus_config_t bus_config = {
        .i2c_port = I2C_MASTER_NUM,
        .sda_io_num = u8g2_esp32_hal.bus.i2c.sda,
        .scl_io_num = u8g2_esp32_hal.bus.i2c.scl,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    ESP_LOGI(TAG, "sda_io_num %d", bus_config.sda_io_num);
    ESP_LOGI(TAG, "scl_io_num %d", bus_config.scl_io_num);
    ESP_ERROR_CHECK(i2c_new_master_bus(&bus_config, &bus_i2c));
    dev_i2c = NULL;
    break;
  }

  case U8X8_MSG_BYTE_SEND: {
    uint8_t *data_ptr = (uint8_t *)arg_ptr;
    ESP_LOG_BUFFER_HEXDUMP(TAG, data_ptr, arg_int, ESP_LOG_VERBOSE);

    while (arg_int > 0) {
      if (i2c_buf_idx < I2C_BUFFER_SIZE) {
        i2c_buffer[i2c_buf_idx++] = *data_ptr;
      }
      data_ptr++;
      arg_int--;
    }
    break;
  }

  case U8X8_MSG_BYTE_START_TRANSFER: {
    uint8_t i2c_address = u8x8_GetI2CAddress(u8x8) >> 1;
    ESP_LOGD(TAG, "Start I2C transfer to %02X.", i2c_address);
    if (dev_i2c == NULL) {
      i2c_device_config_t dev_config = {
          .dev_addr_length = I2C_ADDR_BIT_LEN_7,
          .device_address = i2c_address,
          .scl_speed_hz = I2C_MASTER_FREQ_HZ,
      };
      ESP_ERROR_CHECK(
          i2c_master_bus_add_device(bus_i2c, &dev_config, &dev_i2c));
    }
    i2c_buf_idx = 0;
    break;
  }

  case U8X8_MSG_BYTE_END_TRANSFER: {
    ESP_LOGD(TAG, "End I2C transfer.");
    ESP_ERROR_CHECK(
        i2c_master_transmit(dev_i2c, i2c_buffer, i2c_buf_idx, I2C_TIMEOUT_MS));
    break;
  }
  }
  return 0;
} // u8g2_esp32_i2c_byte_cb

/*
 * HAL callback function as prescribed by the U8G2 library.  This callback is
 * invoked to handle callbacks for GPIO and delay functions.
 */
uint8_t u8g2_esp32_gpio_and_delay_cb(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int,
                                     void *arg_ptr) {
  ESP_LOGD(TAG,
           "gpio_and_delay_cb: Received a msg: %d, arg_int: %d, arg_ptr: %p",
           msg, arg_int, arg_ptr);

  switch (msg) {
    // Initialize the GPIO and DELAY HAL functions.  If the pins for DC and
    // RESET have been specified then we define those pins as GPIO outputs.
  case U8X8_MSG_GPIO_AND_DELAY_INIT: {
    uint64_t bitmask = 0;
    if (u8g2_esp32_hal.dc != U8G2_ESP32_HAL_UNDEFINED) {
      bitmask = bitmask | (1ull << u8g2_esp32_hal.dc);
    }
    if (u8g2_esp32_hal.reset != U8G2_ESP32_HAL_UNDEFINED) {
      bitmask = bitmask | (1ull << u8g2_esp32_hal.reset);
    }
    if (u8g2_esp32_hal.bus.spi.cs != U8G2_ESP32_HAL_UNDEFINED) {
      bitmask = bitmask | (1ull << u8g2_esp32_hal.bus.spi.cs);
    }

    if (bitmask == 0) {
      break;
    }
    gpio_config_t gpioConfig;
    gpioConfig.pin_bit_mask = bitmask;
    gpioConfig.mode = GPIO_MODE_OUTPUT;
    gpioConfig.pull_up_en = GPIO_PULLUP_DISABLE;
    gpioConfig.pull_down_en = GPIO_PULLDOWN_ENABLE;
    gpioConfig.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&gpioConfig);
    break;
  }

    // Set the GPIO reset pin to the value passed in through arg_int.
  case U8X8_MSG_GPIO_RESET:
    if (u8g2_esp32_hal.reset != U8G2_ESP32_HAL_UNDEFINED) {
      gpio_set_level(u8g2_esp32_hal.reset, arg_int);
    }
    break;
    // Set the GPIO client select pin to the value passed in through arg_int.
  case U8X8_MSG_GPIO_CS:
    if (u8g2_esp32_hal.bus.spi.cs != U8G2_ESP32_HAL_UNDEFINED) {
      gpio_set_level(u8g2_esp32_hal.bus.spi.cs, arg_int);
    }
    break;
    // Set the Software I²C pin to the value passed in through arg_int.
  case U8X8_MSG_GPIO_I2C_CLOCK:
    if (u8g2_esp32_hal.bus.i2c.scl != U8G2_ESP32_HAL_UNDEFINED) {
      gpio_set_level(u8g2_esp32_hal.bus.i2c.scl, arg_int);
      //				printf("%c",(arg_int==1?'C':'c'));
    }
    break;
    // Set the Software I²C pin to the value passed in through arg_int.
  case U8X8_MSG_GPIO_I2C_DATA:
    if (u8g2_esp32_hal.bus.i2c.sda != U8G2_ESP32_HAL_UNDEFINED) {
      gpio_set_level(u8g2_esp32_hal.bus.i2c.sda, arg_int);
      //				printf("%c",(arg_int==1?'D':'d'));
    }
    break;

    // Delay for the number of milliseconds passed in through arg_int.
  case U8X8_MSG_DELAY_MILLI:
    vTaskDelay(arg_int / portTICK_PERIOD_MS);
    break;
  }
  return 0;
} // u8g2_esp32_gpio_and_delay_cb
