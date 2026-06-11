/**
 * @file board.c
 * @brief Waveshare ESP32-S3-Touch-LCD-1.54 board implementation
 *
 * Board with integrated ST7789 SPI display (with touch via CST816S I2C),
 * and ES8311 I2C-controlled stereo audio codec for DAC output.
 */

#include "iot_board.h"

#include "dac_es8311.h"
#include "playback_control.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"
#include "esp_lvgl_port.h"

#include "sdkconfig.h"

static const char TAG[] = "Waveshare-ESP32-S3-Touch-LCD-1.54";

static bool s_board_initialized = false;
static bool s_touch_deferred = false;

// I2C bus handle for ES8311 + CST816S touch controller
static i2c_master_bus_handle_t s_i2c_dac_bus_handle = NULL;

// CST816S touch controller (I2C addr 0x15)
#define CST816S_ADDR            0x15
#define CST816S_REG_STATUS      0x00
#define CST816S_REG_XY          0x03
#define CST816S_REG_CHIP_STATUS 0xA7
#define CST816S_CHIP_ID         0xB4
#define CST816S_REG_CONFIG_START 0x5D

// Display touch parameters (swap + mirror applied at panel level)
#define TOUCH_SWAP_XY   true
#define TOUCH_MIRROR_X  true
#define TOUCH_MIRROR_Y  false
#define TOUCH_WIDTH     240
#define TOUCH_HEIGHT    240

static i2c_master_dev_handle_t s_cst816s_dev = NULL;
static lv_indev_t *s_touch_indev = NULL;

static bool s_gpio7_state = false;

void set_gpio7_level(bool level) {
  if (level != s_gpio7_state) {
    gpio_set_level((gpio_num_t)7, level ? 1 : 0);
    s_gpio7_state = level;
    ESP_LOGI(TAG, "GPIO7 changed state to %s", level ? "HIGH" : "LOW");
  }
}

void init_gpio7(void) {
  gpio_reset_pin((gpio_num_t)7);
  gpio_set_direction((gpio_num_t)7, GPIO_MODE_OUTPUT);
  set_gpio7_level(true);
}

// Battery power latch (GPIO2 / BAT_EN). The board powers up momentarily when
// KEY_PWR (GPIO5) is pressed; firmware must drive BAT_EN HIGH to hold the
// latch closed so the board keeps running on battery after USB is removed.
// Driving it LOW opens the latch and powers the board off.
#define BAT_EN_GPIO ((gpio_num_t)2)

void board_power_latch_init(void) {
  gpio_reset_pin(BAT_EN_GPIO);
  gpio_set_direction(BAT_EN_GPIO, GPIO_MODE_OUTPUT);
  gpio_set_level(BAT_EN_GPIO, 1);
  ESP_LOGI(TAG, "Battery power latch held (GPIO2 HIGH)");
}

void board_power_off(void) {
  ESP_LOGI(TAG, "Powering off — releasing battery latch (GPIO2 LOW)");
  gpio_set_level(BAT_EN_GPIO, 0);
}

#ifdef CONFIG_MUTE_GPIO
static esp_err_t init_mute_gpio(void) {
  if (CONFIG_MUTE_GPIO < 0) {
    return ESP_OK;
  }

  gpio_config_t io_conf = {
      .pin_bit_mask = (1ULL << CONFIG_MUTE_GPIO),
      .mode = GPIO_MODE_OUTPUT,
      .pull_up_en = GPIO_PULLUP_DISABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  //ESP_RETURN_ON_ERROR(gpio_config(&io_conf), TAG, "Failed to configure mute GPIO");

  // Initialize to unmuted state — set opposite of active level
  gpio_set_level(CONFIG_MUTE_GPIO, !CONFIG_MUTE_GPIO_LEVEL);

  ESP_LOGI(TAG, "Mute GPIO %d initialized (active %s, init %s)",
           CONFIG_MUTE_GPIO,
           CONFIG_MUTE_GPIO_LEVEL ? "high" : "low",
           CONFIG_MUTE_GPIO_LEVEL ? "low" : "high");
  return ESP_OK;
}
#endif

// ============================================================================
// CST816S Touch Driver
// ============================================================================

static bool cst816s_i2c_write_reg(i2c_master_bus_handle_t bus, i2c_master_dev_handle_t dev,
                                  uint8_t reg, uint8_t val, TickType_t timeout) {
  uint8_t buf[2] = { reg, val };
  return i2c_master_transmit(dev, buf, 2, timeout) == ESP_OK;
}

static bool cst816s_read_reg(i2c_master_bus_handle_t bus, i2c_master_dev_handle_t dev,
                             uint8_t reg, uint8_t *val, size_t len, TickType_t timeout) {
  // I2C register read: write register address, then read data
  int xfer_timeout = (timeout == portMAX_DELAY) ? -1 : (int) (timeout / portTICK_PERIOD_MS);
  return i2c_master_transmit_receive(dev, &reg, 1, val, len, xfer_timeout) == ESP_OK;
}

static esp_err_t init_touch_controller(void) {
  const int timeout = pdMS_TO_TICKS(100);

  // Register CST816S on I2C bus
  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = CST816S_ADDR,
      .scl_speed_hz = 400000,
  };
  esp_err_t err = i2c_master_bus_add_device(s_i2c_dac_bus_handle, &dev_cfg, &s_cst816s_dev);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to add CST816S I2C device: %s", esp_err_to_name(err));
    return err;
  }

  // Configure GPIO 48 (INT) as interrupt input
  const gpio_config_t int_cfg = {
      .pin_bit_mask = (1ULL << BOARD_I2C_TOUCH_INT_GPIO),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_ENABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_ANYEDGE,
  };
  gpio_config(&int_cfg);

  // Write default configuration registers
  struct reg_config {
    uint8_t reg;
    uint8_t val;
  };
  static const struct reg_config cfg[] = {
    { 0xB1, 0x5B },  // Touch mode settings
    { 0xB2, 0x0E },  // Gate switch time
    { 0xB3, 0x00 },  // Button mode disable
    { 0x94, 0x0B },  // Touch count interrupt enable
    { 0x95, 0x0B },  // Touch count interrupt enable
    { 0x96, 0x01 },  // Auto sleep after touch
    { 0x98, 0x3D },  // Monitor period
    { 0x99, 0x2B },  // Sleep time
    { 0x9A, 0x01 },  // LED rate
  };
  for (size_t i = 0; i < sizeof(cfg) / sizeof(cfg[0]); i++) {
    cst816s_i2c_write_reg(s_i2c_dac_bus_handle, s_cst816s_dev, cfg[i].reg, cfg[i].val, timeout);
  }

  // Verify device ID by reading register 0xA7
  uint8_t chip_id = 0;
  if (cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev, CST816S_REG_CHIP_STATUS,
                       &chip_id, 1, timeout)) {
    ESP_LOGI(TAG, "CST816S chip ID: 0x%02X", chip_id);
  } else {
    ESP_LOGW(TAG, "Failed to read CST816S chip ID");
  }

  // Clear any pending interrupts by reading status register
  uint8_t status = 0;
  cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev, CST816S_REG_STATUS, &status, 1, timeout);

  ESP_LOGI(TAG, "CST816S touch controller initialized");
  return ESP_OK;
}

static void touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
  (void)indev;
  if (!s_cst816s_dev) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  const TickType_t timeout = pdMS_TO_TICKS(10);

  // Read touch status (number of touch points)
  uint8_t status = 0;
  if (!cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev, CST816S_REG_STATUS,
                        &status, 1, timeout)) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  uint8_t touch_count = status & 0x0F;
  if (touch_count == 0) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  // Read touch coordinates (register 0x03):
  // Response: [0]=touch_count, [1]=X_H, [2]=X_L, [3]=Y_H, [4]=Y_L
  uint8_t xybuf[5] = { 0 };
  if (!cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev, CST816S_REG_XY, xybuf, 5, timeout)) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  uint16_t x = (xybuf[1] & 0x0F) << 8 | xybuf[2];
  uint16_t y = (xybuf[3] & 0x0F) << 8 | xybuf[4];

  // Apply swap and mirror to match display orientation
  if (TOUCH_SWAP_XY) {
    uint16_t tmp = x;
    x = y;
    y = tmp;
  }
  if (TOUCH_MIRROR_X) {
    x = TOUCH_WIDTH - 1 - x;
  }
  if (TOUCH_MIRROR_Y) {
    y = TOUCH_HEIGHT - 1 - y;
  }

  data->point.x = x;
  data->point.y = y;
  data->state = LV_INDEV_STATE_PRESSED;

  // Detect tap (brief press) — trigger mute toggle
  // We use a simple heuristic: if the indev was previously released and now pressed,
  // it's a tap. LVGL input device state tracking handles this internally.
}

static esp_err_t init_lvgl_touch(void) {
  esp_err_t err = init_touch_controller();
  if (err != ESP_OK) {
    return err;
  }

  // Create LVGL input device
  s_touch_indev = lv_indev_create();
  lv_indev_set_type(s_touch_indev, LV_INDEV_TYPE_POINTER);
  lv_indev_set_read_cb(s_touch_indev, touch_read_cb);

  ESP_LOGI(TAG, "LVGL touch input device created");
  return ESP_OK;
}

// ============================================================================
// Board resource lookup
// ============================================================================

board_res_handle_t iot_board_get_handle(int id) {
  switch (id) {
#ifdef CONFIG_DAC_ES8311
  case BOARD_I2C_DAC_ID:
    return (board_res_handle_t)s_i2c_dac_bus_handle;
#endif
  case BOARD_I2C_TOUCH_ID:
    return (board_res_handle_t)s_i2c_dac_bus_handle;
  default:
    return NULL;
  }
}

// ============================================================================
// Board init
// ============================================================================

esp_err_t iot_board_init(void) {
  esp_err_t err = ESP_OK;

  if (s_board_initialized) {
    ESP_LOGW(TAG, "Board already initialized");
    return ESP_OK;
  }

  // Hold the battery power latch closed first so the board survives USB removal.
  board_power_latch_init();

  init_gpio7();
#ifdef CONFIG_MUTE_GPIO
  init_mute_gpio();
#endif

#if defined(CONFIG_DAC_ES8311)
  // Initialize I2C bus for ES8311 + CST816S touch controller
  // Pins 41 (SCL) and 42 (SDA) shared between ES8311 and CST816S
  i2c_master_bus_config_t i2c_cfg = {
      .i2c_port = 0,
      .sda_io_num = BOARD_I2C_TOUCH_SDA_GPIO,
      .scl_io_num = BOARD_I2C_TOUCH_SCL_GPIO,
      .clk_source = I2C_CLK_SRC_DEFAULT,
      .glitch_ignore_cnt = 7,
      .flags.enable_internal_pullup = true,
  };
  err = i2c_new_master_bus(&i2c_cfg, &s_i2c_dac_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize DAC I2C bus: %s", esp_err_to_name(err));
    return err;
  }
  ESP_LOGI(TAG, "DAC I2C bus initialized: sda=%d, scl=%d",
           BOARD_I2C_TOUCH_SDA_GPIO, BOARD_I2C_TOUCH_SCL_GPIO);

  // Register and initialize ES8311 DAC
  dac_register(&dac_es8311_ops);

  err = dac_init(s_i2c_dac_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize ES8311 DAC: %s", esp_err_to_name(err));
    return err;
  }

  // Initialize CST816S touch controller hardware (I2C device, GPIO, registers)
  // LVGL input device creation is deferred — lvgl_port_lock() is not available
  // until display_init() runs later in main.c
  if (init_touch_controller() != ESP_OK) {
    ESP_LOGW(TAG, "Touch controller init failed, continuing without touch");
  }

  // Mark that deferred LVGL touch init is pending
  s_touch_deferred = true;
#endif

  s_board_initialized = true;
  ESP_LOGI(TAG, "Waveshare ESP32-S3-Touch-LCD-1.54 initialized");
  return ESP_OK;
}

void iot_board_init_lvgl_resources(void) {
  if (!s_touch_deferred) {
    return;
  }
  s_touch_deferred = false;

  if (!s_cst816s_dev) {
    ESP_LOGW(TAG, "Touch controller not initialized, skipping LVGL init");
    return;
  }

  if (lvgl_port_lock(1000)) {
    esp_err_t err = init_lvgl_touch();
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "LVGL touch init failed, continuing without touch");
    } else {
      ESP_LOGI(TAG, "Deferred LVGL touch init complete");
    }
    lvgl_port_unlock();
  } else {
    ESP_LOGW(TAG, "Failed to acquire LVGL lock — touch init skipped");
    // Keep s_touch_deferred = true so we retry next time
    s_touch_deferred = true;
  }
}

esp_err_t iot_board_deinit(void) {
  s_board_initialized = false;
  return ESP_OK;
}
