/**
 * @file board.c
 * @brief Waveshare ESP32-S3-Touch-LCD-1.54 board implementation
 *
 * Board with integrated ST7789 SPI display (with touch via CST816S I2C),
 * and ES8311 I2C-controlled stereo audio codec for DAC output.
 */

#include "iot_board.h"

#include "dac.h"
#include "dac_es8311.h"
#include "playback_control.h"
#include "settings.h"

#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_log.h"
#include "esp_sleep.h"
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
#define CST816S_ADDR             0x15
#define CST816S_REG_GESTURE_ID   0x01
#define CST816S_REG_FINGER_NUM   0x02
#define CST816S_REG_XPOS_H       0x03
#define CST816S_REG_CHIP_STATUS  0xA7
#define CST816S_CHIP_ID          0xB4
#define CST816S_REG_CONFIG_START 0x5D

// Display touch parameters (swap + mirror applied at panel level)
#define TOUCH_SWAP_XY  true
#define TOUCH_MIRROR_X true
#define TOUCH_MIRROR_Y false
#define TOUCH_WIDTH    240
#define TOUCH_HEIGHT   240

static i2c_master_dev_handle_t s_cst816s_dev = NULL;
static lv_indev_t *s_touch_indev = NULL;

static bool s_gpio7_state = false;

static void set_gpio7_level(bool level) {
  if (level != s_gpio7_state) {
    gpio_set_level((gpio_num_t)7, level ? 1 : 0);
    s_gpio7_state = level;
    ESP_LOGI(TAG, "GPIO7 changed state to %s", level ? "HIGH" : "LOW");
  }
}

static void init_gpio7(void) {
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
  // A prior power-off may have left the pin held LOW across deep sleep; release
  // the hold before re-driving it so the latch can close again.
  gpio_hold_dis(BAT_EN_GPIO);
  gpio_reset_pin(BAT_EN_GPIO);
  gpio_set_direction(BAT_EN_GPIO, GPIO_MODE_OUTPUT);
  gpio_set_level(BAT_EN_GPIO, 1);
  ESP_LOGI(TAG, "Battery power latch held (GPIO2 HIGH)");
}

void board_power_off(void) {
  ESP_LOGI(TAG, "Powering off — releasing battery latch (GPIO2 LOW)");
  // Release the latch and hold the pin LOW so it survives the transition.
  gpio_set_level(BAT_EN_GPIO, 0);
  gpio_hold_en(BAT_EN_GPIO);
  gpio_deep_sleep_hold_en();

  // Halt the CPU in deep sleep so it stops drawing current and cannot
  // re-latch. On battery the rail now collapses and the board powers off
  // cleanly; if USB is still supplying the rail, the board stays in deep
  // sleep (screen off) until USB is removed or it is reset. Without this the
  // rail sags just far enough to trip the brownout reset, which reboots and
  // re-drives the latch HIGH — the board appears to "blink off and restart".
  esp_deep_sleep_start();
}

// ============================================================================
// Battery monitor (GPIO1 ADC via a 1:2 divider, GPIO3 charge status)
// ============================================================================
// Ported from the Waveshare bsp_power_manager: the battery rail is read on
// ADC1 channel 0 (GPIO1) through a 2:1 divider, so the measured voltage is
// multiplied by 2 (using a 3.0 scale to match the reference).

#define BAT_ADC_CHANNEL ADC_CHANNEL_0   // GPIO1
#define BAT_CHG_GPIO    ((gpio_num_t)3) // CHG_STAT, active low = charging

static adc_oneshot_unit_handle_t s_bat_adc = NULL;
static adc_cali_handle_t s_bat_cali = NULL;
static bool s_bat_calibrated = false;

static void board_battery_init(void) {
  // Charge-status input
  gpio_config_t chg_cfg = {
      .intr_type = GPIO_INTR_DISABLE,
      .mode = GPIO_MODE_INPUT,
      .pin_bit_mask = 1ULL << BAT_CHG_GPIO,
      .pull_up_en = GPIO_PULLUP_ENABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
  };
  gpio_config(&chg_cfg);

  adc_oneshot_unit_init_cfg_t unit_cfg = {.unit_id = ADC_UNIT_1};
  if (adc_oneshot_new_unit(&unit_cfg, &s_bat_adc) != ESP_OK) {
    ESP_LOGW(TAG, "Battery ADC init failed");
    s_bat_adc = NULL;
    return;
  }
  adc_oneshot_chan_cfg_t chan_cfg = {
      .bitwidth = ADC_BITWIDTH_DEFAULT,
      .atten = ADC_ATTEN_DB_12,
  };
  adc_oneshot_config_channel(s_bat_adc, BAT_ADC_CHANNEL, &chan_cfg);

  adc_cali_curve_fitting_config_t cali_cfg = {
      .unit_id = ADC_UNIT_1,
      .chan = BAT_ADC_CHANNEL,
      .atten = ADC_ATTEN_DB_12,
      .bitwidth = ADC_BITWIDTH_DEFAULT,
  };
  s_bat_calibrated =
      (adc_cali_create_scheme_curve_fitting(&cali_cfg, &s_bat_cali) == ESP_OK);
  ESP_LOGI(TAG, "Battery monitor initialized (cali=%s)",
           s_bat_calibrated ? "yes" : "no");
}

static float board_battery_voltage(void) {
  if (!s_bat_adc || !s_bat_calibrated) {
    return -1.0f;
  }
  int raw = 0;
  if (adc_oneshot_read(s_bat_adc, BAT_ADC_CHANNEL, &raw) != ESP_OK) {
    return -1.0f;
  }
  int mv = 0;
  if (adc_cali_raw_to_voltage(s_bat_cali, raw, &mv) != ESP_OK) {
    return -1.0f;
  }
  return ((float)mv / 1000.0f) * 3.0f; // divider compensation (matches BSP)
}

bool board_battery_read(int *percent, bool *charging) {
  if (!s_bat_adc) {
    return false;
  }
  float v = board_battery_voltage();
  if (v < 0.0f) {
    return false;
  }

  if (percent) {
    // Piecewise-linear interpolation over a single-cell LiPo discharge curve.
    // Smooths the reading instead of jumping in coarse 20% steps.
    static const struct {
      float v;
      int pct;
    } curve[] = {
        {3.30f, 0},  {3.50f, 10}, {3.60f, 20}, {3.68f, 35}, {3.74f, 50},
        {3.82f, 65}, {3.92f, 80}, {4.02f, 90}, {4.12f, 98}, {4.20f, 100},
    };
    const size_t n = sizeof(curve) / sizeof(curve[0]);

    int pct;
    if (v <= curve[0].v) {
      pct = curve[0].pct;
    } else if (v >= curve[n - 1].v) {
      pct = curve[n - 1].pct;
    } else {
      pct = curve[n - 1].pct;
      for (size_t i = 1; i < n; i++) {
        if (v < curve[i].v) {
          float span = curve[i].v - curve[i - 1].v;
          float frac = (v - curve[i - 1].v) / span;
          float pct_span = (float)(curve[i].pct - curve[i - 1].pct);
          pct = curve[i - 1].pct + (int)(frac * pct_span + 0.5f);
          break;
        }
      }
    }
    *percent = pct;
  }
  if (charging) {
    *charging = (gpio_get_level(BAT_CHG_GPIO) == 0);
  }
  return true;
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
  esp_err_t err = gpio_config(&io_conf);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to configure mute GPIO: %s", esp_err_to_name(err));
    return err;
  }

  // Initialize to unmuted state — set opposite of active level
  gpio_set_level(CONFIG_MUTE_GPIO, !CONFIG_MUTE_GPIO_LEVEL);

  ESP_LOGI(TAG, "Mute GPIO %d initialized (active %s, init %s)",
           CONFIG_MUTE_GPIO, CONFIG_MUTE_GPIO_LEVEL ? "high" : "low",
           CONFIG_MUTE_GPIO_LEVEL ? "low" : "high");
  return ESP_OK;
}
#endif

// ============================================================================
// CST816S Touch Driver
// ============================================================================

static bool cst816s_i2c_write_reg(i2c_master_bus_handle_t bus,
                                  i2c_master_dev_handle_t dev, uint8_t reg,
                                  uint8_t val, int timeout_ms) {
  (void)bus;
  uint8_t buf[2] = {reg, val};
  return i2c_master_transmit(dev, buf, 2, timeout_ms) == ESP_OK;
}

static bool cst816s_read_reg(i2c_master_bus_handle_t bus,
                             i2c_master_dev_handle_t dev, uint8_t reg,
                             uint8_t *val, size_t len, int timeout_ms) {
  (void)bus;
  // I2C register read: write register address, then read data
  return i2c_master_transmit_receive(dev, &reg, 1, val, len, timeout_ms) ==
         ESP_OK;
}

static void cst816s_reset(void) {
#if BOARD_I2C_TOUCH_RST_GPIO >= 0
  gpio_reset_pin((gpio_num_t)BOARD_I2C_TOUCH_RST_GPIO);
  gpio_set_direction((gpio_num_t)BOARD_I2C_TOUCH_RST_GPIO, GPIO_MODE_OUTPUT);
  gpio_set_level((gpio_num_t)BOARD_I2C_TOUCH_RST_GPIO, 0);
  vTaskDelay(pdMS_TO_TICKS(10));
  gpio_set_level((gpio_num_t)BOARD_I2C_TOUCH_RST_GPIO, 1);
  vTaskDelay(pdMS_TO_TICKS(50));
#endif
}

static esp_err_t init_touch_controller(void) {
  const int timeout_ms = 100;

  cst816s_reset();

  // Register CST816S on I2C bus
  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = CST816S_ADDR,
      .scl_speed_hz = 400000,
  };
  esp_err_t err =
      i2c_master_bus_add_device(s_i2c_dac_bus_handle, &dev_cfg, &s_cst816s_dev);
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
      {0xB1, 0x5B}, // Touch mode settings
      {0xB2, 0x0E}, // Gate switch time
      {0xB3, 0x00}, // Button mode disable
      {0x94, 0x0B}, // Touch count interrupt enable
      {0x95, 0x0B}, // Touch count interrupt enable
      {0x96, 0x01}, // Auto sleep after touch
      {0x98, 0x3D}, // Monitor period
      {0x99, 0x2B}, // Sleep time
      {0x9A, 0x01}, // LED rate
  };
  for (size_t i = 0; i < sizeof(cfg) / sizeof(cfg[0]); i++) {
    cst816s_i2c_write_reg(s_i2c_dac_bus_handle, s_cst816s_dev, cfg[i].reg,
                          cfg[i].val, timeout_ms);
  }

  // Verify device ID by reading register 0xA7
  uint8_t chip_id = 0;
  if (cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev,
                       CST816S_REG_CHIP_STATUS, &chip_id, 1, timeout_ms)) {
    ESP_LOGI(TAG, "CST816S chip ID: 0x%02X", chip_id);
  } else {
    ESP_LOGW(TAG, "Failed to read CST816S chip ID");
  }

  // Clear any pending interrupts by reading status register
  uint8_t status = 0;
  cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev, CST816S_REG_GESTURE_ID,
                   &status, 1, timeout_ms);

  ESP_LOGI(TAG, "CST816S touch controller initialized");
  return ESP_OK;
}

static void touch_read_cb(lv_indev_t *indev, lv_indev_data_t *data) {
  (void)indev;
  if (!s_cst816s_dev) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  const int timeout_ms = 10;

  // Read number of active fingers.
  uint8_t touch_count = 0;
  if (!cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev,
                        CST816S_REG_FINGER_NUM, &touch_count, 1, timeout_ms)) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  touch_count &= 0x0F;
  if (touch_count == 0) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  // Read touch coordinates from XPOSH, XPOSL, YPOSH, YPOSL.
  uint8_t xybuf[4] = {0};
  if (!cst816s_read_reg(s_i2c_dac_bus_handle, s_cst816s_dev, CST816S_REG_XPOS_H,
                        xybuf, sizeof(xybuf), timeout_ms)) {
    data->state = LV_INDEV_STATE_RELEASED;
    return;
  }

  uint16_t x = (uint16_t)(((xybuf[0] & 0x0F) << 8) | xybuf[1]);
  uint16_t y = (uint16_t)(((xybuf[2] & 0x0F) << 8) | xybuf[3]);

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
  // We use a simple heuristic: if the indev was previously released and now
  // pressed, it's a tap. LVGL input device state tracking handles this
  // internally.
}

static esp_err_t init_lvgl_touch(void) {
  if (s_touch_indev != NULL) {
    return ESP_OK;
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

  // Hold the battery power latch closed first so the board survives USB
  // removal.
  board_power_latch_init();
  board_battery_init();

  init_gpio7();
#ifdef CONFIG_MUTE_GPIO
  err = init_mute_gpio();
  if (err != ESP_OK) {
    return err;
  }
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

  // Restore saved volume (ES8311 boots at 0 dB until programmed)
  float vol_db;
  if (ESP_OK == settings_get_volume(&vol_db)) {
    dac_set_volume(vol_db);
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

  for (int attempt = 0; attempt < 5; attempt++) {
    if (!lvgl_port_lock(1000)) {
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }

    esp_err_t err = init_lvgl_touch();
    if (err != ESP_OK) {
      ESP_LOGW(TAG, "LVGL touch init failed, continuing without touch");
    } else {
      ESP_LOGI(TAG, "Deferred LVGL touch init complete");
    }
    lvgl_port_unlock();
    return;
  }

  ESP_LOGW(TAG, "Failed to acquire LVGL lock — touch init skipped");
  s_touch_deferred = true;
}

esp_err_t iot_board_deinit(void) {
  s_board_initialized = false;
  return ESP_OK;
}
