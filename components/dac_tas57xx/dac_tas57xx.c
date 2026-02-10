/**
 * Implementation of control interface to TI TAX57xx DAC/Amp chips
 * tas5754m datasheet:
 * https://www.ti.com/lit/ds/symlink/tas5754m.pdf
 */

#include "dac_tas57xx.h"
#include <math.h>
#include <sys/param.h>

#include "driver/i2s_std.h"
#include "driver/i2c_master.h"
#include "driver/i2c_types.h"
#include "esp_log.h"

#define TAS575x (0x98 >> 1)
#define TAS578x (0x90 >> 1)

#define I2C_TIMEOUT    100
#define I2C_LINE_SPEED 100000

static const char TAG[] = "TAS57xx DAC";

struct tas57xx_cmd_s {
  uint8_t reg;
  uint8_t value;
};

static const struct tas57xx_cmd_s tas57xx_init_seq[] = {
    {0x00, 0x00}, // select page 0
    {0x02, 0x10}, // standby
    {0x0d, 0x10}, // use SCK for PLL
    {0x25, 0x08}, // ignore SCK halt
    {0x08, 0x10}, // Mute control enable
    {0x54, 0x02}, // Mute output control
    {0x3D, 0x6C}, // Set chan B volume -70db
    {0x3E, 0x6C}, // Set chan A volume -70db
    // {0x28, 0x03}, // I2S length 32 bits
    {0x28, 0x00}, // I2S length 16 bits
    {0x02, 0x00}, // restart
    {0xff, 0xff}  // end of table
};

// Commands available - care to match ordinal with struct below
typedef enum {
  TAS57XX_ACTIVE = 0,
  TAS57XX_STANDBY,
  TAS57XX_DOWN,
  TAS57XX_ANALOGUE_OFF,
  TAS57XX_ANALOGUE_ON,
  TAS57XX_SET_VOLUME_A_L,
  TAS57XX_SET_VOLUME_B_R,
  TAS57XX_MUTE,
  TAS57XX_UNMUTE,
} tas57xx_cmd_e;

static const struct tas57xx_cmd_s tas57xx_cmd[] = {
    {0x02, 0x00}, // TAS57XX_ACTIVE
    {0x02, 0x10}, // TAS57XX_STANDBY
    {0x02, 0x01}, // TAS57XX_DOWN
    {0x56, 0x10}, // TAS57XX_ANALOGUE_OFF
    {0x56, 0x00}, // TAS57XX_ANALOGUE_ON
    {0x3E, 0x30}, // TAS57XX_SET_VOLUME_A_L - Channel A
    {0x3D, 0x30}, // TAS57XX_SET_VOLUME_B_R - Channel B
    {0x03, 0x11}, // TAS57XX_MUTE (BA)
    {0x03, 0x00}, // TAS57XX_UNMUTE (BA)
};

static uint8_t tas57xx_addr;
static i2c_master_bus_handle_t s_bus_handle = NULL;
static i2c_master_dev_handle_t tas57xx_device_handle;

static esp_err_t write_cmd(tas57xx_cmd_e cmd, ...);
static int tas57xx_detect(i2c_master_bus_handle_t s_bus_handle);

// I2C functions
static esp_err_t i2c_init(int i2c_port, int sda_io, int scl_io);
static esp_err_t i2c_deinit(int i2c_port, int sda_io, int scl_i);
static esp_err_t i2c_bus_write(i2c_master_dev_handle_t dev, uint8_t addr,
                               uint8_t reg, const uint8_t *data, size_t len);
static esp_err_t i2c_bus_add_device(uint8_t addr,
                                    i2c_master_dev_handle_t *dev_handle);
static esp_err_t i2c_bus_remove_device(i2c_master_dev_handle_t dev_handle);

static esp_err_t tas57xx_init(void) {
  esp_err_t err = ESP_OK;

  // Set up I2C (always uses port 0)
  err = i2c_init(0, CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "Could not configure i2c bus: %d", err);
    return err;
  }
  // Detect TAS57xx chip
  tas57xx_addr = tas57xx_detect(s_bus_handle);

  if (!tas57xx_addr) {
    ESP_LOGW(TAG, "No TAS57xx detected");
    return ESP_ERR_NOT_FOUND;
  }

  err = i2c_bus_add_device(tas57xx_addr, &tas57xx_device_handle);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "Could not add device to bus: %s", esp_err_to_name(err));
    return err;
  }

  // Initialize
  for (int i = 0; tas57xx_init_seq[i].reg != 0xff; i++) {
    err = i2c_bus_write(tas57xx_device_handle, tas57xx_addr,
                        tas57xx_init_seq[i].reg, &tas57xx_init_seq[i].value,
                        sizeof(uint8_t));
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to initialize TAS57xx at 0x%02x, err: %s",
               tas57xx_init_seq[i].reg, esp_err_to_name(err));
      return err;
    }
    ESP_LOGD(TAG, "i2c write %x at %u", tas57xx_init_seq[i].reg,
             tas57xx_init_seq[i].value);
  }

  return err;
}

static esp_err_t tas57xx_deinit(void) {
  esp_err_t err = ESP_OK;

  if (tas57xx_device_handle) {
    err = i2c_bus_remove_device(tas57xx_device_handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "failed to remove from i2c bus, err: %s",
               esp_err_to_name(err));
    }
  }

  err = i2c_deinit(0, CONFIG_DAC_I2C_SDA, CONFIG_DAC_I2C_SCL);
  return err;
}

static void tas57xx_set_power_mode(dac_power_mode_t mode) {
  switch (mode) {
  case DAC_POWER_STANDBY:
    write_cmd(TAS57XX_STANDBY);
    break;
  case DAC_POWER_ON:
    write_cmd(TAS57XX_ACTIVE);
    break;
  case DAC_POWER_OFF:
    write_cmd(TAS57XX_DOWN);
    break;
  default:
    ESP_LOGW(TAG, "Unhandled power mode");
    break;
  }
}

static void tas57xx_enable_speaker(bool enable) {
  if (enable) {
    write_cmd(TAS57XX_ANALOGUE_ON);
  } else {
    write_cmd(TAS57XX_ANALOGUE_OFF);
  }
}

static void tas57xx_enable_line_out(bool enable) {
  (void)enable;
  ESP_LOGW(TAG, "Not supported yet");
}

static void tas57xx_set_volume(float volume_airplay_db) {
  // Clamp AirPlay input range (-30 to 0)
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }

  // Volume mapping (2:1 scaling):
  // AirPlay 0 dB    -> DAC CONFIG_DAC_MAX_VOLUME
  // AirPlay -25 dB  -> DAC (MAX - 50)
  // AirPlay -30..-25 dB -> DAC mute(-127)..(MAX-50) (steep roll-off)
  float max_db = (float)CONFIG_DAC_MAX_VOLUME;
  float db_level;
  if (volume_airplay_db >= -25.0f) {
    // 2:1 linear scaling: 25 dB AirPlay range -> 50 dB DAC range
    // AirPlay 0 -> MAX, AirPlay -25 -> MAX - 50
    db_level = max_db + (volume_airplay_db * 2.0f);
  } else {
    // Roll-off: map -30..-25 to -127..(MAX-50)
    // normalized: 0 at -30, 1 at -25
    float normalized = (volume_airplay_db + 30.0f) / 5.0f;
    float rolloff_top = max_db - 50.0f;
    db_level = -127.0f + normalized * (127.0f + rolloff_top);
  }

  // Clamp to DAC valid range
  if (db_level > 0.0f) {
    db_level = 0.0f;
  }
  if (db_level < -127.0f) {
    db_level = -127.0f;
  }

  // Convert dB to DAC register: reg = -dB * 2 (0x00=0dB, 0xFE=-127dB)
  uint8_t reg_val = (uint8_t)(-db_level * 2.0f);

  ESP_LOGD(TAG, "Volume: AirPlay %.1f dB -> DAC %.1f dB -> reg 0x%02X",
           volume_airplay_db, db_level, reg_val);

  write_cmd(TAS57XX_SET_VOLUME_A_L, reg_val);
  write_cmd(TAS57XX_SET_VOLUME_B_R, reg_val);
}

const dac_ops_t dac_tas57xx_ops = {
    .init = tas57xx_init,
    .deinit = tas57xx_deinit,
    .set_volume = tas57xx_set_volume,
    .set_power_mode = tas57xx_set_power_mode,
    .enable_speaker = tas57xx_enable_speaker,
    .enable_line_out = tas57xx_enable_line_out,
};

static esp_err_t write_cmd(tas57xx_cmd_e cmd, ...) {
  va_list args;
  esp_err_t err = ESP_OK;
  va_start(args, cmd);

  switch (cmd) {
  case TAS57XX_SET_VOLUME_A_L:
  case TAS57XX_SET_VOLUME_B_R:
    uint8_t val = (uint8_t)va_arg(args, int);
    err = i2c_bus_write(tas57xx_device_handle, tas57xx_addr,
                        tas57xx_cmd[cmd].reg, &val, sizeof(uint8_t));
    break;
  default:
    err =
        i2c_bus_write(tas57xx_device_handle, tas57xx_addr, tas57xx_cmd[cmd].reg,
                      &(tas57xx_cmd[cmd].value), sizeof(uint8_t));
  }

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed i2c write to TAS57xx: %s", esp_err_to_name(err));
  }

  va_end(args);
  return err;
}

/**
 * Find a known chip ID on the I2C bus
 */
static int tas57xx_detect(i2c_master_bus_handle_t s_bus_handle) {
  uint8_t supported_chips[] = {TAS578x, TAS575x};
  if (!s_bus_handle) {
    ESP_LOGE(TAG, "Invalid i2c handle!");
    return -1;
  }

  for (int i = 0; i < sizeof(supported_chips); i++) {
    if (ESP_OK ==
        i2c_master_probe(s_bus_handle, supported_chips[i], I2C_TIMEOUT)) {
      ESP_LOGI(TAG, "Detected TAS57xx at @0x%x", supported_chips[i]);
      return supported_chips[i];
    }
  }
  return 0;
}

////////////////////////  I2C Bus ///////////////////////

/**
 * Initialize the bus
 */
static esp_err_t i2c_init(int i2c_port, int sda_io, int scl_io) {
  esp_err_t err = ESP_OK;

  if (s_bus_handle != NULL) {
    ESP_LOGW(TAG, "i2c already initialized");
    return err;
  }
  if (sda_io < 0 || scl_io < 0) {
    ESP_LOGW(TAG, "Invalid i2c pins: sda=%d, scl=%d", sda_io, scl_io);
    return ESP_ERR_INVALID_ARG;
  }

  i2c_master_bus_config_t i2c_config = {.i2c_port = i2c_port,
                                        .sda_io_num = sda_io,
                                        .scl_io_num = scl_io,
                                        .clk_source = I2C_CLK_SRC_DEFAULT,
                                        .glitch_ignore_cnt = 7,
                                        .flags.enable_internal_pullup = true};

  err = i2c_new_master_bus(&i2c_config, &s_bus_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize i2c master bus: %s",
             esp_err_to_name(err));
    s_bus_handle = NULL;
    return err;
  }
  ESP_LOGI(TAG, "i2c bus %d initialized: sda=%d, scl=%d", i2c_port, sda_io,
           scl_io);

  return err;
}

static esp_err_t i2c_deinit(int i2c_port, int sda_io, int scl_io) {
  esp_err_t err = ESP_OK;

  if (s_bus_handle != NULL) {
    err = i2c_del_master_bus(s_bus_handle);
    s_bus_handle = NULL;
  }
  return err;
}

static esp_err_t i2c_bus_add_device(uint8_t addr,
                                    i2c_master_dev_handle_t *dev_handle) {
  if (s_bus_handle == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  i2c_device_config_t dev_cfg = {.dev_addr_length = I2C_ADDR_BIT_LEN_7,
                                 .device_address = addr,
                                 .scl_speed_hz = I2C_LINE_SPEED};

  return i2c_master_bus_add_device(s_bus_handle, &dev_cfg, dev_handle);
}

static esp_err_t i2c_bus_remove_device(i2c_master_dev_handle_t dev_handle) {
  return i2c_master_bus_rm_device(dev_handle);
}

/**
 * Write data to an I2C device
 */
static esp_err_t i2c_bus_write(i2c_master_dev_handle_t dev, uint8_t addr,
                               uint8_t reg, const uint8_t *data, size_t len) {
  if (dev == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  esp_err_t ret = ESP_OK;

  if (reg == 0xFF) {
    // No register, write data directly
    ret = i2c_master_transmit(dev, data, len, I2C_TIMEOUT);
  } else {
    // Allocate buffer for reg + data
    uint8_t *buf = malloc(len + 1);
    if (buf == NULL) {
      return ESP_ERR_NO_MEM;
    }

    buf[0] = reg;
    memcpy(buf + 1, data, len);

    ret = i2c_master_transmit(dev, buf, len + 1, I2C_TIMEOUT);
    free(buf);
  }

  if (ret != ESP_OK) {
    ESP_LOGD(TAG, "I2C write to 0x%02x failed: %s", addr, esp_err_to_name(ret));
  }
  return ret;
}
