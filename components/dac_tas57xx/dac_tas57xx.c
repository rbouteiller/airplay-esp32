/**
 * Implementation of control interface to TI TAX57xx DAC/Amp chips
 * tas5754m datasheet:
 * https://www.ti.com/lit/ds/symlink/tas5754m.pdf
 */

#include "dac_tas57xx.h"
#include "board_utils.h"
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/param.h>

#include "driver/i2s_std.h"
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define TAS575x (0x98 >> 1)
#define TAS578x (0x90 >> 1)

// TAS578x device ID register (Book 0, Page 0)
#define TAS578x_REG_DEVICE_ID 0x67

#define I2C_TIMEOUT    100
#define I2C_LINE_SPEED 100000

static const char TAG[] = "TAS57xx DAC";

struct tas57xx_cmd_s {
  uint8_t reg;
  uint8_t value;
};

// Registers applied after the HF config (not covered by the HF flow).
// HF exits standby unmuted, so mute first to prevent pop.
static const struct tas57xx_cmd_s tas57xx_init_seq[] = {
    {0x00, 0x00}, // select page 0
    {0x03, 0x11}, // mute both channels before any other change
    {0x0d, 0x10}, // use SCK for PLL
    {0x25, 0x08}, // ignore SCK halt
    {0x08, 0x10}, // Mute control enable (GPIO3)
    {0x54, 0x02}, // Mute output control
    {0x3D, 0x6C}, // Set chan B volume -70dB
    {0x3E, 0x6C}, // Set chan A volume -70dB
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
static dac_power_mode_t s_power_state = DAC_POWER_OFF;
static uint8_t *s_hf_buf = NULL; // Cached hybrid flow (TAS5754M only)
static long s_hf_size = 0;

static esp_err_t write_cmd(tas57xx_cmd_e cmd, ...);
static int tas57xx_detect(i2c_master_bus_handle_t s_bus_handle);

/**
 * Write a hybrid flow configuration byte stream to the DAC.
 * Format: [reg, len, data[0..len-1], ...] terminated by 0xFF, 0xFF.
 * The HF config manages its own standby entry/exit.
 */
static esp_err_t tas57xx_write_hf(const uint8_t *stream) {
  esp_err_t err;
  int pos = 0;
  while (!(stream[pos] == 0xFF && stream[pos + 1] == 0xFF)) {
    uint8_t reg = stream[pos];
    uint8_t len = stream[pos + 1];
    const uint8_t *data = &stream[pos + 2];
    err = board_i2c_write(tas57xx_device_handle, reg, data, len);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "HF write failed at offset %d (reg 0x%02X): %s", pos, reg,
               esp_err_to_name(err));
      return err;
    }
    pos += 2 + len;
  }
  ESP_LOGI(TAG, "HybridFlow loaded");
  return ESP_OK;
}

static esp_err_t tas57xx_init(void *i2c_bus) {
  esp_err_t err = ESP_OK;

  s_bus_handle = (i2c_master_bus_handle_t)i2c_bus;
  if (s_bus_handle == NULL) {
    ESP_LOGE(TAG, "No I2C bus handle provided");
    return ESP_ERR_INVALID_ARG;
  }
  // Detect TAS57xx chip
  tas57xx_addr = tas57xx_detect(s_bus_handle);

  if (!tas57xx_addr) {
    ESP_LOGW(TAG, "No TAS57xx detected");
    return ESP_ERR_NOT_FOUND;
  }

  err = board_i2c_add_device(s_bus_handle, tas57xx_addr, I2C_LINE_SPEED,
                             &tas57xx_device_handle);
  if (ESP_OK != err) {
    ESP_LOGE(TAG, "Could not add device to bus: %s", esp_err_to_name(err));
    return err;
  }

  // Read chip identity for feature availability
  if (tas57xx_addr == TAS578x) {
    uint8_t page = 0x00;
    board_i2c_write(tas57xx_device_handle, 0x00, &page, 1);
    uint8_t device_id = 0;
    if (board_i2c_read(tas57xx_device_handle, TAS578x_REG_DEVICE_ID, &device_id,
                       1) == ESP_OK) {
      ESP_LOGI(TAG, "TAS578x device ID: 0x%02X", device_id);
    }
  } else if (tas57xx_addr == TAS575x) {
    ESP_LOGI(TAG, "TAS575x detected (no device ID register)");
  }

  // Load and cache hybrid flow from SPIFFS for TAS575x (TAS5754M with miniDSP)
  static const char *hf_path = "/spiffs/hf/tas57xx_fw.bin";
  if (tas57xx_addr == TAS575x) {
    FILE *f = fopen(hf_path, "rb");
    if (f) {
      fseek(f, 0, SEEK_END);
      long size = ftell(f);
      fseek(f, 0, SEEK_SET);
      uint8_t *buf = malloc(size);
      if (buf && fread(buf, 1, size, f) == (size_t)size) {
        s_hf_buf = buf;
        s_hf_size = size;
        err = tas57xx_write_hf(s_hf_buf);
      } else {
        ESP_LOGE(TAG, "Failed to read HF file %s", hf_path);
        free(buf);
        err = ESP_ERR_NO_MEM;
      }
      fclose(f);
      if (err != ESP_OK) {
        return err;
      }
    } else {
      ESP_LOGI(TAG, "No HF file at %s, skipping", hf_path);
    }
  }

  // Apply additional init registers
  for (int i = 0; tas57xx_init_seq[i].reg != 0xff; i++) {
    err = board_i2c_write(tas57xx_device_handle, tas57xx_init_seq[i].reg,
                          &tas57xx_init_seq[i].value, sizeof(uint8_t));
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write init reg 0x%02x: %s",
               tas57xx_init_seq[i].reg, esp_err_to_name(err));
      return err;
    }
  }

  return err;
}

static esp_err_t tas57xx_deinit(void) {
  esp_err_t err = ESP_OK;

  if (tas57xx_device_handle) {
    err = board_i2c_remove_device(tas57xx_device_handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "failed to remove from i2c bus, err: %s",
               esp_err_to_name(err));
    }
    tas57xx_device_handle = NULL;
  }

  s_bus_handle = NULL;
  free(s_hf_buf);
  s_hf_buf = NULL;
  s_hf_size = 0;
  return err;
}

/**
 * Re-apply HF config and init registers after a full shutdown.
 * Shutdown (reg 0x02=0x01) loses miniDSP RAM contents.
 */
static void tas57xx_restore_config(void) {
  if (s_hf_buf) {
    esp_err_t err = tas57xx_write_hf(s_hf_buf);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to restore HF config: %s", esp_err_to_name(err));
    }
  }
  for (int i = 0; tas57xx_init_seq[i].reg != 0xff; i++) {
    board_i2c_write(tas57xx_device_handle, tas57xx_init_seq[i].reg,
                    &tas57xx_init_seq[i].value, sizeof(uint8_t));
  }
}

static void tas57xx_enable_speaker(bool enable) {
  if (enable) {
    write_cmd(TAS57XX_ANALOGUE_ON);
  } else {
    write_cmd(TAS57XX_ANALOGUE_OFF);
  }
}

static void tas57xx_set_power_mode(dac_power_mode_t mode) {
  tas57xx_enable_speaker(false);
  switch (mode) {
  case DAC_POWER_STANDBY:
    write_cmd(TAS57XX_MUTE);
    write_cmd(TAS57XX_STANDBY);
    if (s_power_state == DAC_POWER_OFF) {
      // Wait for standby state to settle before writing miniDSP config
      vTaskDelay(pdMS_TO_TICKS(50));
      tas57xx_restore_config();
    }
    break;
  case DAC_POWER_ON:
    write_cmd(TAS57XX_MUTE);
    write_cmd(TAS57XX_ACTIVE);
    // Allow PLL lock and charge pump settling before unmuting
    vTaskDelay(pdMS_TO_TICKS(50));
    write_cmd(TAS57XX_UNMUTE);
    tas57xx_enable_speaker(true);
    break;
  case DAC_POWER_OFF:
    write_cmd(TAS57XX_MUTE);
    write_cmd(TAS57XX_DOWN);
    break;
  default:
    ESP_LOGW(TAG, "Unhandled power mode");
    break;
  }
  s_power_state = mode;
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
  // AirPlay 0 dB    -> DAC CONFIG_TAS57XX_MAX_VOLUME
  // AirPlay -25 dB  -> DAC (MAX - 50)
  // AirPlay -30..-25 dB -> DAC mute(-127)..(MAX-50) (steep roll-off)
  float max_db = (float)CONFIG_TAS57XX_MAX_VOLUME;
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
    err = board_i2c_write(tas57xx_device_handle, tas57xx_cmd[cmd].reg, &val,
                          sizeof(uint8_t));
    break;
  default:
    err = board_i2c_write(tas57xx_device_handle, tas57xx_cmd[cmd].reg,
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
