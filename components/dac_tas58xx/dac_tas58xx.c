/**
 * Implementation of control interface to TI TAS58xx (TAS5825M) DAC/Amp
 * TAS5825M datasheet:
 * https://www.ti.com/lit/ds/symlink/tas5825m.pdf
 */

#include "dac_tas58xx.h"
#include "dac_tas58xx_eq.h"
#include <math.h>
#include <string.h>
#include <sys/param.h>

#include "driver/i2c_master.h"
#include "driver/i2c_types.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

/* ---------- TAS5825M I2C addresses (7-bit) ---------- */
#define TAS5825M_ADDR_GND 0x4C // ADR pin = 0 Ω to GND
#define TAS5825M_ADDR_1K  0x4D // ADR pin = 1 kΩ to GND
#define TAS5825M_ADDR_4K7 0x4E // ADR pin = 4.7 kΩ to GND
#define TAS5825M_ADDR_15K 0x4F // ADR pin = 15 kΩ to GND

/* ---------- Register addresses (Book 0, Page 0) ---------- */
#define REG_PAGE_SEL 0x00
#define REG_BOOK_SEL 0x7F

#define REG_RESET_CTRL   0x01
#define REG_DEVICE_CTRL1 0x02
#define REG_DEVICE_CTRL2 0x03

#define REG_SIG_CH_CTRL    0x28
#define REG_CLOCK_DET_CTRL 0x29

#define REG_SAP_CTRL1 0x33 // I2S format + word length
#define REG_SAP_CTRL2 0x34 // Data offset
#define REG_SAP_CTRL3 0x35 // L/R channel routing

#define REG_DSP_PGM_MODE 0x40
#define REG_DSP_CTRL     0x46

#define REG_DIG_VOL        0x4C // Digital volume (both channels)
#define REG_DIG_VOL_CTRL1  0x4E // Volume ramp control
#define REG_AUTO_MUTE_CTRL 0x50
#define REG_AUTO_MUTE_TIME 0x51
#define REG_ANA_CTRL       0x53
#define REG_AGAIN          0x54 // Analog gain

#define REG_DIE_ID      0x67 // Expected: 0x95
#define REG_POWER_STATE 0x68

#define REG_CHAN_FAULT    0x70
#define REG_GLOBAL_FAULT1 0x71
#define REG_GLOBAL_FAULT2 0x72
#define REG_WARNING       0x73
#define REG_FAULT_CLEAR   0x78

/* ---------- DEVICE_CTRL2 (0x03) bit fields ---------- */
#define CTRL2_MUTE       (1 << 3)
#define CTRL2_DIS_DSP    (1 << 4)
#define CTRL2_STATE_MASK 0x03
#define CTRL2_DEEP_SLEEP 0x00
#define CTRL2_SLEEP      0x01
#define CTRL2_HIZ        0x02
#define CTRL2_PLAY       0x03

/* ---------- DIG_VOL (0x4C) ---------- */
// 0x00 = +24.0 dB, 0x30 = 0.0 dB, 0xFE = -103.0 dB, 0xFF = mute
// step = -0.5 dB per increment
#define DIG_VOL_0DB  0x30
#define DIG_VOL_MUTE 0xFF

/* ---------- AGAIN (0x54) ---------- */
// bits[4:0]: 0x00 = 0 dB, each step = -0.5 dB, max 0x1F = -15.5 dB

/* ---------- RESET_CTRL (0x01) ---------- */
#define RESET_DIG_CORE (1 << 4)
#define RESET_REG      (1 << 0)

/* ---------- Constants ---------- */
#define I2C_TIMEOUT    100    // ms
#define I2C_LINE_SPEED 400000 // TAS5825M supports fast-mode 400 kHz

#define TAS5825M_DIE_ID 0x95

static const char TAG[] = "TAS58xx DAC";

/* ---------- Init sequence ---------- */
struct tas58xx_cmd_s {
  uint8_t reg;
  uint8_t value;
};

/*
 * Startup procedure from datasheet §9.5.3.1:
 *   1. Go to Book 0 / Page 0
 *   2. Reset device registers
 *   3. Configure device into HiZ with DSP enabled
 *   4. Wait ≥5 ms for clocks to settle
 *   5. Configure I2S format + word length
 *   6. Set DSP to ROM mode (simple passthrough, no custom coefficients)
 *   7. Set default analog gain
 *   8. Set volume ramp rates
 *   9. Configure auto-mute
 *  10. Clear faults
 *
 * NOTE: We do NOT transition to Play here — I2S clocks are not yet
 * running when dac_init() is called, so the PLL cannot lock and the
 * device will stay stuck in HiZ.  The transition to Play happens
 * later via dac_set_power_mode(DAC_POWER_ON) once I2S is active.
 */
static const struct tas58xx_cmd_s tas58xx_init_seq[] = {
    {REG_PAGE_SEL, 0x00},        // Select Book 0 Page 0
    {REG_BOOK_SEL, 0x00},        // Select Book 0
    {REG_PAGE_SEL, 0x00},        // Confirm Page 0
    {REG_RESET_CTRL, RESET_REG}, // Reset control port registers
    {REG_DEVICE_CTRL2, CTRL2_HIZ},

    // I2S format: standard I2S, 16-bit word length
    {REG_SAP_CTRL1, 0x00}, // DATA_FORMAT=I2S(00), WORD_LENGTH=16bit(00)
    {REG_CLOCK_DET_CTRL, 0x00},

    // DSP: Process Flow 1 (Base/Pro, 96kHz, 2.0)
    {REG_DSP_PGM_MODE, 0x01},
    {REG_DSP_CTRL, 0x01}, // Use default coefficients

    // Volume ramp: smooth transitions
    {REG_DIG_VOL_CTRL1, 0x33}, // Default ramp rates

    // Auto-mute: enable for both channels
    {REG_AUTO_MUTE_CTRL, 0x07},
    {REG_AUTO_MUTE_TIME, 0x00},

    // Clear any pending faults
    {REG_FAULT_CLEAR, 0x80},

    // Set digital volume to 0 dB initially
    {REG_DIG_VOL, DIG_VOL_0DB},

    // Analog gain: 0 dB
    {REG_AGAIN, 0x00},

    {0xFF, 0xFF} // End of table sentinel
};

/* ---------- State ---------- */
static uint8_t tas58xx_addr;
static i2c_master_bus_handle_t s_bus_handle = NULL;
static i2c_master_dev_handle_t tas58xx_device_handle;
static bool s_dsp_defaults_written = false;

/**
 * Mutex protecting all TAS5825M register access.
 *
 * The TAS5825M uses a page/book register model: writing to any register
 * beyond Page 0 requires first selecting the target book and page via
 * REG_PAGE_SEL (0x00) and REG_BOOK_SEL (0x7F).  This makes register
 * access non-atomic: a context switch between selecting a page and
 * writing the target register will corrupt the operation.
 *
 * All functions that touch the I2C bus MUST hold this mutex. Public API
 * functions acquire it; internal helpers assume it's already held.
 */
static SemaphoreHandle_t s_reg_mutex = NULL;

#define REG_LOCK()   xSemaphoreTake(s_reg_mutex, portMAX_DELAY)
#define REG_UNLOCK() xSemaphoreGive(s_reg_mutex)

/* ---------- Forward declarations ---------- */
static esp_err_t i2c_bus_write(i2c_master_dev_handle_t dev, uint8_t addr,
                               uint8_t reg, const uint8_t *data, size_t len);
static esp_err_t i2c_bus_read(i2c_master_dev_handle_t dev, uint8_t addr,
                              uint8_t reg, uint8_t *data, size_t len);
static esp_err_t i2c_bus_add_device(uint8_t addr,
                                    i2c_master_dev_handle_t *dev_handle);
static esp_err_t i2c_bus_remove_device(i2c_master_dev_handle_t dev_handle);

static esp_err_t tas58xx_write_reg(uint8_t reg, uint8_t value);
static esp_err_t tas58xx_read_reg(uint8_t reg, uint8_t *value);

/* ---------- Detect ---------- */

static uint8_t tas58xx_detect(i2c_master_bus_handle_t bus) {
  static const uint8_t addrs[] = {TAS5825M_ADDR_GND, TAS5825M_ADDR_1K,
                                  TAS5825M_ADDR_4K7, TAS5825M_ADDR_15K};

  if (!bus) {
    ESP_LOGE(TAG, "Invalid I2C handle");
    return 0;
  }

  for (int i = 0; i < sizeof(addrs) / sizeof(addrs[0]); i++) {
    if (ESP_OK == i2c_master_probe(bus, addrs[i], I2C_TIMEOUT)) {
      ESP_LOGI(TAG, "Detected TAS5825M at @0x%02X", addrs[i]);
      return addrs[i];
    }
  }
  return 0;
}

/* ---------- DAC ops implementation ---------- */

static void tas58xx_dump_status(const char *context) {
  uint8_t val = 0;

  ESP_LOGD(TAG, "--- %s: TAS5825M status dump ---", context);

  if (tas58xx_read_reg(REG_DEVICE_CTRL2, &val) == ESP_OK) {
    const char *state_str;
    switch (val & CTRL2_STATE_MASK) {
    case CTRL2_DEEP_SLEEP:
      state_str = "DEEP_SLEEP";
      break;
    case CTRL2_SLEEP:
      state_str = "SLEEP";
      break;
    case CTRL2_HIZ:
      state_str = "HIZ";
      break;
    case CTRL2_PLAY:
      state_str = "PLAY";
      break;
    default:
      state_str = "UNKNOWN";
      break;
    }
    ESP_LOGD(TAG, "  DEVICE_CTRL2=0x%02X  state=%s  mute=%s  dsp=%s", val,
             state_str, (val & CTRL2_MUTE) ? "YES" : "no",
             (val & CTRL2_DIS_DSP) ? "DISABLED" : "enabled");
  }

  if (tas58xx_read_reg(REG_POWER_STATE, &val) == ESP_OK) {
    const char *ps_str;
    switch (val) {
    case 0x00:
      ps_str = "DEEP_SLEEP";
      break;
    case 0x01:
      ps_str = "SLEEP";
      break;
    case 0x02:
      ps_str = "HIZ";
      break;
    case 0x03:
      ps_str = "PLAY";
      break;
    default:
      ps_str = "UNKNOWN";
      break;
    }
    ESP_LOGD(TAG, "  POWER_STATE=0x%02X (%s)", val, ps_str);
  }

  if (tas58xx_read_reg(REG_SAP_CTRL1, &val) == ESP_OK) {
    const char *fmt_str;
    switch ((val >> 4) & 0x03) {
    case 0:
      fmt_str = "I2S";
      break;
    case 1:
      fmt_str = "TDM/DSP";
      break;
    case 2:
      fmt_str = "RJ";
      break;
    case 3:
      fmt_str = "LJ";
      break;
    default:
      fmt_str = "?";
      break;
    }
    int wlen = 16 + ((val >> 0) & 0x03) * 8; // 00=16, 01=20, 10=24, 11=32
    ESP_LOGD(TAG, "  SAP_CTRL1=0x%02X  format=%s  word_len=%d-bit", val,
             fmt_str, wlen);
  }

  if (tas58xx_read_reg(REG_DIG_VOL, &val) == ESP_OK) {
    float db = (0x30 - (int)val) * 0.5f;
    ESP_LOGD(TAG, "  DIG_VOL=0x%02X (%.1f dB%s)", val, db,
             val == DIG_VOL_MUTE ? " MUTED" : "");
  }

  if (tas58xx_read_reg(REG_AGAIN, &val) == ESP_OK) {
    float again_db = -(val & 0x1F) * 0.5f;
    ESP_LOGD(TAG, "  AGAIN=0x%02X (%.1f dB)", val, again_db);
  }

  if (tas58xx_read_reg(REG_AUTO_MUTE_CTRL, &val) == ESP_OK) {
    ESP_LOGD(TAG, "  AUTO_MUTE_CTRL=0x%02X", val);
  }

  uint8_t chan_fault = 0, global1 = 0, global2 = 0, warning = 0;
  tas58xx_read_reg(REG_CHAN_FAULT, &chan_fault);
  tas58xx_read_reg(REG_GLOBAL_FAULT1, &global1);
  tas58xx_read_reg(REG_GLOBAL_FAULT2, &global2);
  tas58xx_read_reg(REG_WARNING, &warning);
  if (chan_fault || global1 || global2 || warning) {
    ESP_LOGW(TAG,
             "  FAULTS: chan=0x%02X global1=0x%02X global2=0x%02X warn=0x%02X",
             chan_fault, global1, global2, warning);
  } else {
    ESP_LOGD(TAG, "  FAULTS: none");
  }

  if (tas58xx_read_reg(REG_DSP_PGM_MODE, &val) == ESP_OK) {
    ESP_LOGD(TAG, "  DSP_PGM_MODE=0x%02X", val);
  }
  if (tas58xx_read_reg(REG_DSP_CTRL, &val) == ESP_OK) {
    ESP_LOGD(TAG, "  DSP_CTRL=0x%02X", val);
  }

  ESP_LOGD(TAG, "--- end status dump ---");
}

static esp_err_t tas58xx_init(void *i2c_bus) {
  esp_err_t err;

  ESP_LOGI(TAG, "Initializing TAS5825M");

  /* Create the register-access mutex (once) */
  if (s_reg_mutex == NULL) {
    s_reg_mutex = xSemaphoreCreateMutex();
    if (s_reg_mutex == NULL) {
      ESP_LOGE(TAG, "Failed to create register mutex");
      return ESP_ERR_NO_MEM;
    }
  }
  s_bus_handle = (i2c_master_bus_handle_t)i2c_bus;
  if (s_bus_handle == NULL) {
    ESP_LOGE(TAG, "No I2C bus handle provided");
    return ESP_ERR_INVALID_ARG;
  }

  // Detect device
  tas58xx_addr = tas58xx_detect(s_bus_handle);
  if (!tas58xx_addr) {
    ESP_LOGE(TAG, "No TAS5825M detected on I2C bus!");
    return ESP_ERR_NOT_FOUND;
  }

  err = i2c_bus_add_device(tas58xx_addr, &tas58xx_device_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not add device to I2C bus: %s", esp_err_to_name(err));
    return err;
  }

  // Verify die ID
  uint8_t die_id = 0;
  err = tas58xx_read_reg(REG_DIE_ID, &die_id);
  if (err == ESP_OK) {
    ESP_LOGI(TAG, "Die ID: 0x%02X %s", die_id,
             (die_id == TAS5825M_DIE_ID) ? "(OK)" : "(UNEXPECTED!)");
  } else {
    ESP_LOGE(TAG, "Failed to read die ID: %s", esp_err_to_name(err));
  }

  // Run init sequence
  ESP_LOGI(TAG, "Running init sequence...");
  for (int i = 0; tas58xx_init_seq[i].reg != 0xFF; i++) {
    err = tas58xx_write_reg(tas58xx_init_seq[i].reg, tas58xx_init_seq[i].value);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Init failed at step %d: reg 0x%02X val 0x%02X: %s", i,
               tas58xx_init_seq[i].reg, tas58xx_init_seq[i].value,
               esp_err_to_name(err));
      return err;
    }
    ESP_LOGD(TAG, "  [%02d] reg 0x%02X <- 0x%02X", i, tas58xx_init_seq[i].reg,
             tas58xx_init_seq[i].value);

    // Pause after HiZ transition to let clocks settle
    if (tas58xx_init_seq[i].reg == REG_DEVICE_CTRL2 &&
        (tas58xx_init_seq[i].value & CTRL2_STATE_MASK) == CTRL2_HIZ) {
      ESP_LOGD(TAG, "  Waiting 10 ms for HiZ clock settle");
      vTaskDelay(pdMS_TO_TICKS(10));
    }

    // Pause after DSP configuration before going to PLAY
    if (tas58xx_init_seq[i].reg == REG_DSP_CTRL) {
      ESP_LOGD(TAG, "  Waiting 5 ms for DSP settle");
      vTaskDelay(pdMS_TO_TICKS(5));
    }
  }

  // Give the device time to reach PLAY state
  vTaskDelay(pdMS_TO_TICKS(10));

  // Dump full status after init
  tas58xx_dump_status("post-init");

  ESP_LOGI(TAG, "TAS5825M initialized at I2C addr 0x%02X", tas58xx_addr);
  return ESP_OK;
}

static esp_err_t tas58xx_deinit(void) {
  esp_err_t err = ESP_OK;

  // Put device into deep sleep
  tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_DEEP_SLEEP);

  if (tas58xx_device_handle) {
    err = i2c_bus_remove_device(tas58xx_device_handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to remove from I2C bus: %s", esp_err_to_name(err));
    }
    tas58xx_device_handle = NULL;
  }

  s_bus_handle = NULL;
  return err;
}

static void tas58xx_set_power_mode(dac_power_mode_t mode) {
  REG_LOCK();
  uint8_t cur_ctrl2 = 0;
  tas58xx_read_reg(REG_DEVICE_CTRL2, &cur_ctrl2);
  uint8_t cur_state = cur_ctrl2 & CTRL2_STATE_MASK;

  if (mode == DAC_POWER_ON) {
    // Always go through HIZ first (per datasheet §9.5.3.1)
    // The PLL needs valid I2S clocks to lock — they must be present
    // by the time this function is called.
    if (cur_state != CTRL2_HIZ) {
      ESP_LOGW(TAG, "Transitioning to HIZ first (from state %d)", cur_state);
      tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_HIZ);
      vTaskDelay(pdMS_TO_TICKS(10));
    }

    /*
     * Per TAS5825M datasheet §7.6.2.2, exiting DEEP_SLEEP is similar
     * to a power-on-reset — all registers may revert to defaults.
     * Re-program the critical DSP registers so the correct process
     * flow, I2S format, and coefficient mode are active.
     */
    if (cur_state == CTRL2_DEEP_SLEEP) {
      ESP_LOGI(TAG, "Woke from DEEP_SLEEP — re-programming DSP registers");
      tas58xx_write_reg(REG_SAP_CTRL1, 0x00); /* I2S, 16-bit */
      tas58xx_write_reg(REG_CLOCK_DET_CTRL, 0x00);
      tas58xx_write_reg(REG_DSP_PGM_MODE, 0x01); /* PF1 (Base/Pro, 96kHz) */
      tas58xx_write_reg(REG_DSP_CTRL, 0x01);     /* USE_DEFAULT_COEFFS */
      vTaskDelay(pdMS_TO_TICKS(5));
      tas58xx_write_reg(REG_DIG_VOL_CTRL1, 0x33);
      tas58xx_write_reg(REG_AUTO_MUTE_CTRL, 0x07);
      tas58xx_write_reg(REG_AUTO_MUTE_TIME, 0x00);
      tas58xx_write_reg(REG_DIG_VOL, DIG_VOL_0DB);
      tas58xx_write_reg(REG_AGAIN, 0x00);

      /* Coefficient RAM may be invalid after DEEP_SLEEP — force
       * full re-write of signal-path defaults on next EQ update. */
      s_dsp_defaults_written = false;
    }

    // Clear any faults accumulated while clocks were absent
    tas58xx_write_reg(REG_FAULT_CLEAR, 0x80);
    vTaskDelay(pdMS_TO_TICKS(5));

    // Request transition to PLAY (unmuted)
    tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_PLAY);

    // Poll POWER_STATE until the device actually reaches PLAY.
    // The TAS5825M won't transition until its PLL locks on SCLK.
    uint8_t ps = 0;
    bool reached_play = false;
    for (int attempt = 0; attempt < 50; attempt++) { // up to ~500 ms
      vTaskDelay(pdMS_TO_TICKS(10));
      if (tas58xx_read_reg(REG_POWER_STATE, &ps) == ESP_OK && ps == 0x03) {
        ESP_LOGI(TAG, "Reached PLAY state after %d ms", (attempt + 1) * 10);
        reached_play = true;
        break;
      }
    }
    if (!reached_play) {
      ESP_LOGE(TAG,
               "FAILED to reach PLAY — POWER_STATE=0x%02X "
               "(is I2S providing BCLK/WS on GPIO %d/%d?)",
               ps, CONFIG_I2S_BCK_IO, CONFIG_I2S_WS_IO);
    }

    // Clear any faults from PLAY transition
    tas58xx_write_reg(REG_FAULT_CLEAR, 0x80);

    tas58xx_dump_status("power-on");
  } else if (mode == DAC_POWER_STANDBY) {
    tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_HIZ);
  } else {
    tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_DEEP_SLEEP);
    /* DEEP_SLEEP may reset registers and coefficient RAM — ensure
     * full re-initialization happens on the next wake-up. */
    s_dsp_defaults_written = false;
  }

  REG_UNLOCK();
}

static void tas58xx_enable_speaker(bool enable) {
  REG_LOCK();

  // Use mute bit in DEVICE_CTRL2 to enable/disable output.
  // Read current register, modify mute bit, write back.
  uint8_t val;
  esp_err_t err = tas58xx_read_reg(REG_DEVICE_CTRL2, &val);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read DEVICE_CTRL2");
    REG_UNLOCK();
    return;
  }

  ESP_LOGI(TAG, "Speaker %s (DEVICE_CTRL2 was 0x%02X)",
           enable ? "ENABLE" : "DISABLE", val);

  if (enable) {
    val &= ~CTRL2_MUTE; // Clear mute bit
  } else {
    val |= CTRL2_MUTE; // Set mute bit
  }

  tas58xx_write_reg(REG_DEVICE_CTRL2, val);

  REG_UNLOCK();
}

static void tas58xx_enable_line_out(bool enable) {
  (void)enable;
  ESP_LOGW(TAG, "Line out not supported on TAS5825M");
}

static void tas58xx_set_volume(float volume_airplay_db) {
  REG_LOCK();

  // Clamp AirPlay input range (-30 to 0)
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }

  // TAS5825M DIG_VOL register:
  //   0x00 = +24.0 dB
  //   0x30 = 0.0 dB
  //   0xFE = -103.0 dB
  //   0xFF = mute
  //   Step = -0.5 dB per count
  //
  // Volume mapping (2:1 scaling):
  //   AirPlay 0 dB    -> DAC CONFIG_TAS58XX_MAX_VOLUME
  //   AirPlay -25 dB  -> DAC (MAX - 50)
  //   AirPlay -30..-25 dB -> steep roll-off to mute
  float max_db = (float)CONFIG_TAS58XX_MAX_VOLUME;
  float db_level;

  if (volume_airplay_db >= -25.0f) {
    // 2:1 linear scaling: 25 dB AirPlay range -> 50 dB DAC range
    db_level = max_db + (volume_airplay_db * 2.0f);
  } else {
    // Roll-off: map -30..-25 to -103..(MAX-50)
    float normalized = (volume_airplay_db + 30.0f) / 5.0f;
    float rolloff_top = max_db - 50.0f;
    db_level = -103.0f + normalized * (103.0f + rolloff_top);
  }

  // Clamp to TAS5825M valid range: +24 dB to -103 dB
  if (db_level > 24.0f) {
    db_level = 24.0f;
  }
  if (db_level < -103.0f) {
    db_level = -103.0f;
  }

  // Convert dB to register value:
  // reg = 0x30 - (db_level * 2)  (since 0x30 = 0 dB and step = -0.5 dB)
  uint8_t reg_val;
  if (db_level <= -103.0f) {
    reg_val = DIG_VOL_MUTE;
  } else {
    int raw = DIG_VOL_0DB - (int)(db_level * 2.0f);
    if (raw < 0x00) {
      raw = 0x00;
    }
    if (raw > 0xFE) {
      raw = 0xFE;
    }
    reg_val = (uint8_t)raw;
  }

  ESP_LOGD(TAG, "Volume: AirPlay %.1f dB -> DAC %.1f dB -> reg 0x%02X",
           volume_airplay_db, db_level, reg_val);

  tas58xx_write_reg(REG_DIG_VOL, reg_val);

  REG_UNLOCK();
}

/* ---------- Public ops struct ---------- */

const dac_ops_t dac_tas58xx_ops = {
    .init = tas58xx_init,
    .deinit = tas58xx_deinit,
    .set_volume = tas58xx_set_volume,
    .set_power_mode = tas58xx_set_power_mode,
    .enable_speaker = tas58xx_enable_speaker,
    .enable_line_out = tas58xx_enable_line_out,
};

/* ---------- Register read/write helpers ---------- */

static esp_err_t tas58xx_write_reg(uint8_t reg, uint8_t value) {
  return i2c_bus_write(tas58xx_device_handle, tas58xx_addr, reg, &value,
                       sizeof(uint8_t));
}

static esp_err_t tas58xx_read_reg(uint8_t reg, uint8_t *value) {
  return i2c_bus_read(tas58xx_device_handle, tas58xx_addr, reg, value,
                      sizeof(uint8_t));
}

/* ==================  15-Band Parametric EQ  ================== */

#include "dac_tas58xx_eq_data.h"

#define BQ_COEFF_BOOK 0xAA /* TAS5825M coefficient book */
#define BQ_COEFF_SIZE 20   /* bytes per biquad (5 × 4) */

/* Book / Page / Register for EQ mode control */
#define EQ_MODE_BOOK 0x8C
#define EQ_MODE_PAGE 0x0B
#define EQ_MODE_REG  0x28
#define EQ_MODE_SIZE 8 /* 4 bytes gang_eq + 4 bytes bypass_eq */

/* 15 center frequencies matching mrtoy-me/esphome-tas58xx reference */
static const float eq_center_freq[TAS58XX_EQ_BANDS] = {
    20.0f,  31.5f,   50.0f,   80.0f,   125.0f,  200.0f,  315.0f,   500.0f,
    800.0f, 1250.0f, 2000.0f, 3150.0f, 5000.0f, 8000.0f, 16000.0f,
};

/* 1.0 in 5.27 fixed-point (1 sign + 4 int + 27 frac = 32-bit) */
#define FP_ONE 0x08000000

/* ---------- helpers ---------- */

/** Select a book/page for coefficient access. */
static inline esp_err_t select_book_page(uint8_t book, uint8_t page) {
  esp_err_t err;
  err = tas58xx_write_reg(REG_PAGE_SEL, 0x00);
  if (err != ESP_OK) {
    return err;
  }
  err = tas58xx_write_reg(REG_BOOK_SEL, book);
  if (err != ESP_OK) {
    return err;
  }
  return tas58xx_write_reg(REG_PAGE_SEL, page);
}

/** Return to Book 0, Page 0. */
static inline esp_err_t select_default_page(void) {
  esp_err_t err;
  err = tas58xx_write_reg(REG_PAGE_SEL, 0x00);
  if (err != ESP_OK) {
    return err;
  }
  err = tas58xx_write_reg(REG_BOOK_SEL, 0x00);
  if (err != ESP_OK) {
    return err;
  }
  return tas58xx_write_reg(REG_PAGE_SEL, 0x00);
}

/**
 * Write a single biquad's 5 coefficients (20 bytes, big-endian) to the
 * TAS5825M coefficient RAM.
 * Caller must already have selected the coefficient Book.
 */
static esp_err_t write_biquad_coeff(uint8_t page, uint8_t reg_start,
                                    const int32_t coeff[5]) {
  esp_err_t err;

  /* Select coefficient page */
  err = tas58xx_write_reg(REG_PAGE_SEL, page);
  if (err != ESP_OK) {
    return err;
  }

  uint8_t buf[BQ_COEFF_SIZE];
  for (int i = 0; i < 5; i++) {
    buf[i * 4 + 0] = (uint8_t)((coeff[i] >> 24) & 0xFF);
    buf[i * 4 + 1] = (uint8_t)((coeff[i] >> 16) & 0xFF);
    buf[i * 4 + 2] = (uint8_t)((coeff[i] >> 8) & 0xFF);
    buf[i * 4 + 3] = (uint8_t)((coeff[i]) & 0xFF);
  }

  return i2c_bus_write(tas58xx_device_handle, tas58xx_addr, reg_start, buf,
                       BQ_COEFF_SIZE);
}

/**
 * Write a single biquad's pre-computed 20-byte coefficient block to the
 * TAS5825M coefficient RAM.  The caller must already have selected the
 * correct book (0xAA); this function selects the page and writes the data.
 */
static esp_err_t write_biquad_raw(uint8_t page, uint8_t sub_addr,
                                  const uint8_t data[EQ_COEFF_BYTES]) {
  esp_err_t err;
  err = tas58xx_write_reg(REG_PAGE_SEL, page);
  if (err != ESP_OK) {
    return err;
  }

  return i2c_bus_write(tas58xx_device_handle, tas58xx_addr, sub_addr, data,
                       EQ_COEFF_BYTES);
}

static esp_err_t write_dsp_coeff32(uint8_t page, uint8_t reg, int32_t val) {
  esp_err_t err = tas58xx_write_reg(REG_PAGE_SEL, page);
  if (err != ESP_OK) {
    return err;
  }
  uint8_t buf[4] = {(uint8_t)(val >> 24), (uint8_t)(val >> 16),
                    (uint8_t)(val >> 8), (uint8_t)(val)};
  return i2c_bus_write(tas58xx_device_handle, tas58xx_addr, reg, buf, 4);
}

/**
 * Write default coefficient values for all DSP signal-path blocks in
 * Book 0x8C
 */
static esp_err_t write_dsp_signal_path_defaults(void) {
  esp_err_t err;

  ESP_LOGD(TAG, "DSP: writing signal-path defaults (Books 0x8C + 0xAA)");

  /*
   * ── Book 0x8C: control coefficients ──
   * All values from SLAA786A Table 9 (Process Flow 1).
   */
  err = select_book_page(0x8C, 0x00);
  if (err != ESP_OK) {
    return err;
  }

  /* Volume softening filter alpha (Page 0x01 Reg 0x2C) */
  write_dsp_coeff32(0x01, 0x2C, 0x00E2C46B);

  /*
   * DRC — 3-band Dynamic Range Compression (Pages 0x06–0x07)
   */
  write_dsp_coeff32(0x06, 0x58, 0x00800000); /* DRC1 mixer gain (unity) */
  write_dsp_coeff32(0x06, 0x5C, 0x00800000); /* DRC2 mixer gain (unity) */
  write_dsp_coeff32(0x06, 0x60, 0x00800000); /* DRC3 mixer gain (unity) */
  /* DRC1 time constants */
  write_dsp_coeff32(0x06, 0x64, 0x7FFFFFFF); /* DRC1 Energy  */
  write_dsp_coeff32(0x06, 0x68, 0x7FFFFFFF); /* DRC1 Attack  */
  write_dsp_coeff32(0x06, 0x6C, 0x7FFFFFFF); /* DRC1 Decay   */
  /* DRC1 slopes and thresholds */
  write_dsp_coeff32(0x06, 0x70, 0x00000000); /* K0_1 (no compression) */
  write_dsp_coeff32(0x06, 0x74, 0x00000000); /* K1_1 */
  write_dsp_coeff32(0x06, 0x78, 0x00000000); /* K2_1 */
  write_dsp_coeff32(0x06, 0x7C, 0xE7000000); /* T1_1 threshold */
  write_dsp_coeff32(0x07, 0x08, 0xFE800000); /* T2_1 threshold */
  write_dsp_coeff32(0x07, 0x0C, 0x00000000); /* off1_1 */
  write_dsp_coeff32(0x07, 0x10, 0x00000000); /* off2_1 */
  /* DRC2 time constants */
  write_dsp_coeff32(0x07, 0x14, 0x7FFFFFFF); /* DRC2 Energy  */
  write_dsp_coeff32(0x07, 0x18, 0x7FFFFFFF); /* DRC2 Attack  */
  write_dsp_coeff32(0x07, 0x1C, 0x7FFFFFFF); /* DRC2 Decay   */
  /* DRC2 slopes and thresholds */
  write_dsp_coeff32(0x07, 0x20, 0x00000000); /* k0_2 */
  write_dsp_coeff32(0x07, 0x24, 0x00000000); /* k1_2 */
  write_dsp_coeff32(0x07, 0x28, 0x00000000); /* k2_2 */
  write_dsp_coeff32(0x07, 0x2C, 0xE7000000); /* t1_2 */
  write_dsp_coeff32(0x07, 0x30, 0xFE800000); /* t2_2 */
  write_dsp_coeff32(0x07, 0x34, 0x00000000); /* off1_2 */
  write_dsp_coeff32(0x07, 0x38, 0x00000000); /* off2_2 */
  /* DRC3 time constants */
  write_dsp_coeff32(0x07, 0x3C, 0x7FFFFFFF); /* DRC3 Energy  */
  write_dsp_coeff32(0x07, 0x40, 0x7FFFFFFF); /* DRC3 Attack  */
  write_dsp_coeff32(0x07, 0x44, 0x7FFFFFFF); /* DRC3 Decay   */
  /* DRC3 slopes and thresholds */
  write_dsp_coeff32(0x07, 0x48, 0x00000000); /* k0_3 */
  write_dsp_coeff32(0x07, 0x4C, 0x00000000); /* k1_3 */
  write_dsp_coeff32(0x07, 0x50, 0x00000000); /* k2_3 */
  write_dsp_coeff32(0x07, 0x54, 0xE7000000); /* t1_3 */
  write_dsp_coeff32(0x07, 0x58, 0xFE800000); /* t2_3 */
  write_dsp_coeff32(0x07, 0x5C, 0x00000000); /* off1_3 */
  write_dsp_coeff32(0x07, 0x60, 0x00000000); /* off2_3 */

  /* FS Clipper (Page 0x07) */
  write_dsp_coeff32(0x07, 0x64, 0x00800000); /* THD Boost (unity) */
  write_dsp_coeff32(0x07, 0x6C, 0x3FFFFFFF); /* CH-L Fine Volume  */
  write_dsp_coeff32(0x07, 0x70, 0x3FFFFFFF); /* CH-R Fine Volume  */

  /* DPEQ Control (Page 0x09) */
  write_dsp_coeff32(0x09, 0x28, 0x02DEAD00); /* DPEQ sense energy alpha */
  write_dsp_coeff32(0x09, 0x2C, 0x74013901); /* DPEQ threshold gain */
  write_dsp_coeff32(0x09, 0x30, 0x0020C49B); /* DPEQ threshold offset */

  /* Spatializer (Page 0x0A) */
  write_dsp_coeff32(0x0A, 0x38, 0x00000000); /* Spatializer level (off) */

  /* Output Crossbar (Page 0x0A) — default: straight stereo */
  write_dsp_coeff32(0x0A, 0x64, 0x00800000); /* Dig L ← L  (unity) */
  write_dsp_coeff32(0x0A, 0x68, 0x00000000); /* Dig L ← R  (zero)  */
  write_dsp_coeff32(0x0A, 0x6C, 0x00000000); /* Dig R ← L  (zero)  */
  write_dsp_coeff32(0x0A, 0x70, 0x00800000); /* Dig R ← R  (unity) */
  write_dsp_coeff32(0x0A, 0x74, 0x00800000); /* Ana L ← L  (unity) */
  write_dsp_coeff32(0x0A, 0x78, 0x00000000); /* Ana L ← R  (zero)  */
  write_dsp_coeff32(0x0A, 0x7C, 0x00000000); /* Ana R ← L  (zero)  */
  write_dsp_coeff32(0x0B, 0x08, 0x00800000); /* Ana R ← R  (unity) */

  /* Volume Control (Page 0x0B) */
  write_dsp_coeff32(0x0B, 0x0C, 0x00800000); /* CH-L Volume (unity) */
  write_dsp_coeff32(0x0B, 0x10, 0x00800000); /* CH-R Volume (unity) */

  /* Input Mixer (Page 0x0B) */
  write_dsp_coeff32(0x0B, 0x14, 0x00800000); /* L → L (unity) */
  write_dsp_coeff32(0x0B, 0x18, 0x00000000); /* R → L (zero)  */
  write_dsp_coeff32(0x0B, 0x1C, 0x00000000); /* L → R (zero)  */
  write_dsp_coeff32(0x0B, 0x20, 0x00800000); /* R → R (unity) */

  /* Bypass DC Block (Page 0x0B) */
  write_dsp_coeff32(0x0B, 0x24, 0x00000000);

  /* EQ Control (Page 0x0B) */
  write_dsp_coeff32(0x0B, 0x28, 0x00000000); /* GangEQ = 0 */
  write_dsp_coeff32(0x0B, 0x2C, 0x00000000); /* BypassEQ = 0 */

  /* Level Meter (Page 0x0B) */
  write_dsp_coeff32(0x0B, 0x30, 0x00A7264A); /* Softening filter alpha */
  write_dsp_coeff32(0x0B, 0x34, 0x00000000); /* Level meter input mux */

  /* Bank Switch (Page 0x0C) */
  write_dsp_coeff32(0x0C, 0x20, 0x00000000);

  /*
   * ── Book 0xAA: ALL biquad coefficient RAM ──
   *
   * We must initialize EVERY BQ slot in Book 0xAA:
   *   - 30 EQ BQs (15 L + 15 R) — from eq_left_addr / eq_right_addr
   *   - 8 DRC crossover BQs — linear layout from Page 0x07:0x78
   *   - 3 DPEQ BQs — Pages 0x09-0x0A
   *   - 2 Spatializer BQs — Page 0x0A
   */
  err = select_book_page(0xAA, 0x00);
  if (err != ESP_OK) {
    select_default_page();
    return err;
  }

  /* Unity BQ: B0=1.0 (5.27), B1=B2=A1=A2=0 */
  static const int32_t unity_bq[5] = {FP_ONE, 0, 0, 0, 0};

  /*
   * ── DRC crossover BQs (8 total, Pages 0x07-0x09) ──
   * Linear from Page 0x07 Reg 0x78.
   */

  /* DRC low BQ1: 0x07:0x78 → crosses to 0x08 (use individual writes) */
  write_dsp_coeff32(0x07, 0x78, FP_ONE);
  write_dsp_coeff32(0x07, 0x7C, 0x00000000);
  write_dsp_coeff32(0x08, 0x08, 0x00000000);
  write_dsp_coeff32(0x08, 0x0C, 0x00000000);
  write_dsp_coeff32(0x08, 0x10, 0x00000000);

  /* DRC low BQ2: 0x08:0x14 (fits on page) */
  write_biquad_coeff(0x08, 0x14, unity_bq);

  /* DRC high BQ1: 0x08:0x28 (fits on page) */
  write_biquad_coeff(0x08, 0x28, unity_bq);

  /* DRC high BQ2: 0x08:0x3C (fits on page) */
  write_biquad_coeff(0x08, 0x3C, unity_bq);

  /* DRC mid BQ1: 0x08:0x50 (fits on page) */
  write_biquad_coeff(0x08, 0x50, unity_bq);

  /* DRC mid BQ2: 0x08:0x64 (fits: 0x64+19=0x77) */
  write_biquad_coeff(0x08, 0x64, unity_bq);

  /* DRC mid BQ3: 0x08:0x78 → crosses to 0x09 (use individual writes) */
  write_dsp_coeff32(0x08, 0x78, FP_ONE);
  write_dsp_coeff32(0x08, 0x7C, 0x00000000);
  write_dsp_coeff32(0x09, 0x08, 0x00000000);
  write_dsp_coeff32(0x09, 0x0C, 0x00000000);
  write_dsp_coeff32(0x09, 0x10, 0x00000000);

  /* DRC mid BQ4: 0x09:0x14 (fits on page) */
  write_biquad_coeff(0x09, 0x14, unity_bq);

  /*
   * ── DPEQ BQs (3 total, Pages 0x09-0x0A) ──
   */
  write_biquad_coeff(0x09, 0x34, unity_bq); /* DPEQ sense BQ */
  write_biquad_coeff(0x09, 0x5C, unity_bq); /* DPEQ low-level path BQ */
  write_biquad_coeff(0x0A, 0x0C, unity_bq); /* DPEQ high-level path BQ */

  /*
   * ── Spatializer BQs (2 total, Page 0x0A) ──
   */
  write_biquad_coeff(0x0A, 0x3C, unity_bq); /* Spatializer BQ1 */
  write_biquad_coeff(0x0A, 0x50, unity_bq); /* Spatializer BQ2 */

  /*
   * ── EQ BQs (30 total, Pages 0x01-0x06) ──
   */
  for (int bq = 0; bq < TAS58XX_EQ_BANDS; bq++) {
    write_biquad_coeff(eq_left_addr[bq].page, eq_left_addr[bq].sub_addr,
                       unity_bq);
    write_biquad_coeff(eq_right_addr[bq].page, eq_right_addr[bq].sub_addr,
                       unity_bq);
  }

  err = select_default_page();

  s_dsp_defaults_written = true;
  ESP_LOGD(TAG, "DSP: signal-path defaults written (Book 0x8C + 0xAA)");
  return err;
}

static esp_err_t ensure_custom_coeffs_mode(void) {
  uint8_t dsp_ctrl;
  esp_err_t err = tas58xx_read_reg(REG_DSP_CTRL, &dsp_ctrl);
  if (err != ESP_OK) {
    return err;
  }

  if (dsp_ctrl & 0x01) {
    /* Mute while we reconfigure the entire coefficient RAM */
    uint8_t saved_ctrl2 = 0;
    tas58xx_read_reg(REG_DEVICE_CTRL2, &saved_ctrl2);
    bool was_unmuted = !(saved_ctrl2 & CTRL2_MUTE);
    if (was_unmuted) {
      tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2 | CTRL2_MUTE);
      vTaskDelay(pdMS_TO_TICKS(5)); /* let mute take effect */
    }

    /* Write all signal-path coefficients first */
    if (!s_dsp_defaults_written) {
      err = write_dsp_signal_path_defaults();
      if (err != ESP_OK) {
        if (was_unmuted) {
          tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2);
        }
        return err;
      }
    }

    /* Now safe to clear USE_DEFAULT_COEFFS */
    ESP_LOGD(TAG, "DSP: clearing USE_DEFAULT_COEFFS");
    err = tas58xx_write_reg(REG_DSP_CTRL, dsp_ctrl & ~0x01);

    /* Verify the bit was actually cleared */
    {
      uint8_t verify = 0xFF;
      tas58xx_read_reg(REG_DSP_CTRL, &verify);
      uint8_t pgm = 0xFF;
      tas58xx_read_reg(REG_DSP_PGM_MODE, &pgm);
      ESP_LOGD(TAG,
               "DSP: post-clear DSP_CTRL=0x%02X (expect 0x00) "
               "DSP_PGM_MODE=0x%02X (expect 0x01)",
               verify, pgm);
      if (verify & 0x01) {
        ESP_LOGE(TAG, "DSP: USE_DEFAULT_COEFFS still set!");
      }
      if (pgm != 0x01) {
        ESP_LOGW(TAG,
                 "DSP: unexpected DSP_PGM_MODE — process flow may be wrong! "
                 "EQ addresses assume PF1 (0x01)");
      }
    }

    /* Unmute */
    if (was_unmuted) {
      vTaskDelay(pdMS_TO_TICKS(5));
      tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2);
    }
  }
  return err;
}

/**
 * Program one biquad on both channels using pre-computed 20-byte coefficient
 * blocks from dac_tas58xx_eq_data.h.
 *
 * Enters Book 0xAA, writes CH-L then CH-R, returns to Book 0 / Page 0.
 * Assumes the caller holds REG_LOCK.
 */
static esp_err_t program_biquad_raw(int bq,
                                    const uint8_t data[EQ_COEFF_BYTES]) {
  esp_err_t err;

  /* Ensure DSP has all signal-path defaults before using custom coefficients */
  err = ensure_custom_coeffs_mode();
  if (err != ESP_OK) {
    return err;
  }

  /* Enter coefficient book */
  err = select_book_page(BQ_COEFF_BOOK, 0x00);
  if (err != ESP_OK) {
    goto out;
  }

  /* Channel 1 (Left) */
  err =
      write_biquad_raw(eq_left_addr[bq].page, eq_left_addr[bq].sub_addr, data);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "EQ: CH1 BQ%d raw write failed: %s", bq,
             esp_err_to_name(err));
    goto out;
  }

  /* Channel 2 (Right) */
  err = write_biquad_raw(eq_right_addr[bq].page, eq_right_addr[bq].sub_addr,
                         data);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "EQ: CH2 BQ%d raw write failed: %s", bq,
             esp_err_to_name(err));
    goto out;
  }

  ESP_LOGD(TAG,
           "EQ: BQ%d raw write OK (L page=0x%02X:0x%02X, R page=0x%02X:0x%02X)",
           bq, eq_left_addr[bq].page, eq_left_addr[bq].sub_addr,
           eq_right_addr[bq].page, eq_right_addr[bq].sub_addr);

out:
  select_default_page();
  return err;
}

static esp_err_t write_eq_mode(bool enable) {
  esp_err_t err;

  err = select_book_page(EQ_MODE_BOOK, EQ_MODE_PAGE);
  if (err != ESP_OK) {
    return err;
  }

  uint8_t mode_data[EQ_MODE_SIZE] = {
      0x00, 0x80, 0x00, 0x00,                 /* gang_eq = 0x00800000 */
      0x00, 0x00, 0x00, enable ? 0x00 : 0x01, /* bypass_eq */
  };

  err = i2c_bus_write(tas58xx_device_handle, tas58xx_addr, EQ_MODE_REG,
                      mode_data, EQ_MODE_SIZE);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "EQ: mode write failed: %s", esp_err_to_name(err));
  } else {
    ESP_LOGD(TAG, "EQ: %s", enable ? "ENABLED" : "BYPASSED");
  }

  select_default_page();
  return err;
}

/* ---------- Public API ---------- */

esp_err_t tas58xx_eq_enable(bool enable) {
  REG_LOCK();

  /* Ensure DSP defaults are written before touching EQ mode */
  esp_err_t err = ensure_custom_coeffs_mode();
  if (err != ESP_OK) {
    REG_UNLOCK();
    return err;
  }

  err = write_eq_mode(enable);
  REG_UNLOCK();
  return err;
}

esp_err_t tas58xx_eq_set_band(int band, float gain_db) {
  if (band < 0 || band >= TAS58XX_EQ_BANDS) {
    ESP_LOGE(TAG, "EQ: invalid band %d", band);
    return ESP_ERR_INVALID_ARG;
  }

  /* Clamp gain to integer dB range of pre-computed table */
  int gain_int = (int)roundf(gain_db);
  if (gain_int > TAS58XX_EQ_MAX_GAIN_DB) {
    gain_int = (int)TAS58XX_EQ_MAX_GAIN_DB;
  }
  if (gain_int < TAS58XX_EQ_MIN_GAIN_DB) {
    gain_int = (int)TAS58XX_EQ_MIN_GAIN_DB;
  }

  int idx = gain_int + EQ_GAIN_OFFSET;
  ESP_LOGD(TAG, "EQ: band %d (%.0f Hz) -> %+d dB (table idx %d)", band,
           eq_center_freq[band], gain_int, idx);

  REG_LOCK();
  esp_err_t err = program_biquad_raw(band, eq_coeff_table[idx][band].bytes);
  REG_UNLOCK();
  return err;
}

esp_err_t tas58xx_eq_set_all(const float gains_db[TAS58XX_EQ_BANDS]) {
  if (!gains_db) {
    return ESP_ERR_INVALID_ARG;
  }

  REG_LOCK();

  /* Mute to prevent DSP glitches while bulk-updating coefficients */
  uint8_t saved_ctrl2 = 0;
  tas58xx_read_reg(REG_DEVICE_CTRL2, &saved_ctrl2);
  if (!(saved_ctrl2 & CTRL2_MUTE)) {
    tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2 | CTRL2_MUTE);
  }

  esp_err_t first_err = ESP_OK;
  for (int i = 0; i < TAS58XX_EQ_BANDS; i++) {
    int gain_int = (int)roundf(gains_db[i]);
    if (gain_int > (int)TAS58XX_EQ_MAX_GAIN_DB) {
      gain_int = (int)TAS58XX_EQ_MAX_GAIN_DB;
    }
    if (gain_int < (int)TAS58XX_EQ_MIN_GAIN_DB) {
      gain_int = (int)TAS58XX_EQ_MIN_GAIN_DB;
    }

    int idx = gain_int + EQ_GAIN_OFFSET;
    esp_err_t err = program_biquad_raw(i, eq_coeff_table[idx][i].bytes);
    if (err != ESP_OK && first_err == ESP_OK) {
      first_err = err;
    }
  }

  /* Restore original mute state */
  tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2);

  REG_UNLOCK();
  return first_err;
}

esp_err_t tas58xx_eq_flat(void) {
  ESP_LOGD(TAG, "EQ: resetting all bands to flat");

  /* Index for 0 dB gain = unity passthrough */
  const int flat_idx = EQ_GAIN_OFFSET;

  REG_LOCK();

  /* Mute during bulk update */
  uint8_t saved_ctrl2 = 0;
  tas58xx_read_reg(REG_DEVICE_CTRL2, &saved_ctrl2);
  if (!(saved_ctrl2 & CTRL2_MUTE)) {
    tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2 | CTRL2_MUTE);
  }

  esp_err_t first_err = ESP_OK;
  for (int i = 0; i < TAS58XX_EQ_BANDS; i++) {
    esp_err_t err = program_biquad_raw(i, eq_coeff_table[flat_idx][i].bytes);
    if (err != ESP_OK && first_err == ESP_OK) {
      first_err = err;
    }
  }

  /* Enable EQ after programming flat coefficients */
  if (first_err == ESP_OK) {
    first_err = write_eq_mode(true);
  }

  /* Restore original mute state */
  tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2);

  REG_UNLOCK();
  return first_err;
}

float tas58xx_eq_get_center_freq(int band) {
  if (band < 0 || band >= TAS58XX_EQ_BANDS) {
    return 0.0f;
  }
  return eq_center_freq[band];
}

/* =====================  I2C Bus  ===================== */
static esp_err_t i2c_bus_add_device(uint8_t addr,
                                    i2c_master_dev_handle_t *dev_handle) {
  if (s_bus_handle == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  i2c_device_config_t dev_cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = addr,
      .scl_speed_hz = I2C_LINE_SPEED,
  };

  return i2c_master_bus_add_device(s_bus_handle, &dev_cfg, dev_handle);
}

static esp_err_t i2c_bus_remove_device(i2c_master_dev_handle_t dev_handle) {
  return i2c_master_bus_rm_device(dev_handle);
}

static esp_err_t i2c_bus_write(i2c_master_dev_handle_t dev, uint8_t addr,
                               uint8_t reg, const uint8_t *data, size_t len) {
  (void)addr;
  if (dev == NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  /* Max payload is BQ_COEFF_SIZE (20) bytes; +1 for the register byte. */
  static uint8_t buf[BQ_COEFF_SIZE + 1];
  if (len > BQ_COEFF_SIZE) {
    return ESP_ERR_INVALID_SIZE;
  }

  buf[0] = reg;
  memcpy(buf + 1, data, len);

  esp_err_t ret = i2c_master_transmit(dev, buf, len + 1, I2C_TIMEOUT);

  if (ret != ESP_OK) {
    ESP_LOGD(TAG, "I2C write reg 0x%02X failed: %s", reg, esp_err_to_name(ret));
  }
  return ret;
}

static esp_err_t i2c_bus_read(i2c_master_dev_handle_t dev, uint8_t addr,
                              uint8_t reg, uint8_t *data, size_t len) {
  (void)addr;
  if (dev == NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  return i2c_master_transmit_receive(dev, &reg, 1, data, len, I2C_TIMEOUT);
}
