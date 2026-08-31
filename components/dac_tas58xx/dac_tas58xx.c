/**
 * Implementation of control interface to TI TAS58xx (TAS5825M) DAC/Amp
 * TAS5825M datasheet:
 * https://www.ti.com/lit/ds/symlink/tas5825m.pdf
 */

#include "dac_tas58xx.h"
#include "board_utils.h"
#include "sdkconfig.h"
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "driver/i2c_master.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

/* ---------- TAS5825M I2C addresses (7-bit) ---------- */
#define TAS5825M_ADDR_GND 0x4C // ADR pin = 0 Ω to GND
#define TAS5825M_ADDR_1K  0x4D // ADR pin = 1 kΩ to GND
#define TAS5825M_ADDR_4K7 0x4E // ADR pin = 4.7 kΩ to GND
#define TAS5825M_ADDR_15K 0x4F // ADR pin = 15 kΩ to GND

/* ---------- TAS5805M I2C addresses (7-bit) ---------- */
#define TAS5805M_ADDR_4K7  0x2C // ADR pin = 4.7 kΩ to DVDD
#define TAS5805M_ADDR_15K  0x2D // ADR pin = 15 kΩ to DVDD
#define TAS5805M_ADDR_47K  0x2E // ADR pin = 47 kΩ to DVDD
#define TAS5805M_ADDR_120K 0x2F // ADR pin = 120 kΩ to DVDD

/* ---------- Register addresses (Book 0, Page 0) ---------- */
#define REG_PAGE_SEL 0x00
#define REG_BOOK_SEL 0x7F

#define REG_RESET_CTRL   0x01
#define REG_DEVICE_CTRL1 0x02
#define REG_DEVICE_CTRL2 0x03

#define REG_SIG_CH_CTRL    0x28
#define REG_CLOCK_DET_CTRL 0x29

#define REG_SDOUT_SEL 0x30

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

#define REG_GPIO_CTL 0x60
#define REG_GPIO0    0x61
#define REG_GPIO1    0x62
#define REG_GPIO2    0x63

#define REG_DSP_MISC 0x66

#define REG_GPIO_OFF     0x00
#define REG_GPIO_WARN    0b1000
#define REG_GPIO_FAULT   0b1011
#define REG_GPIO_SDOUT   0b1001
#define REG_GPIO_CTL_OUT 0b0111

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

/* ---------- DEVICE_CTRL1 (0x02) bit fields ---------- */
// Modulation mode (bits 0-1) and switching freq (bits 4-6) live here too;
// use read-modify-write so those defaults are preserved.
#define CTRL1_PBTL_EN     (1 << 2) // Parallel bridge-tied load (mono)
#define CTRL1_PBTL_CH_SEL (1 << 1) // PBTL data source: 0 = left, 1 = right

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

#define TAS5805M_DIE_ID 0x0
#define TAS5825M_DIE_ID 0x95

static const char TAG[] = "TAS58xx DAC";

typedef enum {
  TAS58XX_MODEL_UNKNOWN = 0,
  TAS58XX_MODEL_TAS5805M = 1,
  TAS58XX_MODEL_TAS5825M = 2,
} tas58xx_model_t;

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
static const struct tas58xx_cmd_s tas5825m_init_seq[] = {
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

    // Set SDOUT source to Pre-DSP
    {REG_SDOUT_SEL, 0x01},

    // GPIO config - WARN/FLT LEDs and SDOUT pin
    {REG_GPIO0, REG_GPIO_WARN},
    {REG_GPIO1, REG_GPIO_FAULT},
    {REG_GPIO2, REG_GPIO_SDOUT},
    {REG_GPIO_CTL, REG_GPIO_CTL_OUT},

    // Set digital volume to 0 dB initially
    {REG_DIG_VOL, DIG_VOL_0DB},

    // Analog gain: 0 dB
    {REG_AGAIN, 0x00},

    {0xFF, 0xFF} // End of table sentinel
};

/* TAS5805M is slightly simpler configuration, namely
   - lack of GPIO configuration
   - no process flow select register
   - DSP_MISC register to configure BQ coefficients per channel */
static const struct tas58xx_cmd_s tas5805m_init_seq[] = {
    {REG_PAGE_SEL, 0x00},        // Select Book 0 Page 0
    {REG_BOOK_SEL, 0x00},        // Select Book 0
    {REG_PAGE_SEL, 0x00},        // Confirm Page 0
    {REG_RESET_CTRL, RESET_REG}, // Reset control port registers
    {REG_DEVICE_CTRL2, CTRL2_HIZ},

    // I2S format: standard I2S, 16-bit word length
    {REG_SAP_CTRL1, 0x00}, // DATA_FORMAT=I2S(00), WORD_LENGTH=16bit(00)
    {REG_CLOCK_DET_CTRL, 0x00},

    // Volume ramp: smooth transitions
    {REG_DIG_VOL_CTRL1, 0x33}, // Default ramp rates

    // Auto-mute: enable for both channels
    {REG_AUTO_MUTE_CTRL, 0x03},
    {REG_AUTO_MUTE_TIME, 0x00},

    // Clear any pending faults
    {REG_FAULT_CLEAR, 0x80},

    // Set SDOUT source to Pre-DSP
    {REG_SDOUT_SEL, 0x01},

    // Set BQ coefficients to be unique per channel
    {REG_DSP_MISC, 0x08},

    // Set digital volume to 0 dB initially
    {REG_DIG_VOL, DIG_VOL_0DB},

    // Analog gain: 0 dB
    {REG_AGAIN, 0x00},

    {0xFF, 0xFF} // End of table sentinel
};

/* ---------- State ---------- */

/* Maximum number of TAS58xx chips managed on the shared I2C bus.
 * Dual-DAC boards (e.g. Esparagus Audio Brick Dual) place a second
 * TAS5825M on the same bus at a different address for a 2.1 setup. Extra
 * chips are detected at runtime; boards with a single DAC simply report
 * one device. */
#define TAS58XX_MAX_DEVICES 2

/* Per-chip state. All chips share the same I2S stream and I2C bus. */
typedef struct {
  uint8_t addr;                   /* 7-bit I2C address */
  tas58xx_model_t model;          /* TAS5805M / TAS5825M */
  i2c_master_dev_handle_t handle; /* I2C device handle */
  bool dsp_defaults_written;      /* signal-path coeffs programmed */
  bool pbtl_mono;                 /* bridged (PBTL) mono output stage */
  tas58xx_mix_t mix;              /* input-mixer routing */
  uint8_t *hf_buf;                /* cached PPC3 dump (NULL if none) */
  size_t hf_size;                 /* bytes in hf_buf */
  char hf_path[48];               /* where the dump came from */
  int32_t hf_mix[4];              /* the dump's own mixer gains, 9.23 */
  bool hf_mix_seen;               /* ...and whether it wrote all four */
} tas58xx_dev_t;

static tas58xx_dev_t s_devs[TAS58XX_MAX_DEVICES];
static int s_dev_count = 0;
static i2c_master_bus_handle_t s_bus_handle = NULL;

/* Whether the second amplifier is bridged (PBTL) mono. Read at init only. */
static bool s_second_pbtl = true;
/* The wiring the chips were actually brought up in. PBTL is only writable
 * during init, so a change made later must not alter how the running chips
 * are driven until the user has rewired and restarted. */
static bool s_active_second_pbtl = true;

/* Cached master AirPlay volume so a level change can be re-applied alone. */
static float s_last_airplay_db = -15.0f;

/* Per-output level trim (dB) and mute, folded into the input mixer gains. */
static float s_ch_gain_db[TAS58XX_MAX_DEVICES][TAS58XX_BQ_CHANNELS];
static bool s_ch_mute[TAS58XX_MAX_DEVICES][TAS58XX_BQ_CHANNELS];

/* Requested input routing per amplifier. Held separately from the detected
 * device so it can be restored from NVS before the chips are probed; the
 * default depends on the wiring and is only used where nothing was stored. */
static tas58xx_mix_t s_dev_mix[TAS58XX_MAX_DEVICES];
static bool s_dev_mix_cfg[TAS58XX_MAX_DEVICES];

/*
 * Device currently targeted by the low-level register helpers.
 *
 * All register access is serialized by s_reg_mutex, so a single
 * "current device" pointer, set while the lock is held, is sufficient to
 * route the page/book helpers and I2C read/write helpers to the correct
 * chip. Entry points (ops + public EQ API) set s_cur under the lock for
 * each device they touch.
 */
static tas58xx_dev_t *s_cur = NULL;

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
 * functions acquire it; internal helpers assume it's already held. The
 * lock also guards s_cur, which selects the target chip.
 */
static SemaphoreHandle_t s_reg_mutex = NULL;

#define REG_LOCK()   xSemaphoreTake(s_reg_mutex, portMAX_DELAY)
#define REG_UNLOCK() xSemaphoreGive(s_reg_mutex)

/* ---------- Forward declarations ---------- */
static esp_err_t tas58xx_write_reg(uint8_t reg, uint8_t value);
static esp_err_t tas58xx_read_reg(uint8_t reg, uint8_t *value);
static esp_err_t tas58xx_init_one(tas58xx_dev_t *dev);
static esp_err_t tas58xx_apply_input_mix(void);
static esp_err_t tas58xx_run_init_seq(tas58xx_dev_t *dev);

/* Linear scale the input mixer should apply to one output path. */
static float tas58xx_ch_scale(int dev, int ch) {
  if (s_ch_mute[dev][ch]) {
    return 0.0f;
  }
  return powf(10.0f, s_ch_gain_db[dev][ch] / 20.0f);
}
static esp_err_t bq_program_chain(void);
static void bq_chain_defaults(void);
static bool bq_load_config(void);
static bool bq_chain_is_flat(int dev);
static bool bq_chain_is_from_dump(int dev);
static bool tas58xx_seed_bq_from_hf(int idx);

/* ---------- Detect ---------- */

/*
 * Probe the bus for every supported TAS58xx address and record each chip
 * found (up to TAS58XX_MAX_DEVICES) into s_devs[]. Devices are recorded
 * in ascending-address order; the caller assigns roles based on index.
 *
 * Returns the number of devices detected.
 */
static int tas58xx_detect(i2c_master_bus_handle_t bus) {
  static const struct {
    uint8_t addr;
    tas58xx_model_t model;
    const char *name;
  } candidates[] = {
      {TAS5825M_ADDR_GND, TAS58XX_MODEL_TAS5825M, "TAS5825M"},
      {TAS5825M_ADDR_1K, TAS58XX_MODEL_TAS5825M, "TAS5825M"},
      {TAS5825M_ADDR_4K7, TAS58XX_MODEL_TAS5825M, "TAS5825M"},
      {TAS5825M_ADDR_15K, TAS58XX_MODEL_TAS5825M, "TAS5825M"},
      {TAS5805M_ADDR_4K7, TAS58XX_MODEL_TAS5805M, "TAS5805M"},
      {TAS5805M_ADDR_15K, TAS58XX_MODEL_TAS5805M, "TAS5805M"},
      {TAS5805M_ADDR_47K, TAS58XX_MODEL_TAS5805M, "TAS5805M"},
      {TAS5805M_ADDR_120K, TAS58XX_MODEL_TAS5805M, "TAS5805M"},
  };

  if (!bus) {
    ESP_LOGE(TAG, "Invalid I2C handle");
    return 0;
  }

  int found = 0;
  for (int i = 0; i < sizeof(candidates) / sizeof(candidates[0]) &&
                  found < TAS58XX_MAX_DEVICES;
       i++) {
    if (ESP_OK == i2c_master_probe(bus, candidates[i].addr, I2C_TIMEOUT)) {
      ESP_LOGI(TAG, "Detected %s at @0x%02X", candidates[i].name,
               candidates[i].addr);
      s_devs[found].addr = candidates[i].addr;
      s_devs[found].model = candidates[i].model;
      s_devs[found].handle = NULL;
      s_devs[found].dsp_defaults_written = false;
      s_devs[found].pbtl_mono = false;
      s_devs[found].mix = TAS58XX_MIX_STEREO;
      found++;
    }
  }
  return found;
}

/* ---------- DAC ops implementation ---------- */

static void tas58xx_dump_status(const char *context) {
  uint8_t val = 0;

  ESP_LOGD(TAG, "--- %s: TAS58xx @0x%02X status dump ---", context,
           s_cur ? s_cur->addr : 0);

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
    float db = (float)(0x30 - (int)val) * 0.5f;
    ESP_LOGD(TAG, "  DIG_VOL=0x%02X (%.1f dB%s)", val, db,
             val == DIG_VOL_MUTE ? " MUTED" : "");
  }

  if (tas58xx_read_reg(REG_AGAIN, &val) == ESP_OK) {
    float again_db = -(float)(val & 0x1F) * 0.5f;
    ESP_LOGD(TAG, "  AGAIN=0x%02X (%.1f dB)", val, again_db);
  }

  if (tas58xx_read_reg(REG_AUTO_MUTE_CTRL, &val) == ESP_OK) {
    ESP_LOGD(TAG, "  AUTO_MUTE_CTRL=0x%02X", val);
  }

  uint8_t chan_fault = 0, global1 = 0, global2 = 0, ot_warning = 0;
  tas58xx_read_reg(REG_CHAN_FAULT, &chan_fault);
  tas58xx_read_reg(REG_GLOBAL_FAULT1, &global1);
  tas58xx_read_reg(REG_GLOBAL_FAULT2, &global2);
  tas58xx_read_reg(REG_WARNING, &ot_warning);

  if (chan_fault || global1 || global2 || ot_warning) {
    if (chan_fault) {
      if (chan_fault & BIT(0)) {
        ESP_LOGW(TAG, "Right channel over current fault");
      }

      if (chan_fault & BIT(1)) {
        ESP_LOGW(TAG, "Left channel over current fault");
      }

      if (chan_fault & BIT(2)) {
        ESP_LOGW(TAG, "Right channel DC fault");
      }

      if (chan_fault & BIT(3)) {
        ESP_LOGW(TAG, "Left channel DC fault");
      }
    }

    if (global1) {
      if (global1 & BIT(0)) {
        ESP_LOGW(TAG, "PVDD UV fault");
      }

      if (global1 & BIT(1)) {
        ESP_LOGW(TAG, "PVDD OV fault");
      }

      // This fault is often triggered by lack of I2S clock, which is expected
      // during longer pauses (when mute state is triggeered).
      if (global1 & BIT(2)) {
        ESP_LOGW(TAG, "Clock fault");
      }

      // Bits 3-4 are reserved

      // Bit 5 applies only to tas5825m
      if (global1 & BIT(5)) {
        ESP_LOGW(TAG, "EEPROM boot load error");
      }

      if (global1 & BIT(6)) {
        ESP_LOGW(TAG, "The recent BQ write failed");
      }

      if (global1 & BIT(7)) {
        ESP_LOGW(TAG, "OTP CRC check error");
      }
    }

    if (global2) {
      if (global2 & BIT(0)) {
        ESP_LOGW(TAG, "Over temperature shut down fault");
      }

      // Bits 1-2 only apply to tas5825m
      if (global2 & BIT(1)) {
        ESP_LOGW(TAG, "Left channel cycle by cycle over current fault");
      }

      if (global2 & BIT(2)) {
        ESP_LOGW(TAG, "Right channel cycle by cycle over current fault");
      }
    }

    if (ot_warning) {
      if (ot_warning & BIT(0)) {
        ESP_LOGW(TAG, "Over temperature warning level 1, 112C");
      }

      if (ot_warning & BIT(1)) {
        ESP_LOGW(TAG, "Over temperature warning level 2, 122C");
      }

      if (ot_warning & BIT(2)) {
        ESP_LOGW(TAG, "Over temperature warning level 3, 134C");
      }

      if (ot_warning & BIT(3)) {
        ESP_LOGW(TAG, "Over temperature warning level 4, 146C");
      }

      // Bits 4-5 apply to tas5825m only
      if (ot_warning & BIT(4)) {
        ESP_LOGW(TAG, "Right channel cycle by cycle over current warning");
      }

      if (ot_warning & BIT(5)) {
        ESP_LOGW(TAG, "Left channel cycle by cycle over current warning");
      }
    }
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

/* A clock fault just means I2S has stopped, which is normal between tracks. */
#define GLOBAL1_CLOCK_FAULT BIT(2)

static const char *const s_chan_fault_names[8] = {
    "right over-current",
    "left over-current",
    "right DC",
    "left DC",
};
static const char *const s_global1_fault_names[8] = {
    "PVDD under-voltage", "PVDD over-voltage", "clock stopped", NULL, NULL,
    "EEPROM boot load",   "BQ write failed",   "OTP CRC",
};
static const char *const s_global2_fault_names[8] = {
    "over-temperature shutdown",
    "left cycle-by-cycle over-current",
    "right cycle-by-cycle over-current",
};

/* Appends at `at`, returning the new offset; never runs past len - 1. */
static size_t fault_names(char *buf, size_t len, size_t at, uint8_t bits,
                          const char *const names[8]) {
  for (int b = 0; b < 8; b++) {
    if (!(bits & BIT(b)) || names[b] == NULL) {
      continue;
    }
    const int n =
        snprintf(buf + at, len - at, "%s%s", at ? ", " : "", names[b]);
    if (n < 0) {
      return at;
    }
    at += (size_t)n;
    if (at >= len) {
      return len - 1;
    }
  }
  return at;
}

bool dac_tas58xx_fault_report(char *buf, size_t len) {
  bool serious = false;
  size_t at = 0;

  if (!buf || len == 0) {
    return false;
  }
  buf[0] = '\0';

  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    if (s_devs[i].handle == NULL) {
      continue;
    }
    s_cur = &s_devs[i];

    uint8_t chan = 0, global1 = 0, global2 = 0;
    tas58xx_read_reg(REG_CHAN_FAULT, &chan);
    tas58xx_read_reg(REG_GLOBAL_FAULT1, &global1);
    tas58xx_read_reg(REG_GLOBAL_FAULT2, &global2);
    if (!chan && !global1 && !global2) {
      continue;
    }
    if (chan || global2 || (global1 & (uint8_t)~GLOBAL1_CLOCK_FAULT)) {
      serious = true;
    }

    const int n = snprintf(buf + at, len - at, "%s@0x%02X ", at ? "; " : "",
                           s_devs[i].addr);
    if (n < 0 || at + (size_t)n >= len) {
      break;
    }
    at += (size_t)n;
    at = fault_names(buf, len, at, chan, s_chan_fault_names);
    at = fault_names(buf, len, at, global1, s_global1_fault_names);
    at = fault_names(buf, len, at, global2, s_global2_fault_names);
  }
  s_cur = NULL;
  REG_UNLOCK();

  return serious;
}

void dac_tas58xx_fault_clear(void) {
  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    if (s_devs[i].handle == NULL) {
      continue;
    }
    s_cur = &s_devs[i];
    tas58xx_write_reg(REG_FAULT_CLEAR, 0x80);
  }
  s_cur = NULL;
  REG_UNLOCK();
}

#if CONFIG_SPKFAULT_GPIO < 0
/*
 * Boards without a FAULTZ line to the MCU (e.g. the rev-D dual-DAC brick)
 * would otherwise never notice an over-current or over-temperature shutdown,
 * so poll the fault registers instead.
 */
#define FAULT_POLL_MS 2000

static TaskHandle_t s_fault_task = NULL;
static volatile bool s_fault_task_stop = false;

static void tas58xx_fault_task(void *arg) {
  static uint8_t last[TAS58XX_MAX_DEVICES][3];

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(FAULT_POLL_MS));
    if (s_fault_task_stop) {
      s_fault_task = NULL;
      vTaskDelete(NULL);
    }

    REG_LOCK();
    for (int i = 0; i < s_dev_count; i++) {
      if (s_devs[i].handle == NULL) {
        continue;
      }
      s_cur = &s_devs[i];

      uint8_t now[3] = {0};
      tas58xx_read_reg(REG_CHAN_FAULT, &now[0]);
      tas58xx_read_reg(REG_GLOBAL_FAULT1, &now[1]);
      tas58xx_read_reg(REG_GLOBAL_FAULT2, &now[2]);
      now[1] &= (uint8_t)~GLOBAL1_CLOCK_FAULT;

      if (memcmp(now, last[i], sizeof(now)) == 0) {
        continue;
      }
      memcpy(last[i], now, sizeof(now));

      if (now[0] || now[1] || now[2]) {
        ESP_LOGE(TAG,
                 "@0x%02X FAULT: CHAN=0x%02X GLOBAL1=0x%02X GLOBAL2=0x%02X",
                 s_devs[i].addr, now[0], now[1], now[2]);
        if (now[0] & 0x03) {
          ESP_LOGE(TAG,
                   "@0x%02X over-current - check the speaker wiring matches "
                   "the DAC configuration (PBTL outputs must not stay bridged "
                   "in bi-amp mode)",
                   s_devs[i].addr);
        }
        tas58xx_dump_status("fault");
      } else {
        ESP_LOGW(TAG, "@0x%02X faults cleared", s_devs[i].addr);
      }
    }
    s_cur = NULL;
    REG_UNLOCK();
  }
}
#endif /* CONFIG_SPKFAULT_GPIO < 0 */

/*
 * Enable the PBTL (mono) output stage for a bridged sub. This is a
 * control-port setting (DEVICE_CTRL1 bit 2) and must be established while the
 * device is still in HiZ, before the output stage drives the paralleled load.
 * Exiting DEEP_SLEEP resets DEVICE_CTRL1, so this has to be re-applied on
 * every power-on, not just at init. Assumes REG_LOCK is held and s_cur == dev.
 */
static esp_err_t tas58xx_apply_pbtl(tas58xx_dev_t *dev) {
  if (!dev->pbtl_mono) {
    return ESP_OK;
  }
  uint8_t ctrl1 = 0;
  tas58xx_read_reg(REG_DEVICE_CTRL1, &ctrl1);
  ctrl1 |= CTRL1_PBTL_EN;
  esp_err_t err = tas58xx_write_reg(REG_DEVICE_CTRL1, ctrl1);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "@0x%02X failed to enable PBTL: %s", dev->addr,
             esp_err_to_name(err));
    return err;
  }
  ESP_LOGI(TAG, "@0x%02X PBTL mono mode enabled (DEVICE_CTRL1=0x%02X)",
           dev->addr, ctrl1);
  return ESP_OK;
}

/*
 * A tuned PPC3 dump is a complete device configuration — clocking, I2S format,
 * the process flow select and every coefficient — so it stands in for the
 * built-in init sequence rather than running alongside it. That is what makes
 * it the full configuration option: a flow whose coefficient map TI never
 * published is still reachable, because the dump replays TI's own writes.
 *
 * Stream format matches the TAS57xx loader: [reg, len, data[0..len-1]]
 * repeated, terminated by 0xFF 0xFF. [0xFE, 1, ms] pauses. Register addresses
 * are 7-bit, so neither opcode can collide with a real write.
 */
#define HF_OP_DELAY 0xFE
#define HF_OP_END   0xFF

/* Input-mixer gain matrix: four 9.23 words in Book 0x8C, on a different page
 * per part (SLAA786A Table 9 vs SLOA263A Table 5). */
#define MIX_BOOK      0x8C
#define MIX_PAGE_5825 0x0B
#define MIX_BASE_5825 0x14
#define MIX_PAGE_5805 0x29
#define MIX_BASE_5805 0x18
#define MIX_BYTES     16

static esp_err_t tas58xx_write_hf(tas58xx_dev_t *dev, const uint8_t *stream,
                                  size_t size) {
  size_t pos = 0;
  int writes = 0;

  while (pos + 1 < size) {
    const uint8_t reg = stream[pos];
    const uint8_t len = stream[pos + 1];

    if (reg == HF_OP_END && len == HF_OP_END) {
      ESP_LOGI(TAG, "@0x%02X PPC3 dump applied (%d writes)", dev->addr, writes);
      return ESP_OK;
    }
    if (pos + 2 + (size_t)len > size) {
      ESP_LOGE(TAG, "@0x%02X PPC3 dump truncated at offset %u", dev->addr,
               (unsigned)pos);
      return ESP_ERR_INVALID_SIZE;
    }
    if (reg == HF_OP_DELAY) {
      vTaskDelay(pdMS_TO_TICKS(len ? stream[pos + 2] : 1));
      pos += 2 + (size_t)len;
      continue;
    }

    const esp_err_t err =
        board_i2c_write(dev->handle, reg, &stream[pos + 2], len);
    if (err != ESP_OK) {
      ESP_LOGE(TAG,
               "@0x%02X PPC3 dump write failed at offset %u (reg 0x%02X): %s",
               dev->addr, (unsigned)pos, reg, esp_err_to_name(err));
      return err;
    }
    writes++;
    pos += 2 + (size_t)len;
  }

  ESP_LOGE(TAG, "@0x%02X PPC3 dump has no terminator", dev->addr);
  return ESP_ERR_INVALID_SIZE;
}

/* Defined further down, beside the coefficient state it reads. */
static uint32_t tas58xx_flow_sample_rate(void);

/*
 * Build search candidate `c` for device `i`, most specific first. Returns
 * false when the slot does not apply, so the caller just skips it.
 */
static bool tas58xx_hf_candidate(char *out, size_t len, int c, int i,
                                 bool multi, uint32_t fs) {
  switch (c) {
  case 0:
    if (!multi) {
      return false;
    }
    snprintf(out, len, "/spiffs/hf/tas5825m_fw%d-%" PRIu32 ".bin", i, fs);
    return true;
  case 1:
    /* The unindexed names only ever stand in for the first device. */
    if (multi && i != 0) {
      return false;
    }
    snprintf(out, len, "/spiffs/hf/tas5825m_fw-%" PRIu32 ".bin", fs);
    return true;
  case 2:
    if (!multi) {
      return false;
    }
    snprintf(out, len, "/spiffs/hf/tas5825m_fw%d.bin", i);
    return true;
  default:
    if (multi && i != 0) {
      return false;
    }
    snprintf(out, len, "/spiffs/hf/tas5825m_fw.bin");
    return true;
  }
}

/*
 * Read the dump's own input-mixer gains back out of it. The routing a tuning
 * exports is part of that tuning, but the per-output trim has to be folded
 * into the same four coefficients — so the trim can only ever be applied on
 * top of these, never instead of them.
 */
static void tas58xx_seed_mix_from_hf(tas58xx_dev_t *d) {
  d->hf_mix_seen = false;

  uint8_t raw[MIX_BYTES] = {0};
  uint16_t seen = 0;
  uint8_t book = 0, page = 0;
  size_t pos = 0;

  while (pos + 1 < d->hf_size) {
    const uint8_t reg = d->hf_buf[pos];
    const uint8_t len = d->hf_buf[pos + 1];

    if (reg == HF_OP_END && len == HF_OP_END) {
      break;
    }
    if (pos + 2 + (size_t)len > d->hf_size) {
      break;
    }
    if (reg == HF_OP_DELAY) {
      pos += 2 + (size_t)len;
      continue;
    }

    /* Block writes auto-increment, and a page select part way through one
     * moves the rest of it, so the stream has to be followed byte by byte. */
    for (uint8_t k = 0; k < len; k++) {
      const uint8_t a = (uint8_t)(reg + k);
      const uint8_t v = d->hf_buf[pos + 2 + k];

      if (a == REG_PAGE_SEL) {
        page = v;
        continue;
      }
      /* 0x7F selects the book only while page 0 is current; on a coefficient
       * page it is the last data byte of the last section. */
      if (a == REG_BOOK_SEL && page == 0) {
        book = v;
        continue;
      }
      if (book != MIX_BOOK || page != MIX_PAGE_5825) {
        continue;
      }
      if (a >= MIX_BASE_5825 && a < MIX_BASE_5825 + MIX_BYTES) {
        const uint8_t off = (uint8_t)(a - MIX_BASE_5825);
        raw[off] = v;
        seen |= (uint16_t)(1u << off);
      }
    }
    pos += 2 + (size_t)len;
  }

  /* A dump that writes only part of the matrix leaves the rest holding
   * whatever the flow defaulted to, which nothing here can know. */
  if (seen != 0xFFFF) {
    ESP_LOGD(TAG, "@0x%02X dump leaves the input mixer at its flow default",
             d->addr);
    return;
  }
  for (int m = 0; m < 4; m++) {
    d->hf_mix[m] =
        (int32_t)(((uint32_t)raw[m * 4] << 24) |
                  ((uint32_t)raw[m * 4 + 1] << 16) |
                  ((uint32_t)raw[m * 4 + 2] << 8) | (uint32_t)raw[m * 4 + 3]);
  }
  d->hf_mix_seen = true;
  ESP_LOGI(TAG, "@0x%02X dump carries its own input-mixer routing", d->addr);
}

/*
 * Load a tuned PPC3 dump for device index i, newest-to-oldest naming:
 *   /spiffs/hf/tas5825m_fw<i>-<rate>.bin   (multi-device, rate-specific)
 *   /spiffs/hf/tas5825m_fw-<rate>.bin      (single device, rate-specific)
 *   /spiffs/hf/tas5825m_fw<i>.bin          (multi-device, any rate)
 *   /spiffs/hf/tas5825m_fw.bin             (single device, any rate)
 * The first device falls back to the unindexed names.
 * Absent is the normal case: the chip then runs the built-in init sequence.
 */
static void tas58xx_load_hf(int i, bool multi) {
  tas58xx_dev_t *d = &s_devs[i];
  char path[48];
  /* Re-init without a deinit would otherwise strand the previous dump. */
  free(d->hf_buf);
  d->hf_buf = NULL;
  d->hf_size = 0;
  d->hf_mix_seen = false;

  /* A dump replays a process flow, which is a TAS5825M feature: the TAS5805M
   * has no flow-select register and lays its coefficients out differently. */
  if (d->model != TAS58XX_MODEL_TAS5825M) {
    return;
  }

  /*
   * Rate-specific dumps win. PPC3 bakes every coefficient at the rate the
   * flow was exported for, so a 48 kHz tuning played at 44.1 kHz puts every
   * corner ~8% low. The unsuffixed names remain as the fallback so existing
   * single-rate installs keep working untouched.
   */
  const uint32_t fs = tas58xx_flow_sample_rate();
  FILE *f = NULL;

  for (int c = 0; c < 4 && f == NULL; c++) {
    if (!tas58xx_hf_candidate(path, sizeof(path), c, i, multi, fs)) {
      continue;
    }
    f = fopen(path, "rb");
  }
  if (!f) {
    ESP_LOGI(TAG,
             "No TAS5825M PPC3 dump for @0x%02X at %" PRIu32
             " Hz — runs the built-in flow",
             d->addr, fs);
    return;
  }

  fseek(f, 0, SEEK_END);
  const long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  /* tas58xx_write_hf() reads a two-byte header before any payload. */
  if (size < 2) {
    ESP_LOGE(TAG, "PPC3 dump %s is empty or unreadable", path);
    fclose(f);
    return;
  }

  uint8_t *buf = malloc((size_t)size);
  if (!buf || fread(buf, 1, (size_t)size, f) != (size_t)size) {
    ESP_LOGE(TAG, "Failed to read PPC3 dump %s", path);
    free(buf);
    fclose(f);
    return;
  }
  fclose(f);

  d->hf_buf = buf;
  d->hf_size = (size_t)size;
  snprintf(d->hf_path, sizeof(d->hf_path), "%s", path);
  tas58xx_seed_mix_from_hf(d);
  ESP_LOGI(TAG, "Loaded PPC3 dump %s (%ld bytes) for @0x%02X", path, size,
           d->addr);
}

/*
 * A PPC3 dump is a whole-device configuration, so it also carries the EVM's
 * host and pinout settings. Put back the two that describe this board rather
 * than the tuning. Assumes the dump left the device on book 0, page 0.
 */
static esp_err_t tas58xx_fixup_after_hf(tas58xx_dev_t *dev) {
  /*
   * PPC3 exports from an EVM that feeds 24-bit data and so leaves SAP_CTRL1 at
   * its 24-bit reset default, while this firmware always sends 16-bit I2S —
   * the part would keep clocking in eight bits that were never sent.
   */
  esp_err_t err = tas58xx_write_reg(REG_SAP_CTRL1, 0x00);
  if (err != ESP_OK) {
    return err;
  }

  /*
   * The EVM brings GPIO1 out as SDOUT; on these boards it is the amp's fault
   * line into the MCU, which otherwise reads the data stream as a fault stuck
   * on and mutes. Only the TAS5825M has these pins.
   */
  if (dev->model == TAS58XX_MODEL_TAS5825M) {
    tas58xx_write_reg(REG_GPIO0, REG_GPIO_WARN);
    tas58xx_write_reg(REG_GPIO1, REG_GPIO_FAULT);
    tas58xx_write_reg(REG_GPIO2, REG_GPIO_SDOUT);
    err = tas58xx_write_reg(REG_GPIO_CTL, REG_GPIO_CTL_OUT);
  }
  return err;
}

/*
 * Initialize a single TAS58xx chip: add it to the I2C bus, verify its die
 * ID, run the model-specific register init sequence, and (for the sub)
 * enable PBTL mono output. Assumes REG_LOCK is held; sets s_cur to dev.
 */
static esp_err_t tas58xx_init_one(tas58xx_dev_t *dev) {
  esp_err_t err;

  s_cur = dev;

  err = board_i2c_add_device(s_bus_handle, dev->addr, I2C_LINE_SPEED,
                             &dev->handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Could not add @0x%02X to I2C bus: %s", dev->addr,
             esp_err_to_name(err));
    return err;
  }

  // Verify die ID
  uint8_t die_id = 0;
  err = tas58xx_read_reg(REG_DIE_ID, &die_id);
  if (err == ESP_OK) {
    const tas58xx_model_t die_model =
        (die_id == TAS5825M_DIE_ID)   ? TAS58XX_MODEL_TAS5825M
        : (die_id == TAS5805M_DIE_ID) ? TAS58XX_MODEL_TAS5805M
                                      : TAS58XX_MODEL_UNKNOWN;
    ESP_LOGI(TAG, "@0x%02X Die ID: 0x%02X %s", dev->addr, die_id,
             (die_model == TAS58XX_MODEL_TAS5825M)   ? "(TAS5825M)"
             : (die_model == TAS58XX_MODEL_TAS5805M) ? "(TAS5805M)"
                                                     : "(UNEXPECTED!)");
    /*
     * The model in use came from the I2C address, which is a different range
     * per part. A disagreement means the wrong init sequence and coefficient
     * map are about to be used, so say so loudly — but 0x00 is also what an
     * unimplemented register reads, so it is not trustworthy enough to
     * silently switch the driver over.
     */
    if (die_model != TAS58XX_MODEL_UNKNOWN && die_model != dev->model) {
      ESP_LOGW(TAG, "@0x%02X address says %s but the die reads 0x%02X (%s)",
               dev->addr,
               dev->model == TAS58XX_MODEL_TAS5825M ? "TAS5825M" : "TAS5805M",
               die_id,
               die_model == TAS58XX_MODEL_TAS5825M ? "TAS5825M" : "TAS5805M");
    }
  } else {
    ESP_LOGE(TAG, "@0x%02X Failed to read die ID: %s", dev->addr,
             esp_err_to_name(err));
  }

  // A tuned dump owns the whole configuration, so it stands in for the
  // built-in sequence rather than running after it.
  if (dev->hf_buf) {
    ESP_LOGI(TAG, "@0x%02X applying PPC3 dump %s (%s)...", dev->addr,
             dev->hf_path, dev->pbtl_mono ? "PBTL mono" : "BTL stereo");
    err = tas58xx_write_hf(dev, dev->hf_buf, dev->hf_size);
    if (err != ESP_OK) {
      return err;
    }
    err = tas58xx_fixup_after_hf(dev);
    if (err != ESP_OK) {
      return err;
    }
    // The dump brought its own coefficients; ours would overwrite the tuning.
    dev->dsp_defaults_written = true;
  } else {
    err = tas58xx_run_init_seq(dev);
    if (err != ESP_OK) {
      return err;
    }
  }

  /*
   * Configure the PBTL (mono) output stage while still in HiZ. The channel
   * routing is a DSP-coefficient change applied once the device reaches
   * PLAY (see tas58xx_apply_input_mix()).
   */
  err = tas58xx_apply_pbtl(dev);
  if (err != ESP_OK) {
    return err;
  }

  // Give the device time to settle
  vTaskDelay(pdMS_TO_TICKS(10));

  tas58xx_dump_status("post-init");

  ESP_LOGI(TAG, "%s @0x%02X initialized",
           dev->model == TAS58XX_MODEL_TAS5805M ? "TAS5805M" : "TAS5825M",
           dev->addr);
  return ESP_OK;
}

/* Run the built-in register init sequence for dev's model. */
static esp_err_t tas58xx_run_init_seq(tas58xx_dev_t *dev) {
  esp_err_t err;
  const struct tas58xx_cmd_s *seq = (dev->model == TAS58XX_MODEL_TAS5825M)
                                        ? tas5825m_init_seq
                                        : tas5805m_init_seq;

  ESP_LOGI(TAG, "@0x%02X running init sequence (%s)...", dev->addr,
           dev->pbtl_mono ? "PBTL mono" : "BTL stereo");
  for (int i = 0; seq[i].reg != 0xFF; i++) {
    err = tas58xx_write_reg(seq[i].reg, seq[i].value);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Init failed at step %d: reg 0x%02X val 0x%02X: %s", i,
               seq[i].reg, seq[i].value, esp_err_to_name(err));
      return err;
    }
    ESP_LOGD(TAG, "  [%02d] reg 0x%02X <- 0x%02X", i, seq[i].reg, seq[i].value);

    // Pause after HiZ transition to let clocks settle
    if (seq[i].reg == REG_DEVICE_CTRL2 &&
        (seq[i].value & CTRL2_STATE_MASK) == CTRL2_HIZ) {
      ESP_LOGD(TAG, "  Waiting 10 ms for HiZ clock settle");
      vTaskDelay(pdMS_TO_TICKS(10));
    }
    // Pause after DSP configuration before going to PLAY
    if (seq[i].reg == REG_DSP_CTRL) {
      ESP_LOGD(TAG, "  Waiting 5 ms for DSP settle");
      vTaskDelay(pdMS_TO_TICKS(5));
    }
  }

  return ESP_OK;
}

static esp_err_t tas58xx_init(void *i2c_bus) {
  esp_err_t err;

  ESP_LOGI(TAG, "Initializing TAS58XX");

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

  /* SPIFFS is mounted before board init, so any stored biquad chains are
   * available in time for the first PLAY transition to program them. */
  if (!bq_load_config()) {
    bq_chain_defaults();
  }

  // Detect all chips on the bus (up to TAS58XX_MAX_DEVICES)
  s_dev_count = tas58xx_detect(s_bus_handle);
  if (s_dev_count == 0) {
    ESP_LOGE(TAG, "No TAS5825M/TAS5805M detected on I2C bus!");
    return ESP_ERR_NOT_FOUND;
  }

  /*
   * Role assignment. A single chip always drives stereo satellites. On a
   * dual-DAC board the second chip is either a bridged (PBTL) mono amplifier
   * fed L+R, or a second stereo pair. Any crossover between the two is a
   * matter for the biquad chains, not for the wiring.
   */
  if (s_dev_count > 1) {
    s_active_second_pbtl = s_second_pbtl;
    if (s_second_pbtl) {
      s_devs[1].pbtl_mono = true;
    }
    ESP_LOGI(TAG, "Detected %d TAS58xx device(s) - second is %s", s_dev_count,
             s_second_pbtl ? "PBTL mono" : "stereo");
  } else {
    ESP_LOGI(TAG, "Detected %d TAS58xx device(s) - stereo", s_dev_count);
  }

  /* A bridged amplifier drives one output, so summing L+R into it is the only
   * sensible default; everything else passes the pair straight through. A
   * stereo routing stored before the amplifier was bridged is meaningless now,
   * so it falls back to the sum as well. */
  for (int i = 0; i < s_dev_count; i++) {
    s_devs[i].mix = s_dev_mix_cfg[i]      ? s_dev_mix[i]
                    : s_devs[i].pbtl_mono ? TAS58XX_MIX_MONO
                                          : TAS58XX_MIX_STEREO;
    if (s_devs[i].pbtl_mono && s_devs[i].mix == TAS58XX_MIX_STEREO) {
      s_devs[i].mix = TAS58XX_MIX_MONO;
    }
    s_dev_mix[i] = s_devs[i].mix;
  }

  /* Read the dumps before taking the register lock — SPIFFS is slow and
   * nothing here touches the bus. */
  for (int i = 0; i < s_dev_count; i++) {
    tas58xx_load_hf(i, s_dev_count > 1);
  }

  /*
   * A stored chain only speaks for the sections the user actually placed, so
   * where it is empty the resident dump's own tuning is what the part will be
   * running and what the EQ page has to show. A chain saved before its dump
   * was ever read back is in the same position for every section: it cannot
   * describe a tuning it never saw, and programming it would flatten all
   * thirty. Either way the dump is the better answer.
   */
  for (int i = 0; i < s_dev_count; i++) {
    if (bq_chain_is_flat(i)) {
      tas58xx_seed_bq_from_hf(i);
    } else if (!bq_chain_is_from_dump(i) && s_devs[i].hf_buf) {
      ESP_LOGW(TAG,
               "@0x%02X stored chain predates %s — using the dump's tuning "
               "instead (the stored one is kept until the EQ page saves)",
               s_devs[i].addr, s_devs[i].hf_path);
      tas58xx_seed_bq_from_hf(i);
    }
  }

  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    err = tas58xx_init_one(&s_devs[i]);
    if (err != ESP_OK) {
      REG_UNLOCK();
      return err;
    }
  }
  REG_UNLOCK();

#if CONFIG_SPKFAULT_GPIO < 0
  s_fault_task_stop = false;
  if (s_fault_task == NULL &&
      xTaskCreate(tas58xx_fault_task, "tas58xx_fault", 3072, NULL, 2,
                  &s_fault_task) != pdPASS) {
    ESP_LOGW(TAG, "Failed to start the fault monitor task");
    s_fault_task = NULL;
  }
#endif

  return ESP_OK;
}

static esp_err_t tas58xx_deinit(void) {
  esp_err_t err = ESP_OK;

#if CONFIG_SPKFAULT_GPIO < 0
  s_fault_task_stop = true;
#endif

  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    tas58xx_dev_t *dev = &s_devs[i];
    free(dev->hf_buf);
    dev->hf_buf = NULL;
    dev->hf_size = 0;
    if (!dev->handle) {
      continue;
    }
    s_cur = dev;
    // Put device into deep sleep
    tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_DEEP_SLEEP);

    esp_err_t e = board_i2c_remove_device(dev->handle);
    if (e != ESP_OK) {
      ESP_LOGE(TAG, "Failed to remove @0x%02X from I2C bus: %s", dev->addr,
               esp_err_to_name(e));
      err = e;
    }
    dev->handle = NULL;
  }
  s_cur = NULL;
  s_dev_count = 0;
  REG_UNLOCK();

  s_bus_handle = NULL;
  return err;
}

/* Apply a power mode to a single chip. Assumes REG_LOCK is held. */
static uint8_t tas58xx_dig_vol_reg(const tas58xx_dev_t *dev);

static void set_power_mode_dev(tas58xx_dev_t *dev, dac_power_mode_t mode) {
  s_cur = dev;
  uint8_t cur_ctrl2 = 0;
  tas58xx_read_reg(REG_DEVICE_CTRL2, &cur_ctrl2);
  uint8_t cur_state = cur_ctrl2 & CTRL2_STATE_MASK;

  if (mode == DAC_POWER_ON) {
    // Always go through HIZ first (per datasheet §9.5.3.1)
    // The PLL needs valid I2S clocks to lock — they must be present
    // by the time this function is called.
    if (cur_state != CTRL2_HIZ) {
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
      if (dev->hf_buf) {
        /*
         * A dump is the whole configuration — process flow, routing, DRC and
         * every coefficient — so replaying it is the only way to get any of
         * that back. Writing the stock registers below instead would leave
         * the amp on the built-in flow with the tuning gone, and disconnect
         * puts it to sleep after every session.
         */
        ESP_LOGI(TAG, "@0x%02X woke from DEEP_SLEEP — replaying %s", dev->addr,
                 dev->hf_path);
        if (tas58xx_write_hf(dev, dev->hf_buf, dev->hf_size) == ESP_OK) {
          tas58xx_fixup_after_hf(dev);
          /* The dump brought its own coefficients; ours would overwrite the
           * tuning. */
          dev->dsp_defaults_written = true;
        } else {
          dev->dsp_defaults_written = false;
        }
      } else {
        ESP_LOGI(TAG, "Woke from DEEP_SLEEP — re-programming DSP registers");
        tas58xx_write_reg(REG_SAP_CTRL1, 0x00); /* I2S, 16-bit */
        tas58xx_write_reg(REG_CLOCK_DET_CTRL, 0x00);
        tas58xx_write_reg(REG_DSP_PGM_MODE, 0x01); /* PF1 (Base/Pro, 96kHz) */
        tas58xx_write_reg(REG_DSP_CTRL, 0x01);     /* USE_DEFAULT_COEFFS */
        vTaskDelay(pdMS_TO_TICKS(5));
        tas58xx_write_reg(REG_DIG_VOL_CTRL1, 0x33);
        tas58xx_write_reg(REG_AUTO_MUTE_CTRL, 0x07);
        tas58xx_write_reg(REG_AUTO_MUTE_TIME, 0x00);
        tas58xx_write_reg(REG_AGAIN, 0x00);

        /* Coefficient RAM may be invalid after DEEP_SLEEP — force
         * full re-write of signal-path defaults on next EQ update. */
        dev->dsp_defaults_written = false;
      }
    }

    /* DEVICE_CTRL1 is reset by DEEP_SLEEP and the device is in HiZ here, so
     * re-bridge the outputs before the output stage is allowed to drive. */
    tas58xx_apply_pbtl(dev);

    /* DEEP_SLEEP also resets DIG_VOL to 0 dB, which would be a full-scale
     * blast on the first frame after PLAY. */
    tas58xx_write_reg(REG_DIG_VOL, tas58xx_dig_vol_reg(dev));

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

    /*
     * Re-apply the input mixer once the DSP is running (coefficient RAM
     * writes require active I2S clocks). The per-output trim shares those
     * four coefficients with the routing, so this has to run on a dump board
     * too — tas58xx_apply_input_mix() starts from the dump's own routing
     * there rather than ours. The biquads are the same story: the chain was
     * read back from the dump at load, so pushing it here restores that
     * tuning — or the user's edit of it.
     */
    tas58xx_apply_input_mix();
    bq_program_chain();

    tas58xx_dump_status("power-on");
  } else if (mode == DAC_POWER_STANDBY) {
    tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_HIZ);
  } else {
    tas58xx_write_reg(REG_DEVICE_CTRL2, CTRL2_DEEP_SLEEP);
    /* DEEP_SLEEP may reset registers and coefficient RAM — ensure
     * full re-initialization happens on the next wake-up. */
    dev->dsp_defaults_written = false;
  }
}

/* Fan a power-mode change out to every managed chip. */
static void tas58xx_set_power_mode(dac_power_mode_t mode) {
  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    set_power_mode_dev(&s_devs[i], mode);
  }
  s_cur = NULL;
  REG_UNLOCK();
}

/* Enable/disable (mute) output on a single chip. Assumes REG_LOCK held. */
static void enable_speaker_dev(tas58xx_dev_t *dev, bool enable) {
  s_cur = dev;

  // Use mute bit in DEVICE_CTRL2 to enable/disable output.
  // Read current register, modify mute bit, write back.
  uint8_t val;
  esp_err_t err = tas58xx_read_reg(REG_DEVICE_CTRL2, &val);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "@0x%02X failed to read DEVICE_CTRL2", dev->addr);
    return;
  }

  ESP_LOGI(TAG, "@0x%02X speaker %s (DEVICE_CTRL2 was 0x%02X)", dev->addr,
           enable ? "ENABLE" : "DISABLE", val);

  if (enable) {
    val &= ~CTRL2_MUTE; // Clear mute bit
  } else {
    val |= CTRL2_MUTE; // Set mute bit
  }

  tas58xx_write_reg(REG_DEVICE_CTRL2, val);
}

static void tas58xx_enable_speaker(bool enable) {
  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    enable_speaker_dev(&s_devs[i], enable);
  }
  s_cur = NULL;
  REG_UNLOCK();
}

static void tas58xx_enable_line_out(bool enable) {
  (void)enable;
  ESP_LOGW(TAG, "Line out not supported on TAS58XX");
}

// Map an AirPlay volume (-30..0 dB) to a TAS5825M DIG_VOL dB level
// (+24..-103 dB), applying the 2:1 scaling and low-end roll-off.
static float tas58xx_map_volume_db(float volume_airplay_db) {
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }

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
  return db_level;
}

// Convert a TAS5825M DIG_VOL dB level to a register value.
//   0x00 = +24.0 dB, 0x30 = 0.0 dB, 0xFE = -103.0 dB, 0xFF = mute
//   Step = -0.5 dB per count.
static uint8_t tas58xx_db_to_reg(float db_level) {
  if (db_level > 24.0f) {
    db_level = 24.0f;
  }
  if (db_level <= -103.0f) {
    return DIG_VOL_MUTE;
  }
  int raw = DIG_VOL_0DB - (int)(db_level * 2.0f);
  if (raw < 0x00) {
    raw = 0x00;
  }
  if (raw > 0xFE) {
    raw = 0xFE;
  }
  return (uint8_t)raw;
}

// DIG_VOL value this chip should hold at the current master volume.
static uint8_t tas58xx_dig_vol_reg(const tas58xx_dev_t *dev) {
  (void)dev;
  return tas58xx_db_to_reg(tas58xx_map_volume_db(s_last_airplay_db));
}

// Re-apply the cached master volume to every chip. Per-output level lives in
// the input mixer, not here. Assumes REG_LOCK is held.
static void tas58xx_apply_volume_locked(void) {
  ESP_LOGD(TAG, "Volume: AirPlay %.1f dB", s_last_airplay_db);

  for (int i = 0; i < s_dev_count; i++) {
    s_cur = &s_devs[i];
    tas58xx_write_reg(REG_DIG_VOL, tas58xx_dig_vol_reg(&s_devs[i]));
  }
  s_cur = NULL;
}

static void tas58xx_set_volume(float volume_airplay_db) {
  REG_LOCK();
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }
  s_last_airplay_db = volume_airplay_db;
  tas58xx_apply_volume_locked();
  REG_UNLOCK();
}

/* Re-push one chip's mixer so a level or mute change lands immediately.
 * Only takes effect while the chip is in PLAY, which is why the PLAY
 * transition re-applies the mixer unconditionally. */
static esp_err_t tas58xx_refresh_mix(int dev) {
  if (s_reg_mutex == NULL || dev >= s_dev_count) {
    return ESP_OK;
  }
  REG_LOCK();
  s_cur = &s_devs[dev];
  esp_err_t err = tas58xx_apply_input_mix();
  s_cur = NULL;
  REG_UNLOCK();
  return err;
}

esp_err_t dac_tas58xx_set_gain_db(int dev, int ch, float gain_db) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || ch < 0 ||
      ch >= TAS58XX_BQ_CHANNELS) {
    return ESP_ERR_INVALID_ARG;
  }
  if (gain_db > TAS58XX_GAIN_MAX_DB) {
    gain_db = TAS58XX_GAIN_MAX_DB;
  }
  if (gain_db < TAS58XX_GAIN_MIN_DB) {
    gain_db = TAS58XX_GAIN_MIN_DB;
  }
  s_ch_gain_db[dev][ch] = gain_db;
  ESP_LOGI(TAG, "Amp %d output %c level: %+.1f dB", dev, 'A' + ch, gain_db);
  return tas58xx_refresh_mix(dev);
}

float dac_tas58xx_get_gain_db(int dev, int ch) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || ch < 0 ||
      ch >= TAS58XX_BQ_CHANNELS) {
    return 0.0f;
  }
  return s_ch_gain_db[dev][ch];
}

esp_err_t dac_tas58xx_set_ch_mute(int dev, int ch, bool mute) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || ch < 0 ||
      ch >= TAS58XX_BQ_CHANNELS) {
    return ESP_ERR_INVALID_ARG;
  }
  s_ch_mute[dev][ch] = mute;
  ESP_LOGI(TAG, "Amp %d output %c %s", dev, 'A' + ch,
           mute ? "muted" : "unmuted");
  return tas58xx_refresh_mix(dev);
}

bool dac_tas58xx_get_ch_mute(int dev, int ch) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || ch < 0 ||
      ch >= TAS58XX_BQ_CHANNELS) {
    return false;
  }
  return s_ch_mute[dev][ch];
}

int dac_tas58xx_get_device_count(void) {
  return s_dev_count;
}

bool dac_tas58xx_get_second_pbtl(void) {
  return s_second_pbtl;
}

bool dac_tas58xx_get_active_second_pbtl(void) {
  return s_active_second_pbtl;
}

void dac_tas58xx_set_second_pbtl(bool pbtl) {
  s_second_pbtl = pbtl;
  ESP_LOGI(TAG, "Second amplifier: %s (applied at next init)",
           pbtl ? "PBTL mono" : "stereo");
}

bool dac_tas58xx_is_pbtl(int dev) {
  if (dev < 0 || dev >= s_dev_count) {
    return false;
  }
  return s_devs[dev].pbtl_mono;
}

esp_err_t dac_tas58xx_set_mix(int dev, tas58xx_mix_t mix) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || mix < 0 ||
      mix >= TAS58XX_MIX_COUNT) {
    return ESP_ERR_INVALID_ARG;
  }

  s_dev_mix[dev] = mix;
  s_dev_mix_cfg[dev] = true;

  /* Before init there is no chip to write to; tas58xx_init() picks the value
   * up when it assigns roles. */
  if (s_reg_mutex == NULL || dev >= s_dev_count) {
    return ESP_OK;
  }

  REG_LOCK();
  s_devs[dev].mix = mix;
  s_cur = &s_devs[dev];
  /* Only lands if the chip is in PLAY, which is why the PLAY transition
   * re-applies it unconditionally. */
  esp_err_t err = tas58xx_apply_input_mix();
  s_cur = NULL;
  REG_UNLOCK();

  ESP_LOGI(TAG, "Amp %d input routing: %d", dev, (int)mix);
  return err;
}

tas58xx_mix_t dac_tas58xx_get_mix(int dev) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES) {
    return TAS58XX_MIX_STEREO;
  }
  return dev < s_dev_count ? s_devs[dev].mix : s_dev_mix[dev];
}

/* ---------- Public ops struct ---------- */

static void tas58xx_on_i2s_started(uint32_t sample_rate_hz);

const dac_ops_t dac_tas58xx_ops = {
    .init = tas58xx_init,
    .deinit = tas58xx_deinit,
    .set_volume = tas58xx_set_volume,
    .set_power_mode = tas58xx_set_power_mode,
    .enable_speaker = tas58xx_enable_speaker,
    .enable_line_out = tas58xx_enable_line_out,
    .on_i2s_started = tas58xx_on_i2s_started,
};

/* ---------- Register read/write helpers ---------- */

static esp_err_t tas58xx_write_reg(uint8_t reg, uint8_t value) {
  return board_i2c_write(s_cur->handle, reg, &value, sizeof(uint8_t));
}

static esp_err_t tas58xx_read_reg(uint8_t reg, uint8_t *value) {
  return board_i2c_read(s_cur->handle, reg, value, sizeof(uint8_t));
}

/* ==================  Cascaded biquad EQ  ================== */

#include "dac_tas58xx_eq_addr.h"

#define BQ_COEFF_BOOK 0xAA /* TAS5825M coefficient book */
#define BQ_COEFF_SIZE 20   /* bytes per biquad (5 × 4) */

/*
 * Rate every runtime filter design is evaluated against. Boards differ:
 * esparagus-louder and the dual-DAC brick clock the part at 44.1 kHz while
 * the rest run 48 kHz, and a corner designed at the wrong rate lands 8.8%
 * out. dac_on_i2s_started() replaces this with the rate actually in use.
 */
#ifdef CONFIG_OUTPUT_SAMPLE_RATE_HZ
static double s_bq_fs = (double)CONFIG_OUTPUT_SAMPLE_RATE_HZ;
#else
static double s_bq_fs = 48000.0;
#endif

static uint32_t tas58xx_flow_sample_rate(void) {
  return (uint32_t)s_bq_fs;
}

/*
 * The user's biquad chain, per amplifier and per channel. This is the single
 * source of truth for the filtering: the hardware's coefficient RAM is only
 * ever written from here, so crossovers, shelves and room correction are all
 * just sections the user has placed in the chain.
 */
static tas58xx_bq_t s_bq[TAS58XX_MAX_DEVICES][TAS58XX_BQ_CHANNELS]
                        [TAS58XX_BQ_SLOTS];
static bool s_bq_ganged[TAS58XX_MAX_DEVICES];
static bool s_bq_ready;
/* Chain was read back from a PPC3 dump and not replaced since, so swapping
 * that dump for another rate's export may re-read it. */
static bool s_bq_from_hf[TAS58XX_MAX_DEVICES];
/* Chain descends from the resident dump — seeded from it, and possibly edited
 * since. Survives edits and is stored, because only such a chain can speak for
 * the sections the dump tuned; one authored before the dump was ever read back
 * knows nothing of them and must not be allowed to flatten them. */
static bool s_bq_seeded[TAS58XX_MAX_DEVICES];

/* Book / Page / Register for EQ mode control */
#define EQ_MODE_BOOK 0x8C
#define EQ_MODE_PAGE 0x0B
#define EQ_MODE_REG  0x28
#define EQ_MODE_SIZE 8 /* 4 bytes gang_eq + 4 bytes bypass_eq */

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

  return board_i2c_write(s_cur->handle, reg_start, buf, BQ_COEFF_SIZE);
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

  return board_i2c_write(s_cur->handle, sub_addr, data, EQ_COEFF_BYTES);
}

static esp_err_t write_dsp_coeff32(uint8_t page, uint8_t reg, int32_t val) {
  esp_err_t err = tas58xx_write_reg(REG_PAGE_SEL, page);
  if (err != ESP_OK) {
    return err;
  }
  uint8_t buf[4] = {(uint8_t)(val >> 24), (uint8_t)(val >> 16),
                    (uint8_t)(val >> 8), (uint8_t)(val)};
  return board_i2c_write(s_cur->handle, reg, buf, 4);
}

/**
 * Write default coefficient values for all DSP signal-path blocks in
 * Book 0x8C
 */
static esp_err_t write_dsp_signal_path_defaults(void) {
  esp_err_t err = ESP_OK;

  switch (s_cur->model) {
  case TAS58XX_MODEL_TAS5805M: {
    ESP_LOGD(TAG, "DSP: writing signal-path defaults (Books 0x8C + 0xAA)");

    /*
     * ── Book 0xAA: ALL biquad coefficient RAM ──
     *
     * We must initialize EVERY BQ slot in Book 0xAA:
     *   - 30 EQ BQs (15 L + 15 R) — from tas58xx_eq_left_addr /
     * tas58xx_eq_right_addr
     */
    err = select_book_page(0xAA, 0x00);
    if (err != ESP_OK) {
      select_default_page();
      return err;
    }

    /* Unity BQ: B0=1.0 (5.27), B1=B2=A1=A2=0 */
    static const int32_t unity_bq[5] = {FP_ONE, 0, 0, 0, 0};

    /*
     * ── EQ BQs (30 total, Pages 0x01-0x06) ──
     */
    for (int bq = 0; bq < TAS58XX_BQ_SLOTS; bq++) {
      write_biquad_coeff(tas5805m_eq_left_addr[bq].page,
                         tas5805m_eq_left_addr[bq].sub_addr, unity_bq);
      write_biquad_coeff(tas5805m_eq_right_addr[bq].page,
                         tas5805m_eq_right_addr[bq].sub_addr, unity_bq);
    }

    err = select_default_page();

    s_cur->dsp_defaults_written = true;
    ESP_LOGD(TAG, "DSP: signal-path defaults written (Book 0x8C + 0xAA)");
  } break;

  case TAS58XX_MODEL_TAS5825M: {
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
    write_dsp_coeff32(0x06, 0x7C, (int32_t)0xE7000000); /* T1_1 threshold */
    write_dsp_coeff32(0x07, 0x08, (int32_t)0xFE800000); /* T2_1 threshold */
    write_dsp_coeff32(0x07, 0x0C, 0x00000000);          /* off1_1 */
    write_dsp_coeff32(0x07, 0x10, 0x00000000);          /* off2_1 */
    /* DRC2 time constants */
    write_dsp_coeff32(0x07, 0x14, 0x7FFFFFFF); /* DRC2 Energy  */
    write_dsp_coeff32(0x07, 0x18, 0x7FFFFFFF); /* DRC2 Attack  */
    write_dsp_coeff32(0x07, 0x1C, 0x7FFFFFFF); /* DRC2 Decay   */
    /* DRC2 slopes and thresholds */
    write_dsp_coeff32(0x07, 0x20, 0x00000000);          /* k0_2 */
    write_dsp_coeff32(0x07, 0x24, 0x00000000);          /* k1_2 */
    write_dsp_coeff32(0x07, 0x28, 0x00000000);          /* k2_2 */
    write_dsp_coeff32(0x07, 0x2C, (int32_t)0xE7000000); /* t1_2 */
    write_dsp_coeff32(0x07, 0x30, (int32_t)0xFE800000); /* t2_2 */
    write_dsp_coeff32(0x07, 0x34, 0x00000000);          /* off1_2 */
    write_dsp_coeff32(0x07, 0x38, 0x00000000);          /* off2_2 */
    /* DRC3 time constants */
    write_dsp_coeff32(0x07, 0x3C, 0x7FFFFFFF); /* DRC3 Energy  */
    write_dsp_coeff32(0x07, 0x40, 0x7FFFFFFF); /* DRC3 Attack  */
    write_dsp_coeff32(0x07, 0x44, 0x7FFFFFFF); /* DRC3 Decay   */
    /* DRC3 slopes and thresholds */
    write_dsp_coeff32(0x07, 0x48, 0x00000000);          /* k0_3 */
    write_dsp_coeff32(0x07, 0x4C, 0x00000000);          /* k1_3 */
    write_dsp_coeff32(0x07, 0x50, 0x00000000);          /* k2_3 */
    write_dsp_coeff32(0x07, 0x54, (int32_t)0xE7000000); /* t1_3 */
    write_dsp_coeff32(0x07, 0x58, (int32_t)0xFE800000); /* t2_3 */
    write_dsp_coeff32(0x07, 0x5C, 0x00000000);          /* off1_3 */
    write_dsp_coeff32(0x07, 0x60, 0x00000000);          /* off2_3 */

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
     *   - 30 EQ BQs (15 L + 15 R) — from tas58xx_eq_left_addr /
     * tas58xx_eq_right_addr
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
    for (int bq = 0; bq < TAS58XX_BQ_SLOTS; bq++) {
      write_biquad_coeff(tas5825m_eq_left_addr[bq].page,
                         tas5825m_eq_left_addr[bq].sub_addr, unity_bq);
      write_biquad_coeff(tas5825m_eq_right_addr[bq].page,
                         tas5825m_eq_right_addr[bq].sub_addr, unity_bq);
    }

    err = select_default_page();

    s_cur->dsp_defaults_written = true;
    ESP_LOGD(TAG, "DSP: signal-path defaults written (Book 0x8C + 0xAA)");
  } break;

  default:
    ESP_LOGE(TAG, "Unknown TAS58XX model %d in write_dsp_signal_path_defaults",
             s_cur->model);
    return ESP_ERR_INVALID_STATE;
  }

  return err;
}

static esp_err_t ensure_custom_coeffs_mode(void) {
  // Only applicable to TAS5825M
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
    if (!s_cur->dsp_defaults_written) {
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
                 "DSP: unknown DSP_PGM_MODE=0x%02X — "
                 "BiQuad addresses assume PF1 (0x01)",
                 pgm);
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
 * Program one biquad using pre-computed 20-byte coefficient blocks from
 * dac_tas58xx_eq_data.h. Either channel may be NULL to leave it untouched.
 *
 * Enters Book 0xAA, writes CH-L then CH-R, returns to Book 0 / Page 0.
 * Assumes the caller holds REG_LOCK.
 */
static esp_err_t program_biquad_pair(int bq, const uint8_t *left_data,
                                     const uint8_t *right_data) {
  esp_err_t err;

  if (s_cur->model == TAS58XX_MODEL_TAS5825M) {
    /* Ensure DSP has all signal-path defaults before using custom coefficients
     */
    err = ensure_custom_coeffs_mode();
    if (err != ESP_OK) {
      return err;
    }
  }

  /* Enter coefficient book */
  err = select_book_page(BQ_COEFF_BOOK, 0x00);
  if (err != ESP_OK) {
    goto out;
  }

  const eq_bq_addr_t *eq_left_addr = (s_cur->model == TAS58XX_MODEL_TAS5805M)
                                         ? tas5805m_eq_left_addr
                                         : tas5825m_eq_left_addr;
  const eq_bq_addr_t *eq_right_addr = (s_cur->model == TAS58XX_MODEL_TAS5805M)
                                          ? tas5805m_eq_right_addr
                                          : tas5825m_eq_right_addr;

  /* Channel 1 (Left) */
  if (left_data) {
    err = write_biquad_raw(eq_left_addr[bq].page, eq_left_addr[bq].sub_addr,
                           left_data);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "EQ: CH1 BQ%d raw write failed: %s", bq,
               esp_err_to_name(err));
      goto out;
    }
  }

  /* Channel 2 (Right) */
  if (right_data) {
    err = write_biquad_raw(eq_right_addr[bq].page, eq_right_addr[bq].sub_addr,
                           right_data);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "EQ: CH2 BQ%d raw write failed: %s", bq,
               esp_err_to_name(err));
      goto out;
    }
  }

  ESP_LOGD(TAG,
           "EQ: BQ%d raw write OK (L page=0x%02X:0x%02X, R page=0x%02X:0x%02X)",
           bq, eq_left_addr[bq].page, eq_left_addr[bq].sub_addr,
           eq_right_addr[bq].page, eq_right_addr[bq].sub_addr);

out:
  select_default_page();
  return err;
}

/** Take the EQ block out of bypass so the programmed chain is audible. */
static esp_err_t write_eq_mode(bool enable) {
  esp_err_t err;

  switch (s_cur->model) {
  case TAS58XX_MODEL_TAS5805M: {
    select_default_page();

    uint8_t value = enable ? 0x08 : 0x09; /* bit0 = BYPASS_EQ */
    err = tas58xx_write_reg(REG_DSP_MISC, value);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "EQ: mode write failed: %s", esp_err_to_name(err));
    } else {
      ESP_LOGD(TAG, "EQ: %s", enable ? "ENABLED" : "BYPASSED");
    }
  } break;

  case TAS58XX_MODEL_TAS5825M: {
    err = select_book_page(EQ_MODE_BOOK, EQ_MODE_PAGE);
    if (err != ESP_OK) {
      return err;
    }

    uint8_t mode_data[EQ_MODE_SIZE] = {
        0x00, 0x80, 0x00, 0x00,                 /* gang_eq = 0x00800000 */
        0x00, 0x00, 0x00, enable ? 0x00 : 0x01, /* bypass_eq */
    };

    err = board_i2c_write(s_cur->handle, EQ_MODE_REG, mode_data, EQ_MODE_SIZE);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "EQ: mode write failed: %s", esp_err_to_name(err));
    } else {
      ESP_LOGD(TAG, "EQ: %s", enable ? "ENABLED" : "BYPASSED");
    }

    select_default_page();
  } break;

  default:
    ESP_LOGE(TAG, "Unknown TAS58XX model %d in write_eq_mode", s_cur->model);
    return ESP_ERR_INVALID_STATE;
  }

  return err;
}

/* Index of the chip s_cur points at, for reaching per-device state. */
static inline int cur_dev_index(void) {
  return (int)(s_cur - s_devs);
}

/* Fill every chain with pass-through sections. */
static void bq_chain_defaults(void) {
  for (int d = 0; d < TAS58XX_MAX_DEVICES; d++) {
    s_bq_ganged[d] = true;
    s_bq_from_hf[d] = false;
    s_bq_seeded[d] = false;
    for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
      for (int i = 0; i < TAS58XX_BQ_SLOTS; i++) {
        tas58xx_bq_init_bypass(&s_bq[d][c][i]);
      }
    }
  }
  s_bq_ready = true;
}

/* True when a chain says nothing, so a tuning already loaded outranks it. */
static bool bq_chain_is_flat(int dev) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || !s_bq_ready) {
    return true;
  }
  for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
    for (int i = 0; i < TAS58XX_BQ_SLOTS; i++) {
      if (s_bq[dev][c][i].type != TAS58XX_BQ_BYPASS) {
        return false;
      }
    }
  }
  return true;
}

/* True when the chain was seeded from the resident dump, so it accounts for
 * the sections that dump tuned even where the user has since edited it. */
static bool bq_chain_is_from_dump(int dev) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES || !s_bq_ready) {
    return false;
  }
  return s_bq_seeded[dev];
}

/*
 * Read a device's biquad chain back out of its resident PPC3 dump.
 *
 * A dump's EQ sections land in exactly the coefficient RAM this chain writes,
 * so the tuning can be recovered from the buffer alone — no I2C, no clocks.
 * Without it the chain would claim to be flat while the part played the
 * tuning, and the first edit from the EQ page would wipe all thirty sections.
 *
 * Only the shapes are lost: a dump stores coefficients, not the filters that
 * produced them, so every non-trivial section comes back as CUSTOM.
 */

/* Over 2 kB all told, which the main task's stack cannot spare: this runs
 * from board init, and overflowing it there corrupts the freshly built I2C
 * bus object sitting below it. */
typedef struct {
  uint8_t raw[TAS58XX_BQ_CHANNELS][TAS58XX_BQ_SLOTS][EQ_COEFF_BYTES];
  uint32_t seen[TAS58XX_BQ_CHANNELS][TAS58XX_BQ_SLOTS];
  tas58xx_bq_t chain[TAS58XX_BQ_CHANNELS][TAS58XX_BQ_SLOTS];
} bq_seed_scratch_t;

static bool tas58xx_seed_bq_from_hf(int idx) {
  if (idx < 0 || idx >= s_dev_count) {
    return false;
  }
  tas58xx_dev_t *d = &s_devs[idx];
  /* Dumps replay a TAS5825M process flow; the TAS5805M lays its coefficients
   * out differently and tas58xx_load_hf() never loads one for it. */
  if (!d->hf_buf || d->model != TAS58XX_MODEL_TAS5825M) {
    return false;
  }

  bq_seed_scratch_t *sc =
      heap_caps_calloc(1, sizeof(*sc), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!sc) {
    sc = calloc(1, sizeof(*sc));
  }
  if (!sc) {
    ESP_LOGE(TAG, "@0x%02X out of memory reading %s back", d->addr, d->hf_path);
    return false;
  }

  const eq_bq_addr_t *addr[TAS58XX_BQ_CHANNELS] = {tas5825m_eq_left_addr,
                                                   tas5825m_eq_right_addr};
  const uint32_t all_bytes = (1u << EQ_COEFF_BYTES) - 1u;
  uint8_t book = 0, page = 0;
  size_t pos = 0;
  bool ok = false;

  while (pos + 1 < d->hf_size) {
    const uint8_t reg = d->hf_buf[pos];
    const uint8_t len = d->hf_buf[pos + 1];

    if (reg == HF_OP_END && len == HF_OP_END) {
      break;
    }
    if (pos + 2 + (size_t)len > d->hf_size) {
      break;
    }
    if (reg == HF_OP_DELAY) {
      pos += 2 + (size_t)len;
      continue;
    }

    /* Block writes auto-increment, and a page select part way through one
     * moves the rest of it, so the stream has to be followed byte by byte. */
    for (uint8_t k = 0; k < len; k++) {
      const uint8_t a = (uint8_t)(reg + k);
      const uint8_t v = d->hf_buf[pos + 2 + k];

      if (a == REG_PAGE_SEL) {
        page = v;
        continue;
      }
      /* 0x7F selects the book only while page 0 is current; on a coefficient
       * page it is the last data byte of the last section. */
      if (a == REG_BOOK_SEL && page == 0) {
        book = v;
        continue;
      }
      if (book != BQ_COEFF_BOOK) {
        continue;
      }
      for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
        for (int s = 0; s < TAS58XX_BQ_SLOTS; s++) {
          if (addr[c][s].page != page || a < addr[c][s].sub_addr ||
              a >= addr[c][s].sub_addr + EQ_COEFF_BYTES) {
            continue;
          }
          const uint8_t off = (uint8_t)(a - addr[c][s].sub_addr);
          sc->raw[c][s][off] = v;
          sc->seen[c][s] |= 1u << off;
        }
      }
    }
    pos += 2 + (size_t)len;
  }

  /* A dump that only rewrites part of the chain leaves the rest holding
   * whatever was there before, which nothing here can know. */
  for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
    for (int s = 0; s < TAS58XX_BQ_SLOTS; s++) {
      if (sc->seen[c][s] != all_bytes) {
        ESP_LOGW(TAG,
                 "@0x%02X %s does not carry a complete EQ chain (ch %d BQ%d) — "
                 "the EQ page will not show its tuning",
                 d->addr, d->hf_path, c + 1, s + 1);
        goto out;
      }
    }
  }

  for (int c = 0; c < TAS58XX_BQ_CHANNELS; c++) {
    for (int s = 0; s < TAS58XX_BQ_SLOTS; s++) {
      tas58xx_bq_unpack(sc->raw[c][s], &sc->chain[c][s]);
      const char *why = NULL;
      if (!tas58xx_bq_validate(&sc->chain[c][s], &why)) {
        ESP_LOGW(TAG, "@0x%02X %s ch %d BQ%d unusable: %s", d->addr, d->hf_path,
                 c + 1, s + 1, why);
        goto out;
      }
    }
  }

  /* The dump decides the ganging too: identical chains are what ganged
   * means, and claiming otherwise would un-gang the pair on the next edit. */
  bool ganged = true;
  for (int s = 0; s < TAS58XX_BQ_SLOTS && ganged; s++) {
    ganged = memcmp(sc->raw[0][s], sc->raw[1][s], EQ_COEFF_BYTES) == 0;
  }

  if (!s_bq_ready) {
    bq_chain_defaults();
  }
  memcpy(s_bq[idx], sc->chain, sizeof(sc->chain));
  s_bq_ganged[idx] = ganged;
  s_bq_from_hf[idx] = true;
  s_bq_seeded[idx] = true;

  int active = 0;
  for (int s = 0; s < TAS58XX_BQ_SLOTS; s++) {
    if (sc->chain[0][s].type != TAS58XX_BQ_BYPASS ||
        sc->chain[1][s].type != TAS58XX_BQ_BYPASS) {
      active++;
    }
  }
  ESP_LOGI(TAG, "@0x%02X read %d tuned section(s) back from %s (%s)", d->addr,
           active, d->hf_path, ganged ? "ganged" : "per-channel");
  ok = true;

out:
  free(sc);
  return ok;
}

/*
 * Design and write the current chip's whole biquad chain from s_bq. A ganged
 * amplifier sends its left chain to both channels; the right chain stays in
 * memory so un-ganging brings the old tuning back.
 * Assumes REG_LOCK is held, s_cur is set and the chip is in PLAY.
 */
static esp_err_t bq_program_chain(void) {
  const int dev = cur_dev_index();
  esp_err_t first_err = ESP_OK;

  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!s_bq_ready) {
    bq_chain_defaults();
  }

  const bool ganged = s_bq_ganged[dev];
  for (int i = 0; i < TAS58XX_BQ_SLOTS; i++) {
    uint8_t left[EQ_COEFF_BYTES], right[EQ_COEFF_BYTES];
    tas58xx_bq_design_packed(&s_bq[dev][0][i], s_bq_fs, left);
    tas58xx_bq_design_packed(ganged ? &s_bq[dev][0][i] : &s_bq[dev][1][i],
                             s_bq_fs, right);
    esp_err_t err = program_biquad_pair(i, left, right);
    if (err != ESP_OK && first_err == ESP_OK) {
      first_err = err;
    }
  }

  /*
   * Coefficients are only audible once the EQ block is out of bypass, and
   * the chip powers up bypassed. Clearing it here means the chain is the
   * one thing that has to be right, rather than one of two. A dump arrives
   * with the block already enabled and its own gang word, which this would
   * overwrite.
   */
  if (!s_cur->hf_buf) {
    esp_err_t err = write_eq_mode(true);
    if (err != ESP_OK && first_err == ESP_OK) {
      first_err = err;
    }
  }
  return first_err;
}

/*
 * Program the input mixer of the current chip (s_cur) for its assigned
 * channel routing. Switches the DSP to custom-coefficient mode and
 * overrides the mixer gains. Assumes REG_LOCK is held and the chip is in
 * PLAY (coefficient RAM writes require active I2S clocks).
 */
static esp_err_t tas58xx_apply_input_mix(void) {
  const bool is_5805 = (s_cur->model == TAS58XX_MODEL_TAS5805M);
  if (!is_5805 && s_cur->model != TAS58XX_MODEL_TAS5825M) {
    return ESP_ERR_NOT_SUPPORTED; /* unknown part — the map is unverified */
  }
  /* Routing anything but the pair straight through is a process-flow change,
   * which is a TAS5825M feature. The level and mute folded in below are only
   * gains, so those still reach a TAS5805M. */
  if (is_5805 && s_cur->mix != TAS58XX_MIX_STEREO) {
    ESP_LOGW(TAG,
             "@0x%02X input routing only implemented for TAS5825M; "
             "chip will play the left channel only",
             s_cur->addr);
    return ESP_ERR_NOT_SUPPORTED;
  }

  /* Only the TAS5825M keeps its coefficient RAM behind USE_DEFAULT_COEFFS;
   * the TAS5805M takes the write directly, as it does for its biquads. */
  if (!is_5805) {
    /* Enter custom-coefficient mode (writes straight-stereo signal-path
     * defaults, then clears USE_DEFAULT_COEFFS). */
    const esp_err_t cerr = ensure_custom_coeffs_mode();
    if (cerr != ESP_OK) {
      ESP_LOGE(TAG, "@0x%02X mixer: failed to enter custom coeff mode: %s",
               s_cur->addr, esp_err_to_name(cerr));
      return cerr;
    }
  }

  /*
   * Input mixer gains live in Book 0x8C as 9.23 fixed point, but on a
   * different page per part (SLAA786A Table 9 vs SLOA263A Table 5).
   * In PBTL the paralleled output follows one channel, so feeding both
   * output paths makes the content independent of PBTL_CH_SEL.
   */
  const uint8_t mix_page = is_5805 ? MIX_PAGE_5805 : MIX_PAGE_5825;
  const uint8_t mix_base = is_5805 ? MIX_BASE_5805 : MIX_BASE_5825;

  static const int32_t UNITY_9_23 = 0x00800000; /*  0 dB */
  static const int32_t HALF_9_23 = 0x00400000;  /* -6 dB */

  int32_t l_to_l = 0, r_to_l = 0, l_to_r = 0, r_to_r = 0;
  const char *desc;
  switch (s_cur->mix) {
  case TAS58XX_MIX_MONO:
    l_to_l = r_to_l = l_to_r = r_to_r = HALF_9_23;
    desc = "mono L+R -6 dB";
    break;
  case TAS58XX_MIX_LEFT:
    l_to_l = l_to_r = UNITY_9_23;
    desc = "left channel";
    break;
  case TAS58XX_MIX_RIGHT:
    r_to_l = r_to_r = UNITY_9_23;
    desc = "right channel";
    break;
  default:
    /* Written rather than skipped so switching back off a summed routing
     * restores the pair instead of leaving the old gains in place. */
    l_to_l = r_to_r = UNITY_9_23;
    desc = "stereo";
    break;
  }

  if (s_cur->hf_mix_seen) {
    /* The routing a dump exported is part of its tuning, so it stands in for
     * ours. The trim below still has to reach the same coefficients. */
    l_to_l = s_cur->hf_mix[0];
    r_to_l = s_cur->hf_mix[1];
    l_to_r = s_cur->hf_mix[2];
    r_to_r = s_cur->hf_mix[3];
    desc = "dump routing";
  }

  /* The mixer is a gain matrix, so the per-output level and mute are the same
   * knob as the routing: scale whichever paths feed that output. */
  const int dev = (int)(s_cur - s_devs);
  const float sa = tas58xx_ch_scale(dev, 0);
  const float sb = tas58xx_ch_scale(dev, 1);
  l_to_l = (int32_t)lrintf((float)l_to_l * sa);
  r_to_l = (int32_t)lrintf((float)r_to_l * sa);
  l_to_r = (int32_t)lrintf((float)l_to_r * sb);
  r_to_r = (int32_t)lrintf((float)r_to_r * sb);

  esp_err_t err = select_book_page(MIX_BOOK, mix_page);
  if (err != ESP_OK) {
    select_default_page();
    return err;
  }
  write_dsp_coeff32(mix_page, (uint8_t)(mix_base + 0), l_to_l);
  write_dsp_coeff32(mix_page, (uint8_t)(mix_base + 4), r_to_l);
  write_dsp_coeff32(mix_page, (uint8_t)(mix_base + 8), l_to_r);
  write_dsp_coeff32(mix_page, (uint8_t)(mix_base + 12), r_to_r);
  err = select_default_page();

  ESP_LOGI(TAG, "@0x%02X input mixer applied (%s, A %+.1f dB%s, B %+.1f dB%s)",
           s_cur->addr, desc, s_ch_gain_db[dev][0],
           s_ch_mute[dev][0] ? " muted" : "", s_ch_gain_db[dev][1],
           s_ch_mute[dev][1] ? " muted" : "");
  return err;
}

/* ---------- Public API ---------- */

/*
 * Push the current chip's chain, muting across the bulk coefficient update
 * so the part does not click its way through fifteen partial states.
 * Assumes REG_LOCK is held and s_cur is set.
 */
static esp_err_t bq_program_chain_muted(void) {
  uint8_t saved_ctrl2 = 0;
  tas58xx_read_reg(REG_DEVICE_CTRL2, &saved_ctrl2);
  if (!(saved_ctrl2 & CTRL2_MUTE)) {
    tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2 | CTRL2_MUTE);
  }

  esp_err_t err = bq_program_chain();

  tas58xx_write_reg(REG_DEVICE_CTRL2, saved_ctrl2);
  return err;
}

/* Re-push every amplifier's chain. Takes REG_LOCK itself. */
static esp_err_t bq_reprogram_all(void) {
  if (s_reg_mutex == NULL) {
    return ESP_OK; /* not up yet; the PLAY transition will do it */
  }

  REG_LOCK();
  esp_err_t first_err = ESP_OK;
  for (int d = 0; d < s_dev_count; d++) {
    s_cur = &s_devs[d];
    esp_err_t err = bq_program_chain_muted();
    if (err != ESP_OK && first_err == ESP_OK) {
      first_err = err;
    }
  }
  s_cur = NULL;
  REG_UNLOCK();
  return first_err;
}

/* ==================  Parametric biquad chain API  ================== */

/*
 * Stored the same way the TAS57xx hybrid-flow tunings are: a fixed-size
 * struct with a magic and a version, rewritten whole. The geometry is in the
 * header so a build with different limits rejects the file rather than
 * reading it crooked.
 */
#define BQ_CFG_PATH    "/spiffs/eq/tas58xx.cfg"
#define BQ_CFG_TMP     "/spiffs/eq/tas58xx.tmp"
#define BQ_CFG_MAGIC   0x35384251u /* "58BQ" */
#define BQ_CFG_VERSION 1u

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint8_t devices;
  uint8_t channels;
  uint8_t slots;
  uint8_t ganged; /* one bit per amplifier */
  uint8_t seeded; /* one bit per amplifier: chain descends from its dump */
  uint8_t pad[3]; /* keeps the array 4-byte aligned on flash */
  tas58xx_bq_t bq[TAS58XX_MAX_DEVICES][TAS58XX_BQ_CHANNELS][TAS58XX_BQ_SLOTS];
} bq_cfg_file_t;

uint32_t dac_tas58xx_bq_sample_rate(void) {
  return (uint32_t)s_bq_fs;
}

bool dac_tas58xx_bq_get(int dev, int ch, tas58xx_bq_t out[TAS58XX_BQ_SLOTS]) {
  if (!out || dev < 0 || dev >= TAS58XX_MAX_DEVICES || ch < 0 ||
      ch >= TAS58XX_BQ_CHANNELS) {
    return false;
  }
  if (!s_bq_ready) {
    bq_chain_defaults();
  }
  memcpy(out, s_bq[dev][ch], sizeof(s_bq[dev][ch]));
  return true;
}

esp_err_t dac_tas58xx_bq_set(int dev, int ch,
                             const tas58xx_bq_t in[TAS58XX_BQ_SLOTS]) {
  if (!in || dev < 0 || dev >= TAS58XX_MAX_DEVICES || ch < 0 ||
      ch >= TAS58XX_BQ_CHANNELS) {
    return ESP_ERR_INVALID_ARG;
  }
  for (int i = 0; i < TAS58XX_BQ_SLOTS; i++) {
    const char *why = NULL;
    if (!tas58xx_bq_validate(&in[i], &why)) {
      ESP_LOGW(TAG, "BQ: dev %d ch %d slot %d rejected: %s", dev, ch, i, why);
      return ESP_ERR_INVALID_ARG;
    }
  }

  if (s_reg_mutex == NULL) {
    if (!s_bq_ready) {
      bq_chain_defaults();
    }
    memcpy(s_bq[dev][ch], in, sizeof(s_bq[dev][ch]));
    s_bq_from_hf[dev] = false;
    return ESP_OK;
  }

  REG_LOCK();
  if (!s_bq_ready) {
    bq_chain_defaults();
  }
  memcpy(s_bq[dev][ch], in, sizeof(s_bq[dev][ch]));
  s_bq_from_hf[dev] = false;
  esp_err_t err = ESP_OK;
  if (dev < s_dev_count) {
    s_cur = &s_devs[dev];
    err = bq_program_chain_muted();
    s_cur = NULL;
  }
  REG_UNLOCK();
  return err;
}

void dac_tas58xx_bq_set_ganged(int dev, bool ganged) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES) {
    return;
  }
  if (!s_bq_ready) {
    bq_chain_defaults();
  }
  if (s_bq_ganged[dev] == ganged) {
    return;
  }
  s_bq_ganged[dev] = ganged;
  bq_reprogram_all();
}

bool dac_tas58xx_bq_get_ganged(int dev) {
  if (dev < 0 || dev >= TAS58XX_MAX_DEVICES) {
    return true;
  }
  if (!s_bq_ready) {
    bq_chain_defaults();
  }
  return s_bq_ganged[dev];
}

esp_err_t dac_tas58xx_bq_reset(void) {
  bq_chain_defaults();
  return bq_reprogram_all();
}

esp_err_t dac_tas58xx_bq_commit(void) {
  if (!s_bq_ready) {
    bq_chain_defaults();
  }

  bq_cfg_file_t *cfg = calloc(1, sizeof(*cfg));
  if (!cfg) {
    return ESP_ERR_NO_MEM;
  }
  cfg->magic = BQ_CFG_MAGIC;
  cfg->version = BQ_CFG_VERSION;
  cfg->devices = TAS58XX_MAX_DEVICES;
  cfg->channels = TAS58XX_BQ_CHANNELS;
  cfg->slots = TAS58XX_BQ_SLOTS;
  for (int d = 0; d < TAS58XX_MAX_DEVICES; d++) {
    if (s_bq_ganged[d]) {
      cfg->ganged |= (uint8_t)(1u << d);
    }
    if (s_bq_seeded[d]) {
      cfg->seeded |= (uint8_t)(1u << d);
    }
  }
  memcpy(cfg->bq, s_bq, sizeof(cfg->bq));

  /* Written to one side and renamed, so a reset mid-write leaves the
   * previous tuning intact rather than a truncated file. */
  esp_err_t err = ESP_OK;
  FILE *f = fopen(BQ_CFG_TMP, "wb");
  if (!f) {
    ESP_LOGE(TAG, "BQ: cannot open %s for writing", BQ_CFG_TMP);
    err = ESP_FAIL;
  } else {
    const size_t n = fwrite(cfg, 1, sizeof(*cfg), f);
    if (fclose(f) != 0 || n != sizeof(*cfg)) {
      ESP_LOGE(TAG, "BQ: short write to %s (%u of %u bytes)", BQ_CFG_TMP,
               (unsigned)n, (unsigned)sizeof(*cfg));
      remove(BQ_CFG_TMP);
      err = ESP_FAIL;
    } else {
      remove(BQ_CFG_PATH);
      if (rename(BQ_CFG_TMP, BQ_CFG_PATH) != 0) {
        ESP_LOGE(TAG, "BQ: cannot rename %s to %s", BQ_CFG_TMP, BQ_CFG_PATH);
        remove(BQ_CFG_TMP);
        err = ESP_FAIL;
      } else {
        ESP_LOGI(TAG, "BQ: committed %u bytes to %s", (unsigned)sizeof(*cfg),
                 BQ_CFG_PATH);
      }
    }
  }

  free(cfg);
  return err;
}

/* Read the stored chains into memory. Returns false when there is nothing
 * usable on disk, leaving the current chains alone. */
static bool bq_load_config(void) {
  FILE *f = fopen(BQ_CFG_PATH, "rb");
  if (!f) {
    return false;
  }

  bq_cfg_file_t *cfg = calloc(1, sizeof(*cfg));
  if (!cfg) {
    fclose(f);
    return false;
  }

  const size_t n = fread(cfg, 1, sizeof(*cfg), f);
  fclose(f);

  bool ok =
      n == sizeof(*cfg) && cfg->magic == BQ_CFG_MAGIC &&
      cfg->version == BQ_CFG_VERSION && cfg->devices == TAS58XX_MAX_DEVICES &&
      cfg->channels == TAS58XX_BQ_CHANNELS && cfg->slots == TAS58XX_BQ_SLOTS;
  if (!ok) {
    ESP_LOGW(TAG,
             "BQ: ignoring %s (%u bytes, magic 0x%08" PRIX32
             ", version %" PRIu32 ")",
             BQ_CFG_PATH, (unsigned)n, cfg->magic, cfg->version);
    free(cfg);
    return false;
  }

  /* A corrupt slot would be packed and left running, so the whole file is
   * refused if any section fails to make sense. */
  for (int d = 0; d < TAS58XX_MAX_DEVICES && ok; d++) {
    for (int c = 0; c < TAS58XX_BQ_CHANNELS && ok; c++) {
      for (int i = 0; i < TAS58XX_BQ_SLOTS && ok; i++) {
        ok = tas58xx_bq_validate(&cfg->bq[d][c][i], NULL);
      }
    }
  }
  if (!ok) {
    ESP_LOGW(TAG, "BQ: %s holds an invalid filter, ignoring it", BQ_CFG_PATH);
    free(cfg);
    return false;
  }

  memcpy(s_bq, cfg->bq, sizeof(s_bq));
  for (int d = 0; d < TAS58XX_MAX_DEVICES; d++) {
    s_bq_ganged[d] = (cfg->ganged & (1u << d)) != 0;
    s_bq_seeded[d] = (cfg->seeded & (1u << d)) != 0;
    s_bq_from_hf[d] = false;
  }
  s_bq_ready = true;
  free(cfg);
  ESP_LOGI(TAG, "BQ: loaded chains from %s", BQ_CFG_PATH);
  return true;
}

esp_err_t dac_tas58xx_bq_revert(void) {
  if (!bq_load_config()) {
    bq_chain_defaults();
  }
  return bq_reprogram_all();
}

/*
 * A PPC3 dump's coefficients are fixed at export time, so redesigning the
 * biquads cannot follow a rate change — only loading the dump exported for the
 * new rate can. Any device that swaps dumps has its chain re-read from the new
 * one, unless the user has since replaced that chain with their own.
 */
static void tas58xx_reload_hf_for_rate(void) {
  REG_LOCK();
  for (int i = 0; i < s_dev_count; i++) {
    tas58xx_dev_t *d = &s_devs[i];
    if (!d->hf_buf) {
      continue; /* built-in flow — a redesign covers the change */
    }

    char prev[sizeof(d->hf_path)];
    memcpy(prev, d->hf_path, sizeof(prev));

    /* Detach first: the loader frees whatever is resident, and we need the
     * old dump intact to put back if this rate has no export of its own. */
    uint8_t *prev_buf = d->hf_buf;
    const size_t prev_size = d->hf_size;
    d->hf_buf = NULL;
    d->hf_size = 0;

    tas58xx_load_hf(i, s_dev_count > 1);

    if (!d->hf_buf || strcmp(prev, d->hf_path) == 0) {
      /* No dump exported for this rate: the tuning already in coefficient
       * RAM is the closest available, so leave it running. Keeping the buffer
       * also keeps the device on the "dump owns the flow" path, which a
       * later power-on would otherwise overwrite with the default chain. */
      free(d->hf_buf);
      d->hf_buf = prev_buf;
      d->hf_size = prev_size;
      memcpy(d->hf_path, prev, sizeof(d->hf_path));
      tas58xx_seed_mix_from_hf(d);
      continue;
    }
    free(prev_buf);

    ESP_LOGI(TAG, "@0x%02X switching to %s", d->addr, d->hf_path);
    s_cur = d;
    if (tas58xx_write_hf(d, d->hf_buf, d->hf_size) == ESP_OK) {
      tas58xx_fixup_after_hf(d);
      /* The dump brought its own coefficients; ours would overwrite them. */
      d->dsp_defaults_written = true;
      /* It also rewrote the mixer words the per-output trim shares with the
       * routing. A trim only ever attenuates, so leaving the dump's own gains
       * standing would make every output jump louder — and unmute a muted
       * one — for the rest of the session. */
      tas58xx_apply_input_mix();
      /* The new dump has just rewritten the coefficient RAM, so follow it —
       * unless the chain is the user's rather than its predecessor's, in
       * which case the reprogram below puts theirs back over the top. */
      if (s_bq_from_hf[i]) {
        tas58xx_seed_bq_from_hf(i);
      }
    }
  }
  REG_UNLOCK();
}

/*
 * Every section's corner is a fraction of the sample rate, so a rate change
 * invalidates the whole coefficient set and the chains must be redesigned.
 */
static void tas58xx_on_i2s_started(uint32_t sample_rate_hz) {
  if (sample_rate_hz < 8000 || sample_rate_hz > 192000) {
    ESP_LOGW(TAG, "ignoring implausible I2S rate %" PRIu32 " Hz",
             sample_rate_hz);
    return;
  }
  if ((double)sample_rate_hz == s_bq_fs) {
    return;
  }

  ESP_LOGI(TAG, "I2S now %" PRIu32 " Hz (was %.0f), redesigning filters",
           sample_rate_hz, s_bq_fs);
  s_bq_fs = (double)sample_rate_hz;

  tas58xx_reload_hf_for_rate();
  bq_reprogram_all();
}
