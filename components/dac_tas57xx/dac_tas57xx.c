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
#include "freertos/semphr.h"
#include "freertos/task.h"

#define TAS575x (0x98 >> 1)
#define TAS578x (0x90 >> 1)

// TAS578x device ID register (Book 0, Page 0)
#define TAS578x_REG_DEVICE_ID 0x67

// Registers (Book 0, Page 0). See TAS5754M datasheet §8.4.2.
#define TAS57XX_REG_PAGE         0x00
#define TAS57XX_REG_RESET        0x01 // module/register reset, standby only
#define TAS57XX_REG_GPIO_OE      0x08 // per-GPIO output enable
#define TAS57XX_REG_IGNORE_ERR   0x25 // clock error masks
#define TAS57XX_REG_DSP_PROGRAM  0x2B // DSP program selection
#define TAS57XX_REG_ANALOG_MUTE  0x6C
#define TAS57XX_REG_DSP_OVERFLOW 0x5A // ch A/B analogue mute monitor
#define TAS57XX_REG_SHORT_DETECT 0x6D // line output short, live + sticky
#define TAS57XX_REG_SPK_MUTE     0x72 // SPK_MUTE pin decoder (external UVP)
// DSP boot done flag + power state. The register map puts these bits at
// P0-R118; §8.4.2.54 heads the same description "P0-R117", which is reserved.
#define TAS57XX_REG_POWER_STATE 0x76
#define TAS57XX_REG_AUTO_MUTE   0x78 // auto-mute flags

// P0-R43 value meaning "user program in RAM", i.e. a hybrid flow is running.
// The reset default is 0x01 (a built-in ROM process flow).
#define TAS57XX_DSP_PROGRAM_RAM 0x1F

// P0-R1 bit 4: resets the DSP, interpolation filter and DAC modules, and
// clears the coefficient RAM. Auto-clearing, and only settable in standby.
// Leaves the mode registers alone, unlike bit 0.
#define TAS57XX_RESET_MODULES 0x10

// P44-R1 bit 2 enables adaptive mode, which lets the DSP write updated
// coefficients into the inactive CRAM bank and swap to it. The dynamic blocks
// in a flow (DRC, DBE) depend on it. PurePath Control Console sets this as a
// post-initialisation step, separate from the flow data, so a flow file on its
// own always leaves it disabled.
#define TAS57XX_PAGE_CRAM_CTRL 0x2C
#define TAS57XX_REG_CRAM_MODE  0x01
#define TAS57XX_CRAM_ADAPTIVE  0x04
#define TAS57XX_CRAM_SWITCH    0x01

// P0-R37 error masks. Bit 3 ignores an MCLK halt; bit 2 ignores LRCK/SCLK
// missing, which otherwise forces powerdown and wipes the miniDSP RAM.
#define TAS57XX_IGNORE_MCLK_HALT     0x08
#define TAS57XX_IGNORE_CLOCK_MISSING 0x04

// P0-R8 bit 4 enables GPIO5 as an output, which drives the board's amp mute.
// A flow overwrites this register with whatever its own reference board used.
#define TAS57XX_GPIO5_OE 0x10

// P0-R94 bit 6 reads high when no MCLK is present at the pin, independently of
// which reference P0-R13 selects, so it can be probed before committing.
#define TAS57XX_REG_CLOCK_STATUS 0x5E
#define TAS57XX_MCLK_MISSING     0x40
#define TAS57XX_REG_PLL_REF      0x0D
#define TAS57XX_PLL_REF_MCLK     0x00
#define TAS57XX_PLL_REF_BCK      0x10

// miniDSP RAM page ranges. Coefficients are double buffered across 0x2C-0x34
// and 0x3E-0x46; the instruction RAM starts at 0x98.
#define TAS57XX_PAGE_COEFF_FIRST   0x2C
#define TAS57XX_PAGE_COEFF_LAST    0x46
#define TAS57XX_PAGE_PROGRAM_FIRST 0x98

// Registers 0x00-0x07 of a RAM page are control registers, memory starts at 8.
#define TAS57XX_RAM_FIRST_REG 0x08

// A bi-amp flow feeds both crossover ways from one input mixer, whose left and
// right gains sit as a 3.24 pair at these two coefficient slots. Only a flow
// authored this way has them, which is why they are written blind.
#define TAS57XX_PAGE_INPUT_MIX  0x32
#define TAS57XX_REG_INPUT_MIX_A 0x5C
#define TAS57XX_REG_INPUT_MIX_B 0x70
#define TAS57XX_INPUT_MIX_LEN   8

// P0-R61/R62 digital volume limits. 0x00 is +24 dB, 0x30 is 0 dB and 0xFE is
// -103 dB in 0.5 dB steps (0xFF is reserved, not mute). Boost is never used.
#define TAS57XX_VOL_REG_MAX_DB 24.0f
#define TAS57XX_VOL_MIN_DB     -103.0f

#define I2C_TIMEOUT    100
#define I2C_LINE_SPEED 100000

static const char TAG[] = "TAS57xx DAC";

struct tas57xx_cmd_s {
  uint8_t reg;
  uint8_t value;
};

// Board plumbing that a hybrid flow cannot know about. The PLL starts on BCK,
// which is all the ROM program needs and is the only safe choice when no MCLK
// is wired; a gap in BCK/LRCK must not force powerdown, as that would wipe the
// miniDSP RAM the flow lives in. tas57xx_program_device() moves the PLL onto
// MCLK if it finds one. GPIO5 drives the amplifier mute; a flow is authored
// against TI's EVM, where that pin carries SDOUT, so it has to be claimed back.
// Applied both before and after a download.
static const struct tas57xx_cmd_s tas57xx_init_seq[] = {
    {0x00, 0x00}, // select page 0
    {0x03, 0x11}, // mute both channels before any other change
    {0x0d, TAS57XX_PLL_REF_BCK},
    {0x25, TAS57XX_IGNORE_MCLK_HALT | TAS57XX_IGNORE_CLOCK_MISSING},
    {0x08, 0x10}, // GPIO5 output enable — amplifier mute
    {0x54, 0x02}, // GPIO5 source = register, i.e. 0x56 bit 4
    {0xff, 0xff}  // end of table
};

// Set once the I2S clocks are running. The miniDSP boots its program from BCK,
// so a flow downloaded before then is never executed.
static bool s_i2s_running = false;
// Set once a flow has been downloaded with the clocks up, so the power-mode
// and I2S-start paths do not each re-download it.
static bool s_flow_resident = false;

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

#define TAS57XX_MAX_DEVICES 2

typedef struct {
  uint8_t addr;                   // 7-bit I2C address
  i2c_master_dev_handle_t handle; // per-device I2C handle
  uint8_t *hf_buf;                // cached hybrid flow (NULL if none)
  long hf_size;
  bool is_sub;        // true for index > 0 (sub / .1 channel)
  bool has_input_mix; // flow carries a recognised bi-amp input mixer
} tas57xx_dev_t;

static tas57xx_dev_t s_devs[TAS57XX_MAX_DEVICES];
static int s_dev_count = 0;
static i2c_master_bus_handle_t s_bus_handle = NULL;
static dac_power_mode_t s_power_state = DAC_POWER_OFF;
static SemaphoreHandle_t s_dac_mutex = NULL;

// Sub level trim (dB) added to the master volume for sub devices, and the
// cached master volume so the trim can be re-applied on its own.
static float s_sub_offset_db = 0.0f;
static float s_last_airplay_db = -15.0f;

// Which input channel a bi-amp flow's mixer takes. Cached so it can be set
// before dac_init() and re-applied after every flow download.
static tas57xx_input_src_t s_input_src = TAS57XX_INPUT_MIX;

// Candidate TAS575x addresses (ADR strap 0x98/0x9A/0x9C/0x9E >> 1).
// 0x4C is always treated as the mains (L/R) device at index 0.
static const uint8_t tas575x_addrs[] = {TAS575x, 0x4D, 0x4E, 0x4F};

static esp_err_t write_cmd(i2c_master_dev_handle_t handle, tas57xx_cmd_e cmd,
                           ...);
static int tas57xx_detect_all(i2c_master_bus_handle_t bus);

#if CONFIG_TAS57XX_FAULT_MONITOR
static void tas57xx_monitor_task(void *arg);
static TaskHandle_t s_monitor_task = NULL;
#endif

/**
 * Write a hybrid flow configuration byte stream to the DAC.
 * Format: [reg, len, data[0..len-1], ...] terminated by 0xFF, 0xFF.
 * The HF config manages its own standby entry/exit.
 */
static esp_err_t tas57xx_write_hf(i2c_master_dev_handle_t handle,
                                  const uint8_t *stream, uint8_t err_masks) {
  esp_err_t err;
  int pos = 0;
  uint8_t page = 0;
  bool probed = false;
  int coeff_bad = 0, coeff_n = 0, prog_bad = 0, prog_n = 0, shown = 0;

  while (!(stream[pos] == 0xFF && stream[pos + 1] == 0xFF)) {
    uint8_t reg = stream[pos];
    uint8_t len = stream[pos + 1];
    const uint8_t *data = &stream[pos + 2];
    bool sel_page = (reg == TAS57XX_REG_PAGE && len == 1);

    if (sel_page && !probed && data[0] >= TAS57XX_PAGE_COEFF_FIRST) {
      // Sample the clocks on page 0 before the first RAM page is selected;
      // the loop's own page-select write below puts the page back.
      const uint8_t p0 = 0x00;
      uint8_t pll = 0, clk = 0, pwr = 0;
      probed = true;
      board_i2c_write(handle, TAS57XX_REG_PAGE, &p0, sizeof(p0));
      board_i2c_read(handle, 0x04, &pll, 1);
      board_i2c_read(handle, 0x5e, &clk, 1);
      board_i2c_read(handle, 0x02, &pwr, 1);
      ESP_LOGI(TAG,
               "pre-RAM clocks: r4=0x%02X pll=%s r94=0x%02X (mclk-miss=%d "
               "sclk-bad=%d rate-bad=%d) r2=0x%02X %s",
               pll, (pll & 0x10) ? "UNLOCKED" : "locked", clk, (clk >> 6) & 1,
               (clk >> 1) & 1, clk & 1, pwr,
               (pwr & 0x10) ? "standby" : "RUNNING");
    }

    // A flow configures the GPIOs for TI's EVM, where GPIO2 carries SDOUT.
    // That pin is adjacent to MCLK, so never let a flow drive it as an output.
    const uint8_t gpio_oe = TAS57XX_GPIO5_OE;
    if (page == 0 && reg == TAS57XX_REG_GPIO_OE && len == 1) {
      data = &gpio_oe;
    }

    // The EVM always has MCLK, so a flow unmasks the clock errors. Its tail
    // leaves standby, so on a board without MCLK the part would run with the
    // clock-missing detector armed and power itself down, taking the RAM the
    // flow was just written into with it.
    if (page == 0 && reg == TAS57XX_REG_IGNORE_ERR && len == 1) {
      data = &err_masks;
    }

    // Bit 7 of the register address is the auto-increment (INC) flag; without
    // it a block write puts every byte into the first register.
    err = board_i2c_write(handle, len > 1 ? (uint8_t)(reg | 0x80) : reg, data,
                          len);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "HF write failed at offset %d (reg 0x%02X): %s", pos, reg,
               esp_err_to_name(err));
      return err;
    }

    // P44-R1: with adaptive mode off no CRAM is reachable over I2C once the
    // DSP is enabled, so RAM can only be read back here, mid-download, while
    // the flow still holds the part in standby.
    bool coeff =
        page >= TAS57XX_PAGE_COEFF_FIRST && page <= TAS57XX_PAGE_COEFF_LAST;
    if (!sel_page && (coeff || page >= TAS57XX_PAGE_PROGRAM_FIRST)) {
      for (int k = 0; k < len && (reg + k) <= 0x7F; k++) {
        uint8_t got = 0;
        // Registers below 8 on a RAM page are control registers (P44-R1 bank
        // switch and friends), not memory, and do not read back what we wrote.
        if ((reg + k) < TAS57XX_RAM_FIRST_REG) {
          continue;
        }
        if (board_i2c_read(handle, (uint8_t)(reg + k), &got, 1) != ESP_OK) {
          continue;
        }
        if (coeff) {
          coeff_n++;
        } else {
          prog_n++;
        }
        if (got == data[k]) {
          continue;
        }
        if (coeff) {
          coeff_bad++;
        } else {
          prog_bad++;
        }
        if (shown < 8) {
          shown++;
          ESP_LOGW(TAG, "  p0x%02X r0x%02X: wrote 0x%02X read 0x%02X", page,
                   (uint8_t)(reg + k), data[k], got);
        }
      }
    }

    if (sel_page) {
      page = data[0];
    }
    pos += 2 + len;
  }

  if (coeff_bad || prog_bad) {
    ESP_LOGE(TAG, "HybridFlow RAM bad: coeff %d/%d, program %d/%d", coeff_bad,
             coeff_n, prog_bad, prog_n);
  } else {
    ESP_LOGI(TAG, "HybridFlow loaded and verified (%d coeff, %d program bytes)",
             coeff_n, prog_n);
  }
  return ESP_OK;
}

// The three gain pairs a bi-amp flow's input mixer is ever authored with,
// indexed by tas57xx_input_src_t.
static const uint8_t tas57xx_input_coeff[][TAS57XX_INPUT_MIX_LEN] = {
    [TAS57XX_INPUT_MIX] = {0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00},
    [TAS57XX_INPUT_LEFT] = {0x7F, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00},
    [TAS57XX_INPUT_RIGHT] = {0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0x00},
};

static const uint8_t tas57xx_input_slots[] = {TAS57XX_REG_INPUT_MIX_A,
                                              TAS57XX_REG_INPUT_MIX_B};

/**
 * Decide whether a flow is a bi-amp mixer flow, by replaying its writes into a
 * shadow of the two input-mixer slots and checking what it leaves there. Only
 * a flow that feeds both crossover ways from one channel-select mixer puts a
 * recognised gain pair in both; anything else — a sub low-pass, a full-range
 * EQ — uses that coefficient RAM for something we must not overwrite.
 *
 * The shadow starts zeroed because the download is preceded by a module reset,
 * which clears coefficient RAM. That matters: a flow converted from a PPC2
 * snapshot writes only the non-zero bytes, one at a time, and relies on the
 * reset for the rest.
 */
static bool tas57xx_flow_has_input_mix(const uint8_t *stream) {
  uint8_t shadow[sizeof(tas57xx_input_slots)][TAS57XX_INPUT_MIX_LEN] = {{0}};
  bool touched[sizeof(tas57xx_input_slots)] = {false};
  int pos = 0;
  uint8_t page = 0;

  while (!(stream[pos] == 0xFF && stream[pos + 1] == 0xFF)) {
    uint8_t reg = stream[pos];
    uint8_t len = stream[pos + 1];
    const uint8_t *data = &stream[pos + 2];

    if (page == TAS57XX_PAGE_INPUT_MIX) {
      for (size_t i = 0; i < sizeof(tas57xx_input_slots); i++) {
        uint8_t slot = tas57xx_input_slots[i];
        for (int k = 0; k < TAS57XX_INPUT_MIX_LEN; k++) {
          int off = slot + k - reg;
          if (off >= 0 && off < len) {
            shadow[i][k] = data[off];
            touched[i] = true;
          }
        }
      }
    }
    if (reg == TAS57XX_REG_PAGE && len == 1) {
      page = data[0];
    }
    pos += 2 + len;
  }

  for (size_t i = 0; i < sizeof(tas57xx_input_slots); i++) {
    if (!touched[i]) {
      return false;
    }
    bool known = false;
    size_t n_coeff =
        sizeof(tas57xx_input_coeff) / sizeof(tas57xx_input_coeff[0]);
    for (size_t k = 0; !known && k < n_coeff; k++) {
      known =
          memcmp(shadow[i], tas57xx_input_coeff[k], TAS57XX_INPUT_MIX_LEN) == 0;
    }
    if (!known) {
      return false;
    }
  }
  return true;
}

/**
 * Point a bi-amp flow's input mixer at the left channel, the right channel or
 * their average. Coefficient RAM is double buffered, so each slot is written
 * into the inactive bank, the banks are swapped, and the same value written
 * again — otherwise the change would be undone by the next swap.
 */
static void tas57xx_write_input_mix(tas57xx_dev_t *d) {
  if (!d->has_input_mix) {
    return;
  }

  const uint8_t page_mix = TAS57XX_PAGE_INPUT_MIX;
  const uint8_t page_cram = TAS57XX_PAGE_CRAM_CTRL;
  const uint8_t page0 = 0x00;
  const uint8_t swap = TAS57XX_CRAM_ADAPTIVE | TAS57XX_CRAM_SWITCH;
  const uint8_t *val = tas57xx_input_coeff[s_input_src];

  for (size_t i = 0; i < sizeof(tas57xx_input_slots); i++) {
    for (int bank = 0; bank < 2; bank++) {
      board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page_mix, sizeof(page_mix));
      board_i2c_write(d->handle, (uint8_t)(tas57xx_input_slots[i] | 0x80), val,
                      TAS57XX_INPUT_MIX_LEN);
      if (bank == 0) {
        board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page_cram,
                        sizeof(page_cram));
        board_i2c_write(d->handle, TAS57XX_REG_CRAM_MODE, &swap, sizeof(swap));
      }
    }
  }
  board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page0, sizeof(page0));
}

/**
 * Confirm the miniDSP is actually running the downloaded flow.
 * P0-R43 reads back the selected DSP program: 0x1F means "user program in
 * RAM" (the hybrid flow), anything else means a built-in ROM flow is running
 * and the flow's crossover/EQ/routing is not in the signal path.
 */
static void tas57xx_verify_hf(tas57xx_dev_t *d) {
  const uint8_t page0 = 0x00;
  board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page0, sizeof(page0));

  uint8_t prog = 0;
  if (board_i2c_read(d->handle, TAS57XX_REG_DSP_PROGRAM, &prog, 1) != ESP_OK) {
    ESP_LOGW(TAG, "@0x%02X could not read back the DSP program register",
             d->addr);
    return;
  }
  if (prog != TAS57XX_DSP_PROGRAM_RAM) {
    ESP_LOGE(TAG,
             "@0x%02X HybridFlow NOT active: P0-R43 = 0x%02X (expected 0x%02X, "
             "user program in RAM) — running a built-in ROM flow",
             d->addr, prog, TAS57XX_DSP_PROGRAM_RAM);
  }
}

/**
 * Dump every page-0 register that can silence the output, for diagnosing a
 * flow that loads and runs but produces nothing.
 */
static void tas57xx_dump_path(tas57xx_dev_t *d) {
  static const uint8_t regs[] = {0x02, 0x03, 0x04, 0x08, 0x0d, 0x0e,
                                 0x25, 0x28, 0x2a, 0x2b, 0x3c, 0x3d,
                                 0x3e, 0x41, 0x56, 0x76};
  const uint8_t page0 = 0x00;
  board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page0, sizeof(page0));

  char line[160];
  size_t n = 0;
  for (size_t k = 0; k < sizeof(regs) && n < sizeof(line); k++) {
    uint8_t v = 0;
    if (board_i2c_read(d->handle, regs[k], &v, 1) != ESP_OK) {
      v = 0xFF;
    }
    int w = snprintf(line + n, sizeof(line) - n, " %02x=%02x", regs[k], v);
    if (w < 0) {
      break;
    }
    n += (size_t)w;
  }
  ESP_LOGI(TAG, "@0x%02X path:%s", d->addr, line);

  // P0-R37 masks the clock errors, so the part reports "run" even if the PLL
  // never locked and the miniDSP has no clock. P0-R94/R90 are the only
  // evidence. R90 is sticky and self-clearing on read.
  uint8_t clk = 0;
  uint8_t fs = 0;
  uint8_t ovf = 0;
  uint8_t pll = 0;
  board_i2c_read(d->handle, 0x5e, &clk, 1);
  board_i2c_read(d->handle, 0x5b, &fs, 1);
  board_i2c_read(d->handle, 0x5a, &ovf, 1);
  // P0-R4 bit 4 is the lock flag the datasheet calls "always correct", and it
  // is inverted. R94 bit 5 reads 0 even when locked, so do not trust it.
  board_i2c_read(d->handle, 0x04, &pll, 1);
  // P0-R92/R93 hold the detected SCLK:FS ratio as a 9-bit word. Without MCLK
  // this is the PLL's only reference, and so sets the miniDSP's cycle budget.
  uint8_t sclk_hi = 0, sclk_lo = 0;
  board_i2c_read(d->handle, 0x5c, &sclk_hi, 1);
  board_i2c_read(d->handle, 0x5d, &sclk_lo, 1);
  ESP_LOGI(TAG,
           "@0x%02X clocks: r94=0x%02X pll=%s sclk=%s rate=%s autoset=%s "
           "detected-fs=%u sclk-ratio=%u dsp-overflow=0x%02X",
           d->addr, clk, (pll & 0x10) ? "UNLOCKED" : "locked",
           (clk & 0x02) ? "INVALID" : "ok", (clk & 0x01) ? "INVALID" : "ok",
           (clk & 0x08) ? "FAILED" : "ok", (fs >> 4) & 0x07,
           (unsigned)(((sclk_hi & 0x01) << 8) | sclk_lo), ovf);
}

/**
 * Apply a register table, stopping at the {0xff, 0xff} terminator.
 */
static esp_err_t tas57xx_write_seq(tas57xx_dev_t *d,
                                   const struct tas57xx_cmd_s *seq) {
  for (int k = 0; seq[k].reg != 0xff; k++) {
    esp_err_t err =
        board_i2c_write(d->handle, seq[k].reg, &seq[k].value, sizeof(uint8_t));
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write reg 0x%02x @0x%02X: %s", seq[k].reg,
               d->addr, esp_err_to_name(err));
      return err;
    }
  }
  return ESP_OK;
}

/**
 * Program a device. A hybrid flow owns the audio configuration — routing,
 * crossover, EQ, dynamics — but not the board's clock source or mute pin, so
 * the init sequence is replayed after the download to take those back.
 */
static void tas57xx_program_device(tas57xx_dev_t *d) {
  write_cmd(d->handle, TAS57XX_MUTE);
  write_cmd(d->handle, TAS57XX_STANDBY);
  tas57xx_write_seq(d, tas57xx_init_seq);

  // The ROM program runs happily on a BCK-derived PLL, but the miniDSP needs a
  // real MCLK. Whether the pin is wired is a board fact the build cannot know,
  // so take the reference from whichever clock is actually present.
  uint8_t clk = 0;
  bool mclk =
      board_i2c_read(d->handle, TAS57XX_REG_CLOCK_STATUS, &clk, 1) == ESP_OK &&
      !(clk & TAS57XX_MCLK_MISSING);
#if CONFIG_TAS57XX_FORCE_BCK_PLL
  mclk = false;
#endif
  const uint8_t pll_ref = mclk ? TAS57XX_PLL_REF_MCLK : TAS57XX_PLL_REF_BCK;
  // With no MCLK a gap in BCK must not reach the clock-missing detector: it
  // powers the part down, and that wipes the miniDSP RAM the flow lives in.
  const uint8_t err_masks =
      mclk ? 0x00 : (TAS57XX_IGNORE_MCLK_HALT | TAS57XX_IGNORE_CLOCK_MISSING);
  board_i2c_write(d->handle, TAS57XX_REG_PLL_REF, &pll_ref, sizeof(pll_ref));
  board_i2c_write(d->handle, TAS57XX_REG_IGNORE_ERR, &err_masks,
                  sizeof(err_masks));
  ESP_LOGI(TAG, "@0x%02X PLL reference = %s", d->addr, mclk ? "MCLK" : "BCK");

  // Without BCK the miniDSP cannot boot the program, and the clock-missing
  // detector holds the part in powerdown, which wipes the RAM it was written
  // to. Defer the download until dac_on_i2s_started().
  bool download = d->hf_buf && s_i2s_running;
  if (download) {
    // PurePath Control Console resets the part before a download, so a flow
    // exported as a snapshot starts from that state and never resets itself.
    // Without this the flow lands underneath a DSP still running the ROM
    // program, and stale state survives into the new one.
    const uint8_t reset = TAS57XX_RESET_MODULES;
    board_i2c_write(d->handle, TAS57XX_REG_RESET, &reset, sizeof(reset));
    vTaskDelay(pdMS_TO_TICKS(10));

    esp_err_t err = tas57xx_write_hf(d->handle, d->hf_buf, err_masks);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Failed to write HF @0x%02X: %s", d->addr,
               esp_err_to_name(err));
      download = false;
    } else {
      // A flow captured as a full PurePath Control Console session resets the
      // mode registers on its way in, which takes the PLL reference back to
      // its default, and its tail exits standby. Both have to be taken back
      // here, in standby: re-selecting R13 on a live DSP makes the PLL
      // re-lock, and the clock-missing detector then powers the part down and
      // wipes the flow out of RAM.
      //
      // CRAM is unreachable while the DSP runs, so adaptive mode also has to
      // be set back in standby, the order PurePath Control Console uses.
      write_cmd(d->handle, TAS57XX_MUTE);
      write_cmd(d->handle, TAS57XX_STANDBY);
      vTaskDelay(pdMS_TO_TICKS(10));

      const uint8_t page0 = 0x00;
      board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page0, sizeof(page0));
      board_i2c_write(d->handle, TAS57XX_REG_PLL_REF, &pll_ref,
                      sizeof(pll_ref));
      board_i2c_write(d->handle, TAS57XX_REG_IGNORE_ERR, &err_masks,
                      sizeof(err_masks));

      const uint8_t page_cram = TAS57XX_PAGE_CRAM_CTRL;
      const uint8_t adaptive_off = 0x00;
      const uint8_t adaptive_on = TAS57XX_CRAM_ADAPTIVE;
      board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page_cram,
                      sizeof(page_cram));
      board_i2c_write(d->handle, TAS57XX_REG_CRAM_MODE, &adaptive_off,
                      sizeof(adaptive_off));
      board_i2c_write(d->handle, TAS57XX_REG_CRAM_MODE, &adaptive_on,
                      sizeof(adaptive_on));

      const uint8_t gpio_oe = TAS57XX_GPIO5_OE;
      board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page0, sizeof(page0));
      board_i2c_write(d->handle, TAS57XX_REG_GPIO_OE, &gpio_oe,
                      sizeof(gpio_oe));

      write_cmd(d->handle, TAS57XX_ACTIVE);
    }
  }

  write_cmd(d->handle, TAS57XX_MUTE); // a flow's tail exits shutdown unmuted
  if (download) {
    s_flow_resident = true;
    tas57xx_verify_hf(d);
    d->has_input_mix = tas57xx_flow_has_input_mix(d->hf_buf);
    ESP_LOGI(TAG, "@0x%02X flow input mixer: %s", d->addr,
             d->has_input_mix ? "present, channel selectable" : "not present");
    // A flow carries whichever input channel it was authored with.
    tas57xx_write_input_mix(d);
  }
}

// Load a hybrid-flow for device index i and program it.
//   single device   -> /spiffs/hf/tas57xx_fw.bin   (legacy name)
//   multiple devices -> /spiffs/hf/tas57xx_fw<i>.bin (mains=0, sub=1, ...)
// A mains device (index 0) with no indexed file falls back to the legacy name.
// A sub with no hybrid-flow runs in normal BTL stereo (no crossover).
static void tas57xx_load_hf(int i, bool multi) {
  tas57xx_dev_t *d = &s_devs[i];

  // TAS578x has no miniDSP / hybrid-flow.
  if (d->addr == TAS578x) {
    return;
  }

  char path[48];
  if (multi) {
    snprintf(path, sizeof(path), "/spiffs/hf/tas57xx_fw%d.bin", i);
  } else {
    snprintf(path, sizeof(path), "/spiffs/hf/tas57xx_fw.bin");
  }

  FILE *f = fopen(path, "rb");
  if (!f && multi && i == 0) {
    // Mains falls back to the legacy unindexed name.
    snprintf(path, sizeof(path), "/spiffs/hf/tas57xx_fw.bin");
    f = fopen(path, "rb");
  }

  if (f) {
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    // tas57xx_write_hf() scans for a two-byte 0xFF 0xFF terminator, so a
    // truncated file would be read past the end of the buffer.
    if (size < 2) {
      ESP_LOGE(TAG, "HF file %s is empty or unreadable", path);
    } else {
      uint8_t *buf = malloc((size_t)size);
      if (buf && fread(buf, 1, (size_t)size, f) == (size_t)size) {
        d->hf_buf = buf;
        d->hf_size = size;
        ESP_LOGI(TAG, "Loaded HF %s (%ld bytes) for @0x%02X", path, size,
                 d->addr);
      } else {
        ESP_LOGE(TAG, "Failed to read HF file %s", path);
        free(buf);
      }
    }
    fclose(f);
    if (d->hf_buf) {
      return;
    }
  }

  // No hybrid-flow present. The device runs in its normal (safe) BTL stereo
  // configuration. A sub with no HF has no low-pass/mono routing, so it plays
  // full-range — provide a mono low-pass flow as tas57xx_fw<i>.bin.
  if (d->is_sub) {
    ESP_LOGW(TAG,
             "No HF for sub @0x%02X — running full-range BTL (no crossover). "
             "Provide a mono low-pass flow as /spiffs/hf/tas57xx_fw%d.bin.",
             d->addr, i);
  } else if (multi) {
    // A second amp is only fitted for a crossover, so a mains without one is
    // a misconfiguration rather than a plain stereo board.
    ESP_LOGW(TAG,
             "No HF at %s — mains @0x%02X runs the built-in stereo flow while "
             "a sub is fitted",
             path, d->addr);
  } else {
    ESP_LOGI(TAG, "No HF at %s — @0x%02X runs the built-in stereo flow", path,
             d->addr);
  }
}

static esp_err_t tas57xx_init(void *i2c_bus) {
  esp_err_t err = ESP_OK;

  if (s_dac_mutex == NULL) {
    s_dac_mutex = xSemaphoreCreateMutex();
    if (s_dac_mutex == NULL) {
      ESP_LOGE(TAG, "Failed to create DAC mutex");
      return ESP_ERR_NO_MEM;
    }
  }

  s_bus_handle = (i2c_master_bus_handle_t)i2c_bus;
  if (s_bus_handle == NULL) {
    ESP_LOGE(TAG, "No I2C bus handle provided");
    return ESP_ERR_INVALID_ARG;
  }

  // Detect all TAS57xx chips on the bus (0x4C = mains at index 0).
  s_dev_count = tas57xx_detect_all(s_bus_handle);
  if (s_dev_count == 0) {
    ESP_LOGW(TAG, "No TAS57xx detected");
    return ESP_ERR_NOT_FOUND;
  }
  ESP_LOGI(TAG, "TAS57xx devices detected: %d", s_dev_count);

  for (int i = 0; i < s_dev_count; i++) {
    err = board_i2c_add_device(s_bus_handle, s_devs[i].addr, I2C_LINE_SPEED,
                               &s_devs[i].handle);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Could not add device @0x%02X to bus: %s", s_devs[i].addr,
               esp_err_to_name(err));
      return err;
    }
  }

  // Read chip identity for the primary device.
  if (s_devs[0].addr == TAS578x) {
    uint8_t page = 0x00;
    board_i2c_write(s_devs[0].handle, 0x00, &page, 1);
    uint8_t device_id = 0;
    if (board_i2c_read(s_devs[0].handle, TAS578x_REG_DEVICE_ID, &device_id,
                       1) == ESP_OK) {
      ESP_LOGI(TAG, "TAS578x device ID: 0x%02X", device_id);
    }
  } else {
    ESP_LOGI(TAG, "TAS575x detected (no device ID register)");
  }

  // Load hybrid-flows (or PBTL fallback for a sub) per device.
  bool multi = s_dev_count > 1;
  for (int i = 0; i < s_dev_count; i++) {
    tas57xx_load_hf(i, multi);
  }

  // Program every device. I2S is not running yet, so the flow itself is held
  // back until dac_on_i2s_started().
  for (int i = 0; i < s_dev_count; i++) {
    tas57xx_program_device(&s_devs[i]);
  }

#if CONFIG_TAS57XX_FAULT_MONITOR
  if (s_monitor_task == NULL &&
      xTaskCreate(tas57xx_monitor_task, "tas57xx_mon", 3072, NULL, 3,
                  &s_monitor_task) != pdPASS) {
    ESP_LOGW(TAG, "Failed to start fault monitor task");
    s_monitor_task = NULL;
  }
#endif

  return err;
}

static esp_err_t tas57xx_deinit(void) {
  esp_err_t err = ESP_OK;

#if CONFIG_TAS57XX_FAULT_MONITOR
  if (s_monitor_task) {
    vTaskDelete(s_monitor_task);
    s_monitor_task = NULL;
  }
#endif

  for (int i = 0; i < s_dev_count; i++) {
    if (s_devs[i].handle) {
      esp_err_t e = board_i2c_remove_device(s_devs[i].handle);
      if (e != ESP_OK) {
        ESP_LOGE(TAG, "failed to remove @0x%02X from i2c bus, err: %s",
                 s_devs[i].addr, esp_err_to_name(e));
        err = e;
      }
      s_devs[i].handle = NULL;
    }
    free(s_devs[i].hf_buf);
    s_devs[i].hf_buf = NULL;
    s_devs[i].hf_size = 0;
  }
  s_dev_count = 0;
  s_bus_handle = NULL;

  if (s_dac_mutex != NULL) {
    vSemaphoreDelete(s_dac_mutex);
    s_dac_mutex = NULL;
  }
  return err;
}

static void tas57xx_apply_volume_locked(void);

/**
 * Re-apply HF config (or PBTL fallback) and init registers after a full
 * shutdown. Shutdown (reg 0x02=0x01) loses miniDSP RAM contents, so the flow
 * must be downloaded again every time the device leaves powerdown
 * (TAS575x HybridFlow user guide SLAU577A §3.2). Caller must hold s_dac_mutex
 * and must have taken the device out of powerdown first.
 */
static void tas57xx_restore_config(void) {
  for (int i = 0; i < s_dev_count; i++) {
    tas57xx_program_device(&s_devs[i]);
  }
  /* The flow's exit-shutdown tail parks the volume, so re-apply ours. */
  tas57xx_apply_volume_locked();
}

/**
 * Take every device out of powerdown into standby, download the flow, and
 * leave the devices muted in standby. Caller must hold s_dac_mutex.
 */
static void tas57xx_reprogram_locked(void) {
  for (int i = 0; i < s_dev_count; i++) {
    write_cmd(s_devs[i].handle, TAS57XX_MUTE);
    write_cmd(s_devs[i].handle, TAS57XX_STANDBY);
  }
  // Wait for the standby state to settle before writing the miniDSP config.
  vTaskDelay(pdMS_TO_TICKS(50));
  tas57xx_restore_config();
  // A flow ends with its own exit-shutdown tail, which leaves the device
  // active and unmuted; park it back in standby for the caller.
  for (int i = 0; i < s_dev_count; i++) {
    write_cmd(s_devs[i].handle, TAS57XX_MUTE);
    write_cmd(s_devs[i].handle, TAS57XX_STANDBY);
  }
}

typedef struct {
  uint8_t power_state;
  uint8_t short_detect;
  uint8_t auto_mute;
  uint8_t analog_mute;
  uint8_t spk_mute;
  uint8_t dsp_overflow;
  bool valid;
} tas57xx_status_t;

static const char *tas57xx_power_state_str(uint8_t state) {
  switch (state) {
  case 0x0:
    return "powerdown";
  case 0x1:
    return "wait for CP voltage";
  case 0x2:
  case 0x3:
    return "calibration";
  case 0x4:
    return "volume ramp up";
  case 0x5:
    return "run (playing)";
  case 0x6:
    return "output short / low impedance";
  case 0x7:
    return "volume ramp down";
  case 0x8:
    return "standby";
  default:
    return "unknown";
  }
}

// Caller must hold s_dac_mutex.
static esp_err_t tas57xx_read_status_locked(tas57xx_dev_t *d,
                                            tas57xx_status_t *st) {
  const uint8_t page0 = 0x00;
  esp_err_t err =
      board_i2c_write(d->handle, TAS57XX_REG_PAGE, &page0, sizeof(page0));
  if (err != ESP_OK) {
    return err;
  }

  const struct {
    uint8_t reg;
    uint8_t *dst;
  } reads[] = {
      {TAS57XX_REG_POWER_STATE, &st->power_state},
      {TAS57XX_REG_SHORT_DETECT, &st->short_detect},
      {TAS57XX_REG_AUTO_MUTE, &st->auto_mute},
      {TAS57XX_REG_ANALOG_MUTE, &st->analog_mute},
      {TAS57XX_REG_SPK_MUTE, &st->spk_mute},
      {TAS57XX_REG_DSP_OVERFLOW, &st->dsp_overflow},
  };

  for (size_t i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
    err = board_i2c_read(d->handle, reads[i].reg, reads[i].dst, 1);
    if (err != ESP_OK) {
      return err;
    }
  }

  st->valid = true;
  return ESP_OK;
}

static void tas57xx_report_status(const tas57xx_dev_t *d,
                                  const tas57xx_status_t *st) {
  // Analogue mute monitor is active low: 0 means the channel is muted.
  // P0-R90 is sticky, so each poll reports overflows since the previous one.
  ESP_LOGI(TAG,
           "@0x%02X state=%s%s analog-mute=[%c%c] auto-mute=[%c%c] "
           "spk_mute=%u dsp-overflow=0x%02X",
           d->addr, tas57xx_power_state_str(st->power_state & 0x0F),
           (st->power_state & 0x80) ? "" : " dsp-booting",
           (st->analog_mute & 0x01) ? '-' : 'A',
           (st->analog_mute & 0x02) ? '-' : 'B',
           (st->auto_mute & 0x01) ? 'A' : '-',
           (st->auto_mute & 0x10) ? 'B' : '-', st->spk_mute & 0x03,
           st->dsp_overflow);
}

void dac_tas57xx_log_status(void) {
  if (s_dac_mutex == NULL) {
    ESP_LOGW(TAG, "Status unavailable, DAC not initialised");
    return;
  }

  for (int i = 0; i < s_dev_count; i++) {
    tas57xx_status_t st = {0};
    xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
    esp_err_t err = tas57xx_read_status_locked(&s_devs[i], &st);
    xSemaphoreGive(s_dac_mutex);

    if (err != ESP_OK) {
      ESP_LOGW(TAG, "@0x%02X status read failed: %s", s_devs[i].addr,
               esp_err_to_name(err));
      continue;
    }
    tas57xx_report_status(&s_devs[i], &st);
  }
}

#if CONFIG_TAS57XX_FAULT_MONITOR
static void tas57xx_monitor_task(void *arg) {
  (void)arg;
  tas57xx_status_t prev[TAS57XX_MAX_DEVICES] = {0};

  while (true) {
    vTaskDelay(pdMS_TO_TICKS(CONFIG_TAS57XX_FAULT_POLL_MS));

    for (int i = 0; i < s_dev_count; i++) {
      tas57xx_status_t st = {0};
      xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
      esp_err_t err = tas57xx_read_status_locked(&s_devs[i], &st);
      xSemaphoreGive(s_dac_mutex);

      if (err != ESP_OK) {
        ESP_LOGW(TAG, "@0x%02X status read failed: %s", s_devs[i].addr,
                 esp_err_to_name(err));
        prev[i].valid = false;
        continue;
      }

      if (st.short_detect & 0x10) {
        ESP_LOGE(TAG, "@0x%02X output shorted", s_devs[i].addr);
      } else if (st.short_detect & 0x01) {
        // Sticky bit, cleared by the read above.
        ESP_LOGE(TAG, "@0x%02X output short since last poll", s_devs[i].addr);
      }

      // Also sticky and cleared by the read, so this is what overflowed during
      // the last poll interval. Reported every time rather than on change, so a
      // one-shot transient at playout start can be told apart from continuous
      // overflow. Ports are the DSP outputs; the shifter is internal to it.
      if (st.dsp_overflow) {
        ESP_LOGW(TAG,
                 "@0x%02X dsp overflow 0x%02X portB1=%c portA1=%c "
                 "portB2=%c portA2=%c shifter=%c",
                 s_devs[i].addr, st.dsp_overflow,
                 (st.dsp_overflow & 0x10) ? 'Y' : '-',
                 (st.dsp_overflow & 0x08) ? 'Y' : '-',
                 (st.dsp_overflow & 0x04) ? 'Y' : '-',
                 (st.dsp_overflow & 0x02) ? 'Y' : '-',
                 (st.dsp_overflow & 0x01) ? 'Y' : '-');
      }

      // Over-temperature, over-current and DC-offset faults high-Z the output
      // without any I2C flag, so infer them from leaving the run state.
      if (prev[i].valid && s_power_state == DAC_POWER_ON &&
          (prev[i].power_state & 0x0F) == 0x05 &&
          (st.power_state & 0x0F) != 0x05) {
        ESP_LOGE(TAG, "@0x%02X dropped out of run while playing -> %s",
                 s_devs[i].addr,
                 tas57xx_power_state_str(st.power_state & 0x0F));
      }

      if (!prev[i].valid || st.power_state != prev[i].power_state ||
          st.auto_mute != prev[i].auto_mute ||
          st.analog_mute != prev[i].analog_mute ||
          st.spk_mute != prev[i].spk_mute) {
        tas57xx_report_status(&s_devs[i], &st);
      }

      prev[i] = st;
    }
  }
}
#endif /* CONFIG_TAS57XX_FAULT_MONITOR */

static void tas57xx_enable_speaker(bool enable) {
  for (int i = 0; i < s_dev_count; i++) {
    write_cmd(s_devs[i].handle,
              enable ? TAS57XX_ANALOGUE_ON : TAS57XX_ANALOGUE_OFF);
  }
}

static void tas57xx_set_power_mode(dac_power_mode_t mode) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  tas57xx_enable_speaker(false);
  switch (mode) {
  case DAC_POWER_STANDBY:
    if (s_power_state == DAC_POWER_OFF) {
      tas57xx_reprogram_locked();
    } else {
      for (int i = 0; i < s_dev_count; i++) {
        write_cmd(s_devs[i].handle, TAS57XX_MUTE);
        write_cmd(s_devs[i].handle, TAS57XX_STANDBY);
      }
    }
    break;
  case DAC_POWER_ON:
    if (s_power_state != DAC_POWER_ON && !s_flow_resident) {
      // Re-download on every wake: powerdown loses the miniDSP RAM outright,
      // and standby cannot be trusted to have preserved it.
      tas57xx_reprogram_locked();
    }
    for (int i = 0; i < s_dev_count; i++) {
      write_cmd(s_devs[i].handle, TAS57XX_MUTE);
      write_cmd(s_devs[i].handle, TAS57XX_ACTIVE);
    }
    // Allow PLL lock and charge pump settling before unmuting
    vTaskDelay(pdMS_TO_TICKS(50));
    for (int i = 0; i < s_dev_count; i++) {
      write_cmd(s_devs[i].handle, TAS57XX_UNMUTE);
    }
    tas57xx_enable_speaker(true);
    // The DSP only boots on the way to the run state, so this is the first
    // point where the flow can be confirmed to be executing.
    vTaskDelay(pdMS_TO_TICKS(50));
    for (int i = 0; i < s_dev_count; i++) {
      tas57xx_status_t st = {0};
      if (tas57xx_read_status_locked(&s_devs[i], &st) == ESP_OK) {
        tas57xx_report_status(&s_devs[i], &st);
      }
      if (s_devs[i].hf_buf) {
        tas57xx_dump_path(&s_devs[i]);
      }
    }
    break;
  case DAC_POWER_OFF:
    s_flow_resident = false; // powerdown wipes the miniDSP RAM
    for (int i = 0; i < s_dev_count; i++) {
      s_devs[i].has_input_mix = false;
      write_cmd(s_devs[i].handle, TAS57XX_MUTE);
      write_cmd(s_devs[i].handle, TAS57XX_DOWN);
    }
    break;
  default:
    ESP_LOGW(TAG, "Unhandled power mode");
    break;
  }
  s_power_state = mode;
  xSemaphoreGive(s_dac_mutex);
}

static void tas57xx_enable_line_out(bool enable) {
  (void)enable;
  ESP_LOGW(TAG, "Not supported yet");
}

/**
 * The miniDSP needs BCK to boot its program, so the flow downloaded during
 * dac_init() — before I2S is running — cannot take effect. Download it again
 * now that the clocks are up. A device still in powerdown is reprogrammed by
 * the next power-mode change instead.
 */
static void tas57xx_on_i2s_started(void) {
  if (s_dac_mutex == NULL || s_dev_count == 0) {
    return;
  }

  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  s_i2s_running = true;
  if (s_power_state != DAC_POWER_OFF && !s_flow_resident) {
    tas57xx_enable_speaker(false);
    tas57xx_reprogram_locked();
    if (s_power_state == DAC_POWER_ON) {
      for (int i = 0; i < s_dev_count; i++) {
        write_cmd(s_devs[i].handle, TAS57XX_ACTIVE);
      }
      vTaskDelay(pdMS_TO_TICKS(50));
      for (int i = 0; i < s_dev_count; i++) {
        write_cmd(s_devs[i].handle, TAS57XX_UNMUTE);
      }
      tas57xx_enable_speaker(true);
    }
  }
  xSemaphoreGive(s_dac_mutex);
}

// Map an AirPlay volume (-30..0 dB) to a DAC dB level using the 2:1 curve.
static float tas57xx_map_volume_db(float volume_airplay_db) {
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }

  // Volume mapping (2:1 scaling):
  // AirPlay 0 dB    -> DAC CONFIG_TAS57XX_MAX_VOLUME
  // AirPlay -25 dB  -> DAC (MAX - 50)
  // AirPlay -30..-25 dB -> DAC mute(-103)..(MAX-50) (steep roll-off)
  float max_db = (float)CONFIG_TAS57XX_MAX_VOLUME;
  float db_level;
  if (volume_airplay_db >= -25.0f) {
    // 2:1 linear scaling: 25 dB AirPlay range -> 50 dB DAC range
    db_level = max_db + (volume_airplay_db * 2.0f);
  } else {
    // Roll-off: map -30..-25 to -103..(MAX-50)
    float normalized = (volume_airplay_db + 30.0f) / 5.0f;
    float rolloff_top = max_db - 50.0f;
    db_level =
        TAS57XX_VOL_MIN_DB + normalized * (rolloff_top - TAS57XX_VOL_MIN_DB);
  }
  return db_level;
}

// Convert a DAC dB level to a P0-R61/R62 register value.
static uint8_t tas57xx_db_to_reg(float db_level) {
  if (db_level > 0.0f) {
    db_level = 0.0f;
  }
  if (db_level < TAS57XX_VOL_MIN_DB) {
    db_level = TAS57XX_VOL_MIN_DB;
  }
  return (uint8_t)((TAS57XX_VOL_REG_MAX_DB - db_level) * 2.0f + 0.5f);
}

// Re-apply the cached master volume to every device, adding the sub offset to
// any sub device. Caller must hold s_dac_mutex.
static void tas57xx_apply_volume_locked(void) {
  float base_db = tas57xx_map_volume_db(s_last_airplay_db);
  uint8_t main_reg = tas57xx_db_to_reg(base_db);
  uint8_t sub_reg = tas57xx_db_to_reg(base_db + s_sub_offset_db);

  ESP_LOGI(TAG,
           "Volume: AirPlay %.1f dB -> DAC %.1f dB (main 0x%02X, sub %+.1f dB "
           "0x%02X)",
           s_last_airplay_db, base_db, main_reg, s_sub_offset_db, sub_reg);

  for (int i = 0; i < s_dev_count; i++) {
    uint8_t reg_val = s_devs[i].is_sub ? sub_reg : main_reg;
    write_cmd(s_devs[i].handle, TAS57XX_SET_VOLUME_A_L, reg_val);
    write_cmd(s_devs[i].handle, TAS57XX_SET_VOLUME_B_R, reg_val);
  }
}

static void tas57xx_set_volume(float volume_airplay_db) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }
  s_last_airplay_db = volume_airplay_db;
  tas57xx_apply_volume_locked();
  xSemaphoreGive(s_dac_mutex);
}

void dac_tas57xx_set_sub_offset_db(float offset_db) {
  if (offset_db > TAS57XX_SUB_OFFSET_MAX_DB) {
    offset_db = TAS57XX_SUB_OFFSET_MAX_DB;
  }
  if (offset_db < TAS57XX_SUB_OFFSET_MIN_DB) {
    offset_db = TAS57XX_SUB_OFFSET_MIN_DB;
  }

  // May be called (e.g. from the web server) before the DAC is initialised;
  // store the value and let the next volume update apply it.
  if (s_dac_mutex == NULL) {
    s_sub_offset_db = offset_db;
    return;
  }

  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  s_sub_offset_db = offset_db;
  tas57xx_apply_volume_locked();
  xSemaphoreGive(s_dac_mutex);
  ESP_LOGI(TAG, "Sub volume offset: %+.1f dB", offset_db);
}

float dac_tas57xx_get_sub_offset_db(void) {
  return s_sub_offset_db;
}

bool dac_tas57xx_has_input_mix(void) {
  for (int i = 0; i < s_dev_count; i++) {
    if (s_devs[i].has_input_mix) {
      return true;
    }
  }
  return false;
}

void dac_tas57xx_set_input_source(tas57xx_input_src_t src) {
  if (src > TAS57XX_INPUT_RIGHT) {
    src = TAS57XX_INPUT_MIX;
  }

  // May be called before dac_init(), or before any flow has been downloaded;
  // the value is re-applied at the end of every download.
  if (s_dac_mutex == NULL) {
    s_input_src = src;
    return;
  }

  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  s_input_src = src;
  for (int i = 0; i < s_dev_count; i++) {
    tas57xx_write_input_mix(&s_devs[i]);
  }
  xSemaphoreGive(s_dac_mutex);
  ESP_LOGI(TAG, "Flow input source: %s",
           src == TAS57XX_INPUT_LEFT    ? "left"
           : src == TAS57XX_INPUT_RIGHT ? "right"
                                        : "(L+R)/2");
}

tas57xx_input_src_t dac_tas57xx_get_input_source(void) {
  return s_input_src;
}

int dac_tas57xx_get_device_count(void) {
  return s_dev_count;
}

const dac_ops_t dac_tas57xx_ops = {
    .init = tas57xx_init,
    .deinit = tas57xx_deinit,
    .set_volume = tas57xx_set_volume,
    .set_power_mode = tas57xx_set_power_mode,
    .on_i2s_started = tas57xx_on_i2s_started,
    .enable_speaker = tas57xx_enable_speaker,
    .enable_line_out = tas57xx_enable_line_out,
};

static esp_err_t write_cmd(i2c_master_dev_handle_t handle, tas57xx_cmd_e cmd,
                           ...) {
  va_list args;
  esp_err_t err = ESP_OK;
  va_start(args, cmd);

  switch (cmd) {
  case TAS57XX_SET_VOLUME_A_L:
  case TAS57XX_SET_VOLUME_B_R:
    uint8_t val = (uint8_t)va_arg(args, int);
    err = board_i2c_write(handle, tas57xx_cmd[cmd].reg, &val, sizeof(uint8_t));
    break;
  default:
    err = board_i2c_write(handle, tas57xx_cmd[cmd].reg,
                          &(tas57xx_cmd[cmd].value), sizeof(uint8_t));
  }

  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed i2c write to TAS57xx: %s", esp_err_to_name(err));
  }

  va_end(args);
  return err;
}

/**
 * Detect all TAS57xx chips on the bus and populate s_devs[].
 * A single TAS578x is supported for legacy boards; otherwise every responding
 * TAS575x address (0x4C..0x4F) is added, with 0x4C as the mains at index 0.
 * Returns the number of devices found.
 */
static int tas57xx_detect_all(i2c_master_bus_handle_t bus) {
  if (!bus) {
    ESP_LOGE(TAG, "Invalid i2c handle!");
    return 0;
  }

  memset(s_devs, 0, sizeof(s_devs));

  // Legacy single TAS578x.
  if (i2c_master_probe(bus, TAS578x, I2C_TIMEOUT) == ESP_OK) {
    s_devs[0].addr = TAS578x;
    ESP_LOGI(TAG, "Detected TAS578x @0x%02X", TAS578x);
    return 1;
  }

  int count = 0;
  const size_t n_addrs = sizeof(tas575x_addrs) / sizeof(tas575x_addrs[0]);
  for (size_t i = 0; i < n_addrs && count < TAS57XX_MAX_DEVICES; i++) {
    if (i2c_master_probe(bus, tas575x_addrs[i], I2C_TIMEOUT) == ESP_OK) {
      s_devs[count].addr = tas575x_addrs[i];
      s_devs[count].is_sub = (count > 0);
      ESP_LOGI(TAG, "Detected TAS575x @0x%02X (%s)", tas575x_addrs[i],
               count == 0 ? "mains" : "sub");
      count++;
    }
  }
  return count;
}
