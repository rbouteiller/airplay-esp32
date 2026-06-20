/**
 * @file dac_es8311.c
 * @brief ES8311 stereo audio codec DAC driver
 *
 * Implements the dac_ops_t interface for the ES8311 via I2C control.
 * Designed for the Waveshare ESP32-S3-Touch-LCD-1.54 board.
 *
 * ES8311 datasheet: https://files.waveshare.com/wiki/common/ES8311.DS.pdf
 * Register map sourced from espressif/esp-bsp es8311_reg.h
 */

#include "dac_es8311.h"
#include "board_utils.h"

#include <stdio.h>
#include <string.h>

#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#define ES8311_ADDR    0x18
#define I2C_LINE_SPEED 400000

// ES8311 register map (from espressif/esp-bsp es8311_reg.h)
#define ES8311_REG00_RESET 0x00
#define ES8311_REG01_CLK1  0x01 // Clock manager: MCLK source, enables
#define ES8311_REG02_CLK2  0x02 // pre_div / pre_multi
#define ES8311_REG03_CLK3  0x03 // fs_mode / adc_osr
#define ES8311_REG04_CLK4  0x04 // dac_osr
#define ES8311_REG05_CLK5  0x05 // adc_div / dac_div
#define ES8311_REG06_CLK6  0x06 // bclk_div
#define ES8311_REG07_CLK7  0x07 // lrck_h
#define ES8311_REG08_CLK8  0x08 // lrck_l
#define ES8311_REG09_SDPIN \
  0x09 // Serial data port in  (I2S format + resolution)
#define ES8311_REG0A_SDPOUT   0x0A // Serial data port out
#define ES8311_REG0D_SYS      0x0D // System: analog power
#define ES8311_REG0E_SYS      0x0E // System: PGA + ADC modulator enable
#define ES8311_REG12_SYS      0x12 // System: DAC power-up
#define ES8311_REG13_SYS      0x13 // System: HP output driver enable
#define ES8311_REG31_DAC_CTRL 0x31 // DAC control: bits [6:5] = mute
#define ES8311_REG32_DAC_VOL \
  0x32 // DAC volume: 0x00=-95.5dB, 0xBF=0dB, 0xFF=+32dB
#define ES8311_REG37_DAC_EQ 0x37 // DAC equalizer bypass
#define ES8311_REG1C_ADC_EQ 0x1C // ADC equalizer bypass / DC cancel

// REG01 bits
#define REG01_MCLK_FROM_BCLK (1 << 7) // derive MCLK internally from BCLK
#define REG01_MCLK_INVERT    (1 << 6)
#define REG01_ALL_CLOCKS_ON  0x3F // bits [5:0] enable all six clock gates

// REG09/REG0A resolution bits [4:2]
#define SDP_16BIT (3 << 2) // 0x0C

// REG31 mute bits
#define DAC_MUTE_BITS ((1 << 6) | (1 << 5))

static const char TAG[] = "ES8311 DAC";

// Clock coefficient table (from espressif/esp-bsp es8311.c coeff_div[])
// Fields: mclk, rate, pre_div, pre_multi, adc_div, dac_div, fs_mode,
//         lrck_h, lrck_l, bclk_div, adc_osr, dac_osr
typedef struct {
  uint32_t mclk;
  uint32_t rate;
  uint8_t pre_div;
  uint8_t pre_multi;
  uint8_t adc_div;
  uint8_t dac_div;
  uint8_t fs_mode;
  uint8_t lrck_h;
  uint8_t lrck_l;
  uint8_t bclk_div;
  uint8_t adc_osr;
  uint8_t dac_osr;
} es8311_coeff_t;

// Subset covering 44.1 kHz and 48 kHz with common MCLK multiples.
// MCLK = sample_rate * 256 when driven from ESP32 I2S MCLK output.
static const es8311_coeff_t s_coeff_div[] = {
    // mclk       rate   pd pm ad dd fm  lh    ll    bd  ao  do
    {11289600, 44100, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFF, 0x04, 0x10,
     0x10},
    {12288000, 48000, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFF, 0x04, 0x10,
     0x10},
    // 256× variants derived from BCLK*8 (no external MCLK pin)
    {5644800, 44100, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFF, 0x04, 0x10,
     0x10},
    {6144000, 48000, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFF, 0x04, 0x10,
     0x10},
    // 384× for higher quality
    {16934400, 44100, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFF, 0x06, 0x10,
     0x10},
    {18432000, 48000, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0xFF, 0x06, 0x10,
     0x10},
};

static uint8_t s_es8311_addr;
static i2c_master_dev_handle_t s_es8311_device = NULL;
static SemaphoreHandle_t s_dac_mutex = NULL;

static esp_err_t es8311_reg_write(uint8_t reg, uint8_t val) {
  // The ES8311 shares I2C bus 0 with the CST816S touch controller, which is
  // polled concurrently by the LVGL task.  Bus contention can cause transient
  // ESP_ERR_INVALID_STATE failures, so retry a few times before giving up.
  esp_err_t err = ESP_OK;
  for (int attempt = 0; attempt < 5; attempt++) {
    err = board_i2c_write(s_es8311_device, reg, &val, sizeof(uint8_t));
    if (err == ESP_OK) {
      return ESP_OK;
    }
    vTaskDelay(pdMS_TO_TICKS(2));
  }
  ESP_LOGE(TAG, "write reg 0x%02X=0x%02X failed after retries: %s", reg, val,
           esp_err_to_name(err));
  return err;
}

static const es8311_coeff_t *find_coeff(uint32_t mclk, uint32_t rate) {
  for (size_t i = 0; i < sizeof(s_coeff_div) / sizeof(s_coeff_div[0]); i++) {
    if (s_coeff_div[i].mclk == mclk && s_coeff_div[i].rate == rate) {
      return &s_coeff_div[i];
    }
  }
  return NULL;
}

static esp_err_t es8311_detect(i2c_master_bus_handle_t bus) {
  uint8_t addrs[] = {ES8311_ADDR, (ES8311_ADDR | 1)};
  for (int i = 0; i < 2; i++) {
    if (ESP_OK == i2c_master_probe(bus, addrs[i], 100)) {
      ESP_LOGI(TAG, "Detected ES8311 at 0x%02X", addrs[i]);
      return ESP_OK;
    }
  }
  ESP_LOGW(TAG, "No ES8311 detected at 0x%02X or 0x%02X", ES8311_ADDR,
           ES8311_ADDR | 1);
  return ESP_ERR_NOT_FOUND;
}

static esp_err_t es8311_configure_clocks(uint32_t sample_rate) {
  // The ESP32-S3 drives MCLK = sample_rate * 256 on I2S_SCK_IO (GPIO8).
  // If CONFIG_I2S_SCK_IO < 0, we must derive MCLK internally from BCLK.
  // BCLK = sample_rate * 32 (16-bit stereo), so MCLK-from-BCLK ratio = 8.
#if defined(CONFIG_I2S_SCK_IO) && CONFIG_I2S_SCK_IO >= 0
  uint32_t mclk = sample_rate * 256;
  uint8_t reg01 = REG01_ALL_CLOCKS_ON; // external MCLK on SCK pin
#else
  // No MCLK pin — derive from BCLK internally
  uint32_t mclk = sample_rate * 256; // virtual MCLK = BCLK * 8
  uint8_t reg01 = REG01_ALL_CLOCKS_ON | REG01_MCLK_FROM_BCLK;
#endif

  const es8311_coeff_t *c = find_coeff(mclk, sample_rate);
  if (!c) {
    ESP_LOGE(TAG, "No clock coeff for mclk=%lu rate=%lu", (unsigned long)mclk,
             (unsigned long)sample_rate);
    return ESP_ERR_NOT_SUPPORTED;
  }

  esp_err_t err;
  err = es8311_reg_write(ES8311_REG01_CLK1, reg01);
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG02_CLK2, (uint8_t)((c->pre_div - 1) << 5) |
                                                (c->pre_multi << 3));
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG03_CLK3,
                         (uint8_t)((c->fs_mode << 6) | c->adc_osr));
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG04_CLK4, c->dac_osr);
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG05_CLK5,
                         (uint8_t)(((c->adc_div - 1) << 4) | (c->dac_div - 1)));
  if (err != ESP_OK) {
    return err;
  }
  // bclk_div < 19: store (bclk_div - 1); otherwise store bclk_div as-is
  uint8_t bclk_reg = (c->bclk_div < 19) ? (c->bclk_div - 1) : c->bclk_div;
  err = es8311_reg_write(ES8311_REG06_CLK6, bclk_reg);
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG07_CLK7, c->lrck_h);
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG08_CLK8, c->lrck_l);
  if (err != ESP_OK) {
    return err;
  }

  return ESP_OK;
}

static esp_err_t es8311_init(void *i2c_bus) {
  i2c_master_bus_handle_t bus = (i2c_master_bus_handle_t)i2c_bus;
  esp_err_t err;

  if (s_dac_mutex == NULL) {
    s_dac_mutex = xSemaphoreCreateMutex();
    if (s_dac_mutex == NULL) {
      ESP_LOGE(TAG, "Failed to create DAC mutex");
      return ESP_ERR_NO_MEM;
    }
  }

  s_es8311_addr = ES8311_ADDR;

  err = es8311_detect(bus);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "No ES8311 detected");
    return ESP_ERR_NOT_FOUND;
  }

  err = board_i2c_add_device(bus, s_es8311_addr, I2C_LINE_SPEED,
                             &s_es8311_device);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to add ES8311 to I2C bus: %s", esp_err_to_name(err));
    return err;
  }

  // Reset: 0x1F → 0x00 → 0x80 (soft reset then normal operation)
  es8311_reg_write(ES8311_REG00_RESET, 0x1F);
  vTaskDelay(pdMS_TO_TICKS(20));
  es8311_reg_write(ES8311_REG00_RESET, 0x00);
  vTaskDelay(pdMS_TO_TICKS(20));
  err = es8311_reg_write(ES8311_REG00_RESET, 0x80);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Reset failed: %s", esp_err_to_name(err));
    return err;
  }
  vTaskDelay(pdMS_TO_TICKS(50));

  // Configure clocks for the output sample rate
  uint32_t rate = CONFIG_OUTPUT_SAMPLE_RATE_HZ;
  err = es8311_configure_clocks(rate);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Clock config failed: %s", esp_err_to_name(err));
    return err;
  }

  // I2S serial port: 16-bit, I2S (Philips) format, slave mode
  // REG09 bits [4:2] = 011 → 16-bit; bits [1:0] = 00 → I2S; bit 6 = 0 → slave
  err = es8311_reg_write(ES8311_REG09_SDPIN, SDP_16BIT);
  if (err != ESP_OK) {
    return err;
  }
  err = es8311_reg_write(ES8311_REG0A_SDPOUT, SDP_16BIT);
  if (err != ESP_OK) {
    return err;
  }

  // Power up analog circuitry
  err = es8311_reg_write(ES8311_REG0D_SYS, 0x01);
  if (err != ESP_OK) {
    return err;
  }
  // Enable analog PGA and ADC modulator
  err = es8311_reg_write(ES8311_REG0E_SYS, 0x02);
  if (err != ESP_OK) {
    return err;
  }
  // Power up DAC
  err = es8311_reg_write(ES8311_REG12_SYS, 0x00);
  if (err != ESP_OK) {
    return err;
  }
  // Enable HP output driver
  err = es8311_reg_write(ES8311_REG13_SYS, 0x10);
  if (err != ESP_OK) {
    return err;
  }
  // Bypass ADC equalizer, cancel DC offset
  err = es8311_reg_write(ES8311_REG1C_ADC_EQ, 0x6A);
  if (err != ESP_OK) {
    return err;
  }
  // Bypass DAC equalizer
  err = es8311_reg_write(ES8311_REG37_DAC_EQ, 0x08);
  if (err != ESP_OK) {
    return err;
  }

  // Default volume: 0 dB
  err = es8311_reg_write(ES8311_REG32_DAC_VOL, 0xBF);
  if (err != ESP_OK) {
    return err;
  }

  // Unmute DAC: REG31 bits [6:5] = 0
  err = es8311_reg_write(ES8311_REG31_DAC_CTRL, 0x00);
  if (err != ESP_OK) {
    return err;
  }

  ESP_LOGI(TAG, "ES8311 initialized at %lu Hz", (unsigned long)rate);
  return ESP_OK;
}

static esp_err_t es8311_deinit(void) {
  if (s_es8311_device) {
    esp_err_t err = board_i2c_remove_device(s_es8311_device);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "failed to remove from i2c bus: %s", esp_err_to_name(err));
    }
    s_es8311_device = NULL;
  }
  if (s_dac_mutex != NULL) {
    vSemaphoreDelete(s_dac_mutex);
    s_dac_mutex = NULL;
  }
  return ESP_OK;
}

static void es8311_set_power_mode(dac_power_mode_t mode) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  switch (mode) {
  case DAC_POWER_ON:
    // Re-run clock configuration now that MCLK is present from the I2S master.
    // The ES8311's clock state machine only locks when MCLK is running at the
    // time REG01-REG08 are written — it cannot lock if they were written before
    // I2S was started.
    es8311_configure_clocks(CONFIG_OUTPUT_SAMPLE_RATE_HZ);
    es8311_reg_write(ES8311_REG12_SYS, 0x00);      // power up DAC
    es8311_reg_write(ES8311_REG13_SYS, 0x10);      // enable HP output
    es8311_reg_write(ES8311_REG31_DAC_CTRL, 0x00); // unmute
    ESP_LOGI(TAG, "DAC powered on (clocks reconfigured with MCLK active)");
    break;
  case DAC_POWER_STANDBY:
    es8311_reg_write(ES8311_REG31_DAC_CTRL, DAC_MUTE_BITS); // mute only
    break;
  case DAC_POWER_OFF:
    es8311_reg_write(ES8311_REG31_DAC_CTRL, DAC_MUTE_BITS);
    es8311_reg_write(ES8311_REG12_SYS, 0x02); // power down DAC
    es8311_reg_write(ES8311_REG13_SYS, 0x00); // disable HP output
    break;
  default:
    ESP_LOGW(TAG, "Unhandled power mode: %d", mode);
    break;
  }
  xSemaphoreGive(s_dac_mutex);
}

static void es8311_set_volume(float volume_airplay_db) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);

  // Clamp AirPlay input to -30..0 dB
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }

  // Map AirPlay -30..0 dB below the configured codec ceiling. For example,
  // max=-60 maps AirPlay 0 dB to -60 dB and AirPlay -30 dB to -120 dB
  // before clamping to the ES8311 register range.
  float db = (float)CONFIG_ES8311_MAX_VOLUME + (volume_airplay_db * 2.0f);
  if (db < -95.5f) {
    db = -95.5f;
  }
  if (db > 32.0f) {
    db = 32.0f;
  }

  // round(db * 2): multiply by 2 again since each step is 0.5 dB
  int steps = (int)(db * 2.0f + (db >= 0.0f ? 0.5f : -0.5f));
  uint8_t reg_val = (uint8_t)(0xBF + steps);
  ESP_LOGD(TAG, "Volume: %.1f dB AirPlay -> %.1f dB DAC -> reg 0x%02X",
           volume_airplay_db, db, reg_val);

  es8311_reg_write(ES8311_REG32_DAC_VOL, reg_val);
  xSemaphoreGive(s_dac_mutex);
}

static void es8311_on_i2s_started(void) {
  es8311_set_power_mode(DAC_POWER_ON);
}

static void es8311_enable_speaker(bool enable) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  if (enable) {
    es8311_reg_write(ES8311_REG12_SYS, 0x00);
    es8311_reg_write(ES8311_REG13_SYS, 0x10);
    es8311_reg_write(ES8311_REG31_DAC_CTRL, 0x00);
  } else {
    es8311_reg_write(ES8311_REG31_DAC_CTRL, DAC_MUTE_BITS);
  }
  xSemaphoreGive(s_dac_mutex);
}

static void es8311_enable_line_out(bool enable) {
  (void)enable;
  ESP_LOGW(TAG, "Line out not supported");
}

const dac_ops_t dac_es8311_ops = {
    .init = es8311_init,
    .deinit = es8311_deinit,
    .set_volume = es8311_set_volume,
    .set_power_mode = es8311_set_power_mode,
    .on_i2s_started = es8311_on_i2s_started,
    .enable_speaker = es8311_enable_speaker,
    .enable_line_out = es8311_enable_line_out,
};
