/**
 * @file dac_es8388.c
 * @brief ES8388 stereo audio codec DAC driver
 *
 * Implements the dac_ops_t interface for the ES8388 via I2C control.
 * Targets the AI-Thinker ESP32-A1S Audio Kit (variant with sda=33, scl=32,
 * bck=27 — see components/boards/esp32-generic's DAC_ES8388 block).
 *
 * The ES8388's analog output stage (LOUT1/2, ROUT1/2 mixers and their
 * enables) sits behind I2C-only register writes — unlike some codecs, it
 * does not default to a usable analog output at power-on reset. A board
 * running airplay-esp32 with no DAC driver at all can pass clean I2S data
 * all the way to the codec and still produce no audible output, because the
 * DAC-to-output mixer path was never enabled. This driver's init sequence
 * exists specifically to close that gap.
 *
 * Register map, bit values and init sequence transcribed from Espressif's
 * own reference driver (esp-adf components/audio_hal/driver/es8388), which
 * ships on the ESP32-LyraT family and is the field-tested baseline most
 * ES8388 drivers derive from. ADC/mic input path is intentionally left
 * unconfigured — airplay-esp32 is receive-only.
 */

#include "dac_es8388.h"
#include "board_utils.h"

#include <stdio.h>
#include <string.h>

#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#define I2C_LINE_SPEED 100000 // ES8388 is specified to 100kHz standard mode

// Two conventions show up in the wild for this chip's I2C address depending
// on how a project's tooling reports it (raw 7-bit vs. a shifted form), and
// board CE-pin strapping adds a second bit of ambiguity on top of that. This
// board's ES8388 was empirically confirmed at 0x10 via squeezelite-esp32
// (logged as "DAC on I2C @16"), but we probe every plausible candidate
// rather than hardcode a single guess.
static const uint8_t kCandidateAddrs[] = {0x10, 0x11, 0x20, 0x22};

// ES8388 register map (from esp-adf es8388.h)
#define ES8388_CONTROL1     0x00
#define ES8388_CONTROL2     0x01
#define ES8388_CHIPPOWER    0x02
#define ES8388_ADCPOWER     0x03
#define ES8388_DACPOWER     0x04
#define ES8388_MASTERMODE   0x08
#define ES8388_DACCONTROL1  0x17
#define ES8388_DACCONTROL2  0x18
#define ES8388_DACCONTROL3  0x19
#define ES8388_DACCONTROL4  0x1A // master DAC volume (left)
#define ES8388_DACCONTROL5  0x1B // master DAC volume (right)
#define ES8388_DACCONTROL16 0x26
#define ES8388_DACCONTROL17 0x27 // left DAC -> left mixer
#define ES8388_DACCONTROL20 0x2A // right DAC -> right mixer
#define ES8388_DACCONTROL21 0x2B
#define ES8388_DACCONTROL23 0x2D
#define ES8388_DACCONTROL24 0x2E // LOUT1 volume
#define ES8388_DACCONTROL25 0x2F // ROUT1 volume
#define ES8388_DACCONTROL26 0x30 // LOUT2 volume
#define ES8388_DACCONTROL27 0x31 // ROUT2 volume

// DACPOWER bits — enable the DAC and each analog output pair. This board's
// exact LOUT/ROUT-to-jack wiring isn't independently confirmed, so all four
// outputs are enabled together (matches esp-adf's own default when no
// single output is specified).
#define DAC_OUTPUT_LOUT1 0x04
#define DAC_OUTPUT_LOUT2 0x08
#define DAC_OUTPUT_ROUT1 0x10
#define DAC_OUTPUT_ROUT2 0x20
#define DAC_OUTPUT_ALL \
  (DAC_OUTPUT_LOUT1 | DAC_OUTPUT_LOUT2 | DAC_OUTPUT_ROUT1 | DAC_OUTPUT_ROUT2)

// DACCONTROL3 bit 2 = mute
#define DAC_MUTE_BIT (1 << 2)

static const char TAG[] = "ES8388 DAC";

static uint8_t s_es8388_addr;
static i2c_master_dev_handle_t s_es8388_device = NULL;
static SemaphoreHandle_t s_dac_mutex = NULL;

static esp_err_t es8388_reg_write(uint8_t reg, uint8_t val) {
  esp_err_t err = ESP_OK;
  for (int attempt = 0; attempt < 5; attempt++) {
    err = board_i2c_write(s_es8388_device, reg, &val, sizeof(uint8_t));
    if (err == ESP_OK) {
      return ESP_OK;
    }
    vTaskDelay(pdMS_TO_TICKS(2));
  }
  ESP_LOGE(TAG, "write reg 0x%02X=0x%02X failed after retries: %s", reg, val,
           esp_err_to_name(err));
  return err;
}

static esp_err_t es8388_detect(i2c_master_bus_handle_t bus,
                               uint8_t *found_addr) {
  for (size_t i = 0; i < sizeof(kCandidateAddrs) / sizeof(kCandidateAddrs[0]);
       i++) {
    if (ESP_OK == i2c_master_probe(bus, kCandidateAddrs[i], 100)) {
      ESP_LOGI(TAG, "Detected ES8388 at 0x%02X", kCandidateAddrs[i]);
      *found_addr = kCandidateAddrs[i];
      return ESP_OK;
    }
  }
  ESP_LOGW(TAG, "No ES8388 detected at any candidate address");
  return ESP_ERR_NOT_FOUND;
}

// Enable the DAC's analog output path and unmute. Split out from init()
// because it also needs to run from on_i2s_started() / enable_speaker() —
// re-affirming the output enable once I2S is actually clocking has been the
// difference between silence and audio on other codecs in this codebase
// (see dac_es8311.c), so the same defensive re-assert is applied here even
// though the ES8388's slave-mode operation doesn't strictly require it.
static esp_err_t es8388_output_enable(void) {
  esp_err_t err = es8388_reg_write(ES8388_DACPOWER, DAC_OUTPUT_ALL);
  if (err != ESP_OK) {
    return err;
  }
  // Unmute: clear DACCONTROL3 bit 2, leave the rest (soft-ramp bit, etc.)
  // as init() left it.
  return es8388_reg_write(ES8388_DACCONTROL3, 0x00);
}

static esp_err_t es8388_init(void *i2c_bus) {
  i2c_master_bus_handle_t bus = (i2c_master_bus_handle_t)i2c_bus;
  esp_err_t err;

  if (s_dac_mutex == NULL) {
    s_dac_mutex = xSemaphoreCreateMutex();
    if (s_dac_mutex == NULL) {
      ESP_LOGE(TAG, "Failed to create DAC mutex");
      return ESP_ERR_NO_MEM;
    }
  }

  err = es8388_detect(bus, &s_es8388_addr);
  if (err != ESP_OK) {
    return err;
  }

  err = board_i2c_add_device(bus, s_es8388_addr, I2C_LINE_SPEED,
                             &s_es8388_device);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to add ES8388 to I2C bus: %s", esp_err_to_name(err));
    return err;
  }

  // Mute first, no soft-ramp, before anything else is touched.
  es8388_reg_write(ES8388_DACCONTROL3, 0x04);
  es8388_reg_write(ES8388_CONTROL2, 0x50);
  es8388_reg_write(ES8388_CHIPPOWER, 0x00); // power up whole chip

  // Undocumented DLL-disable tweaks carried over verbatim from esp-adf's
  // reference sequence ("improves 8kHz sample rate" per their comment) —
  // harmless at 44.1kHz, kept for parity with the field-tested baseline.
  es8388_reg_write(0x35, 0xA0);
  es8388_reg_write(0x37, 0xD0);
  es8388_reg_write(0x39, 0xD0);

  es8388_reg_write(ES8388_MASTERMODE, 0x00); // slave mode — ESP32 drives BCK/WS

  err = es8388_reg_write(ES8388_DACPOWER,
                         0xC0); // DAC + outputs off during config
  if (err != ESP_OK) {
    return err;
  }
  es8388_reg_write(ES8388_CONTROL1, 0x12);    // play mode
  es8388_reg_write(ES8388_DACCONTROL1, 0x18); // 16-bit, standard I2S format
  es8388_reg_write(ES8388_DACCONTROL2, 0x02); // single speed, 256x ratio
  es8388_reg_write(ES8388_DACCONTROL16, 0x00);
  // 0xB8 (not esp-adf's generic 0x90) matches squeezelite-esp32's field-proven
  // config for this exact board/codec pairing — higher DAC-to-mixer gain.
  es8388_reg_write(ES8388_DACCONTROL17, 0xB8); // left DAC -> left mixer
  es8388_reg_write(ES8388_DACCONTROL20, 0xB8); // right DAC -> right mixer
  es8388_reg_write(ES8388_DACCONTROL21, 0x80); // ADC/DAC share LRCK
  es8388_reg_write(ES8388_DACCONTROL23, 0x00);
  es8388_reg_write(ES8388_DACCONTROL24, 0x1E); // LOUT1 0dB
  es8388_reg_write(ES8388_DACCONTROL25, 0x1E); // ROUT1 0dB
  // esp-adf's own reference leaves these at 0x00 (-30dB) by default, an
  // asymmetry vs. LOUT1/ROUT1's 0dB that only matters on a board using a
  // single output pair. We drive all four together and don't know which
  // pair this board's jack taps, so match LOUT1/ROUT1 instead of carrying
  // an unexplained -30dB cut on half the outputs.
  es8388_reg_write(ES8388_DACCONTROL26, 0x1E); // LOUT2 0dB
  es8388_reg_write(ES8388_DACCONTROL27, 0x1E); // ROUT2 0dB

  // Master DAC volume starts at 0dB; set_volume() will apply the real
  // AirPlay-mapped value shortly after init.
  es8388_reg_write(ES8388_DACCONTROL4, 0x00);
  es8388_reg_write(ES8388_DACCONTROL5, 0x00);

  err = es8388_output_enable(); // DACPOWER = all outputs, unmute
  if (err != ESP_OK) {
    return err;
  }

  ESP_LOGI(TAG, "ES8388 initialized (addr=0x%02X)", s_es8388_addr);
  return ESP_OK;
}

static esp_err_t es8388_deinit(void) {
  if (s_es8388_device) {
    esp_err_t err = board_i2c_remove_device(s_es8388_device);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "failed to remove from i2c bus: %s", esp_err_to_name(err));
    }
    s_es8388_device = NULL;
  }
  if (s_dac_mutex != NULL) {
    vSemaphoreDelete(s_dac_mutex);
    s_dac_mutex = NULL;
  }
  return ESP_OK;
}

static void es8388_set_power_mode(dac_power_mode_t mode) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  switch (mode) {
  case DAC_POWER_ON:
    es8388_output_enable();
    ESP_LOGI(TAG, "DAC powered on");
    break;
  case DAC_POWER_STANDBY:
    es8388_reg_write(ES8388_DACCONTROL3, DAC_MUTE_BIT); // mute only
    break;
  case DAC_POWER_OFF:
    es8388_reg_write(ES8388_DACCONTROL3, DAC_MUTE_BIT);
    es8388_reg_write(ES8388_DACPOWER, 0xC0); // disable DAC + all outputs
    break;
  default:
    ESP_LOGW(TAG, "Unhandled power mode: %d", mode);
    break;
  }
  xSemaphoreGive(s_dac_mutex);
}

static void es8388_set_volume(float volume_airplay_db) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);

  // Clamp AirPlay input to -30..0 dB
  if (volume_airplay_db > 0.0f) {
    volume_airplay_db = 0.0f;
  }
  if (volume_airplay_db < -30.0f) {
    volume_airplay_db = -30.0f;
  }

  // Map AirPlay -30..0 dB below the configured codec ceiling, same shape as
  // the ES8311 driver's mapping.
  // 2:1 stretch matches dac_es8311's mapping: AirPlay's -30..0dB range needs
  // to reach the codec's real mute floor, not just fall MAX_VOLUME-30 short
  // of it. Without this, AirPlay mute doesn't actually silence the output —
  // and DAC_CONTROLS_VOLUME disables the software-attenuation fallback that
  // would otherwise cover for it.
  float db = (float)CONFIG_ES8388_MAX_VOLUME + (volume_airplay_db * 2.0f);
  if (db < -96.0f) {
    db = -96.0f;
  }
  if (db > 0.0f) {
    db = 0.0f;
  }

  // DACCONTROL4/5: 0x00 = 0dB, 0xC0 = -96dB, 0.5dB/step -> reg = -db * 2
  uint8_t reg_val = (uint8_t)((-db) * 2.0f + 0.5f);
  ESP_LOGD(TAG, "Volume: %.1f dB AirPlay -> %.1f dB DAC -> reg 0x%02X",
           volume_airplay_db, db, reg_val);

  es8388_reg_write(ES8388_DACCONTROL4, reg_val);
  es8388_reg_write(ES8388_DACCONTROL5, reg_val);
  xSemaphoreGive(s_dac_mutex);
}

static void es8388_on_i2s_started(uint32_t sample_rate_hz) {
  (void)sample_rate_hz;
  es8388_set_power_mode(DAC_POWER_ON);
}

static void es8388_enable_speaker(bool enable) {
  xSemaphoreTake(s_dac_mutex, portMAX_DELAY);
  if (enable) {
    es8388_reg_write(ES8388_DACPOWER, DAC_OUTPUT_ALL);
    es8388_reg_write(ES8388_DACCONTROL3, 0x00);
  } else {
    es8388_reg_write(ES8388_DACCONTROL3, DAC_MUTE_BIT);
  }
  xSemaphoreGive(s_dac_mutex);
}

static void es8388_enable_line_out(bool enable) {
  (void)enable;
  ESP_LOGW(TAG, "Line out not distinguished from speaker on this driver — "
                "all outputs are enabled together");
}

const dac_ops_t dac_es8388_ops = {
    .init = es8388_init,
    .deinit = es8388_deinit,
    .set_volume = es8388_set_volume,
    .set_power_mode = es8388_set_power_mode,
    .on_i2s_started = es8388_on_i2s_started,
    .enable_speaker = es8388_enable_speaker,
    .enable_line_out = es8388_enable_line_out,
};
