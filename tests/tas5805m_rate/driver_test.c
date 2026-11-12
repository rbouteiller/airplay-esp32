// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/* Compile the real driver, replacing only its platform dependencies. Capture
 * the coefficient writes so the UI fixture comes from the hardware path. */
#include <assert.h>
#include <complex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mocks.h"
#include "dac_tas58xx.c"

static struct {
  uint8_t book, page;
  uint8_t regs[128];
  uint8_t coeff[2][TAS58XX_BQ_SLOTS][TAS58XX_BQ_COEFF_BYTES];
  unsigned writes[2][TAS58XX_BQ_SLOTS];
} chips[2];

const char *esp_err_to_name(esp_err_t err) {
  (void)err;
  return "mock";
}
void mock_log(const char *tag, const char *format, ...) {
  (void)tag;
  (void)format;
}
void *heap_caps_calloc(size_t count, size_t size, int caps) {
  (void)caps;
  return calloc(count, size);
}
SemaphoreHandle_t xSemaphoreCreateMutex(void) {
  return (void *)1;
}
int xSemaphoreTake(SemaphoreHandle_t mutex, uint32_t timeout) {
  (void)mutex;
  (void)timeout;
  return 1;
}
int xSemaphoreGive(SemaphoreHandle_t mutex) {
  (void)mutex;
  return 1;
}
void vTaskDelay(uint32_t ticks) {
  (void)ticks;
}
esp_err_t i2c_master_probe(i2c_master_bus_handle_t bus, uint16_t address,
                           int timeout) {
  (void)bus;
  (void)address;
  (void)timeout;
  return ESP_OK;
}
esp_err_t board_i2c_add_device(i2c_master_bus_handle_t bus, uint8_t address,
                               uint32_t speed, i2c_master_dev_handle_t *dev) {
  (void)bus;
  (void)address;
  (void)speed;
  *dev = (void *)1;
  return ESP_OK;
}
esp_err_t board_i2c_remove_device(i2c_master_dev_handle_t dev) {
  (void)dev;
  return ESP_OK;
}
esp_err_t board_i2c_write(i2c_master_dev_handle_t handle, uint8_t reg,
                          const uint8_t *data, size_t size) {
  const int dev = (int)(uintptr_t)handle - 1;
  assert(dev >= 0 && dev < 2);
  if (reg == REG_PAGE_SEL && size == 1) {
    chips[dev].page = data[0];
  } else if (reg == REG_BOOK_SEL && size == 1 && chips[dev].page == 0) {
    chips[dev].book = data[0];
  } else if (chips[dev].book == 0 && chips[dev].page == 0) {
    assert(reg + size <= sizeof(chips[dev].regs));
    memcpy(chips[dev].regs + reg, data, size);
  } else if (chips[dev].book == BQ_COEFF_BOOK &&
             size == TAS58XX_BQ_COEFF_BYTES) {
    const bool is_5805 = s_devs[dev].model == TAS58XX_MODEL_TAS5805M;
    const eq_bq_addr_t *addresses[2] = {
        is_5805 ? tas5805m_eq_left_addr : tas5825m_eq_left_addr,
        is_5805 ? tas5805m_eq_right_addr : tas5825m_eq_right_addr,
    };
    for (int ch = 0; ch < 2; ch++) {
      for (int slot = 0; slot < TAS58XX_BQ_SLOTS; slot++) {
        if (addresses[ch][slot].page == chips[dev].page &&
            addresses[ch][slot].sub_addr == reg) {
          memcpy(chips[dev].coeff[ch][slot], data, size);
          chips[dev].writes[ch][slot]++;
        }
      }
    }
  }
  return ESP_OK;
}
esp_err_t board_i2c_read(i2c_master_dev_handle_t handle, uint8_t reg,
                         uint8_t *data, size_t size) {
  const int dev = (int)(uintptr_t)handle - 1;
  assert(dev >= 0 && dev < 2);
  assert(reg + size <= sizeof(chips[dev].regs));
  memcpy(data, chips[dev].regs + reg, size);
  return ESP_OK;
}

static void setup(uint32_t rate, tas58xx_model_t first,
                  tas58xx_model_t second) {
  memset(chips, 0, sizeof(chips));
  memset(s_devs, 0, sizeof(s_devs));
  s_dev_count = 2;
  s_reg_mutex = (void *)1;
  s_bq_fs = rate;
  bq_chain_defaults();
  for (int dev = 0; dev < 2; dev++) {
    s_devs[dev].model = dev == 0 ? first : second;
    s_devs[dev].handle = (void *)(uintptr_t)(dev + 1);
    s_devs[dev].dsp_defaults_written = true;
    for (int ch = 0; ch < 2; ch++) {
      tas58xx_bq_t *bq = &s_bq[dev][ch][0];
      bq->type = TAS58XX_BQ_PEAKING_Q;
      bq->freq_hz = 2000.0f;
      bq->q = 5.0f;
      bq->gain_db = -12.0f;
    }
  }
  assert(bq_reprogram_all() == ESP_OK);
}

static void check_coefficients(int dev, uint32_t expected_rate) {
  assert(dac_tas58xx_bq_device_sample_rate(dev) == expected_rate);
  for (int ch = 0; ch < 2; ch++) {
    for (int slot = 0; slot < TAS58XX_BQ_SLOTS; slot++) {
      uint8_t expected[TAS58XX_BQ_COEFF_BYTES];
      tas58xx_bq_design_packed(&s_bq[dev][s_bq_ganged[dev] ? 0 : ch][slot],
                               expected_rate, expected);
      assert(chips[dev].writes[ch][slot] > 0);
      assert(memcmp(expected, chips[dev].coeff[ch][slot], sizeof(expected)) ==
             0);
    }
  }
  assert(chips[dev].book == 0 && chips[dev].page == 0);
}

static void test_models_and_rate_changes(void) {
  const uint32_t inputs[] = {32000, 44100, 48000, 88200, 96000};
  const uint32_t internal[] = {96000, 88200, 96000, 88200, 96000};
  for (int first = TAS58XX_MODEL_TAS5805M; first <= TAS58XX_MODEL_TAS5825M;
       first++) {
    for (int second = TAS58XX_MODEL_TAS5805M; second <= TAS58XX_MODEL_TAS5825M;
         second++) {
      for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        setup(inputs[i], first, second);
        const uint32_t rate0 =
            first == TAS58XX_MODEL_TAS5805M ? internal[i] : inputs[i];
        const uint32_t rate1 =
            second == TAS58XX_MODEL_TAS5805M ? internal[i] : inputs[i];
        assert(dac_tas58xx_bq_sample_rate() == rate0);
        check_coefficients(0, rate0);
        check_coefficients(1, rate1);
        s_bq_ganged[1] = false;
        s_bq[1][1][0].freq_hz = 4000.0f;
        assert(bq_reprogram_all() == ESP_OK);
        check_coefficients(1, rate1);
        chips[0].regs[REG_DEVICE_CTRL2] = CTRL2_PLAY;
        chips[1].regs[REG_DEVICE_CTRL2] = CTRL2_HIZ;
        tas58xx_on_i2s_started(44100);
        check_coefficients(0, first == TAS58XX_MODEL_TAS5805M ? 88200 : 44100);
        check_coefficients(1, second == TAS58XX_MODEL_TAS5805M ? 88200 : 44100);
        assert((chips[0].regs[REG_DEVICE_CTRL2] & CTRL2_STATE_MASK) ==
               CTRL2_PLAY);
        assert((chips[1].regs[REG_DEVICE_CTRL2] & CTRL2_STATE_MASK) ==
               CTRL2_HIZ);
      }
    }
  }
}

/* The API exposes raw sections in this shape. Generate them from the actual
 * driver's packed writes, with its per-device rates, for the actual web page.
 */
static void print_fixture(void) {
  printf("{\"devices\":2,\"rate\":%" PRIu32 ",\"amps\":[",
         dac_tas58xx_bq_sample_rate());
  for (int dev = 0; dev < 2; dev++) {
    printf("%s{\"rate\":%" PRIu32 ",\"role\":\"stereo\",\"ganged\":true,"
           "\"pbtl\":false,\"mix\":0,\"gains\":[0,0],\"mutes\":[false,false],"
           "\"channels\":[",
           dev ? "," : "", dac_tas58xx_bq_device_sample_rate(dev));
    for (int ch = 0; ch < 2; ch++) {
      printf("%s[", ch ? "," : "");
      for (int slot = 0; slot < TAS58XX_BQ_SLOTS; slot++) {
        tas58xx_bq_t bq;
        tas58xx_bq_unpack(chips[dev].coeff[ch][slot], &bq);
        printf("%s{\"type\":%u,\"sub\":0,\"freq\":1000,\"q\":0.707,"
               "\"bw\":100,\"gain\":0,\"ripple\":0.5,\"invert\":false,"
               "\"coeff\":[%.9g,%.9g,%.9g,%.9g,%.9g]}",
               slot ? "," : "", bq.type, (double)bq.coeff[0],
               (double)bq.coeff[1], (double)bq.coeff[2], (double)bq.coeff[3],
               (double)bq.coeff[4]);
      }
      printf("]");
    }
    printf("]}");
  }
  printf("]}\n");
}

static void verify_ui_roundtrip(void) {
  /* The JS test emits the shape autoShape() would send back via Apply. */
  for (int dev = 0; dev < 2; dev++) {
    int got_dev;
    tas58xx_bq_t *bq = &s_bq[dev][0][0];
    assert(scanf("%d %f %f %f", &got_dev, &bq->freq_hz, &bq->q, &bq->gain_db) ==
           4);
    assert(got_dev == dev);
    assert(fabsf(bq->freq_hz - 2000.0f) < 1.0f);
  }
  assert(bq_reprogram_all() == ESP_OK);
  for (int dev = 0; dev < 2; dev++) {
    const uint8_t *raw = chips[dev].coeff[0][0];
    double c[5];
    for (int i = 0; i < 5; i++) {
      const uint32_t word = ((uint32_t)raw[4 * i] << 24) |
                            ((uint32_t)raw[4 * i + 1] << 16) |
                            ((uint32_t)raw[4 * i + 2] << 8) | raw[4 * i + 3];
      c[i] = (double)(int32_t)word / (double)(1 << 27);
    }
    const double rate = dac_tas58xx_bq_device_sample_rate(dev);
    double deepest = 1e9, centre = 0;
    for (int hz = 500; hz <= 5000; hz++) {
      const double complex z = cexp(-I * 2.0 * M_PI * hz / rate);
      const double response = cabs((c[0] + c[1] * z + c[2] * z * z) /
                                   (1.0 - c[3] * z - c[4] * z * z));
      if (response < deepest) {
        deepest = response;
        centre = hz;
      }
    }
    assert(fabs(centre - 2000.0) <= 1.0);
    assert(fabs(20.0 * log10(deepest) + 12.0) < 0.01);
  }
}

int main(int argc, char **argv) {
  if (argc == 3) {
    const uint32_t rate = (uint32_t)strtoul(argv[2], NULL, 10);
    setup(rate, TAS58XX_MODEL_TAS5825M, TAS58XX_MODEL_TAS5805M);
    if (strcmp(argv[1], "--fixture") == 0) {
      print_fixture();
    } else {
      assert(strcmp(argv[1], "--roundtrip") == 0);
      verify_ui_roundtrip();
    }
    return EXIT_SUCCESS;
  }
  test_models_and_rate_changes();
  puts("all TAS58xx driver rate tests passed");
  return EXIT_SUCCESS;
}
