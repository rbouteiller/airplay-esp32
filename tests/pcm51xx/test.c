// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#include "mocks.h"
#include "dac.h"
#include "dac_pcm51xx.h"
#include "iot_board.h"
#include "playback_events.h"

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

static int bus_token, device_token, mutex_token;
static bool device_live, bus_live, spi_live, locked, enabled;
static bool fail_probe, fail_add, fail_remove, fail_bus, fail_listener;
static bool fail_gpio, fail_mutex, fail_all_writes;
static int write_count, fail_write;
static uint8_t regs[256];
static void (*before_lock)(void);
static playback_event_callback_t listener;

const char *esp_err_to_name(esp_err_t err) {
  (void)err;
  return "mock error";
}

void mock_log(const char *tag, const char *format, ...) {
  (void)tag;
  (void)format;
}

SemaphoreHandle_t xSemaphoreCreateMutex(void) {
  return fail_mutex ? NULL : &mutex_token;
}

int xSemaphoreTake(SemaphoreHandle_t mutex, uint32_t timeout) {
  assert(mutex == &mutex_token && timeout == portMAX_DELAY);
  if (before_lock) {
    void (*callback)(void) = before_lock;
    before_lock = NULL;
    callback();
  }
  assert(!locked);
  locked = true;
  return 1;
}

int xSemaphoreGive(SemaphoreHandle_t mutex) {
  assert(mutex == &mutex_token && locked);
  locked = false;
  return 1;
}

void vTaskDelay(uint32_t ticks) {
  (void)ticks;
}

esp_err_t gpio_config(const gpio_config_t *config) {
  assert(config->pin_bit_mask == (1ULL << CONFIG_DAC_ENABLE_GPIO));
  return fail_gpio ? ESP_FAIL : ESP_OK;
}

esp_err_t gpio_set_level(int gpio, uint32_t level) {
  assert(gpio == CONFIG_DAC_ENABLE_GPIO);
  enabled = level != 0;
  return ESP_OK;
}

esp_err_t i2c_master_probe(i2c_master_bus_handle_t bus, uint16_t address,
                           int timeout) {
  assert(bus == &bus_token && timeout > 0);
  return !fail_probe && address == CONFIG_PCM51XX_I2C_ADDR ? ESP_OK
                                                           : ESP_ERR_NOT_FOUND;
}

esp_err_t board_i2c_add_device(i2c_master_bus_handle_t bus, uint8_t address,
                               uint32_t speed, i2c_master_dev_handle_t *dev) {
  assert(bus == &bus_token && address == CONFIG_PCM51XX_I2C_ADDR && speed > 0);
  assert(!device_live);
  if (fail_add) {
    return ESP_FAIL;
  }
  device_live = true;
  *dev = &device_token;
  return ESP_OK;
}

esp_err_t board_i2c_remove_device(i2c_master_dev_handle_t dev) {
  // Device removal must be serialized with every register access.
  assert(dev == &device_token && device_live && locked);
  if (fail_remove) {
    return ESP_FAIL;
  }
  device_live = false;
  return ESP_OK;
}

esp_err_t board_i2c_write(i2c_master_dev_handle_t dev, uint8_t reg,
                          const uint8_t *data, size_t size) {
  assert(dev == &device_token && device_live && locked && size == 1);
  write_count++;
  if (write_count == fail_write || fail_all_writes) {
    return ESP_FAIL;
  }
  if (reg == 1) {
    memset(regs, 0, sizeof(regs));
    regs[0x3D] = regs[0x3E] = 0x30; // Hardware reset volume: 0 dB.
  } else {
    regs[reg] = *data;
  }
  return ESP_OK;
}

esp_err_t board_i2c_read(i2c_master_dev_handle_t dev, uint8_t reg,
                         uint8_t *data, size_t size) {
  assert(dev == &device_token && device_live && locked && size == 1);
  *data = regs[reg];
  return ESP_OK;
}

esp_err_t i2c_new_master_bus(const i2c_master_bus_config_t *config,
                             i2c_master_bus_handle_t *bus) {
  (void)config;
  assert(!bus_live);
  if (fail_bus) {
    return ESP_FAIL;
  }
  bus_live = true;
  *bus = &bus_token;
  return ESP_OK;
}

esp_err_t i2c_del_master_bus(i2c_master_bus_handle_t bus) {
  assert(bus == &bus_token && bus_live && !device_live);
  bus_live = false;
  return ESP_OK;
}

esp_err_t spi_bus_initialize(int host, const spi_bus_config_t *config,
                             int dma) {
  (void)config;
  (void)dma;
  assert(host == SPI2_HOST && !spi_live);
  spi_live = true;
  return ESP_OK;
}

esp_err_t spi_bus_free(int host) {
  assert(host == SPI2_HOST && spi_live);
  spi_live = false;
  return ESP_OK;
}

esp_err_t settings_get_volume(float *volume) {
  *volume = -24.0f;
  return ESP_OK;
}

int playback_events_register(playback_event_callback_t callback, void *data) {
  (void)data;
  if (fail_listener) {
    return -1;
  }
  assert(!listener);
  listener = callback;
  return 0;
}

void playback_events_unregister(playback_event_callback_t callback) {
  if (listener == callback) {
    listener = NULL;
  }
}

static void deinit(void) {
  assert(dac_deinit() == ESP_OK);
  assert(!device_live && !enabled && !locked);
}

static void init(void) {
  assert(dac_init(&bus_token) == ESP_OK);
  assert(device_live && !enabled && !locked);
}

static void expect_inactive(void) {
  int writes = write_count;
  dac_set_volume(-12.0f);
  dac_set_power_mode(DAC_POWER_ON);
  dac_on_i2s_started(48000);
  assert(write_count == writes && !enabled);
}

static void test_init_failures(void) {
  assert(dac_init(NULL) == ESP_ERR_INVALID_ARG);
  fail_mutex = true;
  assert(dac_init(&bus_token) == ESP_ERR_NO_MEM);
  fail_mutex = false;
  bool *failures[] = {&fail_gpio, &fail_probe, &fail_add};
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    *failures[i] = true;
    assert(dac_init(&bus_token) != ESP_OK);
    assert(!device_live && !enabled && !locked);
    expect_inactive();
    *failures[i] = false;
    init();
    deinit();
  }

  write_count = 0;
  init();
  int setup_writes = write_count;
  // Repeated init must not add another device or reset the playing DAC.
  dac_set_power_mode(DAC_POWER_ON);
  int writes = write_count;
  assert(dac_init(&bus_token) == ESP_OK && enabled);
  assert(write_count == writes);
  assert(dac_init(&device_token) == ESP_ERR_INVALID_STATE);
  deinit();

  for (int failure = 1; failure <= setup_writes; failure++) {
    write_count = 0;
    fail_write = failure;
    assert(dac_init(&bus_token) == ESP_FAIL);
    assert(!device_live && !enabled && !locked);
    expect_inactive();
    fail_write = 0;
    init();
    deinit();
  }
  printf("Passed all %d initialization write failure points\n", setup_writes);
}

static void test_volume_and_playback(void) {
  dac_set_volume(-24.0f);
  init();
  assert(regs[0x3D] == 0x90 && regs[0x3E] == 0x90);
  const struct {
    float volume;
    uint8_t code;
  } cases[] = {
      {0, 0x30},      {12, 0x30},       {-25, 0x94},
      {-27.5f, 0xC9}, {-30, 0xFF},      {-144, 0xFF},
      {NAN, 0xFF},    {INFINITY, 0xFF}, {-INFINITY, 0xFF},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    dac_set_volume(cases[i].volume);
    assert(regs[0x3D] == cases[i].code && regs[0x3E] == cases[i].code);
  }
  dac_set_volume(-10.0f);
  for (int failure = 1; failure <= 4; failure++) {
    fail_write = write_count + failure;
    dac_set_power_mode(DAC_POWER_ON);
    assert(!enabled && regs[3] == 0x11);
    fail_write = 0;
    dac_set_power_mode(DAC_POWER_ON);
    assert(enabled && regs[3] == 0 && regs[2] == 0);
    dac_set_power_mode(DAC_POWER_STANDBY);
    assert(!enabled && regs[3] == 0x11);
  }
  for (int failure = 1; failure <= 2; failure++) {
    dac_set_power_mode(DAC_POWER_ON);
    fail_write = write_count + failure;
    dac_set_volume(-20.0f);
    assert(!enabled);
    fail_write = 0;
    dac_set_power_mode(DAC_POWER_ON);
    assert(enabled && regs[0x3D] == 0x80 && regs[0x3E] == 0x80);
  }
  fail_all_writes = true;
  dac_set_volume(-144.0f);
  assert(!enabled); // XSMT still works when every bus transaction fails.
  dac_set_power_mode(DAC_POWER_ON);
  assert(!enabled);
  fail_all_writes = false;
  dac_set_power_mode(DAC_POWER_ON);
  assert(enabled && regs[0x3D] == 0xFF && regs[0x3E] == 0xFF);
  fail_write = write_count + 1;
  dac_on_i2s_started(44100);
  assert(!enabled);
  fail_write = 0;
  deinit();
  puts("Passed volume boundaries, playback failures, and recovery");
}

static void test_deinit_lifetime(void) {
  init();
  fail_remove = true;
  assert(dac_deinit() == ESP_FAIL && device_live && !enabled);
  expect_inactive();
  assert(dac_init(&bus_token) == ESP_ERR_INVALID_STATE);
  fail_remove = false;
  deinit();
  // Simulate deinit finishing while a callback waits to acquire the mutex.
  init();
  before_lock = deinit;
  dac_set_power_mode(DAC_POWER_ON);
  expect_inactive();
  init();
  before_lock = deinit;
  dac_on_i2s_started(48000);
  expect_inactive();
  puts("Passed device removal retry and callbacks waiting across deinit");
}

static void test_board_failures(void) {
  bool *failures[] = {&fail_bus, &fail_probe, &fail_listener};
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    *failures[i] = true;
    assert(iot_board_init() != ESP_OK);
    assert(!iot_board_is_init() && !listener);
    assert(!device_live && !bus_live && !spi_live && !enabled);
    *failures[i] = false;
    assert(iot_board_init() == ESP_OK);
    assert(iot_board_is_init() && listener);
    assert(regs[0x3D] == 0x90 && regs[0x3E] == 0x90);
    assert(iot_board_init() == ESP_OK);
    listener(PLAYBACK_SOURCE_AIRPLAY, PLAYBACK_EVENT_PLAYING, NULL, NULL);
    assert(enabled);
    listener(PLAYBACK_SOURCE_AIRPLAY, PLAYBACK_EVENT_PAUSED, NULL, NULL);
    assert(!enabled);
    assert(iot_board_deinit() == ESP_OK);
    assert(!device_live && !bus_live && !spi_live && !listener);
  }
  fail_write = write_count + 11; // Initial volume write must fail board init.
  assert(iot_board_init() == ESP_FAIL);
  assert(!iot_board_is_init() && !device_live && !bus_live && !spi_live);
  fail_write = 0;
  assert(iot_board_init() == ESP_OK);
  fail_remove = true;
  assert(iot_board_deinit() == ESP_FAIL);
  assert(!iot_board_is_init() && bus_live && device_live);
  fail_remove = false;
  assert(iot_board_init() == ESP_OK); // Reclaims the retained bus first.
  assert(iot_board_deinit() == ESP_OK);
  puts("Passed board failure cleanup, saved volume, and initialization retry");
}

int main(void) {
  dac_register(&dac_pcm51xx_ops);
  test_init_failures();
  test_volume_and_playback();
  test_deinit_lifetime();
  test_board_failures();
  return 0;
}
