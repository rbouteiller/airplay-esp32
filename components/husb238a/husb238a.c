// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * @file husb238a.c
 * @brief HUSB238A USB-PD sink controller, strapped for I2C
 *
 * Hynetek's public datasheet documents only the ENABLE bit and the request
 * itself: set SRC_PDO, then write 0x01 to GO_COMMAND. The rest of the
 * register map follows Sonocotta's esphome-husb238a component and the
 * Pythonic-Rainbow/HUSB238A library it was checked against.
 */

#include "husb238a.h"

#include <string.h>

#include "board_utils.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char TAG[] = "husb238a";

/* ADDR/ORIENT strapped to GND; strapped to VDD it would be 0x62. */
#define HUSB238A_ADDR 0x42
#define I2C_SPEED_HZ  400000
#define I2C_PROBE_MS  20
/* The chip turns away the first transaction after the bus comes up, and the
 * probe below is the first thing on the bus at boot. On a 55 mm board it
 * refused one probe, then answered every one after it. */
#define PROBE_TRIES  3
#define PROBE_GAP_MS 10

#define REG_CONTROL1    0x02
#define CONTROL1_ENABLE 0x08 /* every command is ignored without it */
#define REG_GO_COMMAND  0x18
#define GO_SELECT_PDO   0x01
#define GO_GET_SRC_CAP  0x04
#define REG_SRC_PDO     0x19 /* bits 7:3 pick the offer to ask for */
#define SRC_PDO_SHIFT   3
#define REG_STATUS      0x63 /* first of a block that runs to 0x6E */
/* The supply is never measured. The map's VBUS reading at 0x87 held 5.1 V
 * through a 9 V contract that a meter confirmed, so the agreed offer is the
 * only voltage reported. */

/* Offsets into the block read from REG_STATUS. */
#define BLK_STATUS       0 /* 0x63 */
#define STATUS_ATTACH    0x01
#define STATUS_AMS_BUSY  0x80 /* a PD message exchange is in flight */
#define BLK_CONTRACT     4    /* 0x67: bits 7:4 hold the agreed offer */
#define BLK_OFFERS       7    /* 0x6A-0x6E: one per fixed offer */
#define OFFER_DETECT     0x80
#define OFFER_MA_PER_LSB 100
#define OFFER_CURRENT    0x7F
#define BLK_LEN          12

/* Offer codes, as SRC_PDO takes them and CONTRACT_STATUS0 reports them: 1-5
 * are the fixed 5-20 V offers and 0 is plain USB, with no contract. Higher
 * codes are PPS, AVS and EPR, which are never asked for here. */
#define CODE_PLAIN_USB 0

#define POLL_MS          20
#define ATTACH_WAIT_MS   600 /* the cable's debounce, once enabled */
#define OFFERS_WAIT_MS   800
#define IDLE_WAIT_MS     300
#define CONTRACT_WAIT_MS 1500

const int husb238a_fixed_volts[HUSB238A_FIXED_PDOS] = {5, 9, 12, 15, 20};

static i2c_master_dev_handle_t s_dev;
static SemaphoreHandle_t s_lock;
static husb238a_supply_cb_t s_on_supply;
static int s_requested_volts;
static int s_reported_mv;

static esp_err_t read_regs(uint8_t reg, uint8_t *buf, size_t len) {
  return board_i2c_read(s_dev, reg, buf, len);
}

static esp_err_t write_reg(uint8_t reg, uint8_t value) {
  return board_i2c_write(s_dev, reg, &value, 1);
}

/* Index of the highest fixed offer at or below @p volts, or -1. */
static int index_at_most(int volts) {
  int index = -1;
  for (int i = 0; i < HUSB238A_FIXED_PDOS; i++) {
    if (husb238a_fixed_volts[i] <= volts) {
      index = i;
    }
  }
  return index;
}

/* The most the board may ask for, as one of the fixed offers. */
static int max_volts(void) {
  const int index = index_at_most(CONFIG_HUSB238A_MAX_VOLTS);
  return husb238a_fixed_volts[index < 0 ? 0 : index];
}

static int offer_code(const uint8_t *block) {
  return block[BLK_CONTRACT] >> 4;
}

/* Supply the agreed offer gives, or -1 for one never asked for here. */
static int contract_mv(const uint8_t *block) {
  const int code = offer_code(block);
  if (code == CODE_PLAIN_USB) {
    return 5000;
  }
  if (code <= HUSB238A_FIXED_PDOS) {
    return husb238a_fixed_volts[code - 1] * 1000;
  }
  return -1;
}

static void report_supply(int supply_mv) {
  if (supply_mv <= 0 || supply_mv == s_reported_mv) {
    return;
  }
  s_reported_mv = supply_mv;
  if (s_on_supply != NULL) {
    s_on_supply(supply_mv);
  }
}

static bool any_offer(const uint8_t *block) {
  for (int i = 0; i < HUSB238A_FIXED_PDOS; i++) {
    if (block[BLK_OFFERS + i] & OFFER_DETECT) {
      return true;
    }
  }
  return false;
}

/* Let a PD message exchange in flight finish: a command written on top of
 * one can clobber it. */
static void wait_idle(void) {
  uint8_t status;
  for (int t = 0; t < IDLE_WAIT_MS; t += POLL_MS) {
    if (read_regs(REG_STATUS, &status, 1) != ESP_OK ||
        !(status & STATUS_AMS_BUSY)) {
      return;
    }
    vTaskDelay(pdMS_TO_TICKS(POLL_MS));
  }
}

static esp_err_t command(uint8_t go) {
  wait_idle();
  return write_reg(REG_GO_COMMAND, go);
}

/* Read the status block until the cable is attached and the charger's offers
 * are in, asking for the offers if they do not come by themselves. */
static esp_err_t read_offers(uint8_t *block) {
  /* A chip that was only just enabled has not looked at the cable yet. */
  for (int t = 0;; t += POLL_MS) {
    esp_err_t err = read_regs(REG_STATUS, block, BLK_LEN);
    if (err != ESP_OK) {
      return err;
    }
    if ((block[BLK_STATUS] & STATUS_ATTACH) || t >= ATTACH_WAIT_MS) {
      break;
    }
    vTaskDelay(pdMS_TO_TICKS(POLL_MS));
  }
  if (!(block[BLK_STATUS] & STATUS_ATTACH) || any_offer(block)) {
    return ESP_OK;
  }

  esp_err_t err = command(GO_GET_SRC_CAP);
  for (int t = 0; err == ESP_OK && t < OFFERS_WAIT_MS; t += POLL_MS) {
    vTaskDelay(pdMS_TO_TICKS(POLL_MS));
    err = read_regs(REG_STATUS, block, BLK_LEN);
    if (err == ESP_OK && any_offer(block)) {
      break;
    }
  }
  return err;
}

/* Ask for @p volts, or the highest offer below it. Caller holds s_lock. */
static esp_err_t negotiate(int volts) {
  uint8_t block[BLK_LEN];
  esp_err_t err = read_offers(block);
  if (err != ESP_OK) {
    return err;
  }
  if (!(block[BLK_STATUS] & STATUS_ATTACH)) {
    ESP_LOGW(TAG, "Nothing on the USB-C cable; staying at 5 V");
    report_supply(5000);
    return ESP_OK;
  }
  if (!any_offer(block)) {
    ESP_LOGI(TAG, "The supply offers no USB-PD; staying at 5 V");
    report_supply(5000);
    return ESP_OK;
  }

  const int limit = volts < max_volts() ? volts : max_volts();
  int pick = -1;
  for (int i = index_at_most(limit); i >= 0 && pick < 0; i--) {
    if (block[BLK_OFFERS + i] & OFFER_DETECT) {
      pick = i;
    }
  }
  if (pick < 0) {
    ESP_LOGW(TAG, "The charger offers nothing at or below %d V", limit);
    report_supply(contract_mv(block));
    return ESP_OK;
  }
  const int code = pick + 1;
  const int pick_mv = husb238a_fixed_volts[pick] * 1000;
  if (offer_code(block) == code) {
    report_supply(pick_mv); /* agreed before a restart */
    return ESP_OK;
  }

  /* Going down: lower the amplifier's ceiling before its supply drops. */
  if (contract_mv(block) > pick_mv) {
    report_supply(pick_mv);
  }

  const int offer_ma =
      (block[BLK_OFFERS + pick] & OFFER_CURRENT) * OFFER_MA_PER_LSB;
  ESP_LOGI(TAG, "Asking for %d V, offered at up to %d.%d A",
           husb238a_fixed_volts[pick], offer_ma / 1000, offer_ma % 1000 / 100);
  err = write_reg(REG_SRC_PDO, (uint8_t)(code << SRC_PDO_SHIFT));
  if (err == ESP_OK) {
    err = command(GO_SELECT_PDO);
  }
  for (int t = 0; err == ESP_OK && t < CONTRACT_WAIT_MS; t += POLL_MS) {
    vTaskDelay(pdMS_TO_TICKS(POLL_MS));
    err = read_regs(REG_STATUS, block, BLK_LEN);
    if (err == ESP_OK && offer_code(block) == code &&
        !(block[BLK_STATUS] & STATUS_AMS_BUSY)) {
      break;
    }
  }
  if (err != ESP_OK) {
    return err;
  }

  if (offer_code(block) == code) {
    ESP_LOGI(TAG, "Supply now %d V", husb238a_fixed_volts[pick]);
  } else {
    ESP_LOGW(TAG, "The charger refused %d V; supply %d mV",
             husb238a_fixed_volts[pick], contract_mv(block));
  }
  report_supply(contract_mv(block));
  return ESP_OK;
}

esp_err_t husb238a_init(i2c_master_bus_handle_t bus, int volts,
                        husb238a_supply_cb_t on_supply) {
  if (bus == NULL) {
    return ESP_ERR_INVALID_ARG;
  }
  if (s_dev != NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  esp_err_t found = i2c_master_probe(bus, HUSB238A_ADDR, I2C_PROBE_MS);
  for (int i = 1; i < PROBE_TRIES && found != ESP_OK; i++) {
    vTaskDelay(pdMS_TO_TICKS(PROBE_GAP_MS));
    found = i2c_master_probe(bus, HUSB238A_ADDR, I2C_PROBE_MS);
  }
  if (found != ESP_OK) {
    ESP_LOGI(TAG, "No USB-PD trigger at 0x%02X", HUSB238A_ADDR);
    return ESP_ERR_NOT_FOUND;
  }

  s_lock = xSemaphoreCreateMutex();
  if (s_lock == NULL) {
    return ESP_ERR_NO_MEM;
  }
  esp_err_t err =
      board_i2c_add_device(bus, HUSB238A_ADDR, I2C_SPEED_HZ, &s_dev);
  /* Until ENABLE is set the chip turns down every command, though it still
   * acknowledges the writes. */
  uint8_t control1 = 0;
  if (err == ESP_OK) {
    err = read_regs(REG_CONTROL1, &control1, 1);
  }
  if (err == ESP_OK && !(control1 & CONTROL1_ENABLE)) {
    err = write_reg(REG_CONTROL1, control1 | CONTROL1_ENABLE);
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "USB-PD trigger not usable: %s", esp_err_to_name(err));
    if (s_dev != NULL) {
      board_i2c_remove_device(s_dev);
      s_dev = NULL;
    }
    vSemaphoreDelete(s_lock);
    s_lock = NULL;
    return err;
  }

  s_on_supply = on_supply;
  const int limit = volts < max_volts() ? volts : max_volts();
  const int index = index_at_most(limit);
  s_requested_volts = husb238a_fixed_volts[index < 0 ? 0 : index];
  ESP_LOGI(TAG, "USB-PD trigger found; asking for %d V", s_requested_volts);

  xSemaphoreTake(s_lock, portMAX_DELAY);
  err = negotiate(s_requested_volts);
  xSemaphoreGive(s_lock);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "USB-PD negotiation failed: %s", esp_err_to_name(err));
  }
  return err;
}

bool husb238a_present(void) {
  return s_dev != NULL;
}

esp_err_t husb238a_request(int volts) {
  if (s_dev == NULL) {
    return ESP_ERR_INVALID_STATE;
  }
  const int index = index_at_most(volts);
  if (index < 0 || husb238a_fixed_volts[index] != volts ||
      volts > max_volts()) {
    return ESP_ERR_INVALID_ARG;
  }
  xSemaphoreTake(s_lock, portMAX_DELAY);
  s_requested_volts = volts;
  esp_err_t err = negotiate(volts);
  xSemaphoreGive(s_lock);
  return err;
}

esp_err_t husb238a_get_status(husb238a_status_t *status) {
  if (status == NULL) {
    return ESP_ERR_INVALID_ARG;
  }
  memset(status, 0, sizeof(*status));
  status->supply_mv = -1;
  status->max_volts = max_volts();
  if (s_dev == NULL) {
    return ESP_ERR_INVALID_STATE;
  }

  uint8_t block[BLK_LEN];
  xSemaphoreTake(s_lock, portMAX_DELAY);
  status->requested_volts = s_requested_volts;
  esp_err_t err = read_regs(REG_STATUS, block, BLK_LEN);
  xSemaphoreGive(s_lock);
  if (err != ESP_OK) {
    return err;
  }

  status->attached = (block[BLK_STATUS] & STATUS_ATTACH) != 0;
  for (int i = 0; i < HUSB238A_FIXED_PDOS; i++) {
    const uint8_t offer = block[BLK_OFFERS + i];
    if (offer & OFFER_DETECT) {
      status->pd = true;
      status->offer_ma[i] = (offer & OFFER_CURRENT) * OFFER_MA_PER_LSB;
    }
  }
  status->supply_mv = contract_mv(block);
  return ESP_OK;
}
