// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * @file husb238a.h
 * @brief Hynetek HUSB238A USB-PD sink controller, strapped for I2C
 *
 * Strapped for I2C, the chip asks a charger for nothing beyond the 5 V every
 * USB-C port gives until it is told to, and it forgets on every power loss,
 * so the board asks again on every boot. Only the fixed 5-20 V offers are
 * ever chosen: the chip can also negotiate EPR voltages up to 48 V, which no
 * supply rail here is built for.
 */

#include <stdbool.h>

#include "driver/i2c_master.h"
#include "esp_err.h"

/** The fixed offers below EPR: 5, 9, 12, 15 and 20 V. */
#define HUSB238A_FIXED_PDOS 5

/** Volts of each fixed offer, lowest first. */
extern const int husb238a_fixed_volts[HUSB238A_FIXED_PDOS];

/** Told the supply the charger agreed to, in mV, whenever it changes. */
typedef void (*husb238a_supply_cb_t)(int supply_mv);

/** What the chip and the charger at the other end of the cable agreed. */
typedef struct {
  bool attached;       /**< something is on the cable */
  bool pd;             /**< it speaks USB-PD: it sent its offers */
  int supply_mv;       /**< agreed supply: 5000 for plain USB, -1 unknown */
  int requested_volts; /**< what the board asks for */
  int max_volts;       /**< the most it will ever ask for */
  int offer_ma[HUSB238A_FIXED_PDOS]; /**< each offer's current, 0 = none */
} husb238a_status_t;

/**
 * Look for the chip on @p bus and, if it answers, ask the charger for
 * @p volts: the highest fixed offer at or below it that the charger makes,
 * and never above CONFIG_HUSB238A_MAX_VOLTS. Blocks until the charger
 * agrees, which takes up to about two seconds.
 *
 * @p on_supply hears the agreed supply now and after every later change.
 * A board without the chip gets ESP_ERR_NOT_FOUND, and nothing is called.
 */
esp_err_t husb238a_init(i2c_master_bus_handle_t bus, int volts,
                        husb238a_supply_cb_t on_supply);

/** Whether husb238a_init() found the chip. */
bool husb238a_present(void);

/**
 * Ask for another voltage, which must be one of husb238a_fixed_volts and no
 * more than CONFIG_HUSB238A_MAX_VOLTS. Falls back as husb238a_init() does
 * when the charger does not offer it. Blocks like husb238a_init(), and
 * tells the callback before the supply drops as well as after it settles.
 */
esp_err_t husb238a_request(int volts);

/** Read what the charger offers and what it agreed to. */
esp_err_t husb238a_get_status(husb238a_status_t *status);
