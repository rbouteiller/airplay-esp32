// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

/**
 * Initialize mDNS and advertise AirPlay 2 services
 *
 * This publishes:
 * - _airplay._tcp service (AirPlay 2)
 * - _raop._tcp service (Remote Audio Output Protocol)
 *
 * With all required TXT records for iOS to recognize the device
 */
void mdns_airplay_init(void);
