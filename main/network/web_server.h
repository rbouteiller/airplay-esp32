// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

#include <stdbool.h>

/**
 * Web server for control panel
 * Provides:
 * - WiFi configuration
 * - Device name configuration
 * - OTA update
 */

/**
 * Initialize and start the web server
 * @param port HTTP server port (default: 80)
 */
esp_err_t web_server_start(uint16_t port);

/**
 * Stop the web server
 */
void web_server_stop(void);

/**
 * Whether a request comes from this device's own pages or a non-browser
 * client: false when its Host is a name a public domain could hold (DNS
 * rebinding) or its Origin is another site. Every /api/ handler is guarded
 * by it; WebSocket endpoints call it before their handshake.
 */
bool web_request_trusted(httpd_req_t *req);
