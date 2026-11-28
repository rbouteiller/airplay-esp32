// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

/**
 * Optional MQTT now-playing publisher (CONFIG_MQTT_NOWPLAYING, default off).
 *
 * Publishes the now-playing state (play state, title/artist/album/genre,
 * duration, position, volume, artwork URL) as a retained JSON document, adds
 * Home Assistant MQTT discovery for it, and accepts play/pause/next/prev and
 * volume commands, which go to the sender through playback_control / DACP.
 *
 * The broker address, credentials and topics live in NVS (namespace
 * "mqtt_np") and are set at runtime through GET/POST /api/mqtt or the small
 * page at /mqtt. Nothing is compiled in, and MQTT stays off until enabled
 * there.
 *
 * With the Kconfig option off, every function below is an inline no-op and
 * the firmware behaves exactly as before.
 */
#pragma once

#include "esp_err.h"
#include "esp_http_server.h"
#include "sdkconfig.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef CONFIG_MQTT_NOWPLAYING

/** Load config from NVS and register playback listeners. Call once, early. */
esp_err_t mqtt_nowplaying_init(void);

/** Start (or restart) the MQTT client if enabled. Safe to call repeatedly. */
void mqtt_nowplaying_start(void);

/** Register /api/mqtt (GET/POST) and /api/nowplaying[/artwork]. The /mqtt
 * page is data/www/mqtt.html, served by web_server.c's static file table. */
void mqtt_nowplaying_register_http(httpd_handle_t server);

#ifdef CONFIG_MQTT_NOWPLAYING_ARTWORK
#define MQTT_NOWPLAYING_URI_HANDLERS 5 // + /api/nowplaying/artwork
#else
#define MQTT_NOWPLAYING_URI_HANDLERS 4
#endif

#else // !CONFIG_MQTT_NOWPLAYING

static inline esp_err_t mqtt_nowplaying_init(void) {
  return ESP_OK;
}
static inline void mqtt_nowplaying_start(void) {
}
static inline void mqtt_nowplaying_register_http(httpd_handle_t server) {
  (void)server;
}
#define MQTT_NOWPLAYING_URI_HANDLERS 0

#endif // CONFIG_MQTT_NOWPLAYING

#ifdef CONFIG_MQTT_NOWPLAYING_ARTWORK

/**
 * True when cover art should be requested from senders for MQTT: the feature
 * is enabled at runtime, artwork is ticked, and PSRAM is present. Read once
 * at boot (it feeds the mDNS "md" record), so a change via /api/mqtt takes
 * effect after a restart.
 */
bool mqtt_nowplaying_artwork_enabled(void);

/** Copy a cover-art image received over RTSP SET_PARAMETER (PSRAM only). */
void mqtt_nowplaying_set_artwork(const void *data, size_t len,
                                 const char *content_type);

#else

static inline bool mqtt_nowplaying_artwork_enabled(void) {
  return false;
}
static inline void mqtt_nowplaying_set_artwork(const void *data, size_t len,
                                               const char *content_type) {
  (void)data;
  (void)len;
  (void)content_type;
}

#endif // CONFIG_MQTT_NOWPLAYING_ARTWORK
