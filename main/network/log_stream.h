#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

/**
 * WebSocket-based log streaming.
 *
 * Hooks into esp_log via esp_log_set_vprintf() to capture all log output
 * into a ring buffer. Connected WebSocket clients on /ws/logs receive
 * log lines in real-time. Logs continue to go to UART as normal.
 *
 * Requires CONFIG_HTTPD_WS_SUPPORT=y in sdkconfig.
 */

/**
 * Initialize the log capture ring buffer and hook esp_log output.
 * Call before web_server_start() so early logs are captured.
 */
esp_err_t log_stream_init(void);

/**
 * Register the /ws/logs WebSocket handler on the given HTTP server
 * and start the broadcast task.
 */
esp_err_t log_stream_register(httpd_handle_t server);
