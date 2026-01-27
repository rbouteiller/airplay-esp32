#pragma once

#include "esp_err.h"
#include <stdint.h>

/**
 * Captive portal DNS server
 * Responds to all DNS queries with the specified IP address
 */

/**
 * Start the DNS server for captive portal
 * @param redirect_ip IP address to return for all DNS queries (network byte
 * order)
 * @return ESP_OK on success
 */
esp_err_t dns_server_start(uint32_t redirect_ip);

/**
 * Stop the DNS server
 */
void dns_server_stop(void);
