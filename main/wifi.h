#pragma once

#include "esp_err.h"

/**
 * Initialize WiFi in station mode and connect to configured AP
 */
void wifi_init_sta(void);

/**
 * Block until WiFi is connected and has an IP address
 */
void wifi_wait_connected(void);

/**
 * Get the device MAC address as a string (XX:XX:XX:XX:XX:XX)
 */
void wifi_get_mac_str(char *mac_str, size_t len);
