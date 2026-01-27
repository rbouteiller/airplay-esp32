#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/**
 * NTP-like timing for AirPlay 1 synchronization.
 * Sends timing requests to the sender and calculates clock offset from
 * responses. Based on shairport-sync's timing implementation.
 */

/**
 * Start NTP timing client.
 * Sends periodic timing requests to the remote client and calculates offset.
 * @param remote_ip Remote IP address (network byte order)
 * @param remote_port Remote timing port
 * @return ESP_OK on success
 */
esp_err_t ntp_clock_start_client(uint32_t remote_ip, uint16_t remote_port);

/**
 * Stop NTP timing and free resources.
 */
void ntp_clock_stop(void);

/**
 * Check if NTP timing is synchronized.
 * @return true if we have valid offset measurements
 */
bool ntp_clock_is_locked(void);

/**
 * Get current offset from local clock to remote time in nanoseconds.
 * remote_time = local_time + offset
 */
int64_t ntp_clock_get_offset_ns(void);
