#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * Simple PTP (IEEE 1588) slave for AirPlay time synchronization.
 * Listens for SYNC/FOLLOW_UP messages and tracks offset to PTP master.
 */

/**
 * Initialize and start PTP clock synchronization.
 * Creates a task that listens for PTP multicast messages.
 */
esp_err_t ptp_clock_init(void);

/**
 * Stop PTP clock and free resources.
 */
void ptp_clock_stop(void);

/**
 * Clear PTP clock synchronization state.
 * Resets offset and lock status without stopping the clock.
 * Called during TEARDOWN to allow re-sync on new session.
 */
void ptp_clock_clear(void);

/**
 * Check if PTP is locked to a master clock.
 * @return true if synchronized with acceptable accuracy
 */
bool ptp_clock_is_locked(void);

/**
 * Get current PTP time in nanoseconds.
 * Returns local time adjusted by PTP offset.
 * @return PTP time in nanoseconds since epoch
 */
uint64_t ptp_clock_get_time_ns(void);

/**
 * Get current offset from local clock to PTP time in nanoseconds.
 * PTP_time = local_time + offset
 */
int64_t ptp_clock_get_offset_ns(void);

/**
 * Get synchronization statistics.
 */
typedef struct {
    uint32_t sync_count;        // Number of SYNC messages received
    uint32_t followup_count;    // Number of FOLLOW_UP messages received
    int64_t last_offset_ns;     // Last measured offset
    int64_t filtered_offset_ns; // Filtered/averaged offset
    uint32_t lock_time_ms;      // Time since lock achieved (0 if not locked)
} ptp_stats_t;

void ptp_clock_get_stats(ptp_stats_t *stats);
