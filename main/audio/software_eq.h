#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Software 15-band EQ for boards without TAS58xx hardware EQ.
 *
 * PCM format is interleaved stereo int16_t. frame_count is stereo frames,
 * not individual samples.
 */
esp_err_t software_eq_init(uint32_t sample_rate);
void software_eq_set_sample_rate(uint32_t sample_rate);
void software_eq_process(int16_t *pcm, size_t frame_count);
void software_eq_clear_state(void);
bool software_eq_is_active(void);

