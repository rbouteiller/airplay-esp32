// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int esp_err_t;
#define ESP_OK 0

// Time is whatever the test says it is.
extern int64_t mock_now_us;
#define esp_timer_get_time() (mock_now_us)

// Only named by audio_timeline_t, which the mock timeline never looks inside.
typedef void *SemaphoreHandle_t;
typedef int portMUX_TYPE;
