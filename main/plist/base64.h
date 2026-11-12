// SPDX-FileCopyrightText: 2026 airplay-esp32 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <stddef.h>
#include <stdint.h>

size_t base64_encoded_length(size_t input_len);
int base64_encode(const uint8_t *input, size_t input_len, char *output,
                  size_t output_capacity);
int base64_decode(const char *input, size_t input_len, uint8_t *output,
                  size_t output_capacity);
