#pragma once

#include <stddef.h>
#include <stdint.h>

void led_visual_init(void);
void led_visual_update(const int16_t *pcm, size_t stereo_samples);
