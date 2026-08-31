#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
  uint32_t current;
} audio_epoch_t;

void audio_epoch_init(audio_epoch_t *epoch);
uint32_t audio_epoch_get(const audio_epoch_t *epoch);
uint32_t audio_epoch_advance(audio_epoch_t *epoch);
bool audio_epoch_matches(const audio_epoch_t *epoch, uint32_t value);
