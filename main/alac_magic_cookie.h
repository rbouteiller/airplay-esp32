#pragma once

#include "audio_receiver.h"

#define ALAC_MAGIC_COOKIE_SIZE 24

void build_alac_magic_cookie(uint8_t *cookie, const audio_format_t *fmt);
