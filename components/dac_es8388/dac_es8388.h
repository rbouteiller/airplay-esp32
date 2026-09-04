#pragma once

#include "dac.h"

/**
 * ES8388 DAC driver ops — register with dac_register() before calling
 * dac_init().
 */
extern const dac_ops_t dac_es8388_ops;
