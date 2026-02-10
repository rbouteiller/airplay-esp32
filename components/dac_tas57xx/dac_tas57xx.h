#pragma once

#include "dac.h"

/**
 * TAS57xx DAC driver ops — register with dac_register() before calling
 * dac_init().
 */
extern const dac_ops_t dac_tas57xx_ops;
