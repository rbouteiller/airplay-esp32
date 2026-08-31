#pragma once
/**
 * Coefficient RAM addresses of the cascaded EQ biquads (Book 0xAA).
 *
 * Both parts expose 15 sections per channel. Which filter each section runs
 * is decided at runtime — see tas58xx_biquad.c — so only the addresses are
 * fixed here.
 *
 * Addresses from the mrtoy-me/esphome-tas58xx reference.
 */

#include <stdint.h>

#define EQ_COEFF_BYTES 20 /* 5 coefficients × 4 bytes */

/** One section's location: { page, sub-address within the page }. */
typedef struct {
  uint8_t page;
  uint8_t sub_addr;
} eq_bq_addr_t;

static const eq_bq_addr_t tas5805m_eq_left_addr[15] = {
    {0x24, 0x18}, // BQ1  Left
    {0x24, 0x2c}, // BQ2  Left
    {0x24, 0x40}, // BQ3  Left
    {0x24, 0x54}, // BQ4  Left
    {0x24, 0x68}, // BQ5  Left
    {0x24, 0x7c}, // BQ6  Left
    {0x25, 0x18}, // BQ7  Left
    {0x25, 0x2c}, // BQ8  Left
    {0x25, 0x40}, // BQ9  Left
    {0x25, 0x54}, // BQ10 Left
    {0x25, 0x68}, // BQ11 Left
    {0x25, 0x7c}, // BQ12 Left
    {0x26, 0x18}, // BQ13 Left
    {0x26, 0x2c}, // BQ14 Left
    {0x26, 0x40}, // BQ15 Left
};

static const eq_bq_addr_t tas5805m_eq_right_addr[15] = {
    {0x26, 0x54}, // BQ1  Right
    {0x26, 0x68}, // BQ2  Right
    {0x26, 0x7c}, // BQ3  Right
    {0x27, 0x18}, // BQ4  Right
    {0x27, 0x2c}, // BQ5  Right
    {0x27, 0x40}, // BQ6  Right
    {0x27, 0x54}, // BQ7  Right
    {0x27, 0x68}, // BQ8  Right
    {0x27, 0x7c}, // BQ9  Right
    {0x28, 0x18}, // BQ10 Right
    {0x28, 0x2c}, // BQ11 Right
    {0x28, 0x40}, // BQ12 Right
    {0x28, 0x54}, // BQ13 Right
    {0x28, 0x68}, // BQ14 Right
    {0x28, 0x7c}, // BQ15 Right
};

static const eq_bq_addr_t tas5825m_eq_left_addr[15] = {
    {0x01, 0x30}, // BQ1  Left
    {0x01, 0x44}, // BQ2  Left
    {0x01, 0x58}, // BQ3  Left
    {0x01, 0x6C}, // BQ4  Left
    {0x02, 0x08}, // BQ5  Left
    {0x02, 0x1C}, // BQ6  Left
    {0x02, 0x30}, // BQ7  Left
    {0x02, 0x44}, // BQ8  Left
    {0x02, 0x58}, // BQ9  Left
    {0x02, 0x6C}, // BQ10 Left
    {0x03, 0x08}, // BQ11 Left
    {0x03, 0x1C}, // BQ12 Left
    {0x03, 0x30}, // BQ13 Left
    {0x03, 0x44}, // BQ14 Left
    {0x03, 0x58}, // BQ15 Left
};

static const eq_bq_addr_t tas5825m_eq_right_addr[15] = {
    {0x03, 0x6C}, // BQ1  Right
    {0x04, 0x08}, // BQ2  Right
    {0x04, 0x1C}, // BQ3  Right
    {0x04, 0x30}, // BQ4  Right
    {0x04, 0x44}, // BQ5  Right
    {0x04, 0x58}, // BQ6  Right
    {0x04, 0x6C}, // BQ7  Right
    {0x05, 0x08}, // BQ8  Right
    {0x05, 0x1C}, // BQ9  Right
    {0x05, 0x30}, // BQ10 Right
    {0x05, 0x44}, // BQ11 Right
    {0x05, 0x58}, // BQ12 Right
    {0x05, 0x6C}, // BQ13 Right
    {0x06, 0x08}, // BQ14 Right
    {0x06, 0x1C}, // BQ15 Right
};
