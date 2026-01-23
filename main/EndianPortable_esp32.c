/*
 * Wrapper for EndianPortable.c that ensures proper endianness detection on ESP32
 * ESP32 is little-endian, so we need to make sure the swap functions work correctly
 */

#include <endian.h>  // This defines __BYTE_ORDER and __LITTLE_ENDIAN on ESP-IDF

// Now include the original implementation
#include "EndianPortable.c"
