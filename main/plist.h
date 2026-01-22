#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Simple plist builder for AirPlay
 * Builds XML plist format (easier to debug, iOS accepts it)
 */

typedef struct {
    char *buffer;
    size_t size;
    size_t capacity;
} plist_t;

/**
 * Initialize a plist builder
 */
void plist_init(plist_t *p, char *buffer, size_t capacity);

/**
 * Start XML plist document
 */
void plist_begin(plist_t *p);

/**
 * Start a dictionary
 */
void plist_dict_begin(plist_t *p);

/**
 * Add string to dictionary
 */
void plist_dict_string(plist_t *p, const char *key, const char *value);

/**
 * Add integer to dictionary
 */
void plist_dict_int(plist_t *p, const char *key, int64_t value);

/**
 * Add unsigned integer to dictionary
 */
void plist_dict_uint(plist_t *p, const char *key, uint64_t value);

/**
 * Add boolean to dictionary
 */
void plist_dict_bool(plist_t *p, const char *key, bool value);

/**
 * Add base64 data to dictionary
 */
void plist_dict_data(plist_t *p, const char *key, const uint8_t *data, size_t len);

/**
 * Add data as hex string (for pk field)
 */
void plist_dict_data_hex(plist_t *p, const char *key, const uint8_t *data, size_t len);

/**
 * End dictionary
 */
void plist_dict_end(plist_t *p);

/**
 * Start an array with key (inside dict)
 */
void plist_dict_array_begin(plist_t *p, const char *key);

/**
 * Start an array (standalone)
 */
void plist_array_begin(plist_t *p);

/**
 * End array
 */
void plist_array_end(plist_t *p);

/**
 * Add integer to array
 */
void plist_array_int(plist_t *p, int64_t value);

/**
 * End plist document
 * @return Total size of plist
 */
size_t plist_end(plist_t *p);

/**
 * Base64 decode utility
 * @param input Base64 encoded string
 * @param input_len Length of input string
 * @param output Output buffer for decoded data
 * @param output_capacity Size of output buffer
 * @return Number of bytes decoded, or -1 on error
 */
int base64_decode(const char *input, size_t input_len, uint8_t *output, size_t output_capacity);
