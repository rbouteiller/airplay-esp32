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

// ========================================
// Binary plist parser (for AirPlay 2 SETUP)
// ========================================

/**
 * Find a data value by key in a binary plist
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param key Key to search for (e.g., "ekey", "eiv")
 * @param out_data Output buffer for data value
 * @param out_capacity Capacity of output buffer
 * @param out_len Actual length of data found
 * @return true if found, false otherwise
 */
bool bplist_find_data(const uint8_t *plist, size_t plist_len,
                      const char *key, uint8_t *out_data, size_t out_capacity, size_t *out_len);

/**
 * Find a data value by key anywhere in a binary plist
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param key Key to search for (e.g., "ekey", "eiv")
 * @param out_data Output buffer for data value
 * @param out_capacity Capacity of output buffer
 * @param out_len Actual length of data found
 * @return true if found, false otherwise
 */
bool bplist_find_data_deep(const uint8_t *plist, size_t plist_len,
                           const char *key, uint8_t *out_data, size_t out_capacity, size_t *out_len);

/**
 * Get number of stream entries in a binary plist "streams" array
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param count Output stream count
 * @return true if streams array found and count read
 */
bool bplist_get_streams_count(const uint8_t *plist, size_t plist_len, size_t *count);

/**
 * Get stream details by index from a binary plist "streams" array
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param index Stream index
 * @param type Stream type (e.g., 96)
 * @param ekey_len Length of ekey data if present
 * @param eiv_len Length of eiv data if present
 * @param shk_len Length of shk data if present
 * @return true if stream entry parsed
 */
bool bplist_get_stream_info(const uint8_t *plist, size_t plist_len,
                            size_t index, int64_t *type,
                            size_t *ekey_len, size_t *eiv_len, size_t *shk_len);

// Stream key debug info
typedef struct {
    char key[64];
    uint8_t value_type;  // See BPLIST_VALUE_*
    size_t value_len;
    int64_t int_value;
} bplist_kv_info_t;

#define BPLIST_VALUE_UNKNOWN 0
#define BPLIST_VALUE_INT     1
#define BPLIST_VALUE_DATA    2
#define BPLIST_VALUE_STRING  3
#define BPLIST_VALUE_UID     4
#define BPLIST_VALUE_ARRAY   5
#define BPLIST_VALUE_DICT    6

/**
 * Get key/value info for a stream dict (debug helper)
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param index Stream index
 * @param out Output array for key/value info
 * @param out_capacity Capacity of output array
 * @param out_count Number of items written
 * @return true if stream entry parsed
 */
bool bplist_get_stream_kv_info(const uint8_t *plist, size_t plist_len,
                               size_t index, bplist_kv_info_t *out,
                               size_t out_capacity, size_t *out_count);

/**
 * Find stream-specific crypto fields in a binary plist
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param stream_type Stream "type" to match (e.g., 96 for audio)
 * @param ekey Output buffer for encrypted key (optional)
 * @param ekey_capacity Capacity of ekey buffer
 * @param ekey_len Length of ekey found
 * @param eiv Output buffer for IV (optional)
 * @param eiv_capacity Capacity of eiv buffer
 * @param eiv_len Length of eiv found
 * @param shk Output buffer for shared key (optional)
 * @param shk_capacity Capacity of shk buffer
 * @param shk_len Length of shk found
 * @return true if any crypto field was found for the stream, false otherwise
 */
bool bplist_find_stream_crypto(const uint8_t *plist, size_t plist_len,
                               int64_t stream_type,
                               uint8_t *ekey, size_t ekey_capacity, size_t *ekey_len,
                               uint8_t *eiv, size_t eiv_capacity, size_t *eiv_len,
                               uint8_t *shk, size_t shk_capacity, size_t *shk_len);

/**
 * Find an integer value by key in a binary plist
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param key Key to search for
 * @param out_value Output for integer value
 * @return true if found, false otherwise
 */
bool bplist_find_int(const uint8_t *plist, size_t plist_len,
                     const char *key, int64_t *out_value);

/**
 * Find a real/float value by key in a binary plist
 * Handles both real and integer values (converting int to double)
 * @param plist Binary plist data
 * @param plist_len Length of plist
 * @param key Key to search for
 * @param out_value Output for double value
 * @return true if found, false otherwise
 */
bool bplist_find_real(const uint8_t *plist, size_t plist_len,
                      const char *key, double *out_value);
