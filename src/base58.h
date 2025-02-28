#ifndef MXD_BASE58_H
#define MXD_BASE58_H

#include <stddef.h>
#include <stdint.h>

// Base58 encode a byte array into a string
int base58_encode(const uint8_t *data, size_t data_len, char *output,
                  size_t max_length);

// Base58 decode a string into a byte array
int base58_decode(const char *input, uint8_t *output, size_t *output_len);

#endif // MXD_BASE58_H
