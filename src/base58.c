#include "base58.h"
#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int base58_encode(const uint8_t *data, size_t data_len, char *output,
                  size_t max_length) {
  if (!data || !output || data_len == 0 || max_length == 0) {
    return -1;
  }

  // Debug output
  printf("Input data (%zu bytes):\n", data_len);
  for (size_t i = 0; i < data_len; i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");

  // Handle MXD address prefix
  char *out_ptr = output;
  size_t remaining_length = max_length;

  if (data_len == 25 && data[0] == 0x32) {
    if (max_length < 42)
      return -1;
    out_ptr[0] = 'm';
    out_ptr[1] = 'x';
    out_ptr += 2;
    remaining_length -= 2;
  }

  // Count leading zeros
  size_t leading_zeros = 0;
  while (leading_zeros < data_len && data[leading_zeros] == 0) {
    leading_zeros++;
  }

  // Handle special case for all zeros
  if (leading_zeros == data_len) {
    if (data_len + 1 > remaining_length)
      return -1;
    memset(out_ptr, '1', data_len);
    out_ptr[data_len] = '\0';
    return 0;
  }

  // Initialize GMP integers
  mpz_t bn, bn_rem;
  mpz_init(bn);
  mpz_init(bn_rem);

  // Convert input to big number
  mpz_import(bn, data_len, 1, 1, 1, 0, data);

  // Convert to base58 string
  char *reversed_output = (char *)calloc(data_len * 2, sizeof(char));
  if (!reversed_output) {
    mpz_clear(bn);
    mpz_clear(bn_rem);
    return -1;
  }
  size_t output_len = 0;

  // Process until number becomes zero
  while (mpz_cmp_ui(bn, 0) > 0) {
    if (output_len >= data_len * 2) {
      free(reversed_output);
      mpz_clear(bn);
      mpz_clear(bn_rem);
      return -1;
    }

    // Get remainder when divided by 58
    mpz_tdiv_qr_ui(bn, bn_rem, bn, 58);
    reversed_output[output_len++] = BASE58_ALPHABET[mpz_get_ui(bn_rem)];
  }

  // Handle case where input was all zeros but we didn't catch it
  if (output_len == 0) {
    output_len = 1;
    reversed_output[0] = BASE58_ALPHABET[0];
  }

  // Add leading '1's for zeros
  if (leading_zeros + output_len + 1 > remaining_length) {
    free(reversed_output);
    mpz_clear(bn);
    mpz_clear(bn_rem);
    return -1;
  }
  memset(out_ptr, '1', leading_zeros);
  out_ptr += leading_zeros;

  // Reverse the string
  for (size_t i = 0; i < output_len; i++) {
    out_ptr[i] = reversed_output[output_len - 1 - i];
  }
  out_ptr[output_len] = '\0';

  // Debug output
  printf("Output string: %s\n", output);

  // Cleanup
  free(reversed_output);
  mpz_clear(bn);
  mpz_clear(bn_rem);
  return 0;
}

int base58_decode(const char *input, uint8_t *output, size_t *output_len) {
  if (!input || !output || !output_len || *output_len == 0) {
    return -1;
  }

  size_t input_len = strlen(input);
  if (input_len == 0) {
    return -1;
  }

  // Count leading '1's
  size_t zeros = 0;
  for (size_t i = 0; i < input_len && input[i] == '1'; i++) {
    zeros++;
  }

  // Handle special case for all zeros
  if (zeros == input_len) {
    if (zeros > *output_len) {
      return -1;
    }
    memset(output, 0, zeros);
    *output_len = zeros;
    return 0;
  }

  // Initialize GMP integers
  mpz_t bn;
  mpz_init(bn);
  mpz_set_ui(bn, 0);

  // Process each input character
  for (size_t i = zeros; i < input_len; i++) {
    // Lookup value in alphabet
    const char *pos = strchr(BASE58_ALPHABET, input[i]);
    if (!pos) {
      mpz_clear(bn);
      return -1;
    }
    uint32_t value = pos - BASE58_ALPHABET;

    // Multiply by 58 and add value
    mpz_mul_ui(bn, bn, 58);
    mpz_add_ui(bn, bn, value);
  }

  // Convert big number to bytes
  size_t byte_len = (mpz_sizeinbase(bn, 2) + 7) / 8;
  if (zeros + byte_len > *output_len) {
    mpz_clear(bn);
    return -1;
  }

  // Write leading zeros
  memset(output, 0, zeros);

  // Export number to bytes
  size_t count;
  mpz_export(output + zeros, &count, 1, 1, 1, 0, bn);
  *output_len = zeros + count;

  // Cleanup
  mpz_clear(bn);
  return 0;
}
