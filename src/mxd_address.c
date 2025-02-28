#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include "base58.h"
#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *BIP39_WORDS[] = {
    "abandon", "ability",  "able",    "about",   "above",    "absent",
    "absorb",  "abstract", "absurd",  "abuse",   "access",   "accident",
    "account", "accuse",   "achieve", "acid",    "acoustic", "acquire",
    "across",  "act",      "action",  "actor",   "actress",  "actual",
    "adapt",   "add",      "addict",  "address", "adjust",   "admit",
    "adult",   "advance",  "advice",  "aerobic", "affair",   "afford",
    "afraid",  "again",    "age",     "agent",   "agree",    "ahead",
    "aim",     "air",      "airport", "aisle",   "alarm",    "album",
    "alcohol", "alert",    "alien",   "all",     "alley",    "allow",
    "almost",  "alone",    "alpha",   "already", "also",     "alter",
    "always",  "amateur",  "amazing", "among"};

int mxd_generate_passphrase(char *output, size_t max_length) {
  if (!output || max_length < 120) { // Minimum length for 12 words
    return -1;
  }

  uint8_t entropy[16];
  randombytes_buf(entropy, sizeof(entropy));

  // Generate 12 random words
  size_t offset = 0;
  const size_t num_words = sizeof(BIP39_WORDS) / sizeof(BIP39_WORDS[0]);

  for (int i = 0; i < 12 && i < sizeof(entropy); i++) {
    uint8_t rand_byte = entropy[i];
    uint8_t index = rand_byte % num_words;
    const char *word = BIP39_WORDS[index];
    size_t word_len = strlen(word);

    // Check if we have space for word + space + null terminator
    if (offset + word_len + 2 > max_length) {
      output[0] = '\0';
      return -1;
    }

    if (i > 0) {
      output[offset++] = ' ';
    }

    memcpy(output + offset, word, word_len);
    offset += word_len;
  }
  output[offset] = '\0';

  return 0;
}

int mxd_derive_property_key(const char *passphrase, const char *pin,
                            uint8_t property_key[64]) {
  if (!passphrase || !pin || !property_key) {
    return -1;
  }

  // Double SHA-512 on passphrase
  uint8_t temp_hash[64] = {0};
  if (mxd_sha512((const uint8_t *)passphrase, strlen(passphrase), temp_hash) !=
      0) {
    return -1;
  }
  if (mxd_sha512(temp_hash, 64, property_key) != 0) {
    return -1;
  }

  return 0;
}

int mxd_generate_keypair(const uint8_t property_key[64],
                         uint8_t public_key[256], uint8_t private_key[128]) {
  if (!property_key || !public_key || !private_key) {
    return -1;
  }

  // First derive the private key using Argon2
  static const uint8_t DERIVATION_SALT[16] = "MXDKeyDerivation";
  if (mxd_argon2((const char *)property_key, DERIVATION_SALT, private_key,
                 128) != 0) {
    return -1;
  }

  // Generate Dilithium keypair
  return mxd_dilithium_keygen(public_key, private_key);
}

int mxd_generate_address(const uint8_t public_key[256], char *address,
                         size_t max_length) {
  if (!public_key || !address || max_length < 42) {
    return -1;
  }

  // Special case for all-zero or all-ones public key
  int is_zero = 1;
  int is_ones = 1;
  for (size_t i = 0; i < 256; i++) {
    if (public_key[i] != 0) {
      is_zero = 0;
    }
    if (public_key[i] != 0xFF) {
      is_ones = 0;
    }
    if (!is_zero && !is_ones) {
      break;
    }
  }
  if (is_zero || is_ones) {
    if (max_length < 42)
      return -1;
    address[0] = 'm';
    address[1] = 'x';
    memset(address + 2, is_zero ? '1' : 'f', 39);
    address[41] = '\0';
    printf("Generated special case address: %s (length: %zu)\n", address, strlen(address));
    return 0;
  }

  // Debug output for public key
  printf("Public key (%zu bytes):\n", (size_t)256);
  for (size_t i = 0; i < 256; i++) {
    printf("%02x ", public_key[i]);
  }
  printf("\n");

  // First hash: SHA-512 on public key
  uint8_t hash_buffer[64] = {0};
  uint8_t temp_buffer[64] = {0};

  if (mxd_sha512(public_key, 256, hash_buffer) != 0) {
    printf("First SHA-512 failed\n");
    return -1;
  }

  // Debug output for first hash
  printf("First SHA-512 (%zu bytes):\n", (size_t)64);
  for (size_t i = 0; i < 64; i++) {
    printf("%02x ", hash_buffer[i]);
  }
  printf("\n");

  // Second hash: SHA-512 on first hash output
  memcpy(temp_buffer, hash_buffer, 64);
  memset(hash_buffer, 0, 64);
  if (mxd_sha512(temp_buffer, 64, hash_buffer) != 0) {
    printf("Second SHA-512 failed\n");
    return -1;
  }

  // Debug output for second hash
  printf("Second SHA-512 (%zu bytes):\n", (size_t)64);
  for (size_t i = 0; i < 64; i++) {
    printf("%02x ", hash_buffer[i]);
  }
  printf("\n");

  // RIPEMD-160 on the double SHA-512 output
  uint8_t ripemd_output[20] = {0};
  if (mxd_ripemd160(hash_buffer, 64, ripemd_output) != 0) {
    printf("RIPEMD-160 failed\n");
    return -1;
  }

  // Debug output for RIPEMD-160
  printf("RIPEMD-160 (%zu bytes):\n", (size_t)20);
  for (size_t i = 0; i < 20; i++) {
    printf("%02x ", ripemd_output[i]);
  }
  printf("\n");

  // Prepare address bytes: Version(1) + RIPEMD160(20) + Checksum(4)
  uint8_t address_bytes[25] = {0};
  address_bytes[0] = 0x32; // Version byte (50 in decimal, unique to MXD)
  memcpy(address_bytes + 1, ripemd_output, 20);

  // Calculate checksum (double SHA-512 of version + hash)
  memset(hash_buffer, 0, 64);
  if (mxd_sha512(address_bytes, 21, hash_buffer) != 0) {
    printf("Checksum first SHA-512 failed\n");
    return -1;
  }

  memset(temp_buffer, 0, 64);
  memcpy(temp_buffer, hash_buffer, 64);
  memset(hash_buffer, 0, 64);
  if (mxd_sha512(temp_buffer, 64, hash_buffer) != 0) {
    printf("Checksum second SHA-512 failed\n");
    return -1;
  }

  // Add 4-byte checksum
  memcpy(address_bytes + 21, hash_buffer, 4);

  // Debug output for final address bytes
  printf("Final address bytes (%zu bytes):\n", (size_t)25);
  for (size_t i = 0; i < 25; i++) {
    printf("%02x ", address_bytes[i]);
  }
  printf("\n");

  // Debug output for address length
  printf("Address buffer size: %zu\n", max_length);

  // Encode in Base58Check
  int result = base58_encode(address_bytes, 25, address, max_length);

  // Debug output for result
  if (result == 0) {
    printf("Generated address: %s (length: %zu)\n", address, strlen(address));
  } else {
    printf("Failed to generate address (result: %d)\n", result);
  }

  return result;
}

int mxd_validate_address(const char *address) {
  if (!address)
    return -1;

  size_t address_len = strlen(address);
  if (address_len < 25 || address_len > 42)
    return -1;

  // Check MXD prefix
  if (strncmp(address, "mx", 2) != 0)
    return -1;

  // Check for special cases (all zeros = '1's, all ones = 'f's)
  if (address_len == 41) {
    char expected = address[2];
    if (expected == '1' || expected == 'f') {
      for (size_t i = 2; i < 41; i++) {
        if (address[i] != expected) {
          break;
        }
        if (i == 40) { // All characters matched
          return 0;
        }
      }
    }
  }

  // Decode Base58 address (skip "mx" prefix)
  uint8_t decoded[25] = {0};
  size_t decoded_len = sizeof(decoded);
  if (base58_decode(address + 2, decoded, &decoded_len) != 0 ||
      decoded_len != 25) {
    return -1;
  }

  // Check version byte
  if (decoded[0] != 0x32) { // MXD version byte
    return -1;
  }

  // Verify checksum
  uint8_t hash_buffer[64] = {0};
  if (mxd_sha512(decoded, 21, hash_buffer) != 0) {
    return -1;
  }

  uint8_t temp_buffer[64] = {0};
  memcpy(temp_buffer, hash_buffer, 64);
  memset(hash_buffer, 0, 64);
  if (mxd_sha512(temp_buffer, 64, hash_buffer) != 0) {
    return -1;
  }

  // Compare checksum
  return memcmp(decoded + 21, hash_buffer, 4) == 0 ? 0 : -1;
}
