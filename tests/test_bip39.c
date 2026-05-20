#include "../include/mxd_bip39.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void test_generate_12_words(void) {
  char mnemonic[256];

  TEST_START("Generate 12-Word Mnemonic");

  TEST_ASSERT(mxd_bip39_generate(128, mnemonic, sizeof(mnemonic)) == 0,
              "mxd_bip39_generate returns 0 for 128 bits");
  TEST_VALUE("Mnemonic", "%s", mnemonic);

  /* Count words: spaces + 1 */
  int word_count = 1;
  for (const char *p = mnemonic; *p; p++) {
    if (*p == ' ')
      word_count++;
  }
  TEST_ASSERT(word_count == 12, "Mnemonic contains exactly 12 words");

  /* Round-trip: validate must return 0 (checksum embedded in generation) */
  TEST_ASSERT(mxd_bip39_validate(mnemonic) == 0,
              "Generated 12-word mnemonic passes validation");

  TEST_END("Generate 12-Word Mnemonic");
}

static void test_generate_24_words(void) {
  char mnemonic[256];

  TEST_START("Generate 24-Word Mnemonic");

  TEST_ASSERT(mxd_bip39_generate(256, mnemonic, sizeof(mnemonic)) == 0,
              "mxd_bip39_generate returns 0 for 256 bits");
  TEST_VALUE("Mnemonic", "%s", mnemonic);

  int word_count = 1;
  for (const char *p = mnemonic; *p; p++) {
    if (*p == ' ')
      word_count++;
  }
  TEST_ASSERT(word_count == 24, "Mnemonic contains exactly 24 words");

  TEST_ASSERT(mxd_bip39_validate(mnemonic) == 0,
              "Generated 24-word mnemonic passes validation");

  TEST_END("Generate 24-Word Mnemonic");
}

static void test_reject_bad_entropy_bits(void) {
  char mnemonic[256];

  TEST_START("Reject Invalid Entropy Bits");

  TEST_ASSERT(mxd_bip39_generate(64, mnemonic, sizeof(mnemonic)) == -1,
              "entropy_bits=64 rejected with -1");
  TEST_ASSERT(mxd_bip39_generate(192, mnemonic, sizeof(mnemonic)) == -1,
              "entropy_bits=192 rejected with -1");

  TEST_END("Reject Invalid Entropy Bits");
}

static void test_validate_known_good(void) {
  TEST_START("Validate Known-Good Mnemonic");

  /* BIP-39 standard test vector */
  TEST_ASSERT(mxd_bip39_validate(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about") == 0,
    "Standard BIP-39 test vector passes validation");

  TEST_END("Validate Known-Good Mnemonic");
}

static void test_validate_bad_checksum(void) {
  TEST_START("Validate Bad Checksum");

  /* 12 "abandon"s — fails BIP-39 checksum (last word should be "about") */
  TEST_ASSERT(mxd_bip39_validate(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon") == -1,
    "12 'abandon' words rejected due to bad checksum");

  TEST_END("Validate Bad Checksum");
}

static void test_validate_unknown_word(void) {
  TEST_START("Validate Unknown Word");

  TEST_ASSERT(mxd_bip39_validate(
    "xyzzy xyzzy xyzzy xyzzy xyzzy xyzzy "
    "xyzzy xyzzy xyzzy xyzzy xyzzy xyzzy") == -1,
    "Mnemonic with unknown words rejected");

  TEST_END("Validate Unknown Word");
}

static void test_validate_wrong_word_count(void) {
  TEST_START("Validate Wrong Word Count");

  TEST_ASSERT(mxd_bip39_validate("abandon abandon abandon") == -1,
              "3-word mnemonic rejected (not 12 or 24)");

  TEST_END("Validate Wrong Word Count");
}

static void test_seed_with_passphrase(void) {
  TEST_START("Seed Derivation With Passphrase TREZOR");

  /* BIP-39 reference vector: "abandon" x11 + "about", passphrase "TREZOR" */
  const char *mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
  const char *passphrase = "TREZOR";
  uint8_t seed[MXD_BIP39_SEED_LEN];
  static const uint8_t expected[64] = {
    0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72,
    0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05, 0xed,
    0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e,
    0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34, 0x95, 0x53,
    0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82,
    0x64, 0xc1, 0xe1, 0xc9, 0x2f, 0x2c, 0xf1, 0x41,
    0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b,
    0x2f, 0x00, 0x16, 0x98, 0xe7, 0x46, 0x3b, 0x04
  };

  TEST_ASSERT(mxd_bip39_seed(mnemonic, passphrase, seed) == 0,
              "mxd_bip39_seed returns 0 for TREZOR passphrase");
  TEST_ASSERT(memcmp(seed, expected, 64) == 0,
              "Seed bytes match BIP-39 reference vector (TREZOR passphrase)");

  TEST_END("Seed Derivation With Passphrase TREZOR");
}

static void test_seed_empty_passphrase(void) {
  TEST_START("Seed Derivation With Empty Passphrase");

  /* BIP-39 reference vector: "abandon" x11 + "about", passphrase "" */
  const char *mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
  const char *passphrase = "";
  uint8_t seed[MXD_BIP39_SEED_LEN];
  static const uint8_t expected[64] = {
    0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08,
    0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56, 0x81,
    0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70,
    0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda, 0x5f, 0xc1,
    0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70,
    0xd0, 0x86, 0x20, 0x6d, 0xec, 0x8a, 0xa6, 0xc4,
    0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d,
    0x8d, 0x48, 0xb2, 0xd2, 0xce, 0x9e, 0x38, 0xe4
  };

  TEST_ASSERT(mxd_bip39_seed(mnemonic, passphrase, seed) == 0,
              "mxd_bip39_seed returns 0 for empty passphrase");
  TEST_ASSERT(memcmp(seed, expected, 64) == 0,
              "Seed bytes match BIP-39 reference vector (empty passphrase)");

  TEST_END("Seed Derivation With Empty Passphrase");
}

int main(void) {
  printf("Starting BIP-39 tests...\n");

  /* Validation tests first — validate is a building block for generate round-trips */
  test_validate_known_good();
  test_validate_bad_checksum();
  test_validate_unknown_word();
  test_validate_wrong_word_count();

  /* Seed derivation tests (PBKDF2-HMAC-SHA-512) */
  test_seed_with_passphrase();
  test_seed_empty_passphrase();

  /* Generation + round-trip tests */
  test_reject_bad_entropy_bits();
  test_generate_12_words();
  test_generate_24_words();

  printf("All BIP-39 tests passed\n");
  return 0;
}
