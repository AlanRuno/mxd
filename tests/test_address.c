#include "../include/mxd_address.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_passphrase_generation(void) {
  char passphrase[256];
  
  TEST_START("Passphrase Generation");
  
  TEST_ASSERT(mxd_generate_passphrase(passphrase, sizeof(passphrase)) == 0, "Generate passphrase");
  TEST_VALUE("Generated passphrase", "%s", passphrase);

  // Verify we got 12 words
  int word_count = 1;
  for (const char *p = passphrase; *p; p++) {
    if (*p == ' ')
      word_count++;
  }
  TEST_ASSERT(word_count == 12, "Passphrase contains exactly 12 words");
  
  TEST_END("Passphrase Generation");
}

static void test_property_key_derivation(void) {
  const char *test_passphrase = "test passphrase";
  const char *test_pin = "1234";
  uint8_t property_key[64];

  TEST_START("Property Key Derivation");
  TEST_VALUE("Test passphrase", "%s", test_passphrase);
  TEST_VALUE("Test PIN", "%s", test_pin);
  
  TEST_ASSERT(mxd_derive_property_key(test_passphrase, test_pin, property_key) == 0, "Property key derivation successful");
  TEST_ARRAY("Derived property key", property_key, 64);

  // Property key should not be all zeros
  int is_zero = 1;
  for (int i = 0; i < 64; i++) {
    if (property_key[i] != 0) {
      is_zero = 0;
      break;
    }
  }
  TEST_ASSERT(!is_zero, "Property key is not empty");

  TEST_END("Property Key Derivation");
}

static void test_keypair_generation(void) {
  uint8_t property_key[64] = {1}; // Test property key
  uint8_t public_key[256];
  uint8_t private_key[128];

  TEST_START("Keypair Generation");
  TEST_ARRAY("Input property key", property_key, 64);
  
  TEST_ASSERT(mxd_generate_keypair(property_key, public_key, private_key) == 0, "Keypair generation successful");
  TEST_ARRAY("Generated public key", public_key, 256);
  TEST_ARRAY("Generated private key", private_key, 128);

  // Keys should not be all zeros
  int pub_zero = 1, priv_zero = 1;
  for (int i = 0; i < 256; i++) {
    if (i < 128 && private_key[i] != 0)
      priv_zero = 0;
    if (public_key[i] != 0)
      pub_zero = 0;
  }
  TEST_ASSERT(!pub_zero && !priv_zero, "Generated keys are not empty");

  TEST_END("Keypair Generation");
}

static void test_address_generation(void) {
  // Test vector: all zeros
  uint8_t zero_key[256] = {0};
  char zero_address[42];
  assert(mxd_generate_address(zero_key, zero_address, sizeof(zero_address)) ==
         0);
  printf("Zero address: %s\n", zero_address);
  assert(strlen(zero_address) > 25);
  assert(mxd_validate_address(zero_address) == 0);

  // Test vector: all ones
  uint8_t one_key[256];
  memset(one_key, 0xFF, sizeof(one_key));
  char one_address[42];
  assert(mxd_generate_address(one_key, one_address, sizeof(one_address)) == 0);
  printf("One address: %s\n", one_address);
  assert(strlen(one_address) > 25);
  assert(mxd_validate_address(one_address) == 0);

  // Test vector: incremental bytes
  uint8_t inc_key[256];
  for (int i = 0; i < 256; i++) {
    inc_key[i] = (uint8_t)i;
  }
  char inc_address[42];
  assert(mxd_generate_address(inc_key, inc_address, sizeof(inc_address)) == 0);
  printf("Inc address: %s\n", inc_address);
  assert(strlen(inc_address) > 25);
  assert(mxd_validate_address(inc_address) == 0);

  // Test invalid cases
  assert(mxd_generate_address(NULL, inc_address, sizeof(inc_address)) == -1);
  assert(mxd_generate_address(inc_key, NULL, sizeof(inc_address)) == -1);
  assert(mxd_generate_address(inc_key, inc_address, 20) == -1);

  // Test address validation
  assert(mxd_validate_address(NULL) == -1);
  assert(mxd_validate_address("") == -1);
  assert(mxd_validate_address("invalid") == -1);

  // Test checksum validation
  char invalid_address[42];
  strcpy(invalid_address, inc_address);
  invalid_address[strlen(invalid_address) - 1]++; // Modify last character
  assert(mxd_validate_address(invalid_address) == -1);

  printf("Address generation test passed\n");
}

int main(void) {
  printf("Starting address management tests...\n");

  test_passphrase_generation();
  test_property_key_derivation();
  test_keypair_generation();
  test_address_generation();

  printf("All address management tests passed\n");
  return 0;
}
