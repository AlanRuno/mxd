#include "../include/mxd_crypto.h"
#include "test_utils.h"
#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

static void test_sha512(void) {
  const char *input = "test message";
  uint8_t output[64];

  TEST_START("SHA-512");
  TEST_VALUE("Input string", "%s", input);
  
  mxd_sha512((const uint8_t *)input, strlen(input), output);
  TEST_ARRAY("Output hash", output, 64);
  
  TEST_ASSERT(output[0] != 0 || output[1] != 0, "Hash is not empty");
  TEST_END("SHA-512");
}

static void test_ripemd160(void) {
  const char *input = "test message";
  uint8_t output[20];

  TEST_START("RIPEMD-160");
  TEST_VALUE("Input string", "%s", input);
  
  mxd_ripemd160((const uint8_t *)input, strlen(input), output);
  TEST_ARRAY("Output hash", output, 20);
  
  TEST_ASSERT(output[0] != 0 || output[1] != 0, "Hash is not empty");
  TEST_END("RIPEMD-160");
}

static void test_argon2(void) {
  const char *input = "test password";
  const uint8_t salt[16] = "MXDTestSalt1234";
  uint8_t output[32];

  TEST_START("Argon2");
  TEST_VALUE("Input password", "%s", input);
  TEST_ARRAY("Salt", salt, 16);
  
  mxd_argon2(input, salt, output, sizeof(output));
  TEST_ARRAY("Output key", output, 32);
  
  TEST_ASSERT(output[0] != 0 || output[1] != 0, "Key is not empty");
  TEST_END("Argon2");
}

static void test_dilithium(void) {
  uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
  uint8_t secret_key[crypto_sign_SECRETKEYBYTES];

  TEST_START("Dilithium");
  
  // Test key generation
  TEST_ASSERT(mxd_dilithium_keygen(public_key, secret_key) == 0, "Key generation successful");
  TEST_ARRAY("Public key", public_key, crypto_sign_PUBLICKEYBYTES);
  
  // Test signing
  const char *message = "test message";
  uint8_t signature[crypto_sign_BYTES];
  size_t signature_length;

  TEST_VALUE("Message to sign", "%s", message);
  TEST_ASSERT(mxd_dilithium_sign(signature, &signature_length,
                            (const uint8_t *)message, strlen(message),
                            secret_key) == 0, "Message signing successful");
  TEST_ARRAY("Signature", signature, signature_length);

  // Test verification
  TEST_ASSERT(mxd_dilithium_verify(signature, signature_length,
                              (const uint8_t *)message, strlen(message),
                              public_key) == 0, "Signature verification successful");
  
  TEST_END("Dilithium");
}

int main(void) {
  TEST_START("Cryptographic Tests");
  
  if (sodium_init() < 0) {
    printf("Failed to initialize libsodium\n");
    return 1;
  }

  // ISO/IEC 10118-3 (Hash Functions)
  test_sha512();
  test_ripemd160();

  // ISO/IEC 11889 (Key Derivation)
  test_argon2();

  // ISO/IEC 18033-3 (Post-Quantum Signatures)
  test_dilithium();

  TEST_END("Cryptographic Tests");
  return 0;
}
