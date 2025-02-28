#include "../include/mxd_crypto.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <sodium.h>
#include <sodium/crypto_sign.h>
#include <stdio.h>
#include <string.h>

// Initialize OpenSSL and libsodium
static int ensure_crypto_init(void) {
  static int initialized = 0;
  if (!initialized) {
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                            OPENSSL_INIT_ADD_ALL_CIPHERS |
                            OPENSSL_INIT_ADD_ALL_DIGESTS,
                        NULL);

    // Initialize libsodium
    if (sodium_init() < 0) {
      return -1;
    }
    initialized = 1;
  }
  return 0;
}

// SHA-1 hashing implementation using OpenSSL 3.0 EVP interface
int mxd_sha1(const uint8_t *input, size_t length, uint8_t output[20]) {
  if (ensure_crypto_init() < 0) {
    printf("SHA-1: Failed to initialize crypto\n");
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    printf("SHA-1: Failed to create context\n");
    return -1;
  }

  if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)) {
    printf("SHA-1: Failed to initialize digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestUpdate(ctx, input, length)) {
    printf("SHA-1: Failed to update digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestFinal_ex(ctx, output, NULL)) {
    printf("SHA-1: Failed to finalize digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);
  return 0;
}

// SHA-512 hashing implementation using OpenSSL 3.0 EVP interface
int mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]) {
  if (ensure_crypto_init() < 0) {
    printf("SHA-512: Failed to initialize crypto\n");
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    printf("SHA-512: Failed to create context\n");
    return -1;
  }

  if (!EVP_DigestInit_ex(ctx, EVP_sha512(), NULL)) {
    printf("SHA-512: Failed to initialize digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestUpdate(ctx, input, length)) {
    printf("SHA-512: Failed to update digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestFinal_ex(ctx, output, NULL)) {
    printf("SHA-512: Failed to finalize digest\n");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);
  return 0;
}

// RIPEMD-160 hashing implementation using OpenSSL legacy interface
int mxd_ripemd160(const uint8_t *input, size_t length, uint8_t output[20]) {
  if (ensure_crypto_init() < 0) {
    printf("RIPEMD-160: Failed to initialize crypto\n");
    return -1;
  }

  printf("RIPEMD-160: Input length %zu bytes:\n", length);
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", input[i]);
  }
  printf("\n");

  RIPEMD160_CTX ctx;
  if (!RIPEMD160_Init(&ctx)) {
    printf("RIPEMD-160: Failed to initialize context\n");
    return -1;
  }

  if (!RIPEMD160_Update(&ctx, input, length)) {
    printf("RIPEMD-160: Failed to update digest\n");
    return -1;
  }

  if (!RIPEMD160_Final(output, &ctx)) {
    printf("RIPEMD-160: Failed to finalize digest\n");
    return -1;
  }

  return 0;
}

// Argon2 key derivation implementation
int mxd_argon2(const char *input, const uint8_t *salt, uint8_t *output,
               size_t output_length) {
  if (ensure_crypto_init() < 0) {
    return -1;
  }

  // Using Argon2id variant as recommended for highest security
  if (crypto_pwhash(output, output_length, input, strlen(input), salt,
                    crypto_pwhash_OPSLIMIT_SENSITIVE,
                    crypto_pwhash_MEMLIMIT_SENSITIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    return -1; // Memory allocation or other error
  }
  return 0;
}

// Dilithium5 key generation
int mxd_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key) {
  if (ensure_crypto_init() < 0) {
    return -1;
  }

  // Generate keypair using Dilithium5
  return crypto_sign_keypair(public_key, secret_key);
}

// Dilithium5 signing
int mxd_dilithium_sign(uint8_t *signature, size_t *signature_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *secret_key) {
  unsigned long long sig_len;
  int result = crypto_sign_detached(signature, &sig_len, message,
                                    message_length, secret_key);
  *signature_length = (size_t)sig_len;
  return result;
}

// Dilithium5 verification
int mxd_dilithium_verify(const uint8_t *signature, size_t signature_length,
                         const uint8_t *message, size_t message_length,
                         const uint8_t *public_key) {
  return crypto_sign_verify_detached(signature, message, message_length,
                                     public_key);
}
