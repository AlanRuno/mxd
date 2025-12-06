#include "mxd_logging.h"
#include "../include/mxd_crypto.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <sodium.h>
#include <sodium/crypto_sign.h>
#ifdef MXD_PQC_DILITHIUM
#include <oqs/oqs.h>
#endif
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
    MXD_LOG_ERROR("crypto", "SHA-1: Failed to initialize crypto");
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    MXD_LOG_ERROR("crypto", "SHA-1: Failed to create context");
    return -1;
  }

  if (!EVP_DigestInit_ex(ctx, EVP_sha1(), NULL)) {
    MXD_LOG_ERROR("crypto", "SHA-1: Failed to initialize digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestUpdate(ctx, input, length)) {
    MXD_LOG_ERROR("crypto", "SHA-1: Failed to update digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestFinal_ex(ctx, output, NULL)) {
    MXD_LOG_ERROR("crypto", "SHA-1: Failed to finalize digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);
  return 0;
}

// SHA-256 hashing implementation using OpenSSL 3.0 EVP interface
int mxd_sha256(const uint8_t *input, size_t length, uint8_t output[32]) {
  if (ensure_crypto_init() < 0) {
    MXD_LOG_ERROR("crypto", "SHA-256: Failed to initialize crypto");
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    MXD_LOG_ERROR("crypto", "SHA-256: Failed to create context");
    return -1;
  }

  if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
    MXD_LOG_ERROR("crypto", "SHA-256: Failed to initialize digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestUpdate(ctx, input, length)) {
    MXD_LOG_ERROR("crypto", "SHA-256: Failed to update digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestFinal_ex(ctx, output, NULL)) {
    MXD_LOG_ERROR("crypto", "SHA-256: Failed to finalize digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);
  return 0;
}

// SHA-512 hashing implementation using OpenSSL 3.0 EVP interface
int mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]) {
  if (ensure_crypto_init() < 0) {
    MXD_LOG_ERROR("crypto", "SHA-512: Failed to initialize crypto");
    return -1;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    MXD_LOG_ERROR("crypto", "SHA-512: Failed to create context");
    return -1;
  }

  if (!EVP_DigestInit_ex(ctx, EVP_sha512(), NULL)) {
    MXD_LOG_ERROR("crypto", "SHA-512: Failed to initialize digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestUpdate(ctx, input, length)) {
    MXD_LOG_ERROR("crypto", "SHA-512: Failed to update digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  if (!EVP_DigestFinal_ex(ctx, output, NULL)) {
    MXD_LOG_ERROR("crypto", "SHA-512: Failed to finalize digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }

  EVP_MD_CTX_free(ctx);
  return 0;
}

// RIPEMD-160 hashing implementation using OpenSSL legacy interface
int mxd_ripemd160(const uint8_t *input, size_t length, uint8_t output[20]) {
  if (ensure_crypto_init() < 0) {
    MXD_LOG_ERROR("crypto", "RIPEMD-160: Failed to initialize crypto");
    return -1;
  }

  RIPEMD160_CTX ctx;
  if (!RIPEMD160_Init(&ctx)) {
    MXD_LOG_ERROR("crypto", "RIPEMD-160: Failed to initialize context");
    return -1;
  }

  if (!RIPEMD160_Update(&ctx, input, length)) {
    MXD_LOG_ERROR("crypto", "RIPEMD-160: Failed to update digest");
    return -1;
  }

  if (!RIPEMD160_Final(output, &ctx)) {
    MXD_LOG_ERROR("crypto", "RIPEMD-160: Failed to finalize digest");
    return -1;
  }

  return 0;
}

int mxd_hash160(const uint8_t *input, size_t length, uint8_t output[20]) {
  if (ensure_crypto_init() < 0) {
    MXD_LOG_ERROR("crypto", "HASH160: Failed to initialize crypto");
    return -1;
  }
  
  uint8_t sha256_output[32];
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) {
    MXD_LOG_ERROR("crypto", "HASH160: Failed to create SHA-256 context");
    return -1;
  }
  
  if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
    MXD_LOG_ERROR("crypto", "HASH160: Failed to initialize SHA-256 digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  
  if (!EVP_DigestUpdate(ctx, input, length)) {
    MXD_LOG_ERROR("crypto", "HASH160: Failed to update SHA-256 digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  
  if (!EVP_DigestFinal_ex(ctx, sha256_output, NULL)) {
    MXD_LOG_ERROR("crypto", "HASH160: Failed to finalize SHA-256 digest");
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  
  EVP_MD_CTX_free(ctx);
  
  return mxd_ripemd160(sha256_output, 32, output);
}

// Argon2 key derivation implementation (SENSITIVE: ~1GB memory)
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
    return -1;
  }
  return 0;
}

// Argon2 key derivation implementation (INTERACTIVE: ~64MB memory)
int mxd_argon2_lowmem(const char *input, const uint8_t *salt, uint8_t *output,
                      size_t output_length) {
  if (ensure_crypto_init() < 0) {
    return -1;
  }

  // Using Argon2id variant with INTERACTIVE memlimit (~64MB)
  MXD_LOG_INFO("crypto", "Using Argon2 INTERACTIVE profile: memlimit=%zu MB, opslimit=%llu",
               crypto_pwhash_MEMLIMIT_INTERACTIVE / (1024*1024),
               (unsigned long long)crypto_pwhash_OPSLIMIT_INTERACTIVE);
  
  if (crypto_pwhash(output, output_length, input, strlen(input), salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    return -1;
  }
  return 0;
}

// Dilithium5 key generation
int mxd_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key) {
  if (ensure_crypto_init() < 0) {
    return -1;
  }
#ifdef MXD_PQC_DILITHIUM
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
  if (!sig) {
    return -1;
  }
  int rc = OQS_SIG_keypair(sig, public_key, secret_key);
  OQS_SIG_free(sig);
  return rc == OQS_SUCCESS ? 0 : -1;
#else
  return crypto_sign_keypair(public_key, secret_key);
#endif
}

// Dilithium5 signing
int mxd_dilithium_sign(uint8_t *signature, size_t *signature_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *secret_key) {
#ifdef MXD_PQC_DILITHIUM
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
  if (!sig) {
    return -1;
  }
  size_t sig_len = 0;
  int rc = OQS_SIG_sign(sig, signature, &sig_len, message, message_length, secret_key);
  OQS_SIG_free(sig);
  if (rc != OQS_SUCCESS) return -1;
  *signature_length = sig_len;
  return 0;
#else
  unsigned long long sig_len;
  int result = crypto_sign_detached(signature, &sig_len, message,
                                    message_length, secret_key);
  *signature_length = (size_t)sig_len;
  return result;
#endif
}

// Dilithium5 verification
int mxd_dilithium_verify(const uint8_t *signature, size_t signature_length,
                         const uint8_t *message, size_t message_length,
                         const uint8_t *public_key) {
#ifdef MXD_PQC_DILITHIUM
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
  if (!sig) {
    return -1;
  }
  int rc = OQS_SIG_verify(sig, message, message_length, signature, signature_length, public_key);
  OQS_SIG_free(sig);
  return rc == OQS_SUCCESS ? 0 : -1;
#else
  return crypto_sign_verify_detached(signature, message, message_length,
                                     public_key);
#endif
}
