#include "mxd_logging.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_pq01.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <sodium.h>
#include <sodium/crypto_sign.h>
#include <oqs/oqs.h>
#include <string.h>
#include <pthread.h>

/* pq-crystals ML-DSA-87 (FIPS 204) sign / verify / keypair_internal.
 * These are the namespaced symbols produced by vendor/ml-dsa-pqcrystals/ref/
 * compiled with DILITHIUM_MODE=5.  Secret key is 4896 bytes; signature is
 * 4627 bytes — both FIPS 204 sizes, distinct from liboqs round-3 Dilithium5
 * (4864 / 4595 bytes).  Keygen, sign and verify for MXD_SIGALG_DILITHIUM5
 * are routed exclusively through these symbols (Outcome B1, Task 7.3).
 */
extern int pqcrystals_dilithium5_ref_keypair_internal(
    uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
extern int pqcrystals_dilithium5_ref_signature(uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t *sk);
extern int pqcrystals_dilithium5_ref_verify(const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t *pk);

// Initialize OpenSSL and libsodium (thread-safe via pthread_once)
static pthread_once_t crypto_init_once = PTHREAD_ONCE_INIT;
static int crypto_init_result = 0;

static void do_crypto_init(void) {
  // Initialize OpenSSL
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                          OPENSSL_INIT_ADD_ALL_CIPHERS |
                          OPENSSL_INIT_ADD_ALL_DIGESTS,
                      NULL);

  // Initialize libsodium
  if (sodium_init() < 0) {
    crypto_init_result = -1;
    return;
  }
  crypto_init_result = 0;
}

static int ensure_crypto_init(void) {
  pthread_once(&crypto_init_once, do_crypto_init);
  return crypto_init_result;
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
// WARNING: This function uses strlen() and will truncate at null bytes.
// For binary input, use mxd_argon2_lowmem_n() instead.
int mxd_argon2_lowmem(const char *input, const uint8_t *salt, uint8_t *output,
                      size_t output_length) {
  return mxd_argon2_lowmem_n((const uint8_t *)input, strlen(input), salt, output, output_length);
}

// Argon2 key derivation with explicit input length (safe for binary data)
int mxd_argon2_lowmem_n(const uint8_t *input, size_t input_length,
                        const uint8_t *salt, uint8_t *output,
                        size_t output_length) {
  if (ensure_crypto_init() < 0) {
    return -1;
  }

  MXD_LOG_INFO("crypto", "Using Argon2 INTERACTIVE profile: memlimit=%zu MB, opslimit=%llu",
               crypto_pwhash_MEMLIMIT_INTERACTIVE / (1024*1024),
               (unsigned long long)crypto_pwhash_OPSLIMIT_INTERACTIVE);

  if (crypto_pwhash(output, output_length, (const char *)input, input_length, salt,
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
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
  if (!sig) {
    return -1;
  }
  int rc = OQS_SIG_keypair(sig, public_key, secret_key);
  OQS_SIG_free(sig);
  return rc == OQS_SUCCESS ? 0 : -1;
}

// Dilithium5 signing
int mxd_dilithium_sign(uint8_t *signature, size_t *signature_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *secret_key) {
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
}

// Dilithium5 verification
int mxd_dilithium_verify(const uint8_t *signature, size_t signature_length,
                         const uint8_t *message, size_t message_length,
                         const uint8_t *public_key) {
  OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
  if (!sig) {
    return -1;
  }
  int rc = OQS_SIG_verify(sig, message, message_length, signature, signature_length, public_key);
  OQS_SIG_free(sig);
  return rc == OQS_SUCCESS ? 0 : -1;
}

size_t mxd_sig_pubkey_len(uint8_t algo_id) {
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      return 32;
    case MXD_SIGALG_DILITHIUM5:
      return 2592;
    default:
      return 0;
  }
}

size_t mxd_sig_privkey_len(uint8_t algo_id) {
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      return 64;
    case MXD_SIGALG_DILITHIUM5:
      return 4896;  /* FIPS 204 ML-DSA-87 (updated Task 7.3; was 4864 Round-3) */
    default:
      return 0;
  }
}

size_t mxd_sig_signature_len(uint8_t algo_id) {
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      return 64;
    case MXD_SIGALG_DILITHIUM5:
      return 4627;  /* FIPS 204 ML-DSA-87 (updated Task 7.3; was 4595 Round-3) */
    default:
      return 0;
  }
}

const char* mxd_sig_alg_name(uint8_t algo_id) {
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      return "Ed25519";
    case MXD_SIGALG_DILITHIUM5:
      return "Dilithium5";
    default:
      return "Unknown";
  }
}

int mxd_sig_keygen(uint8_t algo_id, uint8_t *public_key, uint8_t *secret_key) {
  if (ensure_crypto_init() < 0) {
    return -1;
  }
  
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      return crypto_sign_keypair(public_key, secret_key);
    
    case MXD_SIGALG_DILITHIUM5:
      {
        /* Random (non-seeded) keygen: generate a random 32-byte ξ then
         * delegate to the pq-crystals FIPS 204 path so the key format
         * matches mxd_sig_keygen_seeded and mxd_sig_sign/verify.       */
        uint8_t xi[32];
        OQS_randombytes(xi, 32);
        int rc = pqcrystals_dilithium5_ref_keypair_internal(public_key, secret_key, xi);
        sodium_memzero(xi, sizeof(xi));
        return rc;
      }

    default:
      MXD_LOG_ERROR("crypto", "Unknown signature algorithm: %u", algo_id);
      return -1;
  }
}

/* mxd_sig_keygen_seeded — deterministic keypair from a caller-supplied seed.
 *
 * MXD-PQ-01 v1.0.x compliance pass (Task 7.3):
 *   The previous DILITHIUM5 path expanded the seed with HKDF-SHA256 into an
 *   8160-byte buffer and fed it to liboqs via OQS_randombytes_custom_algorithm.
 *   That approach used the Round-3 Dilithium5 format (4864-byte SK, 4595-byte
 *   sig) which is incompatible with FIPS 204 ML-DSA-87.
 *
 *   The new path calls mxd_pq01_keygen_at_leaf(seed[0..31], ...) which
 *   dispatches to pqcrystals_dilithium5_ref_keypair_internal — the FIPS 204
 *   §6.1 ML-DSA.KeyGen(ξ) primitive.  SK is 4896 bytes; signature is 4627
 *   bytes.  mxd_sig_sign and mxd_sig_verify also route DILITHIUM5 through
 *   pq-crystals so keygen, sign and verify are all on the same code path.
 *
 *   liboqs dilithium_5 is no longer used for keygen, sign or verify.
 *   It remains in the binary for the random-seed keygen path (mxd_sig_keygen)
 *   and for any future non-Dilithium5 algorithms.
 *
 *   seeded_buf, seeded_pos, hkdf_expand_seed, seeded_randombytes and
 *   OQS_randombytes_custom_algorithm calls removed here.
 */
int mxd_sig_keygen_seeded(uint8_t algo_id, uint8_t *public_key, uint8_t *secret_key,
                          const uint8_t *seed, size_t seed_len) {
  if (ensure_crypto_init() < 0 || !seed || seed_len < 32) {
    return -1;
  }

  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      /* libsodium has native seeded keygen — use first 32 bytes of seed */
      return crypto_sign_seed_keypair(public_key, secret_key, seed);

    case MXD_SIGALG_DILITHIUM5:
      {
        /* Per MXD-PQ-01 §6: ML-DSA-87.KeyGen takes the 32-byte ξ directly.
         * Caller is expected to pass a leaf ξ from mxd_pq01_derive_mxd_path.
         * seed[0..31] is used as ξ; bytes beyond 32 are ignored.           */
        if (seed_len < 32) return -1;
        return mxd_pq01_keygen_at_leaf(seed, public_key, secret_key);
      }

    default:
      MXD_LOG_ERROR("crypto", "Unknown signature algorithm: %u", algo_id);
      return -1;
  }
}

int mxd_sig_sign(uint8_t algo_id, uint8_t *signature, size_t *signature_length,
                 const uint8_t *message, size_t message_length,
                 const uint8_t *secret_key) {
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      {
        unsigned long long sig_len;
        int result = crypto_sign_detached(signature, &sig_len, message,
                                          message_length, secret_key);
        *signature_length = (size_t)sig_len;
        return result;
      }
    
    case MXD_SIGALG_DILITHIUM5:
      {
        /* Route through pq-crystals FIPS 204 ML-DSA-87 — keys are 4896-byte
         * format produced by mxd_sig_keygen / mxd_sig_keygen_seeded.
         * Empty context string (ctx=NULL, ctxlen=0) per MXD-PQ-01 §6.       */
        size_t sig_len = 0;
        int rc = pqcrystals_dilithium5_ref_signature(
            signature, &sig_len,
            message, message_length,
            NULL, 0,
            secret_key);
        if (rc != 0) return -1;
        *signature_length = sig_len;
        return 0;
      }

    default:
      MXD_LOG_ERROR("crypto", "Unknown signature algorithm: %u", algo_id);
      return -1;
  }
}

int mxd_sig_verify(uint8_t algo_id, const uint8_t *signature, size_t signature_length,
                   const uint8_t *message, size_t message_length,
                   const uint8_t *public_key) {
  /* MXD-03 §6 — Length validation is a security boundary.  Check signature_length
   * before dispatching to any primitive.  Callers MUST pass a pubkey buffer
   * whose size matches mxd_sig_pubkey_len(algo_id); this function cannot verify
   * that without a pubkey_length parameter, so callers own that invariant.     */
  switch (algo_id) {
    case MXD_SIGALG_ED25519:
      /* Ed25519: signature must be exactly 64 bytes (RFC 8032 §5.1). */
      if (signature_length != 64) return -1;
      return crypto_sign_verify_detached(signature, message, message_length,
                                         public_key);

    case MXD_SIGALG_DILITHIUM5:
      {
        /* Dilithium5 / ML-DSA-87: signature must be exactly 4627 bytes (FIPS 204).
         * Empty context string matches the sign path above.                   */
        if (signature_length != 4627) return -1;
        return pqcrystals_dilithium5_ref_verify(
            signature, signature_length,
            message, message_length,
            NULL, 0,
            public_key);
      }

    default:
      MXD_LOG_ERROR("crypto", "Unknown signature algorithm: %u", algo_id);
      return -1;
  }
}

// mxd_derive_address() has been moved to src/mxd_address.c (MXD-01 v1.1.x §4).
// Declaration is in include/mxd_address.h.  Do not add a new definition here.
