#ifndef MXD_CRYPTO_H
#define MXD_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef enum {
    MXD_SIGALG_ED25519 = 1,
    MXD_SIGALG_DILITHIUM5 = 2
} mxd_sig_alg_t;

#define MXD_PUBKEY_MAX_LEN 2592
#define MXD_PRIVKEY_MAX_LEN 4896  /* FIPS 204 ML-DSA-87 (was 4864 Round-3, updated Task 7.3) */
#define MXD_SIG_MAX_LEN 4627      /* FIPS 204 ML-DSA-87 (was 4595 Round-3, updated Task 7.3) */

size_t mxd_sig_pubkey_len(uint8_t algo_id);
size_t mxd_sig_privkey_len(uint8_t algo_id);
size_t mxd_sig_signature_len(uint8_t algo_id);
const char* mxd_sig_alg_name(uint8_t algo_id);

// SHA-512 hashing
int mxd_sha512(const uint8_t *input, size_t length, uint8_t output[64]);

// SHA-256 hashing
int mxd_sha256(const uint8_t *input, size_t length, uint8_t output[32]);

// Argon2 key derivation (SENSITIVE: ~1GB memory, use for user passwords)
int mxd_argon2(const char *input, const uint8_t *salt, uint8_t *output,
               size_t output_length);

// Argon2 key derivation (INTERACTIVE: ~64MB memory, use for node keypairs)
// Use mxd_argon2_lowmem_n for binary input that may contain null bytes
int mxd_argon2_lowmem(const char *input, const uint8_t *salt, uint8_t *output,
                      size_t output_length);
int mxd_argon2_lowmem_n(const uint8_t *input, size_t input_length,
                        const uint8_t *salt, uint8_t *output,
                        size_t output_length);

int mxd_sig_keygen(uint8_t algo_id, uint8_t *public_key, uint8_t *secret_key);
int mxd_sig_keygen_seeded(uint8_t algo_id, uint8_t *public_key, uint8_t *secret_key,
                          const uint8_t *seed, size_t seed_len);
int mxd_sig_sign(uint8_t algo_id, uint8_t *signature, size_t *signature_length,
                 const uint8_t *message, size_t message_length,
                 const uint8_t *secret_key);
int mxd_sig_verify(uint8_t algo_id, const uint8_t *signature, size_t signature_length,
                   const uint8_t *message, size_t message_length,
                   const uint8_t *public_key);

// mxd_derive_address() is declared in mxd_address.h (moved in MXD-01 v1.1.x refactor).

int mxd_dilithium_keygen(uint8_t *public_key, uint8_t *secret_key);
int mxd_dilithium_sign(uint8_t *signature, size_t *signature_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *secret_key);
int mxd_dilithium_verify(const uint8_t *signature, size_t signature_length,
                         const uint8_t *message, size_t message_length,
                         const uint8_t *public_key);

#ifdef __cplusplus
}
#endif

#endif // MXD_CRYPTO_H
