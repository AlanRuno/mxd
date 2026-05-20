#include "../include/mxd_pq01.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <string.h>

int mxd_pq01_master(const uint8_t seed[64], uint8_t out_xi32[32], uint8_t out_chain32[32]) {
  if (!seed || !out_xi32 || !out_chain32) return -1;
  uint8_t buf[64];
  unsigned int len = 64;
  if (!HMAC(EVP_sha512(),
            MXD_PQ01_MASTER_KEY, (int)strlen(MXD_PQ01_MASTER_KEY),
            seed, 64,
            buf, &len) || len != 64) {
    return -1;
  }
  memcpy(out_xi32, buf, 32);
  memcpy(out_chain32, buf + 32, 32);
  sodium_memzero(buf, sizeof(buf));
  return 0;
}

int mxd_pq01_child(const uint8_t parent_xi32[32], const uint8_t parent_chain32[32],
                    uint32_t index_normal, uint8_t out_xi32[32], uint8_t out_chain32[32]) {
  if (!parent_xi32 || !parent_chain32 || !out_xi32 || !out_chain32) return -1;
  if (index_normal >= 0x80000000U) return -1;
  uint32_t hardened = index_normal | 0x80000000U;

  uint8_t data[1 + 32 + 4];
  data[0] = 0x00;
  memcpy(data + 1, parent_xi32, 32);
  data[33] = (uint8_t)(hardened >> 24);
  data[34] = (uint8_t)(hardened >> 16);
  data[35] = (uint8_t)(hardened >> 8);
  data[36] = (uint8_t)hardened;

  uint8_t buf[64];
  unsigned int len = 64;
  if (!HMAC(EVP_sha512(),
            parent_chain32, 32,
            data, sizeof(data),
            buf, &len) || len != 64) {
    sodium_memzero(data, sizeof(data));
    return -1;
  }
  memcpy(out_xi32, buf, 32);
  memcpy(out_chain32, buf + 32, 32);
  sodium_memzero(buf, sizeof(buf));
  sodium_memzero(data, sizeof(data));
  return 0;
}

int mxd_pq01_derive_mxd_path(const uint8_t seed[64], uint32_t coin_type, uint32_t account,
                              uint8_t out_xi32[32], uint8_t out_chain32[32]) {
  if (!seed || !out_xi32 || !out_chain32) return -1;
  uint8_t xi[32], chain[32];
  if (mxd_pq01_master(seed, xi, chain) != 0) return -1;
  uint32_t levels[4] = {44, coin_type, account, 0};
  for (int i = 0; i < 4; i++) {
    uint8_t nxi[32], nc[32];
    if (mxd_pq01_child(xi, chain, levels[i], nxi, nc) != 0) {
      sodium_memzero(xi, sizeof(xi));
      sodium_memzero(chain, sizeof(chain));
      return -1;
    }
    memcpy(xi, nxi, 32);
    memcpy(chain, nc, 32);
    sodium_memzero(nxi, sizeof(nxi));
    sodium_memzero(nc, sizeof(nc));
  }
  memcpy(out_xi32, xi, 32);
  memcpy(out_chain32, chain, 32);
  sodium_memzero(xi, sizeof(xi));
  sodium_memzero(chain, sizeof(chain));
  return 0;
}

/* pq-crystals reference (vendor/ml-dsa-pqcrystals/ref/sign.c) exposes a
 * seeded keypair API added by the MXD patch.  With DILITHIUM_MODE=5 the
 * namespaced symbol is pqcrystals_dilithium5_ref_keypair_internal.
 *
 * FIPS 204 §6.1: ML-DSA.KeyGen takes a 32-byte seed ξ deterministically.
 * Public key  = 2592 bytes (SEEDBYTES + K*POLYT1_PACKEDBYTES, K=8).
 * Secret key  = 4896 bytes (2*SEEDBYTES + TRBYTES + (L+K)*POLYETA_PACKEDBYTES
 *                            + K*POLYT0_PACKEDBYTES, L=7 K=8 ETA=2).
 */
extern int pqcrystals_dilithium5_ref_keypair_internal(
    uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);

int mxd_pq01_keygen_at_leaf(const uint8_t leaf_xi32[32],
                             uint8_t out_pub2592[2592], uint8_t out_priv4896[4896]) {
  if (!leaf_xi32 || !out_pub2592 || !out_priv4896) return -1;
  return pqcrystals_dilithium5_ref_keypair_internal(out_pub2592, out_priv4896, leaf_xi32);
}
