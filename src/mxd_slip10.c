#include "../include/mxd_slip10.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <sodium.h>

int mxd_slip10_ed25519_master(const uint8_t seed[64],
                               uint8_t out_priv32[32],
                               uint8_t out_chain32[32]) {
  if (!seed || !out_priv32 || !out_chain32) return -1;

  uint8_t buf[64];
  unsigned int len = 64;
  if (!HMAC(EVP_sha512(),
            MXD_SLIP10_ED25519_MASTER_KEY,
            (int)strlen(MXD_SLIP10_ED25519_MASTER_KEY),
            seed, 64,
            buf, &len) || len != 64) {
    return -1;
  }
  memcpy(out_priv32, buf, 32);
  memcpy(out_chain32, buf + 32, 32);
  sodium_memzero(buf, sizeof(buf));
  return 0;
}

int mxd_slip10_ed25519_child(const uint8_t parent_priv32[32],
                              const uint8_t parent_chain32[32],
                              uint32_t index_normal,
                              uint8_t out_priv32[32],
                              uint8_t out_chain32[32]) {
  if (!parent_priv32 || !parent_chain32 || !out_priv32 || !out_chain32) return -1;
  if (index_normal >= 0x80000000U) return -1;  /* caller-side hardened-only invariant */

  uint32_t hardened = index_normal | 0x80000000U;

  /* data = 0x00 || parent_priv32 || ser32_be(hardened) */
  uint8_t data[1 + 32 + 4];
  data[0] = 0x00;
  memcpy(data + 1, parent_priv32, 32);
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
  memcpy(out_priv32, buf, 32);
  memcpy(out_chain32, buf + 32, 32);
  sodium_memzero(buf, sizeof(buf));
  sodium_memzero(data, sizeof(data));
  return 0;
}

int mxd_slip10_ed25519_derive_mxd_path(const uint8_t seed[64],
                                        uint32_t coin_type,
                                        uint32_t account,
                                        uint8_t out_priv32[32],
                                        uint8_t out_chain32[32]) {
  uint8_t priv[32], chain[32];
  if (mxd_slip10_ed25519_master(seed, priv, chain) != 0) return -1;

  uint32_t levels[4] = { 44, coin_type, account, 0 };
  for (int i = 0; i < 4; i++) {
    uint8_t np[32], nc[32];
    if (mxd_slip10_ed25519_child(priv, chain, levels[i], np, nc) != 0) {
      sodium_memzero(priv, 32); sodium_memzero(chain, 32);
      return -1;
    }
    memcpy(priv, np, 32);
    memcpy(chain, nc, 32);
    sodium_memzero(np, 32); sodium_memzero(nc, 32);
  }
  memcpy(out_priv32, priv, 32);
  memcpy(out_chain32, chain, 32);
  sodium_memzero(priv, 32);
  sodium_memzero(chain, 32);
  return 0;
}
