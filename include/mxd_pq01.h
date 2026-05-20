#ifndef MXD_PQ01_H
#define MXD_PQ01_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_address.h"

// MXD-PQ-01 Dilithium5 HD derivation per the v1.0.x spec.
//
// Master constant: "ml-dsa seed" (deliberately distinct from SLIP-10's
// "ed25519 seed"; see MXD-PQ-01 §3 for tree-independence rationale).
//
// HD derivation propagates a 32-byte ξ at each level, NOT the full 4896-byte
// ML-DSA-87 private key. ML-DSA-87.KeyGen is invoked only at the leaf.

#define MXD_PQ01_MASTER_KEY  "ml-dsa seed"
#define MXD_PQ01_XI_LEN      32

// Master derivation: HMAC-SHA-512(key="ml-dsa seed", BIP-39 seed) → (ξ32, chain32)
int mxd_pq01_master(const uint8_t bip39_seed[64],
                     uint8_t out_xi32[MXD_PQ01_XI_LEN],
                     uint8_t out_chain32[32]);

// Hardened child derivation, SLIP-10-shape:
// HMAC-SHA-512(chain, 0x00 || parent_ξ || ser32_be(index|0x80000000)) → (ξ32', chain32')
int mxd_pq01_child(const uint8_t parent_xi32[MXD_PQ01_XI_LEN],
                    const uint8_t parent_chain32[32],
                    uint32_t index_normal,
                    uint8_t out_xi32[MXD_PQ01_XI_LEN],
                    uint8_t out_chain32[32]);

// Convenience: traverse m/44'/coin'/account'/0' from a BIP-39 seed.
int mxd_pq01_derive_mxd_path(const uint8_t bip39_seed[64],
                              uint32_t coin_type, uint32_t account,
                              uint8_t out_leaf_xi32[MXD_PQ01_XI_LEN],
                              uint8_t out_leaf_chain32[32]);

// Leaf KeyGen: deterministic ML-DSA-87 from 32-byte ξ per FIPS 204 §6.1.
// Calls pqcrystals_dilithium5_ref_keypair_internal from the vendored
// pq-crystals reference; key sizes match DILITHIUM_MODE=5 (K=8, L=7, ETA=2):
//   public key  = 2592 bytes
//   secret key  = 4896 bytes
int mxd_pq01_keygen_at_leaf(const uint8_t leaf_xi32[MXD_PQ01_XI_LEN],
                             uint8_t out_pub2592[2592],
                             uint8_t out_priv4896[4896]);

#ifdef __cplusplus
}
#endif

#endif  // MXD_PQ01_H
