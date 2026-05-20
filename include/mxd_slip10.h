#ifndef MXD_SLIP10_H
#define MXD_SLIP10_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// SLIP-10 ed25519 hierarchical deterministic key derivation per MXD-02 §5, §6.
//
// All derivation in this module is HARDENED — SLIP-10 ed25519 does not
// support non-hardened (xpub-style) derivation.

#define MXD_SLIP10_PRIV_LEN  32
#define MXD_SLIP10_CHAIN_LEN 32

// Master constant for SLIP-10 ed25519, MXD-02 §5. Distinct from MXD-PQ-01's
// "ml-dsa seed" — see MXD-PQ-01 §3 for the rationale on tree independence.
#define MXD_SLIP10_ED25519_MASTER_KEY  "ed25519 seed"

// Derive the SLIP-10 ed25519 master from a BIP-39 seed.
//   seed:        64 bytes (output of mxd_bip39_seed)
//   out_priv32:  receives 32-byte master private key
//   out_chain32: receives 32-byte master chain code
// Returns 0 on success, -1 on error.
int mxd_slip10_ed25519_master(const uint8_t seed[64],
                               uint8_t out_priv32[MXD_SLIP10_PRIV_LEN],
                               uint8_t out_chain32[MXD_SLIP10_CHAIN_LEN]);

// Derive a hardened child from a parent (priv32, chain32).
//   parent_priv32:  parent's 32-byte private key
//   parent_chain32: parent's 32-byte chain code
//   index_normal:   the non-hardened index in [0, 2^31 - 1]; the function
//                   adds the hardened bit internally (i.e. caller passes 44,
//                   not 0x8000002C).
//   out_priv32 / out_chain32: receive the child's (priv, chain).
// Returns 0 on success, -1 on error.
int mxd_slip10_ed25519_child(const uint8_t parent_priv32[MXD_SLIP10_PRIV_LEN],
                              const uint8_t parent_chain32[MXD_SLIP10_CHAIN_LEN],
                              uint32_t index_normal,
                              uint8_t out_priv32[MXD_SLIP10_PRIV_LEN],
                              uint8_t out_chain32[MXD_SLIP10_CHAIN_LEN]);

// Convenience: traverse `m/44'/coin'/account'/0'` from a BIP-39 seed.
// All four indices are hardened. account is the user-facing account number
// (caller passes 0, 1, 2, ...; this function adds the hardened bit).
//   coin_type:    19800 for MXD per MXD-02 §7.2 (caller passes the raw value).
// Returns 0 on success, -1 on error.
int mxd_slip10_ed25519_derive_mxd_path(const uint8_t seed[64],
                                        uint32_t coin_type,
                                        uint32_t account,
                                        uint8_t out_priv32[MXD_SLIP10_PRIV_LEN],
                                        uint8_t out_chain32[MXD_SLIP10_CHAIN_LEN]);

#ifdef __cplusplus
}
#endif

#endif  // MXD_SLIP10_H
