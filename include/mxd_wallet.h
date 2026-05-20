#ifndef MXD_WALLET_H
#define MXD_WALLET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_address.h"
#include "mxd_crypto.h"

// Provisional MXD coin type per MXD-02 §7.2 (pending SLIP-44 PR).
#define MXD_SLIP44_COIN_TYPE  19800

// Result of a wallet derivation. Caller owns nothing dynamic — buffers are inline.
typedef struct {
  uint8_t algo_id;                // MXD_SIGALG_ED25519 only for v2
  uint8_t pub32[32];              // Ed25519 public key
  uint8_t priv32[32];             // Ed25519 32-byte canonical seed (NOT libsodium 64-byte form)
  uint8_t addr32[32];
  char address_mainnet[MXD_ADDR_STR_MAX];
  char address_testnet[MXD_ADDR_STR_MAX];
} mxd_wallet_v2_t;

// Derive an Ed25519 wallet per MXD-02:
//   mnemonic   → BIP-39 seed (with passphrase)
//   seed       → SLIP-10 master at "ed25519 seed"
//   path       → m/44'/19800'/account'/0'
//   priv32 → Ed25519_PublicKey → pub32
//   pub32  → addr32 → address_mainnet / address_testnet
// Returns 0 on success, -1 on error. Caller MUST `mxd_wallet_v2_free(out)` to
// zero sensitive material when done.
int mxd_wallet_derive_v2(const char *mnemonic, const char *passphrase,
                          uint32_t account, mxd_wallet_v2_t *out);

void mxd_wallet_v2_free(mxd_wallet_v2_t *w);  // sodium_memzero on priv fields

#ifdef __cplusplus
}
#endif

#endif  // MXD_WALLET_H
