#include "../include/mxd_wallet.h"
#include "../include/mxd_bip39.h"
#include "../include/mxd_slip10.h"
#include "../include/mxd_logging.h"
#include <sodium.h>
#include <string.h>

int mxd_wallet_derive_v2(const char *mnemonic, const char *passphrase,
                          uint32_t account, mxd_wallet_v2_t *out) {
  if (!mnemonic || !out) return -1;
  if (mxd_bip39_validate(mnemonic) != 0) return -1;

  uint8_t seed[64], priv[32], chain[32];
  if (mxd_bip39_seed(mnemonic, passphrase ? passphrase : "", seed) != 0) return -1;
  if (mxd_slip10_ed25519_derive_mxd_path(seed, MXD_SLIP44_COIN_TYPE, account, priv, chain) != 0) {
    sodium_memzero(seed, sizeof(seed));
    return -1;
  }
  sodium_memzero(seed, sizeof(seed));
  sodium_memzero(chain, sizeof(chain));

  // Derive ed25519 public key from the 32-byte seed.
  unsigned char sk_libsodium[64], pk[32];
  if (crypto_sign_seed_keypair(pk, sk_libsodium, priv) != 0) {
    sodium_memzero(priv, sizeof(priv));
    return -1;
  }
  // sk_libsodium = seed(32) || pub(32). Discard the libsodium 64-byte form;
  // canonical export per MXD-03 §4.3 is the 32-byte seed.
  sodium_memzero(sk_libsodium, sizeof(sk_libsodium));

  memset(out, 0, sizeof(*out));
  out->algo_id = MXD_SIGALG_ED25519;
  memcpy(out->pub32, pk, 32);
  memcpy(out->priv32, priv, 32);
  sodium_memzero(priv, sizeof(priv));

  if (mxd_derive_address(MXD_SIGALG_ED25519, out->pub32, 32, out->addr32) != 0) return -1;
  if (mxd_address_to_string(MXD_SIGALG_ED25519, out->pub32, 32, /*mainnet*/1,
                              out->address_mainnet, sizeof(out->address_mainnet)) != 0) return -1;
  if (mxd_address_to_string(MXD_SIGALG_ED25519, out->pub32, 32, /*mainnet*/0,
                              out->address_testnet, sizeof(out->address_testnet)) != 0) return -1;
  return 0;
}

void mxd_wallet_v2_free(mxd_wallet_v2_t *w) {
  if (!w) return;
  sodium_memzero(w->priv32, sizeof(w->priv32));
  // pub32, addr32, addresses are not sensitive; zero everything for hygiene.
  memset(w, 0, sizeof(*w));
}
