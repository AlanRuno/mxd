#include "../include/mxd_wallet.h"
#include "../include/mxd_bip39.h"
#include "test_utils.h"
#include <string.h>
#include <stdio.h>

static void test_wallet_v2_reproducibility(void) {
  TEST_START("Wallet V2 Reproducibility");

  mxd_wallet_v2_t w1, w2;
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", 0, &w1) == 0,
    "First derivation returns 0");
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", 0, &w2) == 0,
    "Second derivation returns 0");
  TEST_ASSERT(memcmp(w1.pub32, w2.pub32, 32) == 0,
    "pub32 is byte-identical on two calls");
  TEST_ASSERT(memcmp(w1.priv32, w2.priv32, 32) == 0,
    "priv32 is byte-identical on two calls");
  TEST_ASSERT(memcmp(w1.addr32, w2.addr32, 32) == 0,
    "addr32 is byte-identical on two calls");
  TEST_ASSERT(strcmp(w1.address_mainnet, w2.address_mainnet) == 0,
    "address_mainnet is identical on two calls");
  mxd_wallet_v2_free(&w1);
  mxd_wallet_v2_free(&w2);

  TEST_END("Wallet V2 Reproducibility");
}

static void test_wallet_v2_passphrase_separates_trees(void) {
  TEST_START("Wallet V2 Passphrase Separates Trees");

  mxd_wallet_v2_t w_no, w_yes;
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", 0, &w_no) == 0,
    "Derivation with empty passphrase returns 0");
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "TREZOR", 0, &w_yes) == 0,
    "Derivation with TREZOR passphrase returns 0");
  TEST_ASSERT(memcmp(w_no.pub32, w_yes.pub32, 32) != 0,
    "Different passphrases produce different pub32");
  mxd_wallet_v2_free(&w_no);
  mxd_wallet_v2_free(&w_yes);

  TEST_END("Wallet V2 Passphrase Separates Trees");
}

static void test_wallet_v2_account_separates_trees(void) {
  TEST_START("Wallet V2 Account Separates Trees");

  mxd_wallet_v2_t w0, w7;
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", 0, &w0) == 0,
    "Derivation for account 0 returns 0");
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about",
    "", 7, &w7) == 0,
    "Derivation for account 7 returns 0");
  TEST_ASSERT(memcmp(w0.pub32, w7.pub32, 32) != 0,
    "Account 0 and account 7 produce different pub32");
  TEST_ASSERT(strcmp(w0.address_mainnet, w7.address_mainnet) != 0,
    "Account 0 and account 7 produce different address_mainnet");
  mxd_wallet_v2_free(&w0);
  mxd_wallet_v2_free(&w7);

  TEST_END("Wallet V2 Account Separates Trees");
}

static void test_wallet_v2_reject_invalid_mnemonic(void) {
  TEST_START("Wallet V2 Reject Invalid Mnemonic");

  mxd_wallet_v2_t w;
  /* 12 "abandon"s — bad BIP-39 checksum (last word should be "about") */
  TEST_ASSERT(mxd_wallet_derive_v2(
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon",
    "", 0, &w) == -1,
    "Bad checksum mnemonic returns -1");

  TEST_END("Wallet V2 Reject Invalid Mnemonic");
}

int main(void) {
  printf("Starting wallet_v2 tests...\n");

  test_wallet_v2_reproducibility();
  test_wallet_v2_passphrase_separates_trees();
  test_wallet_v2_account_separates_trees();
  test_wallet_v2_reject_invalid_mnemonic();

  printf("All wallet_v2 tests passed\n");
  return 0;
}
