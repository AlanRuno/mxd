#include "../include/mxd_slip10.h"
#include "../include/mxd_bip39.h"
#include "test_utils.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Test 1: SLIP-10 reference vector 1 — 16-byte seed                  */
/* Bypasses mxd_slip10_ed25519_master directly since the spec uses a  */
/* 16-byte seed while our wrapper takes 64. Proves key constant +     */
/* HMAC-SHA-512 algorithm choice match SLIP-10.                       */
/* Seed: 000102030405060708090a0b0c0d0e0f (16 bytes)                  */
/* ------------------------------------------------------------------ */
static void test_slip10_master_vector_1(void) {
  TEST_START("SLIP-10 Master Key Vector 1 (16-byte seed, HMAC-SHA-512 direct)");

  static const uint8_t seed16[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };

  static const uint8_t expected_priv[32] = {
    0x2b, 0x4b, 0xe7, 0xf1, 0x9e, 0xe2, 0x7b, 0xbf,
    0x30, 0xc6, 0x67, 0xb6, 0x42, 0xd5, 0xf4, 0xaa,
    0x69, 0xfd, 0x16, 0x98, 0x72, 0xf8, 0xfc, 0x30,
    0x59, 0xc0, 0x8e, 0xba, 0xe2, 0xeb, 0x19, 0xe7
  };

  static const uint8_t expected_chain[32] = {
    0x90, 0x04, 0x6a, 0x93, 0xde, 0x53, 0x80, 0xa7,
    0x2b, 0x5e, 0x45, 0x01, 0x07, 0x48, 0x56, 0x7d,
    0x5e, 0xa0, 0x2b, 0xbf, 0x65, 0x22, 0xf9, 0x79,
    0xe0, 0x5c, 0x0d, 0x8d, 0x8c, 0xa9, 0xff, 0xfb
  };

  uint8_t buf[64];
  unsigned int len = 64;
  const char *key = MXD_SLIP10_ED25519_MASTER_KEY;

  /* Call OpenSSL HMAC-SHA-512 directly with the 16-byte seed */
  TEST_ASSERT(
    HMAC(EVP_sha512(),
         key, (int)strlen(key),
         seed16, sizeof(seed16),
         buf, &len) != NULL,
    "HMAC-SHA-512 call succeeded");
  TEST_ASSERT(len == 64, "HMAC output is 64 bytes");

  TEST_ASSERT(memcmp(buf, expected_priv, 32) == 0,
              "First 32 bytes match SLIP-10 vector 1 master private key");
  TEST_ASSERT(memcmp(buf + 32, expected_chain, 32) == 0,
              "Last 32 bytes match SLIP-10 vector 1 master chain code");

  TEST_END("SLIP-10 Master Key Vector 1 (16-byte seed, HMAC-SHA-512 direct)");
}

/* ------------------------------------------------------------------ */
/* Test 2: mxd_slip10_ed25519_master with 64-byte BIP-39 seed         */
/* Derives seed from "abandon x11 about" + empty passphrase, then     */
/* verifies: returns 0, output non-zero, deterministic.               */
/* ------------------------------------------------------------------ */
static void test_slip10_master_with_64byte_seed(void) {
  TEST_START("SLIP-10 Master Key from 64-byte BIP-39 Seed (determinism + non-zero)");

  const char *mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
  const char *passphrase = "";

  uint8_t seed[MXD_BIP39_SEED_LEN];
  TEST_ASSERT(mxd_bip39_seed(mnemonic, passphrase, seed) == 0,
              "mxd_bip39_seed returns 0 for standard mnemonic");

  uint8_t priv1[32], chain1[32];
  int rc = mxd_slip10_ed25519_master(seed, priv1, chain1);
  TEST_ASSERT(rc == 0, "mxd_slip10_ed25519_master returns 0");

  /* Sanity: at least one byte non-zero in each output */
  int priv_nonzero = 0, chain_nonzero = 0;
  for (int i = 0; i < 32; i++) {
    if (priv1[i] != 0)  priv_nonzero  = 1;
    if (chain1[i] != 0) chain_nonzero = 1;
  }
  TEST_ASSERT(priv_nonzero,  "Master private key is non-zero");
  TEST_ASSERT(chain_nonzero, "Master chain code is non-zero");

  /* Determinism: second call with same seed must produce identical output */
  uint8_t priv2[32], chain2[32];
  TEST_ASSERT(mxd_slip10_ed25519_master(seed, priv2, chain2) == 0,
              "Second mxd_slip10_ed25519_master call returns 0");
  TEST_ASSERT(memcmp(priv1, priv2, 32) == 0,
              "Master private key is deterministic");
  TEST_ASSERT(memcmp(chain1, chain2, 32) == 0,
              "Master chain code is deterministic");

  TEST_END("SLIP-10 Master Key from 64-byte BIP-39 Seed (determinism + non-zero)");
}

/* ------------------------------------------------------------------ */
/* Test 3: SLIP-10 reference vector 1 — hardened child m/0'           */
/* Uses master priv/chain from vector 1 (Task 2.2) fed directly into  */
/* mxd_slip10_ed25519_child with index_normal=0 (→ 0x80000000).       */
/* Expected from SLIP-10 spec:                                        */
/*   child priv: 68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3 */
/*   child chain: 8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69 */
/* ------------------------------------------------------------------ */
static void test_slip10_child_vector_1(void) {
  TEST_START("SLIP-10 Hardened Child m/0' Vector 1 (index_normal=0 → 0x80000000)");

  static const uint8_t master_priv[32] = {
    0x2b, 0x4b, 0xe7, 0xf1, 0x9e, 0xe2, 0x7b, 0xbf,
    0x30, 0xc6, 0x67, 0xb6, 0x42, 0xd5, 0xf4, 0xaa,
    0x69, 0xfd, 0x16, 0x98, 0x72, 0xf8, 0xfc, 0x30,
    0x59, 0xc0, 0x8e, 0xba, 0xe2, 0xeb, 0x19, 0xe7
  };

  static const uint8_t master_chain[32] = {
    0x90, 0x04, 0x6a, 0x93, 0xde, 0x53, 0x80, 0xa7,
    0x2b, 0x5e, 0x45, 0x01, 0x07, 0x48, 0x56, 0x7d,
    0x5e, 0xa0, 0x2b, 0xbf, 0x65, 0x22, 0xf9, 0x79,
    0xe0, 0x5c, 0x0d, 0x8d, 0x8c, 0xa9, 0xff, 0xfb
  };

  static const uint8_t expected_child_priv[32] = {
    0x68, 0xe0, 0xfe, 0x46, 0xdf, 0xb6, 0x7e, 0x36,
    0x8c, 0x75, 0x37, 0x9a, 0xce, 0xc5, 0x91, 0xda,
    0xd1, 0x9d, 0xf3, 0xcd, 0xe2, 0x6e, 0x63, 0xb9,
    0x3a, 0x8e, 0x70, 0x4f, 0x1d, 0xad, 0xe7, 0xa3
  };

  static const uint8_t expected_child_chain[32] = {
    0x8b, 0x59, 0xaa, 0x11, 0x38, 0x0b, 0x62, 0x4e,
    0x81, 0x50, 0x7a, 0x27, 0xfe, 0xdd, 0xa5, 0x9f,
    0xea, 0x6d, 0x0b, 0x77, 0x9a, 0x77, 0x89, 0x18,
    0xa2, 0xfd, 0x35, 0x90, 0xe1, 0x6e, 0x9c, 0x69
  };

  uint8_t child_priv[32], child_chain[32];
  int rc = mxd_slip10_ed25519_child(master_priv, master_chain, 0,
                                    child_priv, child_chain);
  TEST_ASSERT(rc == 0, "mxd_slip10_ed25519_child returns 0");

  TEST_ASSERT(memcmp(child_priv, expected_child_priv, 32) == 0,
              "Child private key matches SLIP-10 vector 1 m/0'");
  TEST_ASSERT(memcmp(child_chain, expected_child_chain, 32) == 0,
              "Child chain code matches SLIP-10 vector 1 m/0'");

  TEST_END("SLIP-10 Hardened Child m/0' Vector 1 (index_normal=0 → 0x80000000)");
}

/* ------------------------------------------------------------------ */
/* Test 4: mxd_slip10_ed25519_derive_mxd_path — determinism           */
/* Derives the MXD canonical path twice from the same BIP-39 seed and */
/* verifies that both calls produce identical (priv, chain) output.   */
/* ------------------------------------------------------------------ */
static void test_slip10_mxd_path_is_reproducible(void) {
  TEST_START("SLIP-10 MXD Path m/44'/19800'/0'/0' is reproducible");

  const char *mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
  const char *passphrase = "";

  uint8_t seed[MXD_BIP39_SEED_LEN];
  TEST_ASSERT(mxd_bip39_seed(mnemonic, passphrase, seed) == 0,
              "mxd_bip39_seed returns 0");

  uint8_t p1[32], c1[32];
  TEST_ASSERT(mxd_slip10_ed25519_derive_mxd_path(seed, 19800, 0, p1, c1) == 0,
              "First derive_mxd_path call returns 0");

  uint8_t p2[32], c2[32];
  TEST_ASSERT(mxd_slip10_ed25519_derive_mxd_path(seed, 19800, 0, p2, c2) == 0,
              "Second derive_mxd_path call returns 0");

  TEST_ASSERT(memcmp(p1, p2, 32) == 0,
              "Private key is identical across both calls (deterministic)");
  TEST_ASSERT(memcmp(c1, c2, 32) == 0,
              "Chain code is identical across both calls (deterministic)");

  TEST_END("SLIP-10 MXD Path m/44'/19800'/0'/0' is reproducible");
}

/* ------------------------------------------------------------------ */
/* Test 5: mxd_slip10_ed25519_derive_mxd_path — account separation    */
/* Same seed, account=0 vs account=7 must produce DIFFERENT private   */
/* keys, proving hardened account-level derivation works correctly.   */
/* ------------------------------------------------------------------ */
static void test_slip10_mxd_path_account_separation(void) {
  TEST_START("SLIP-10 MXD Path account=0 and account=7 produce distinct keys");

  const char *mnemonic =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
  const char *passphrase = "";

  uint8_t seed[MXD_BIP39_SEED_LEN];
  TEST_ASSERT(mxd_bip39_seed(mnemonic, passphrase, seed) == 0,
              "mxd_bip39_seed returns 0");

  uint8_t p0[32], c0[32];
  TEST_ASSERT(mxd_slip10_ed25519_derive_mxd_path(seed, 19800, 0, p0, c0) == 0,
              "derive_mxd_path account=0 returns 0");

  uint8_t p7[32], c7[32];
  TEST_ASSERT(mxd_slip10_ed25519_derive_mxd_path(seed, 19800, 7, p7, c7) == 0,
              "derive_mxd_path account=7 returns 0");

  TEST_ASSERT(memcmp(p0, p7, 32) != 0,
              "account=0 and account=7 produce different private keys");

  TEST_END("SLIP-10 MXD Path account=0 and account=7 produce distinct keys");
}

int main(void) {
  printf("Starting SLIP-10 tests...\n");

  test_slip10_master_vector_1();
  test_slip10_master_with_64byte_seed();
  test_slip10_child_vector_1();
  test_slip10_mxd_path_is_reproducible();
  test_slip10_mxd_path_account_separation();

  printf("All SLIP-10 tests passed\n");
  return 0;
}
