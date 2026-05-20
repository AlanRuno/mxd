#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include "../src/base58.h"
#include "test_utils.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// ============================================================
// Task 3.2: addr32 = SHA-512(algo_id || pubkey)[0..31]
// MXD-01 v1.1.x §4
// ============================================================

static void test_addr32_for_known_input(void) {
  uint8_t pubkey[32] = {0};  // all-zero ed25519 pub
  uint8_t addr32[MXD_ADDR32_LEN];

  TEST_START("addr32 for known input (Ed25519 all-zeros)");

  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, pubkey, 32, addr32) == 0,
              "mxd_derive_address returns 0 for valid ed25519 pubkey");

  // Compute expected on-the-fly: SHA-512(0x01 || 32 zero bytes)
  uint8_t input[33];
  input[0] = MXD_SIGALG_ED25519;
  memset(input + 1, 0, 32);
  uint8_t hash[64];
  TEST_ASSERT(mxd_sha512(input, sizeof(input), hash) == 0,
              "SHA-512 reference computation succeeds");

  TEST_ASSERT(memcmp(hash, addr32, MXD_ADDR32_LEN) == 0,
              "addr32 equals SHA-512(algo_id || pubkey)[0..31]");

  TEST_END("addr32 for known input (Ed25519 all-zeros)");
}

static void test_addr32_rejects_wrong_pubkey_len(void) {
  uint8_t pubkey[31] = {0};  // wrong length for Ed25519 (needs 32)
  uint8_t addr32[MXD_ADDR32_LEN];

  TEST_START("addr32 rejects wrong pubkey length");

  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, pubkey, 31, addr32) == -1,
              "mxd_derive_address returns -1 for wrong pubkey length");

  TEST_END("addr32 rejects wrong pubkey length");
}

static void test_addr32_algo_id_separation(void) {
  // Same pubkey bytes under different algo_id produce different addr32.
  // Ed25519 uses 32-byte pubkey; Dilithium5 uses 2592-byte pubkey.
  // Both are all-zeros here — the algo_id byte is the only difference
  // in the first 33 bytes, which is sufficient to diverge SHA-512 output.
  uint8_t pubkey32[32] = {0};
  uint8_t pubkey2592[2592] = {0};
  uint8_t a32_ed[MXD_ADDR32_LEN], a32_dl[MXD_ADDR32_LEN];

  TEST_START("addr32 algo_id separation (Ed25519 vs Dilithium5)");

  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, pubkey32, 32, a32_ed) == 0,
              "Ed25519 addr32 derivation succeeds");
  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_DILITHIUM5, pubkey2592, 2592, a32_dl) == 0,
              "Dilithium5 addr32 derivation succeeds");

  TEST_ASSERT(memcmp(a32_ed, a32_dl, MXD_ADDR32_LEN) != 0,
              "Ed25519 and Dilithium5 addr32 must differ");

  TEST_END("addr32 algo_id separation (Ed25519 vs Dilithium5)");
}

static void test_passphrase_generation(void) {
  char passphrase[256];

  TEST_START("Passphrase Generation");

  TEST_ASSERT(mxd_generate_passphrase(passphrase, sizeof(passphrase)) == 0,
              "Generate passphrase");
  TEST_VALUE("Generated passphrase", "%s", passphrase);

  int word_count = 1;
  for (const char *p = passphrase; *p; p++) {
    if (*p == ' ')
      word_count++;
  }
  TEST_ASSERT(word_count == 12, "Passphrase contains exactly 12 words");

  TEST_END("Passphrase Generation");
}

// ============================================================
// Task 3.3: 37-byte payload Base58Check encode/decode
// MXD-01 v1.1.x — "mx" + Base58(version || addr32 || checksum4)
// ============================================================

static void test_address_string_roundtrip_ed25519_mainnet(void) {
  uint8_t pub[32];
  for (int i = 0; i < 32; i++) pub[i] = (uint8_t)i;
  char addr[MXD_ADDR_STR_MAX];

  TEST_START("address_string_roundtrip_ed25519_mainnet");

  TEST_ASSERT(mxd_address_to_string(MXD_SIGALG_ED25519, pub, 32, /*mainnet*/1,
                                     addr, sizeof(addr)) == 0,
              "mxd_address_to_string returns 0 for valid ed25519 mainnet pubkey");

  // Must start with "mx"
  TEST_ASSERT(addr[0] == 'm' && addr[1] == 'x',
              "address starts with \"mx\" prefix");

  // Must pass full validation
  TEST_ASSERT(mxd_validate_address(addr) == 0,
              "mxd_validate_address accepts the generated address");

  // Round-trip parse must yield same algo_id and addr32
  uint8_t algo;
  uint8_t addr32_back[32];
  uint8_t addr32_expected[32];

  TEST_ASSERT(mxd_parse_address(addr, &algo, addr32_back) == 0,
              "mxd_parse_address succeeds on the generated address");
  TEST_ASSERT(algo == MXD_SIGALG_ED25519,
              "parsed algo_id == MXD_SIGALG_ED25519");

  TEST_ASSERT(mxd_derive_address(MXD_SIGALG_ED25519, pub, 32, addr32_expected) == 0,
              "mxd_derive_address succeeds for reference addr32");
  TEST_ASSERT(memcmp(addr32_expected, addr32_back, 32) == 0,
              "round-trip addr32 matches original derivation");

  TEST_END("address_string_roundtrip_ed25519_mainnet");
}

static void test_address_rejects_unknown_version_byte(void) {
  // Forge a 37-byte payload with version 0x40, valid checksum.
  uint8_t payload[37];
  memset(payload, 0, sizeof(payload));
  payload[0] = 0x40;
  for (int i = 1; i <= 32; i++) payload[i] = (uint8_t)i;

  // Compute correct checksum so the failure is purely on version, not checksum.
  uint8_t h1[64], h2[64];
  mxd_sha512(payload, 33, h1);
  mxd_sha512(h1, 64, h2);
  memcpy(payload + 33, h2, 4);

  // base58-encode payload, prepend "mx"
  char encoded[64];
  size_t enc_len = sizeof(encoded);
  char addr[MXD_ADDR_STR_MAX];

  TEST_START("address_rejects_unknown_version_byte");

  TEST_ASSERT(base58_encode(payload, 37, encoded, enc_len) == 0,
              "base58_encode succeeds for forged payload");
  snprintf(addr, sizeof(addr), "mx%s", encoded);

  TEST_ASSERT(mxd_validate_address(addr) == -1,
              "mxd_validate_address rejects address with unknown version byte 0x40");

  TEST_END("address_rejects_unknown_version_byte");
}

// ============================================================
// Task 3.4: Regression guard — legacy sentinel addresses must be rejected
// by the new parser (they were never valid Base58Check payloads).
// ============================================================

static void test_legacy_sentinel_addresses_rejected(void) {
  TEST_START("Legacy Sentinel Addresses Rejected");
  TEST_ASSERT(mxd_validate_address("mx111111111111111111111111111111111111111") == -1,
              "all-ones sentinel rejected");
  TEST_ASSERT(mxd_validate_address("mxffffffffffffffffffffffffffffffffffffffff") == -1,
              "all-fs sentinel rejected");
  TEST_END("Legacy Sentinel Addresses Rejected");
}

static void test_address_parses_composite_version_byte_to_algo_id_3(void) {
  // Per MXD-01 §9: composite version bytes 0x34/0x3C MUST parse successfully
  // and return algo_id=0x03.  The signing/output-construction prohibition is
  // enforced downstream (mxd_address_to_string, mxd_sign_tx_input) — not here.
  uint8_t payload[37];
  memset(payload, 0, sizeof(payload));
  payload[0] = MXD_VBYTE_MAINNET_COMPOSITE;
  for (int i = 1; i <= 32; i++) payload[i] = (uint8_t)0xAA;

  uint8_t h1[64], h2[64];
  mxd_sha512(payload, 33, h1);
  mxd_sha512(h1, 64, h2);
  memcpy(payload + 33, h2, 4);

  char encoded[64];
  size_t enc_len = sizeof(encoded);
  base58_encode(payload, 37, encoded, enc_len);

  char addr[MXD_ADDR_STR_MAX];
  snprintf(addr, sizeof(addr), "mx%s", encoded);

  uint8_t algo;
  uint8_t addr32[32];

  TEST_START("address_parses_composite_version_byte_to_algo_id_3");

  TEST_ASSERT(mxd_parse_address(addr, &algo, addr32) == 0,
              "mxd_parse_address succeeds for composite version byte 0x34 (MXD-01 §9)");
  TEST_ASSERT(algo == 0x03,
              "parsed algo_id == 0x03 for composite version byte 0x34");

  TEST_END("address_parses_composite_version_byte_to_algo_id_3");
}

int main(void) {
  printf("Starting address tests (Task 3.2: addr32 + Task 3.3: 37-byte payload)...\n");

  test_addr32_for_known_input();
  test_addr32_rejects_wrong_pubkey_len();
  test_addr32_algo_id_separation();

  // Legacy tests preserved (will fail if legacy API callers are removed in 3.4)
  test_passphrase_generation();

  // Task 3.3: 37-byte payload encode/decode
  test_address_string_roundtrip_ed25519_mainnet();
  test_address_rejects_unknown_version_byte();
  test_address_parses_composite_version_byte_to_algo_id_3();

  // Task 3.4: Regression guard — legacy sentinel addresses rejected
  test_legacy_sentinel_addresses_rejected();

  printf("All address tests passed.\n");
  return 0;
}
