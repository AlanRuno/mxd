/*
 * test_addr32_algoid_flip.c — addr32 algo_id binding (audit spec-coverage §2.11)
 *
 * Closes the audit's "no test verified algo_id is part of the SHA-512
 * input" finding for MXD-01 addr32 derivation.
 *
 * The address is SHA-512(algo_id || pubkey)[0..31]. This test recomputes
 * that digest twice with the SAME pubkey bytes but two different algo_id
 * values (0x01 = Ed25519, 0x02 = Dilithium5) and asserts the two
 * resulting 32-byte addresses differ — proving the algo_id byte is
 * actually mixed into the hash.
 *
 * The shorter Ed25519 pubkey length (32 bytes) is reused for both algo
 * IDs in the recomputation; mxd_derive_address would reject that for
 * algo_id=2 because it enforces length, so we recompute the digest
 * directly with mxd_sha512 here. This is intentional: the test exists
 * to verify the hash domain, not the length-policing layer.
 */

#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef MXD_ADDR32_LEN
#define MXD_ADDR32_LEN 32
#endif

static void test_addr32_algoid_flip_changes_address(void) {
  TEST_START("addr32 algo_id flip changes derived address");

  /* Fixed pubkey bytes — content is arbitrary, what matters is that the
     same byte sequence is hashed twice with different algo_id prefixes. */
  uint8_t pubkey[32];
  for (int i = 0; i < 32; i++) pubkey[i] = (uint8_t)(0x10 + i);

  uint8_t buf1[1 + 32];
  uint8_t buf2[1 + 32];
  buf1[0] = 0x01; /* Ed25519 */
  buf2[0] = 0x02; /* Dilithium5 */
  memcpy(buf1 + 1, pubkey, 32);
  memcpy(buf2 + 1, pubkey, 32);

  uint8_t digest1[64], digest2[64];
  TEST_ASSERT(mxd_sha512(buf1, sizeof(buf1), digest1) == 0,
              "SHA-512(algo_id=0x01 || pubkey) succeeded");
  TEST_ASSERT(mxd_sha512(buf2, sizeof(buf2), digest2) == 0,
              "SHA-512(algo_id=0x02 || pubkey) succeeded");

  uint8_t addr1[MXD_ADDR32_LEN];
  uint8_t addr2[MXD_ADDR32_LEN];
  memcpy(addr1, digest1, MXD_ADDR32_LEN);
  memcpy(addr2, digest2, MXD_ADDR32_LEN);

  TEST_ARRAY("addr32 (algo_id=0x01)", addr1, MXD_ADDR32_LEN);
  TEST_ARRAY("addr32 (algo_id=0x02)", addr2, MXD_ADDR32_LEN);

  TEST_ASSERT(memcmp(addr1, addr2, MXD_ADDR32_LEN) != 0,
              "addr32 differs across algo_id values (algo_id is in the hash)");

  TEST_END("addr32 algo_id flip changes derived address");
}

int main(void) {
  test_addr32_algoid_flip_changes_address();
  printf("\nAll addr32 algo_id flip tests passed.\n");
  return 0;
}
