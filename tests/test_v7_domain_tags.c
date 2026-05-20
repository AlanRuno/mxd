/*
 * test_v7_domain_tags.c — byte-exact assertion for the v7 domain-tag registry
 *
 * Anchors the C-side constants in include/mxd_domain_tags.h to the
 * documented hex byte sequences in AUDIT_2026-05-05_v6.md. If anyone
 * accidentally edits a tag's bytes (or its length) the build will fail
 * here.
 */

#include "../include/mxd_domain_tags.h"
#include "test_utils.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#include <assert.h>
_Static_assert(MXD_DOMAIN_TAG_TX_LEN == 10,   "MXD-TX-V1 must be 10 bytes");
_Static_assert(MXD_DOMAIN_TAG_VAL_LEN == 11,  "MXD-VAL-V1 must be 11 bytes");
_Static_assert(MXD_DOMAIN_TAG_P2P_LEN == 11,  "MXD-P2P-V1 must be 11 bytes");
_Static_assert(MXD_DOMAIN_TAG_BRG_LEN == 11,  "MXD-BRG-V1 must be 11 bytes");
_Static_assert(MXD_DOMAIN_TAG_CONS_LEN == 11, "MXD-CONS-1 must be 11 bytes");
#endif

static const uint8_t kExpectTX[10]   = { 0x4D, 0x58, 0x44, 0x2D, 0x54, 0x58, 0x2D, 0x56, 0x31, 0x00 };
static const uint8_t kExpectVAL[11]  = { 0x4D, 0x58, 0x44, 0x2D, 0x56, 0x41, 0x4C, 0x2D, 0x56, 0x31, 0x00 };
static const uint8_t kExpectP2P[11]  = { 0x4D, 0x58, 0x44, 0x2D, 0x50, 0x32, 0x50, 0x2D, 0x56, 0x31, 0x00 };
static const uint8_t kExpectBRG[11]  = { 0x4D, 0x58, 0x44, 0x2D, 0x42, 0x52, 0x47, 0x2D, 0x56, 0x31, 0x00 };
static const uint8_t kExpectCONS[11] = { 0x4D, 0x58, 0x44, 0x2D, 0x43, 0x4F, 0x4E, 0x53, 0x2D, 0x31, 0x00 };

static void test_domain_tag_bytes(void) {
  TEST_START("domain tags match documented hex byte sequences");

  TEST_ARRAY("MXD-TX-V1   ", MXD_DOMAIN_TAG_TX, MXD_DOMAIN_TAG_TX_LEN);
  TEST_ARRAY("MXD-VAL-V1  ", MXD_DOMAIN_TAG_VAL, MXD_DOMAIN_TAG_VAL_LEN);
  TEST_ARRAY("MXD-P2P-V1  ", MXD_DOMAIN_TAG_P2P, MXD_DOMAIN_TAG_P2P_LEN);
  TEST_ARRAY("MXD-BRG-V1  ", MXD_DOMAIN_TAG_BRG, MXD_DOMAIN_TAG_BRG_LEN);
  TEST_ARRAY("MXD-CONS-1  ", MXD_DOMAIN_TAG_CONS, MXD_DOMAIN_TAG_CONS_LEN);

  TEST_ASSERT(memcmp(MXD_DOMAIN_TAG_TX,   kExpectTX,   MXD_DOMAIN_TAG_TX_LEN) == 0,
              "MXD-TX-V1 bytes match expected");
  TEST_ASSERT(memcmp(MXD_DOMAIN_TAG_VAL,  kExpectVAL,  MXD_DOMAIN_TAG_VAL_LEN) == 0,
              "MXD-VAL-V1 bytes match expected");
  TEST_ASSERT(memcmp(MXD_DOMAIN_TAG_P2P,  kExpectP2P,  MXD_DOMAIN_TAG_P2P_LEN) == 0,
              "MXD-P2P-V1 bytes match expected");
  TEST_ASSERT(memcmp(MXD_DOMAIN_TAG_BRG,  kExpectBRG,  MXD_DOMAIN_TAG_BRG_LEN) == 0,
              "MXD-BRG-V1 bytes match expected");
  TEST_ASSERT(memcmp(MXD_DOMAIN_TAG_CONS, kExpectCONS, MXD_DOMAIN_TAG_CONS_LEN) == 0,
              "MXD-CONS-1 bytes match expected");

  TEST_END("domain tags match documented hex byte sequences");
}

static void test_domain_tags_disjoint(void) {
  TEST_START("each domain tag is disjoint from the others (no shared 10-byte prefix)");

  /* All tags share their first 4 bytes ("MXD-"); but the 5th byte must
     differ pairwise so a verifier looking at the leading bytes alone
     can route to the right protocol layer. */
  uint8_t fifth_bytes[5] = {
      MXD_DOMAIN_TAG_TX[4],
      MXD_DOMAIN_TAG_VAL[4],
      MXD_DOMAIN_TAG_P2P[4],
      MXD_DOMAIN_TAG_BRG[4],
      MXD_DOMAIN_TAG_CONS[4]
  };
  /* All five must be distinct */
  for (int i = 0; i < 5; i++) {
    for (int j = i + 1; j < 5; j++) {
      TEST_ASSERT(fifth_bytes[i] != fifth_bytes[j],
                  "5th tag bytes are pairwise distinct");
    }
  }
  TEST_END("each domain tag is disjoint from the others (no shared 10-byte prefix)");
}

int main(void) {
  test_domain_tag_bytes();
  test_domain_tags_disjoint();
  printf("\nAll v7 domain-tag tests passed.\n");
  return 0;
}
