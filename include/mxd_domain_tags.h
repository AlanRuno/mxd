#ifndef MXD_DOMAIN_TAGS_H
#define MXD_DOMAIN_TAGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * MXD Domain-Tag Registry (v7 cascade)
 *
 * Each protocol layer that produces signature inputs MUST prepend its
 * domain tag to the signed bytes. This enforces the disjoint-domain
 * rule from MXD-03 §7 / MXD-00: a digest produced for one layer (e.g.
 * a transaction sighash) cannot be replayed as a digest for another
 * (e.g. a P2P handshake challenge) because the leading tag bytes
 * differ across layers.
 *
 * Each tag is its identifier ASCII bytes followed by a single NUL
 * terminator (0x00). Tag lengths are NOT all equal because the
 * identifiers vary in length: MXD-TX-V1 has a 2-letter family code
 * ("TX") and MXD-CONS-1 drops the version "V" letter to keep itself
 * shorter, while MXD-VAL-V1 / MXD-P2P-V1 / MXD-BRG-V1 each have a
 * 3-letter family code.
 *
 * Documented byte content (verified vs. AUDIT_2026-05-05_v6.md):
 *   "MXD-TX-V1\0"  — 10 bytes — 4D 58 44 2D 54 58 2D 56 31 00
 *   "MXD-VAL-V1\0" — 11 bytes — 4D 58 44 2D 56 41 4C 2D 56 31 00
 *   "MXD-P2P-V1\0" — 11 bytes — 4D 58 44 2D 50 32 50 2D 56 31 00
 *   "MXD-BRG-V1\0" — 11 bytes — 4D 58 44 2D 42 52 47 2D 56 31 00
 *   "MXD-CONS-1\0" — 11 bytes — 4D 58 44 2D 43 4F 4E 53 2D 31 00
 *
 * Use the per-tag length macros below when laying out signed buffers
 * — the buffer size for each tag is fixed and known at compile time.
 */

#define MXD_DOMAIN_TAG_TX_LEN   10  /* "MXD-TX-V1\0"  */
#define MXD_DOMAIN_TAG_VAL_LEN  11  /* "MXD-VAL-V1\0" */
#define MXD_DOMAIN_TAG_P2P_LEN  11  /* "MXD-P2P-V1\0" */
#define MXD_DOMAIN_TAG_BRG_LEN  11  /* "MXD-BRG-V1\0" */
#define MXD_DOMAIN_TAG_CONS_LEN 11  /* "MXD-CONS-1\0" */

extern const uint8_t MXD_DOMAIN_TAG_TX[MXD_DOMAIN_TAG_TX_LEN];
extern const uint8_t MXD_DOMAIN_TAG_VAL[MXD_DOMAIN_TAG_VAL_LEN];
extern const uint8_t MXD_DOMAIN_TAG_P2P[MXD_DOMAIN_TAG_P2P_LEN];
extern const uint8_t MXD_DOMAIN_TAG_BRG[MXD_DOMAIN_TAG_BRG_LEN];
extern const uint8_t MXD_DOMAIN_TAG_CONS[MXD_DOMAIN_TAG_CONS_LEN];

#ifdef __cplusplus
}
#endif

#endif /* MXD_DOMAIN_TAGS_H */
