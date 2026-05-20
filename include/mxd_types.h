#ifndef MXD_TYPES_H
#define MXD_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Base unit: 1 MXD = 100,000,000 base units (8 decimals like Bitcoin)
// This ensures deterministic arithmetic across all platforms
typedef uint64_t mxd_amount_t;

#define MXD_AMOUNT_DECIMALS 8
#define MXD_AMOUNT_MULTIPLIER 100000000ULL
#define MXD_AMOUNT_MAX UINT64_MAX

// Maximum MXD value in human-readable form (184467440737.09551615 MXD)
// This is UINT64_MAX / MXD_AMOUNT_MULTIPLIER
#define MXD_AMOUNT_MAX_WHOLE 184467440737ULL

#ifdef __cplusplus
}
#endif

#endif // MXD_TYPES_H
