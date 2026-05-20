#ifndef MXD_CHAIN_H
#define MXD_CHAIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Per MXD-04 v1.1.x §3.1 chain_id registry.
#define MXD_CHAIN_ID_MAINNET    0x4D580001U  // "MX\0\x01"
#define MXD_CHAIN_ID_TESTNET    0x4D580002U
#define MXD_CHAIN_ID_LOCAL_DEV  0x4D58FFFFU

// Read the configured chain_id for this node from runtime config / env.
// Returns one of the constants above (or 0 on error).
uint32_t mxd_get_configured_chain_id(void);

#ifdef __cplusplus
}
#endif

#endif  // MXD_CHAIN_H
