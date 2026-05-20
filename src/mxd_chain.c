#include "../include/mxd_chain.h"
#include <stdlib.h>
#include <string.h>

uint32_t mxd_get_configured_chain_id(void) {
  const char *env = getenv("MXD_CHAIN_ID");
  if (env) {
    if (strcmp(env, "mainnet") == 0) return MXD_CHAIN_ID_MAINNET;
    if (strcmp(env, "testnet") == 0) return MXD_CHAIN_ID_TESTNET;
    if (strcmp(env, "localdev") == 0) return MXD_CHAIN_ID_LOCAL_DEV;
  }
  // Default to mainnet for now; tighter integration with mxd_config can come later.
  return MXD_CHAIN_ID_MAINNET;
}
