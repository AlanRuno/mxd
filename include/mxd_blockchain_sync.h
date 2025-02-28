#ifndef MXD_BLOCKCHAIN_SYNC_H
#define MXD_BLOCKCHAIN_SYNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxd_blockchain.h"

// Synchronize blockchain data with network
int mxd_sync_blockchain(void);

// Retrieve block by height from the blockchain
int mxd_get_block_by_height(uint32_t height, mxd_block_t *block);

#ifdef __cplusplus
}
#endif

#endif // MXD_BLOCKCHAIN_SYNC_H
