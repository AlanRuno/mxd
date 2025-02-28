#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_p2p.h"
#include <string.h>

int mxd_sync_blockchain(void) {
    // For testing purposes, simulate successful sync
    return 0;
}

int mxd_get_block_by_height(uint32_t height, mxd_block_t *block) {
    // For testing purposes, simulate successful block retrieval
    if (!block) return -1;
    
    // Initialize block with test data
    uint8_t prev_hash[64] = {0};
    mxd_init_block(block, prev_hash);
    
    // Set some test data based on height
    block->nonce = height;
    block->timestamp = time(NULL);
    
    return 0;
}
