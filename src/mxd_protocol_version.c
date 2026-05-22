#include "../include/mxd_protocol_version.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_config.h"
#include <string.h>

// Static network type (can be overridden for testing)
// SECURITY FIX: Default to TESTNET for GCP testnet nodes
static mxd_network_type_t current_network = MXD_NETWORK_TESTNET;

// Activation heights for each network
// Note: v6 (addr32 validator identity, block-format change) and v7 (domain-tag
// cascade + SHA-512 chain_id) each require a fresh-genesis restart on all
// networks because the wire format changes.
// v8 is the Phase 3 EVICT block-field. Mainnet is gated FUTURE — operators
// MUST replace UINT32_MAX with a coordinated activation height ≥ current_tip
// + ~1000 blocks before deploying the v8 binary. Until that's set, mainnet
// proposers continue producing v7 blocks and v8 EVICT entries are not
// emitted (the wire format stays backwards-compatible). Testnet and devnet
// run v8 from genesis.
static const mxd_activation_heights_t MAINNET_HEIGHTS = {
    .v2_activation_height = 0,       // v2 from genesis (fresh mainnet)
    .v3_activation_height = 0,       // v3 from genesis (bridge support from block 0)
    .v4_activation_height = 0,       // v4 from genesis (on-chain validator scoring)
    .v5_activation_height = 0,       // v5 from genesis
    .v6_activation_height = 0,       // v6 from genesis (addr32 identity migration)
    .v7_activation_height = 0,       // v7 from genesis (domain-tag cascade)
    .v8_activation_height = UINT32_MAX  // v8 gated — operator sets before deploy
};

static const mxd_activation_heights_t TESTNET_HEIGHTS = {
    .v2_activation_height = 1000,    // v2 activated at height 1,000 (historical)
    .v3_activation_height = 5000,    // v3 will activate at height 5,000 (near future)
    .v4_activation_height = 0,       // v4 from genesis (fresh testnet deploy)
    .v5_activation_height = 0,       // v5 from genesis on fresh testnet
    .v6_activation_height = 0,       // v6 from genesis on fresh testnet
    .v7_activation_height = 0,       // v7 from genesis on fresh testnet
    .v8_activation_height = 55       // v8 retry: integrated auto-EVICT into auto-join thread (chain at h=48; 7 blocks margin)
};

static const mxd_activation_heights_t DEVNET_HEIGHTS = {
    .v2_activation_height = 0,       // v2 from genesis
    .v3_activation_height = 0,       // v3 from genesis (for development)
    .v4_activation_height = 0,       // v4 from genesis (for development)
    .v5_activation_height = 0,       // v5 from genesis (for development)
    .v6_activation_height = 0,       // v6 from genesis (for development)
    .v7_activation_height = 0,       // v7 from genesis (for development)
    .v8_activation_height = 0        // v8 from genesis (for development)
};

// Get activation heights for a specific network
mxd_activation_heights_t mxd_get_activation_heights(mxd_network_type_t network) {
    switch (network) {
        case MXD_NETWORK_MAINNET:
            return MAINNET_HEIGHTS;
        case MXD_NETWORK_TESTNET:
            return TESTNET_HEIGHTS;
        case MXD_NETWORK_DEVNET:
            return DEVNET_HEIGHTS;
        default:
            // SECURITY FIX: Don't log during early init - logging may not be ready
            // Just return safe default (TESTNET)
            return TESTNET_HEIGHTS;
    }
}

// Get the required protocol version for a given block height
uint32_t mxd_get_required_protocol_version(uint32_t height, mxd_network_type_t network) {
    mxd_activation_heights_t heights = mxd_get_activation_heights(network);

    // Determine version based on activation heights (highest first)
    if (height >= heights.v8_activation_height) {
        return MXD_PROTOCOL_VERSION_8;
    } else if (height >= heights.v7_activation_height) {
        return MXD_PROTOCOL_VERSION_7;
    } else if (height >= heights.v6_activation_height) {
        return MXD_PROTOCOL_VERSION_6;
    } else if (height >= heights.v5_activation_height) {
        return MXD_PROTOCOL_VERSION_5;
    } else if (height >= heights.v4_activation_height) {
        return MXD_PROTOCOL_VERSION_4;
    } else if (height >= heights.v3_activation_height) {
        return MXD_PROTOCOL_VERSION_3;
    } else if (height >= heights.v2_activation_height) {
        return MXD_PROTOCOL_VERSION_2;
    } else {
        return MXD_PROTOCOL_VERSION_1;
    }
}

// Check if a block version is valid for its height
int mxd_is_valid_block_version(uint32_t block_version, uint32_t height,
                                mxd_network_type_t network) {
    uint32_t required_version = mxd_get_required_protocol_version(height, network);

    // Block must use the required version for its height
    // We allow exact match only (no forward/backward compatibility during migration)
    if (block_version != required_version) {
        // SECURITY FIX: Don't log during early init - just return failure
        // Logging will happen in calling function if needed
        return 0;
    }

    return 1;
}

// Get network type from configuration
mxd_network_type_t mxd_get_network_type(void) {
    const mxd_config_t* config = mxd_get_config();

    if (!config) {
        // SECURITY FIX: Early initialization - config not loaded yet
        // Don't use MXD_LOG here - logging may not be initialized
        // Return safe default (TESTNET for GCP testnet nodes)
        return current_network;
    }

    // SECURITY FIX: Actually parse config->network_type field
    // Config has char network_type[32] field with "mainnet" or "testnet"
    if (strcmp(config->network_type, "mainnet") == 0) {
        return MXD_NETWORK_MAINNET;
    } else if (strcmp(config->network_type, "testnet") == 0) {
        return MXD_NETWORK_TESTNET;
    } else if (strcmp(config->network_type, "devnet") == 0) {
        return MXD_NETWORK_DEVNET;
    }

    // Fallback to current_network if parsing fails
    return current_network;
}

// Set network type (for testing purposes)
void mxd_set_network_type(mxd_network_type_t network) {
    if (network > MXD_NETWORK_DEVNET) {
        // SECURITY FIX: Don't log during early init - just return
        return;
    }

    // SECURITY FIX: Don't log during early init - just set the value
    current_network = network;
}
