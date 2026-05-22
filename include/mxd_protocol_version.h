#ifndef MXD_PROTOCOL_VERSION_H
#define MXD_PROTOCOL_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * MXD Protocol Versioning
 *
 * Version History:
 * - v1: Initial blockchain (SHA-512, Ed25519)
 * - v2: Hybrid cryptography (Ed25519 + Dilithium5)
 * - v3: Smart contracts with state root tracking
 * - v4: Deterministic on-chain validator scoring
 * - v5: Deterministic proposer + finalization gate + skip timeout
 * - v6: addr32 validator identity (proposer_id, next_proposer, score
 *       entries, rapid membership, validation chain widened to 32 bytes;
 *       score entry size 48->60). Block-format change.
 * - v7: domain-tag cascade — SHA-512 chain_id, SHA-512 fallback proposer
 *       index, MXD-VAL-V1/MXD-P2P-V1/MXD-BRG-V1/MXD-CONS-1 domain tags
 *       prefixed to validator/p2p/bridge/consensus signed payloads, P2P
 *       handshake protocol_version bumped 5->6. Wire-format-breaking;
 *       requires fresh genesis on all networks.
 * - v8: peer-driven validator EVICTION (Phase 3 of permissionless
 *       validator-management). Block layout gains a
 *       rapid_eviction_entries[] field; pre-v8 blocks ignore it.
 *       Wire-format-breaking — bump requires either fresh genesis or a
 *       coordinated activation_height after which proposers begin
 *       emitting v8 blocks.
 */

#define MXD_PROTOCOL_VERSION_1 1
#define MXD_PROTOCOL_VERSION_2 2
#define MXD_PROTOCOL_VERSION_3 3
#define MXD_PROTOCOL_VERSION_4 4
#define MXD_PROTOCOL_VERSION_5 5
#define MXD_PROTOCOL_VERSION_6 6
#define MXD_PROTOCOL_VERSION_7 7
#define MXD_PROTOCOL_VERSION_8 8

#define MXD_CURRENT_PROTOCOL_VERSION MXD_PROTOCOL_VERSION_8

// Activation heights for protocol upgrades
// These define when new protocol versions become mandatory
typedef struct {
    uint32_t v2_activation_height;  // Height when v2 activated (historical)
    uint32_t v3_activation_height;  // Height when v3 will activate (future)
    uint32_t v4_activation_height;  // Height when v4 will activate (on-chain scoring)
    uint32_t v5_activation_height;  // Deterministic proposer + finalization gate + skip timeout
    uint32_t v6_activation_height;  // addr32 validator identity (block-format change)
    uint32_t v7_activation_height;  // Domain-tag cascade + SHA-512 chain_id (wire-format change)
    uint32_t v8_activation_height;  // Peer-driven EVICT block field (Phase 3 validator-mgmt)
} mxd_activation_heights_t;

// Network-specific activation heights
typedef enum {
    MXD_NETWORK_MAINNET = 0,
    MXD_NETWORK_TESTNET = 1,
    MXD_NETWORK_DEVNET = 2
} mxd_network_type_t;

/**
 * Get activation heights for a specific network
 *
 * @param network Network type (mainnet, testnet, devnet)
 * @return Activation heights structure
 */
mxd_activation_heights_t mxd_get_activation_heights(mxd_network_type_t network);

/**
 * Get the required protocol version for a given block height
 *
 * @param height Block height
 * @param network Network type
 * @return Required protocol version (1..8)
 */
uint32_t mxd_get_required_protocol_version(uint32_t height, mxd_network_type_t network);

/**
 * Check if a block version is valid for its height
 *
 * @param block_version Version specified in block
 * @param height Block height
 * @param network Network type
 * @return 1 if valid, 0 if invalid
 */
int mxd_is_valid_block_version(uint32_t block_version, uint32_t height,
                                mxd_network_type_t network);

/**
 * Get network type from configuration
 *
 * @return Current network type
 */
mxd_network_type_t mxd_get_network_type(void);

/**
 * Set network type (for testing purposes)
 *
 * @param network Network type to set
 */
void mxd_set_network_type(mxd_network_type_t network);

#ifdef __cplusplus
}
#endif

#endif // MXD_PROTOCOL_VERSION_H
