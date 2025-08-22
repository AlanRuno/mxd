#ifndef MXD_P2P_H
#define MXD_P2P_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "mxd_blockchain.h"

int mxd_should_relay_block(const mxd_block_t *block, int just_signed);

// Maximum number of peers in the connection pool
#define MXD_MAX_PEERS 256  // Aligned with mxd_dht.h

// Maximum message size
#define MXD_MAX_MESSAGE_SIZE 1048576 // 1MB

// Peer connection states
typedef enum {
  MXD_PEER_DISCONNECTED = 0,
  MXD_PEER_CONNECTING = 1,
  MXD_PEER_CONNECTED = 2,
  MXD_PEER_FAILED = 3
} mxd_peer_state_t;

// Peer information
typedef struct {
  char address[256];       // IP address or hostname
  uint16_t port;           // Port number
  mxd_peer_state_t state;  // Connection state
  uint64_t last_seen;      // Last seen timestamp
  uint32_t latency;        // Connection latency in ms
  uint8_t public_key[256]; // Peer's public key
  uint8_t in_rapid_table;  // Whether peer is in the Rapid Table
  uint32_t rapid_table_position; // Position in the Rapid Table (0 = highest)
} mxd_peer_t;

// Message types
typedef enum {
  MXD_MSG_HANDSHAKE = 0,
  MXD_MSG_PING = 1,
  MXD_MSG_PONG = 2,
  MXD_MSG_GET_PEERS = 3,
  MXD_MSG_PEERS = 4,
  MXD_MSG_GET_BLOCKS = 5,
  MXD_MSG_BLOCKS = 6,
  MXD_MSG_GET_TRANSACTIONS = 7,
  MXD_MSG_TRANSACTIONS = 8,
  MXD_MSG_BLOCK_VALIDATION = 9,     // Block validation chain message
  MXD_MSG_VALIDATION_SIGNATURE = 10, // Single validation signature
  MXD_MSG_GET_VALIDATION_CHAIN = 11, // Request validation chain for block
  MXD_MSG_VALIDATION_CHAIN = 12,     // Complete validation chain response
  MXD_MSG_RAPID_TABLE_UPDATE = 13    // Rapid Table update message
} mxd_message_type_t;

// Message header
typedef struct {
  uint32_t magic;          // Network magic number
  mxd_message_type_t type; // Message type
  uint32_t length;         // Payload length
  uint8_t checksum[64];    // SHA-512 checksum of payload
} mxd_message_header_t;

// Initialize P2P networking
int mxd_init_p2p(uint16_t port, const uint8_t *public_key);

// Start P2P networking
int mxd_start_p2p(void);

// Stop P2P networking
int mxd_stop_p2p(void);

// Add peer to connection pool
int mxd_add_peer(const char *address, uint16_t port);

// Remove peer from connection pool
int mxd_remove_peer(const char *address, uint16_t port);

// Get peer information
int mxd_get_peer(const char *address, uint16_t port, mxd_peer_t *peer);

// Get all connected peers
int mxd_get_peers(mxd_peer_t *peers, size_t *peer_count);

// Send message to peer
int mxd_send_message(const char *address, uint16_t port,
                     mxd_message_type_t type, const void *payload,
                     size_t payload_length);

// Broadcast message to all peers
int mxd_broadcast_message(mxd_message_type_t type, const void *payload,
                          size_t payload_length);

// Broadcast message to Rapid Table peers only (priority propagation)
int mxd_broadcast_to_rapid_table(mxd_message_type_t type, const void *payload,
                                size_t payload_length);

// Broadcast block with validation chain to peers
int mxd_broadcast_block_with_validation(const void *block_data, size_t block_length,
                                       const void *validation_chain, size_t validation_length);

// Relay block based on validation signature count (X=3)
int mxd_relay_block_by_validation_count(const void *block_data, size_t block_length,
                                       uint32_t signature_count);

// Send validation signature to next validator in chain
int mxd_send_validation_signature(const char *address, uint16_t port,
                                 const uint8_t *block_hash, const uint8_t *signature,
                                 uint16_t signature_length, uint32_t chain_position);

// Request validation chain for block
int mxd_request_validation_chain(const char *address, uint16_t port,
                                const uint8_t *block_hash);

// Update peer's Rapid Table status
int mxd_update_peer_rapid_table_status(const char *address, uint16_t port,
                                      uint8_t in_rapid_table, uint32_t position);

// Get peers from Rapid Table only
int mxd_get_rapid_table_peers(mxd_peer_t *peers, size_t *peer_count);

// Set minimum number of signatures required for block relay
int mxd_set_min_relay_signatures(uint32_t threshold);

// Get minimum number of signatures required for block relay
uint32_t mxd_get_min_relay_signatures(void);

// Set message handler callback
typedef void (*mxd_message_handler_t)(const char *address, uint16_t port,
                                      mxd_message_type_t type,
                                      const void *payload,
                                      size_t payload_length);
int mxd_set_message_handler(mxd_message_handler_t handler);

// Start DHT-based peer discovery
int mxd_start_peer_discovery(void);

// Stop DHT-based peer discovery
int mxd_stop_peer_discovery(void);

/**
 * Reset rate limiting counters.
 * 
 * @return 0 on success, -1 if P2P is not initialized
 */
int mxd_reset_rate_limit(void);

// Enable NAT traversal
int mxd_enable_nat_traversal(void);

// Disable NAT traversal
int mxd_disable_nat_traversal(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_P2P_H
