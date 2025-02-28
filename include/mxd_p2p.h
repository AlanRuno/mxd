#ifndef MXD_P2P_H
#define MXD_P2P_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

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
  MXD_MSG_TRANSACTIONS = 8
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
