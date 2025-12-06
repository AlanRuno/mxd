#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/rand.h>
#include "mxd_config.h"
#include "mxd_crypto.h"
#include "mxd_dht.h"
#include "mxd_p2p.h"
#include "mxd_logging.h"
#include "mxd_secrets.h"
#include "mxd_address.h"

static struct {
    char address[256];
    uint16_t port;
    int active;
} manual_peers[MXD_MAX_PEERS];
static size_t manual_peer_count = 0;
static pthread_mutex_t manual_peer_mutex = PTHREAD_MUTEX_INITIALIZER;


static int p2p_initialized = 0;
static uint16_t p2p_port = 0;
static uint8_t node_public_key[256] = {0};
static uint8_t node_private_key[128] = {0};
static mxd_config_t node_config;
static uint64_t last_message_time = 0;
static size_t messages_this_second = 0;
static uint64_t last_tx_time = 0;
static size_t tx_this_second = 0;
static uint32_t consecutive_errors = 0;
static mxd_message_handler_t message_handler = NULL;
static int error_simulation_count = 0;

static int server_socket = -1;
static pthread_t server_thread;
static pthread_t connection_threads[MXD_MAX_PEERS];
static volatile int server_running = 0;
static pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int socket;
    char address[256];
    uint16_t port;
    time_t connected_at;
    time_t last_keepalive_sent;
    time_t last_keepalive_received;
    int active;
    int keepalive_failures;
} peer_connection_t;

static peer_connection_t active_connections[MXD_MAX_PEERS];
static size_t active_connection_count = 0;

typedef struct {
    char address[256];
    uint16_t port;
    time_t last_message_sent;
    time_t last_message_received;
    uint32_t messages_sent;
    uint32_t messages_received;
    int active;
} unified_peer_t;

static unified_peer_t unified_peers[MXD_MAX_PEERS];
static size_t unified_peer_count = 0;
static pthread_mutex_t unified_peer_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MXD_KEEPALIVE_INTERVAL 30
#define MXD_KEEPALIVE_TIMEOUT 90
#define MXD_MAX_KEEPALIVE_FAILURES 3

static pthread_t keepalive_thread;
static volatile int keepalive_running = 0;
static int keepalive_thread_created = 0;

static pthread_t peer_connector_thread;
static volatile int peer_connector_running = 0;
static int peer_connector_thread_created = 0;

typedef struct {
    uint32_t magic;      // Network byte order
    uint8_t type;        // Fixed size instead of enum
    uint8_t reserved[3]; // Padding for alignment
    uint32_t length;     // Network byte order
    uint8_t checksum[64]; // SHA-512 checksum
} __attribute__((packed)) mxd_wire_header_t;

typedef struct {
    char node_id[256];        // Node identifier (wallet address)
    uint32_t protocol_version; // Protocol version
    uint16_t listen_port;      // Listening port
    uint8_t public_key[256];   // Dilithium public key
    uint8_t challenge[32];     // Random challenge nonce
    uint16_t signature_length; // Length of signature
    uint8_t signature[5000];   // Signature (max Dilithium5 size ~4595 bytes)
} mxd_handshake_payload_t;

static void* connection_handler(void* arg);
static int try_establish_persistent_connection(const char *address, uint16_t port);

static int read_n(int sock, void *buffer, size_t n) {
    size_t total_read = 0;
    uint8_t *buf = (uint8_t*)buffer;
    
    while (total_read < n) {
        ssize_t bytes_read = recv(sock, buf + total_read, n - total_read, 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                return -2;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -3; // Timeout
            }
            return -1; // Other error
        }
        total_read += bytes_read;
    }
    
    return 0;
}

static int write_n(int sock, const void *buffer, size_t n) {
    size_t total_written = 0;
    const uint8_t *buf = (const uint8_t*)buffer;
    
#ifdef MSG_NOSIGNAL
    int flags = MSG_NOSIGNAL;
#else
    int flags = 0;
#endif
    
    while (total_written < n) {
        ssize_t bytes_written = send(sock, buf + total_written, n - total_written, flags);
        if (bytes_written <= 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                return -1; // Error
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        total_written += bytes_written;
    }
    
    return 0;
}

static void header_to_wire(const mxd_message_header_t *header, mxd_wire_header_t *wire) {
    wire->magic = htonl(header->magic);
    wire->type = (uint8_t)header->type;
    wire->reserved[0] = 0;
    wire->reserved[1] = 0;
    wire->reserved[2] = 0;
    wire->length = htonl(header->length);
    memcpy(wire->checksum, header->checksum, 64);
}

static void wire_to_header(const mxd_wire_header_t *wire, mxd_message_header_t *header) {
    header->magic = ntohl(wire->magic);
    header->type = (mxd_message_type_t)wire->type;
    header->length = ntohl(wire->length);
    memcpy(header->checksum, wire->checksum, 64);
}

static int parse_wire_header(const uint8_t *buffer, mxd_message_header_t *header, uint32_t expected_magic) {
    mxd_wire_header_t *wire = (mxd_wire_header_t*)buffer;
    
    uint32_t magic = ntohl(wire->magic);
    uint8_t type = wire->type;
    uint32_t length = ntohl(wire->length);
    
    if (magic != expected_magic) {
        return -1;
    }
    
    if (type > MXD_MSG_RAPID_TABLE_UPDATE) {
        return -1;
    }
    
    if (length > MXD_MAX_MESSAGE_SIZE || length == 0) {
        return -1;
    }
    
    if (wire->reserved[0] != 0 || wire->reserved[1] != 0 || wire->reserved[2] != 0) {
        return -1;
    }
    
    header->magic = magic;
    header->type = (mxd_message_type_t)type;
    header->length = length;
    memcpy(header->checksum, wire->checksum, 64);
    
    return 0;
}

static int send_on_socket(int sock, mxd_message_type_t type, const void* payload, size_t payload_length) {
    if (sock < 0 || !payload || payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        return -1;
    }
    
    mxd_message_header_t header = {
        .magic = secrets->network_magic,
        .type = type,
        .length = payload_length
    };
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        return -1;
    }
    
    mxd_wire_header_t wire_header;
    header_to_wire(&header, &wire_header);
    
    if (write_n(sock, &wire_header, sizeof(wire_header)) != 0) {
        return -1;
    }
    
    if (write_n(sock, payload, payload_length) != 0) {
        return -1;
    }
    
    return 0;
}

static void update_unified_peer_sent(const char *address, uint16_t port) {
    pthread_mutex_lock(&unified_peer_mutex);
    
    int found = 0;
    int inactive_slot = -1;
    
    for (size_t i = 0; i < unified_peer_count; i++) {
        if (strcmp(unified_peers[i].address, address) == 0 && unified_peers[i].port == port) {
            unified_peers[i].last_message_sent = time(NULL);
            unified_peers[i].messages_sent++;
            unified_peers[i].active = 1;
            found = 1;
            break;
        }
        if (!unified_peers[i].active && inactive_slot == -1) {
            inactive_slot = i;
        }
    }
    
    if (!found) {
        int slot = (inactive_slot >= 0) ? inactive_slot : unified_peer_count;
        
        if (slot < MXD_MAX_PEERS) {
            strncpy(unified_peers[slot].address, address, sizeof(unified_peers[0].address) - 1);
            unified_peers[slot].address[sizeof(unified_peers[0].address) - 1] = '\0';
            unified_peers[slot].port = port;
            unified_peers[slot].last_message_sent = time(NULL);
            unified_peers[slot].last_message_received = 0;
            unified_peers[slot].messages_sent = 1;
            unified_peers[slot].messages_received = 0;
            unified_peers[slot].active = 1;
            
            if (inactive_slot < 0) {
                unified_peer_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&unified_peer_mutex);
}

static void update_unified_peer_received(const char *address, uint16_t port) {
    pthread_mutex_lock(&unified_peer_mutex);
    
    int found = 0;
    int inactive_slot = -1;
    
    for (size_t i = 0; i < unified_peer_count; i++) {
        if (strcmp(unified_peers[i].address, address) == 0 && unified_peers[i].port == port) {
            unified_peers[i].last_message_received = time(NULL);
            unified_peers[i].messages_received++;
            unified_peers[i].active = 1;
            found = 1;
            break;
        }
        if (!unified_peers[i].active && inactive_slot == -1) {
            inactive_slot = i;
        }
    }
    
    if (!found) {
        int slot = (inactive_slot >= 0) ? inactive_slot : unified_peer_count;
        
        if (slot < MXD_MAX_PEERS) {
            strncpy(unified_peers[slot].address, address, sizeof(unified_peers[0].address) - 1);
            unified_peers[slot].address[sizeof(unified_peers[0].address) - 1] = '\0';
            unified_peers[slot].port = port;
            unified_peers[slot].last_message_sent = 0;
            unified_peers[slot].last_message_received = time(NULL);
            unified_peers[slot].messages_sent = 0;
            unified_peers[slot].messages_received = 1;
            unified_peers[slot].active = 1;
            
            if (inactive_slot < 0) {
                unified_peer_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&unified_peer_mutex);
}

static void reset_rate_limit(void) {
    last_message_time = 0;
    messages_this_second = 0;
    last_tx_time = 0;
    tx_this_second = 0;
    consecutive_errors = 0;
    error_simulation_count = 0;
}

// Public function to reset rate limiting
int mxd_reset_rate_limit(void) {
    if (!p2p_initialized) {
        return -1;
    }
    reset_rate_limit();
    return 0;
}

// Message validation function
static int validate_message(const mxd_message_header_t *header, const void *payload) {
    if (!header || !payload) {
        return -1;
    }

    // Check magic number
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        return -1;
    }
    uint32_t expected_magic = secrets->network_magic;
    if (header->magic != expected_magic) {
        MXD_LOG_WARN("p2p", "Invalid network magic: received=0x%08X expected=0x%08X type=%u length=%u", 
                   header->magic, expected_magic, header->type, header->length);
        return -1;
    }

    // Check message size
    if (header->length > MXD_MAX_MESSAGE_SIZE) {
        MXD_LOG_WARN("p2p", "Message size %u exceeds maximum %d", header->length, MXD_MAX_MESSAGE_SIZE);
        return -1;
    }
    
    // Validate message type
    if (header->type > MXD_MSG_RAPID_TABLE_UPDATE) {
        MXD_LOG_WARN("p2p", "Invalid message type %d", header->type);
        return -1;
    }
    
    // Additional input validation
    if (header->length == 0) {
        MXD_LOG_WARN("p2p", "Empty message payload");
        return -1;
    }

    // Compute and verify SHA-512 checksum
    uint8_t computed_checksum[64];
    if (mxd_sha512(payload, header->length, computed_checksum) != 0) {
        return -1;
    }
    
    return memcmp(header->checksum, computed_checksum, 64) == 0 ? 0 : -1;
}

// Rate limiting function
static int check_rate_limit(mxd_message_type_t type) {
    uint64_t current_time = time(NULL);

    // Reset counters if time has changed
    if (current_time != last_message_time) {
        last_message_time = current_time;
        messages_this_second = 0;
    }
    if (current_time != last_tx_time) {
        last_tx_time = current_time;
        tx_this_second = 0;
    }

    // Check appropriate rate limit
    if (type == MXD_MSG_TRANSACTIONS) {
        // Allow exactly 10 transactions per second
        if (tx_this_second >= 10) {
            return -1;
        }
        tx_this_second++;
    } else {
        // Allow exactly 100 messages per second
        if (messages_this_second >= 100) {
            return -1;
        }
        messages_this_second++;
    }

    return 0;
}

// Set message handler callback
int mxd_set_message_handler(mxd_message_handler_t handler) {
    if (!p2p_initialized) {
        return -1;
    }
    message_handler = handler;
    return 0;
}

static void handle_get_peers_message(const char *address, uint16_t port, const void *payload, size_t length) {
    uint16_t peer_listening_port = port;
    
    if (length >= sizeof(uint16_t)) {
        memcpy(&peer_listening_port, payload, sizeof(uint16_t));
        MXD_LOG_INFO("p2p", "GET_PEERS from %s:%d (listening on port %d)", address, port, peer_listening_port);
        
        if (mxd_dht_add_peer(address, peer_listening_port) == 0) {
            MXD_LOG_INFO("p2p", "Added requesting peer %s:%d to DHT", address, peer_listening_port);
        }
    } else {
        MXD_LOG_WARN("p2p", "GET_PEERS message from %s:%d missing listening port", address, port);
    }
    
    mxd_dht_node_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_dht_get_peers(peers, &peer_count) != 0) {
        MXD_LOG_WARN("p2p", "Failed to get peers for GET_PEERS request from %s:%d", address, port);
        return;
    }
    
    size_t active_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            active_count++;
        }
    }
    
    MXD_LOG_DEBUG("p2p", "GET_PEERS: total peers=%zu, active peers=%zu", peer_count, active_count);
    
    size_t payload_size = sizeof(uint32_t) + (active_count * (256 + sizeof(uint16_t)));
    uint8_t *response = malloc(payload_size);
    if (!response) {
        MXD_LOG_ERROR("p2p", "Failed to allocate memory for PEERS response");
        return;
    }
    
    uint32_t count = (uint32_t)active_count;
    memcpy(response, &count, sizeof(uint32_t));
    
    size_t offset = sizeof(uint32_t);
    size_t serialized_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            memcpy(response + offset, peers[i].address, 256);
            offset += 256;
            memcpy(response + offset, &peers[i].port, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            serialized_count++;
            MXD_LOG_DEBUG("p2p", "Serializing peer %zu: %s:%d", serialized_count, peers[i].address, peers[i].port);
        }
    }
    
    MXD_LOG_DEBUG("p2p", "PEERS response: count=%u, serialized=%zu, payload_size=%zu, actual_offset=%zu", 
                 count, serialized_count, payload_size, offset);
    
    if (mxd_send_message(address, peer_listening_port, MXD_MSG_PEERS, response, offset) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send PEERS response to %s:%d", address, peer_listening_port);
    } else {
        MXD_LOG_INFO("p2p", "Sent %u active peers to %s:%d (payload: %zu bytes)", count, address, peer_listening_port, offset);
    }
    
    free(response);
}

static void handle_get_peers_on_socket(int sock, const char *address, uint16_t port, const void *payload, size_t length) {
    uint16_t peer_listening_port = port;
    
    if (length >= sizeof(uint16_t)) {
        memcpy(&peer_listening_port, payload, sizeof(uint16_t));
        MXD_LOG_INFO("p2p", "GET_PEERS from %s:%d (listening on port %d) on persistent connection", address, port, peer_listening_port);
        
        if (mxd_dht_add_peer(address, peer_listening_port) == 0) {
            MXD_LOG_INFO("p2p", "Added requesting peer %s:%d to DHT", address, peer_listening_port);
        }
    } else {
        MXD_LOG_WARN("p2p", "GET_PEERS message from %s:%d missing listening port", address, port);
    }
    
    mxd_dht_node_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    if (mxd_dht_get_peers(peers, &peer_count) != 0) {
        MXD_LOG_WARN("p2p", "Failed to get peers for GET_PEERS request from %s:%d", address, port);
        return;
    }
    
    size_t active_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            active_count++;
        }
    }
    
    MXD_LOG_DEBUG("p2p", "GET_PEERS (socket): total peers=%zu, active peers=%zu", peer_count, active_count);
    
    size_t payload_size = sizeof(uint32_t) + (active_count * (256 + sizeof(uint16_t)));
    uint8_t *response = malloc(payload_size);
    if (!response) {
        MXD_LOG_ERROR("p2p", "Failed to allocate memory for PEERS response");
        return;
    }
    
    uint32_t count = (uint32_t)active_count;
    memcpy(response, &count, sizeof(uint32_t));
    
    size_t offset = sizeof(uint32_t);
    size_t serialized_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            memcpy(response + offset, peers[i].address, 256);
            offset += 256;
            memcpy(response + offset, &peers[i].port, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            serialized_count++;
            MXD_LOG_DEBUG("p2p", "Serializing peer %zu (socket): %s:%d", serialized_count, peers[i].address, peers[i].port);
        }
    }
    
    MXD_LOG_DEBUG("p2p", "PEERS response (socket): count=%u, serialized=%zu, payload_size=%zu, actual_offset=%zu", 
                 count, serialized_count, payload_size, offset);
    
    if (send_on_socket(sock, MXD_MSG_PEERS, response, offset) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send PEERS response to %s:%d on persistent connection", address, peer_listening_port);
    } else {
        MXD_LOG_INFO("p2p", "Sent %u active peers to %s:%d on persistent connection (payload: %zu bytes)", count, address, peer_listening_port, offset);
    }
    
    free(response);
}

static void handle_peers_message(const char *address, uint16_t port, const void *payload, size_t length) {
    if (length < sizeof(uint32_t)) {
        MXD_LOG_WARN("p2p", "Invalid PEERS message from %s:%d (length=%zu, min=%zu)", 
                    address, port, length, sizeof(uint32_t));
        return;
    }
    
    uint32_t peer_count;
    memcpy(&peer_count, payload, sizeof(uint32_t));
    
    size_t available_entries = (length - sizeof(uint32_t)) / (256 + sizeof(uint16_t));
    size_t expected_size = sizeof(uint32_t) + (peer_count * (256 + sizeof(uint16_t)));
    
    MXD_LOG_DEBUG("p2p", "PEERS message from %s:%d: count=%u, length=%zu, expected=%zu, available=%zu", 
                 address, port, peer_count, length, expected_size, available_entries);
    
    if (available_entries == 0) {
        MXD_LOG_WARN("p2p", "PEERS message from %s:%d has no peer data (length=%zu)", 
                    address, port, length);
        return;
    }
    
    if (peer_count > available_entries) {
        MXD_LOG_WARN("p2p", "PEERS message from %s:%d: count=%u exceeds available=%zu (possible mixed version), using available count", 
                    address, port, peer_count, available_entries);
        peer_count = available_entries;
    }
    
    MXD_LOG_INFO("p2p", "Processing %u peers from %s:%d", peer_count, address, port);
    
    size_t offset = sizeof(uint32_t);
    size_t peers_added = 0;
    for (uint32_t i = 0; i < peer_count && i < MXD_MAX_PEERS; i++) {
        char peer_addr[257];
        uint16_t peer_port;
        
        memcpy(peer_addr, (uint8_t*)payload + offset, 256);
        peer_addr[256] = '\0';
        offset += 256;
        memcpy(&peer_port, (uint8_t*)payload + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        
        int is_localhost = (strcmp(peer_addr, "127.0.0.1") == 0 || strcmp(peer_addr, "localhost") == 0);
        int is_self_port = (peer_port == p2p_port);
        
        if (is_localhost && is_self_port) {
            MXD_LOG_DEBUG("p2p", "Skipping self-peer (localhost:%d)", peer_port);
            continue;
        }
        
        if (mxd_dht_add_peer(peer_addr, peer_port) == 0) {
            peers_added++;
            MXD_LOG_INFO("p2p", "Learned new peer from %s:%d -> %s:%d", address, port, peer_addr, peer_port);
        } else {
            MXD_LOG_DEBUG("p2p", "Peer %s:%d already known or failed to add", peer_addr, peer_port);
        }
        
        pthread_mutex_lock(&peer_mutex);
        int already_connected = 0;
        for (size_t j = 0; j < MXD_MAX_PEERS; j++) {
            if (active_connections[j].active && 
                strcmp(active_connections[j].address, peer_addr) == 0 &&
                active_connections[j].port == peer_port) {
                already_connected = 1;
                break;
            }
        }
        pthread_mutex_unlock(&peer_mutex);
        
        if (!already_connected) {
            MXD_LOG_INFO("p2p", "Attempting persistent connection to new peer %s:%d", peer_addr, peer_port);
            if (try_establish_persistent_connection(peer_addr, peer_port) == 0) {
                MXD_LOG_INFO("p2p", "Successfully established persistent connection to %s:%d", peer_addr, peer_port);
            } else {
                MXD_LOG_DEBUG("p2p", "Peer %s:%d does not support persistent connections or connection failed", peer_addr, peer_port);
            }
        }
    }
    
    MXD_LOG_INFO("p2p", "Completed processing PEERS message from %s:%d: %zu peers added to DHT", 
                address, port, peers_added);
}

static void handle_ping_message(const char *address, uint16_t port) {
    MXD_LOG_DEBUG("p2p", "Received PING from %s:%d, sending PONG", address, port);
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && 
            strcmp(active_connections[i].address, address) == 0 &&
            active_connections[i].port == port) {
            active_connections[i].last_keepalive_received = time(NULL);
            active_connections[i].keepalive_failures = 0;
            break;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    
    uint8_t pong_payload = 1;
    mxd_send_message(address, port, MXD_MSG_PONG, &pong_payload, sizeof(pong_payload));
}

static void handle_pong_message(const char *address, uint16_t port) {
    MXD_LOG_DEBUG("p2p", "Received PONG from %s:%d", address, port);
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && 
            strcmp(active_connections[i].address, address) == 0 &&
            active_connections[i].port == port) {
            active_connections[i].last_keepalive_received = time(NULL);
            active_connections[i].keepalive_failures = 0;
            break;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
}

static int create_signed_handshake(mxd_handshake_payload_t *handshake, const uint8_t *challenge, size_t challenge_len) {
    memset(handshake, 0, sizeof(mxd_handshake_payload_t));
    
    strncpy(handshake->node_id, node_config.node_id, sizeof(handshake->node_id) - 1);
    handshake->node_id[sizeof(handshake->node_id) - 1] = '\0';
    handshake->protocol_version = 1;
    handshake->listen_port = p2p_port;
    
    memcpy(handshake->public_key, node_public_key, 256);
    
    if (challenge && challenge_len > 0) {
        memcpy(handshake->challenge, challenge, challenge_len < 32 ? challenge_len : 32);
    } else {
        if (RAND_bytes(handshake->challenge, 32) != 1) {
            MXD_LOG_ERROR("p2p", "Failed to generate challenge nonce");
            return -1;
        }
    }
    
    uint8_t message_to_sign[288];
    memcpy(message_to_sign, handshake->challenge, 32);
    memcpy(message_to_sign + 32, handshake->node_id, 256);
    
    size_t sig_len = 0;
    if (mxd_dilithium_sign(handshake->signature, &sig_len, message_to_sign, 288, node_private_key) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to sign handshake");
        return -1;
    }
    
    handshake->signature_length = (uint16_t)sig_len;
    
    MXD_LOG_DEBUG("p2p", "Created signed handshake with signature length %u", handshake->signature_length);
    return 0;
}

static int handle_handshake_message(const char *address, uint16_t port, 
                                     const void *payload, size_t length,
                                     peer_connection_t *conn) {
    if (!payload || length < sizeof(mxd_handshake_payload_t)) {
        MXD_LOG_WARN("p2p", "Invalid HANDSHAKE payload from %s:%d", address, port);
        return -1;
    }
    
    const mxd_handshake_payload_t *handshake = (const mxd_handshake_payload_t *)payload;
    
    if (strcmp(handshake->node_id, node_config.node_id) == 0) {
        MXD_LOG_INFO("p2p", "Rejecting self-connection from %s:%d (node_id: %s)", 
                   address, port, handshake->node_id);
        return -1;
    }
    
    char derived_address[64];
    if (mxd_generate_address(handshake->public_key, derived_address, sizeof(derived_address)) != 0) {
        MXD_LOG_WARN("p2p", "Failed to derive address from public key for %s:%d", address, port);
        return -1;
    }
    
    if (strcmp(derived_address, handshake->node_id) != 0) {
        MXD_LOG_WARN("p2p", "Address mismatch for %s:%d: claimed=%s, derived=%s", 
                   address, port, handshake->node_id, derived_address);
        return -1;
    }
    
    uint8_t message_to_verify[288];
    memcpy(message_to_verify, handshake->challenge, 32);
    memcpy(message_to_verify + 32, handshake->node_id, 256);
    
    if (mxd_dilithium_verify(handshake->signature, handshake->signature_length, 
                             message_to_verify, 288, handshake->public_key) != 0) {
        MXD_LOG_WARN("p2p", "Signature verification failed for %s:%d (node_id: %s)", 
                   address, port, handshake->node_id);
        return -1;
    }
    
    MXD_LOG_INFO("p2p", "HANDSHAKE from %s:%d (node_id: %s, protocol: %u, listen_port: %u) - signature verified", 
               address, port, handshake->node_id, handshake->protocol_version, 
               handshake->listen_port);
    
    if (conn) {
        strncpy(conn->address, address, sizeof(conn->address) - 1);
        conn->address[sizeof(conn->address) - 1] = '\0';
        conn->port = handshake->listen_port;
        conn->active = 1;
        conn->connected_at = time(NULL);
        conn->last_keepalive_received = time(NULL);
        conn->keepalive_failures = 0;
        
        mxd_handshake_payload_t reply_handshake;
        if (create_signed_handshake(&reply_handshake, NULL, 0) == 0) {
            if (send_on_socket(conn->socket, MXD_MSG_HANDSHAKE, &reply_handshake, sizeof(reply_handshake)) == 0) {
                MXD_LOG_INFO("p2p", "Sent HANDSHAKE reply to %s:%d", address, port);
                
                uint16_t my_listen_port = p2p_port;
                if (send_on_socket(conn->socket, MXD_MSG_GET_PEERS, &my_listen_port, sizeof(uint16_t)) == 0) {
                    MXD_LOG_INFO("p2p", "Sent GET_PEERS to %s:%d over TCP after handshake", address, port);
                } else {
                    MXD_LOG_DEBUG("p2p", "Failed to send GET_PEERS to %s:%d over TCP", address, port);
                }
            } else {
                MXD_LOG_WARN("p2p", "Failed to send HANDSHAKE reply to %s:%d", address, port);
            }
        } else {
            MXD_LOG_ERROR("p2p", "Failed to create HANDSHAKE reply for %s:%d", address, port);
        }
    }
    
    if (mxd_dht_add_peer(address, handshake->listen_port) == 0) {
        MXD_LOG_INFO("p2p", "Added peer %s:%d to DHT after handshake", 
                   address, handshake->listen_port);
    }
    
    return 0;
}

static int handle_incoming_message(const char *address, uint16_t port,
                                 const mxd_message_header_t *header, 
                                 const void *payload) {
    if (!address || !header || !payload) {
        return -1;
    }

    if (validate_message(header, payload) != 0) {
        consecutive_errors++;
        if (consecutive_errors >= 10) {
            return -1;
        }
        return 0;
    }

    consecutive_errors = 0;
    
    update_unified_peer_received(address, port);

    switch (header->type) {
        case MXD_MSG_PING:
            handle_ping_message(address, port);
            break;
        case MXD_MSG_PONG:
            handle_pong_message(address, port);
            break;
        case MXD_MSG_GET_PEERS:
            handle_get_peers_message(address, port, payload, header->length);
            break;
        case MXD_MSG_PEERS:
            handle_peers_message(address, port, payload, header->length);
            break;
        default:
            if (message_handler) {
                message_handler(address, port, header->type, payload, header->length);
            }
            break;
    }

    return 0;
}

static int try_establish_persistent_connection(const char *address, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, address, &server_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    mxd_handshake_payload_t handshake;
    if (create_signed_handshake(&handshake, NULL, 0) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create signed handshake for %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    if (send_on_socket(sock, MXD_MSG_HANDSHAKE, &handshake, sizeof(handshake)) != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to send HANDSHAKE to %s:%d for persistent connection", address, port);
        close(sock);
        return -1;
    }
    
    uint8_t header_buffer[76];
    int read_result = read_n(sock, header_buffer, sizeof(header_buffer));
    if (read_result != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to read HANDSHAKE response from %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        close(sock);
        return -1;
    }
    
    mxd_message_header_t header;
    
    if (parse_wire_header(header_buffer, &header, secrets->network_magic) != 0) {
        MXD_LOG_INFO("p2p", "Failed to parse HANDSHAKE response from %s:%d (invalid wire format)", address, port);
        close(sock);
        return -1;
    }
    
    if (header.type != MXD_MSG_HANDSHAKE) {
        MXD_LOG_INFO("p2p", "Peer %s:%d does not support persistent connections (expected HANDSHAKE, got %d)", 
                   address, port, header.type);
        close(sock);
        return -1;
    }
    
    uint8_t *payload = malloc(header.length);
    if (!payload) {
        close(sock);
        return -1;
    }
    
    if (read_n(sock, payload, header.length) != 0) {
        free(payload);
        close(sock);
        return -1;
    }
    
    const mxd_handshake_payload_t *response = (const mxd_handshake_payload_t *)payload;
    
    if (strcmp(response->node_id, node_config.node_id) == 0) {
        MXD_LOG_INFO("p2p", "Rejecting self-connection to %s:%d (node_id: %s)", 
                   address, port, response->node_id);
        free(payload);
        close(sock);
        return -1;
    }
    
    free(payload);
    
    pthread_mutex_lock(&peer_mutex);
    
    int slot = -1;
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (!active_connections[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&peer_mutex);
        MXD_LOG_WARN("p2p", "No available slots for persistent connection to %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    strncpy(active_connections[slot].address, address, sizeof(active_connections[slot].address) - 1);
    active_connections[slot].address[sizeof(active_connections[slot].address) - 1] = '\0';
    active_connections[slot].port = port;
    active_connections[slot].socket = sock;
    active_connections[slot].active = 1;
    active_connections[slot].connected_at = time(NULL);
    active_connections[slot].last_keepalive_received = time(NULL);
    active_connections[slot].keepalive_failures = 0;
    active_connection_count++;
    
    pthread_t thread;
    pthread_attr_t thread_attr;
    pthread_attr_init(&thread_attr);
    pthread_attr_setstacksize(&thread_attr, 512 * 1024); // 512KB stack
    if (pthread_create(&thread, &thread_attr, connection_handler, &active_connections[slot]) != 0) {
        active_connections[slot].active = 0;
        active_connection_count--;
        pthread_attr_destroy(&thread_attr);
        pthread_mutex_unlock(&peer_mutex);
        close(sock);
        return -1;
    }
    pthread_detach(thread);
    pthread_attr_destroy(&thread_attr);
    
    pthread_mutex_unlock(&peer_mutex);
    
    MXD_LOG_INFO("p2p", "Established persistent connection to %s:%d (slot %d)", address, port, slot);
    return 0;
}

static void* peer_connector_thread_func(void* arg) {
    (void)arg;
    
    MXD_LOG_INFO("p2p", "Peer connector thread started");
    
    while (peer_connector_running) {
        sleep(30);
        
        if (!peer_connector_running) break;
        
        mxd_dht_node_t dht_peers[MXD_MAX_PEERS];
        size_t dht_peer_count = MXD_MAX_PEERS;
        
        if (mxd_dht_get_peers(dht_peers, &dht_peer_count) != 0) {
            continue;
        }
        
        for (size_t i = 0; i < dht_peer_count; i++) {
            if (!dht_peers[i].active) continue;
            
            pthread_mutex_lock(&peer_mutex);
            int already_connected = 0;
            for (size_t j = 0; j < MXD_MAX_PEERS; j++) {
                if (active_connections[j].active && 
                    strcmp(active_connections[j].address, dht_peers[i].address) == 0 &&
                    active_connections[j].port == dht_peers[i].port) {
                    already_connected = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&peer_mutex);
            
            if (!already_connected) {
                MXD_LOG_INFO("p2p", "Proactively attempting persistent connection to DHT peer %s:%d", 
                           dht_peers[i].address, dht_peers[i].port);
                if (try_establish_persistent_connection(dht_peers[i].address, dht_peers[i].port) == 0) {
                    MXD_LOG_INFO("p2p", "Successfully established persistent connection to %s:%d", 
                               dht_peers[i].address, dht_peers[i].port);
                } else {
                    MXD_LOG_DEBUG("p2p", "Failed to establish persistent connection to %s:%d", 
                                dht_peers[i].address, dht_peers[i].port);
                }
            }
        }
    }
    
    MXD_LOG_INFO("p2p", "Peer connector thread stopped");
    return NULL;
}

static void* keepalive_thread_func(void* arg) {
    (void)arg;
    
    MXD_LOG_INFO("p2p", "Keepalive thread started");
    
    typedef struct {
        char address[256];
        uint16_t port;
        int timed_out;
        time_t time_since_last_received;
        int needs_ping;
        int ping_success;
    } peer_action_t;
    
    peer_action_t peer_actions[MXD_MAX_PEERS];
    
    while (keepalive_running) {
        sleep(MXD_KEEPALIVE_INTERVAL);
        
        if (!keepalive_running) break;
        
        time_t now = time(NULL);
        size_t action_count = 0;
        
        pthread_mutex_lock(&unified_peer_mutex);
        
        for (size_t i = 0; i < unified_peer_count && action_count < MXD_MAX_PEERS; i++) {
            if (!unified_peers[i].active) continue;
            
            peer_actions[action_count].timed_out = 0;
            peer_actions[action_count].needs_ping = 0;
            peer_actions[action_count].ping_success = 0;
            strncpy(peer_actions[action_count].address, unified_peers[i].address, sizeof(peer_actions[action_count].address) - 1);
            peer_actions[action_count].address[sizeof(peer_actions[action_count].address) - 1] = '\0';
            peer_actions[action_count].port = unified_peers[i].port;
            
            if (unified_peers[i].last_message_received > 0) {
                time_t time_since_last_received = now - unified_peers[i].last_message_received;
                
                if (time_since_last_received > MXD_KEEPALIVE_TIMEOUT) {
                    peer_actions[action_count].timed_out = 1;
                    peer_actions[action_count].time_since_last_received = time_since_last_received;
                    unified_peers[i].active = 0;
                    action_count++;
                    continue;
                }
            }
            
            time_t time_since_last_sent = (unified_peers[i].last_message_sent > 0) ? 
                                          (now - unified_peers[i].last_message_sent) : MXD_KEEPALIVE_INTERVAL;
            
            if (time_since_last_sent >= MXD_KEEPALIVE_INTERVAL) {
                peer_actions[action_count].needs_ping = 1;
                action_count++;
            }
        }
        
        pthread_mutex_unlock(&unified_peer_mutex);
        
        for (size_t i = 0; i < action_count; i++) {
            if (peer_actions[i].timed_out) {
                MXD_LOG_WARN("p2p", "Peer %s:%d timed out (no response for %ld seconds), marking inactive",
                           peer_actions[i].address, peer_actions[i].port, 
                           peer_actions[i].time_since_last_received);
            } else if (peer_actions[i].needs_ping && !peer_actions[i].timed_out) {
                uint8_t ping_payload = 1;
                if (mxd_send_message(peer_actions[i].address, peer_actions[i].port,
                                   MXD_MSG_PING, &ping_payload, sizeof(ping_payload)) == 0) {
                    MXD_LOG_DEBUG("p2p", "Sent keepalive PING to %s:%d", 
                               peer_actions[i].address, peer_actions[i].port);
                } else {
                    MXD_LOG_DEBUG("p2p", "Failed to send keepalive to %s:%d",
                               peer_actions[i].address, peer_actions[i].port);
                }
            }
        }
        
        pthread_mutex_lock(&peer_mutex);
        
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (!active_connections[i].active) continue;
            
            time_t time_since_last_received = now - active_connections[i].last_keepalive_received;
            
            if (time_since_last_received > MXD_KEEPALIVE_TIMEOUT) {
                MXD_LOG_WARN("p2p", "Incoming connection %s:%d timed out, closing socket",
                           active_connections[i].address, active_connections[i].port);
                close(active_connections[i].socket);
                active_connections[i].active = 0;
                active_connection_count--;
            }
        }
        
        pthread_mutex_unlock(&peer_mutex);
    }
    
    MXD_LOG_INFO("p2p", "Keepalive thread stopped");
    return NULL;
}

static void* connection_handler(void* arg) {
    peer_connection_t *conn = (peer_connection_t*)arg;
    
    MXD_LOG_INFO("p2p", "Connection handler started for %s:%d", conn->address, conn->port);
    
    mxd_handshake_payload_t handshake;
    if (create_signed_handshake(&handshake, NULL, 0) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create signed handshake for %s:%d", conn->address, conn->port);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    if (send_on_socket(conn->socket, MXD_MSG_HANDSHAKE, &handshake, sizeof(handshake)) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send HANDSHAKE to %s:%d", conn->address, conn->port);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    MXD_LOG_INFO("p2p", "Sent HANDSHAKE to %s:%d", conn->address, conn->port);
    
    uint8_t header_buffer[76];
    int read_result = read_n(conn->socket, header_buffer, sizeof(header_buffer));
    if (read_result != 0) {
        MXD_LOG_WARN("p2p", "Failed to read HANDSHAKE from %s:%d (v2 protocol requires HANDSHAKE)", 
                   conn->address, conn->port);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    mxd_message_header_t header;
    if (parse_wire_header(header_buffer, &header, secrets->network_magic) != 0) {
        MXD_LOG_WARN("p2p", "Failed to parse header from %s:%d (invalid v2 wire format)", 
                   conn->address, conn->port);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    if (header.type != MXD_MSG_HANDSHAKE) {
        MXD_LOG_WARN("p2p", "Peer %s:%d sent %d instead of HANDSHAKE (v2 protocol violation)", 
                   conn->address, conn->port, header.type);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    uint8_t *payload = malloc(header.length);
    if (!payload) {
        MXD_LOG_ERROR("p2p", "Failed to allocate memory for HANDSHAKE");
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    if (read_n(conn->socket, payload, header.length) != 0) {
        MXD_LOG_WARN("p2p", "Error reading HANDSHAKE payload from %s:%d", conn->address, conn->port);
        free(payload);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    if (handle_handshake_message(conn->address, conn->port, payload, header.length, conn) != 0) {
        MXD_LOG_INFO("p2p", "Handshake validation failed for %s:%d", conn->address, conn->port);
        free(payload);
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    free(payload);
    
    MXD_LOG_INFO("p2p", "Handshake completed for %s:%d, connection established", 
               conn->address, conn->port);
    
    while (conn->active && server_running) {
        uint8_t header_buffer[76];
        
        int read_result = read_n(conn->socket, header_buffer, sizeof(header_buffer));
        if (read_result != 0) {
            if (read_result == -2) {
                MXD_LOG_DEBUG("p2p", "Peer %s:%d closed connection (EOF)", 
                           conn->address, conn->port);
            } else if (read_result == -3) {
                MXD_LOG_DEBUG("p2p", "Peer %s:%d receive timeout", 
                           conn->address, conn->port);
            } else {
                MXD_LOG_WARN("p2p", "Peer %s:%d error reading header: errno=%d (%s)", 
                           conn->address, conn->port, errno, strerror(errno));
            }
            break;
        }
        
        mxd_message_header_t header;
        if (parse_wire_header(header_buffer, &header, secrets->network_magic) != 0) {
            MXD_LOG_WARN("p2p", "Failed to parse header from %s:%d (invalid v2 wire format)", 
                       conn->address, conn->port);
            break;
        }
        
        uint8_t *payload = malloc(header.length);
        if (!payload) {
            MXD_LOG_ERROR("p2p", "Failed to allocate %u bytes for message", header.length);
            break;
        }
        
        if (read_n(conn->socket, payload, header.length) != 0) {
            MXD_LOG_WARN("p2p", "Error reading payload from %s:%d", conn->address, conn->port);
            free(payload);
            break;
        }
        
        if (header.type == MXD_MSG_GET_PEERS) {
            handle_get_peers_on_socket(conn->socket, conn->address, conn->port, payload, header.length);
        } else {
            handle_incoming_message(conn->address, conn->port, &header, payload);
        }
        free(payload);
    }
    
    close(conn->socket);
    conn->active = 0;
    MXD_LOG_INFO("p2p", "Connection handler stopped for %s:%d", conn->address, conn->port);
    
    return NULL;
}

static void* server_thread_func(void* arg) {
    (void)arg;
    
    MXD_LOG_INFO("p2p", "P2P server thread started");
    
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running && errno != EINTR) {
                MXD_LOG_ERROR("p2p", "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        pthread_mutex_lock(&peer_mutex);
        
        char *client_ip = inet_ntoa(client_addr.sin_addr);
        uint16_t client_port = ntohs(client_addr.sin_port);
        
        int duplicate_found = 0;
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (active_connections[i].active &&
                strcmp(active_connections[i].address, client_ip) == 0 &&
                active_connections[i].port == client_port) {
                duplicate_found = 1;
                break;
            }
        }
        
        if (duplicate_found) {
            MXD_LOG_INFO("p2p", "Duplicate connection from %s:%d rejected", client_ip, client_port);
            close(client_socket);
            pthread_mutex_unlock(&peer_mutex);
            continue;
        }
        
        int slot = -1;
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (!active_connections[i].active) {
                slot = i;
                break;
            }
        }
        
        if (slot < 0) {
            MXD_LOG_WARN("p2p", "Max connections reached, rejecting connection");
            close(client_socket);
            pthread_mutex_unlock(&peer_mutex);
            continue;
        }
        
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        time_t now = time(NULL);
        active_connections[slot].socket = client_socket;
        strncpy(active_connections[slot].address, client_ip, sizeof(active_connections[slot].address) - 1);
        active_connections[slot].port = client_port;
        active_connections[slot].connected_at = now;
        active_connections[slot].last_keepalive_sent = now;
        active_connections[slot].last_keepalive_received = now;
        active_connections[slot].keepalive_failures = 0;
        active_connections[slot].active = 1;
        
        pthread_attr_t conn_attr;
        pthread_attr_init(&conn_attr);
        pthread_attr_setstacksize(&conn_attr, 512 * 1024); // 512KB stack
        if (pthread_create(&connection_threads[slot], &conn_attr, connection_handler, &active_connections[slot]) != 0) {
            MXD_LOG_ERROR("p2p", "Failed to create connection thread");
            pthread_attr_destroy(&conn_attr);
            close(client_socket);
            active_connections[slot].active = 0;
        } else {
            pthread_detach(connection_threads[slot]);
            pthread_attr_destroy(&conn_attr);
            active_connection_count++;
            MXD_LOG_INFO("p2p", "Accepted connection from %s:%d (slot %d)", client_ip, client_port, slot);
        }
        
        pthread_mutex_unlock(&peer_mutex);
    }
    
    MXD_LOG_INFO("p2p", "P2P server thread stopped");
    return NULL;
}

static void derive_node_id(char* node_id_buf, size_t buf_size, const uint8_t* public_key, uint16_t port) {
    int is_zero_key = 1;
    for (int i = 0; i < 256; i++) {
        if (public_key[i] != 0) {
            is_zero_key = 0;
            break;
        }
    }
    
    if (is_zero_key) {
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            snprintf(hostname, sizeof(hostname), "unknown");
        }
        
        char input[512];
        snprintf(input, sizeof(input), "%s:%d", hostname, port);
        
        unsigned char sha_hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)input, strlen(input), sha_hash);
        
        snprintf(node_id_buf, buf_size, "node_");
        for (int i = 0; i < 16 && (5 + i*2) < buf_size - 1; i++) {
            snprintf(node_id_buf + 5 + i*2, 3, "%02x", sha_hash[i]);
        }
        
        MXD_LOG_INFO("p2p", "Derived node_id from hostname (fallback for zero pubkey): %s", node_id_buf);
    } else {
        if (mxd_generate_address(public_key, node_id_buf, buf_size) != 0) {
            MXD_LOG_ERROR("p2p", "Failed to generate wallet address from public key");
            snprintf(node_id_buf, buf_size, "mx_error");
            return;
        }
        
        MXD_LOG_INFO("p2p", "Derived node_id from wallet address: %s", node_id_buf);
    }
}

int mxd_init_p2p(uint16_t port, const uint8_t* public_key, const uint8_t* private_key) {
    if (mxd_init_secrets(NULL) != 0) {
        MXD_LOG_WARN("p2p", "Secrets initialization failed, using defaults");
    }
    
    if (p2p_initialized) {
        return 0;
    }
    
    signal(SIGPIPE, SIG_IGN);
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (secrets) {
        MXD_LOG_INFO("p2p", "Wire format: sizeof(mxd_wire_header_t)=%zu, sizeof(mxd_message_header_t)=%zu, sizeof(mxd_message_type_t)=%zu",
                   sizeof(mxd_wire_header_t), sizeof(mxd_message_header_t), sizeof(mxd_message_type_t));
        MXD_LOG_INFO("p2p", "Network magic: 0x%08X", secrets->network_magic);
    } else {
        MXD_LOG_ERROR("p2p", "Failed to get secrets during initialization");
    }
    
    reset_rate_limit();
    consecutive_errors = 0;
    last_message_time = 0;
    last_tx_time = 0;
    messages_this_second = 0;
    tx_this_second = 0;
    
    p2p_port = port;
    memcpy(node_public_key, public_key, 256);
    memcpy(node_private_key, private_key, 128);
    
    memset(&node_config, 0, sizeof(node_config));
    node_config.port = port;
    
    derive_node_id(node_config.node_id, sizeof(node_config.node_id), public_key, port);
    snprintf(node_config.data_dir, sizeof(node_config.data_dir), "data");
    
    memset(active_connections, 0, sizeof(active_connections));
    active_connection_count = 0;
    
    memset(manual_peers, 0, sizeof(manual_peers));
    manual_peer_count = 0;
    
    p2p_initialized = 1;
    MXD_LOG_INFO("p2p", "P2P initialized on port %d with node_id: %s", port, node_config.node_id);
    return 0;
}

int mxd_start_p2p(void) {
    if (!p2p_initialized) {
        MXD_LOG_ERROR("p2p", "P2P not initialized");
        return 1;
    }
    
    if (server_running) {
        MXD_LOG_WARN("p2p", "P2P server already running");
        return 0;
    }
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        MXD_LOG_ERROR("p2p", "Failed to create socket: %s", strerror(errno));
        return 1;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        MXD_LOG_WARN("p2p", "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(p2p_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        MXD_LOG_ERROR("p2p", "Failed to bind to port %d: %s", p2p_port, strerror(errno));
        close(server_socket);
        server_socket = -1;
        return 1;
    }
    
    if (listen(server_socket, 10) < 0) {
        MXD_LOG_ERROR("p2p", "Failed to listen on socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return 1;
    }
    
    server_running = 1;
    pthread_attr_t server_attr;
    pthread_attr_init(&server_attr);
    pthread_attr_setstacksize(&server_attr, 512 * 1024); // 512KB stack
    if (pthread_create(&server_thread, &server_attr, server_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create server thread: %s", strerror(errno));
        pthread_attr_destroy(&server_attr);
        close(server_socket);
        server_socket = -1;
        server_running = 0;
        return 1;
    }
    pthread_attr_destroy(&server_attr);
    
    usleep(50000);
    
    keepalive_running = 1;
    keepalive_thread_created = 0;
    pthread_attr_t keepalive_attr;
    pthread_attr_init(&keepalive_attr);
    pthread_attr_setstacksize(&keepalive_attr, 512 * 1024); // 512KB stack
    if (pthread_create(&keepalive_thread, &keepalive_attr, keepalive_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create keepalive thread: %s", strerror(errno));
        pthread_attr_destroy(&keepalive_attr);
        keepalive_running = 0;
    } else {
        pthread_attr_destroy(&keepalive_attr);
        keepalive_thread_created = 1;
        MXD_LOG_INFO("p2p", "Keepalive thread started");
    }
    
    const char* enable_peer_connector = getenv("MXD_ENABLE_PEER_CONNECTOR");
    peer_connector_thread_created = 0;
    if (!enable_peer_connector || strcmp(enable_peer_connector, "0") != 0) {
        peer_connector_running = 1;
        pthread_attr_t connector_attr;
        pthread_attr_init(&connector_attr);
        pthread_attr_setstacksize(&connector_attr, 512 * 1024); // 512KB stack
        if (pthread_create(&peer_connector_thread, &connector_attr, peer_connector_thread_func, NULL) != 0) {
            MXD_LOG_ERROR("p2p", "Failed to create peer connector thread: %s", strerror(errno));
            pthread_attr_destroy(&connector_attr);
            peer_connector_running = 0;
        } else {
            pthread_attr_destroy(&connector_attr);
            peer_connector_thread_created = 1;
            MXD_LOG_INFO("p2p", "Peer connector thread started");
        }
    } else {
        MXD_LOG_DEBUG("p2p", "Peer connector thread disabled (set MXD_ENABLE_PEER_CONNECTOR=0 to disable)");
    }
    
    if (!enable_peer_connector || strcmp(enable_peer_connector, "0") != 0) {
        pthread_mutex_lock(&manual_peer_mutex);
        for (size_t i = 0; i < manual_peer_count; i++) {
            if (manual_peers[i].active) {
                MXD_LOG_DEBUG("p2p", "Initial connection attempt to manual peer %s:%d", 
                           manual_peers[i].address, manual_peers[i].port);
                if (try_establish_persistent_connection(manual_peers[i].address, manual_peers[i].port) == 0) {
                    MXD_LOG_INFO("p2p", "Successfully established initial connection to manual peer %s:%d", 
                               manual_peers[i].address, manual_peers[i].port);
                }
            }
        }
        pthread_mutex_unlock(&manual_peer_mutex);
        
        mxd_dht_node_t startup_peers[MXD_MAX_PEERS];
        size_t startup_peer_count = MXD_MAX_PEERS;
        if (mxd_dht_get_peers(startup_peers, &startup_peer_count) == 0) {
            MXD_LOG_INFO("p2p", "Attempting initial connections to %zu DHT peers", startup_peer_count);
            for (size_t i = 0; i < startup_peer_count; i++) {
                if (startup_peers[i].active) {
                    MXD_LOG_DEBUG("p2p", "Initial connection attempt to %s:%d", 
                               startup_peers[i].address, startup_peers[i].port);
                    if (try_establish_persistent_connection(startup_peers[i].address, startup_peers[i].port) == 0) {
                        MXD_LOG_INFO("p2p", "Successfully established initial connection to %s:%d", 
                                   startup_peers[i].address, startup_peers[i].port);
                    }
                }
            }
        }
    }
    
    MXD_LOG_INFO("p2p", "P2P server started on port %d", p2p_port);
    return 0;
}

int mxd_stop_p2p(void) {
    if (!p2p_initialized) {
        return 0;
    }
    
    keepalive_running = 0;
    peer_connector_running = 0;
    server_running = 0;
    
    if (server_socket >= 0) {
        shutdown(server_socket, SHUT_RDWR);
        close(server_socket);
        server_socket = -1;
    }
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active) {
            close(active_connections[i].socket);
            active_connections[i].active = 0;
        }
    }
    active_connection_count = 0;
    pthread_mutex_unlock(&peer_mutex);
    
    pthread_join(server_thread, NULL);
    
    if (keepalive_thread_created) {
        pthread_join(keepalive_thread, NULL);
        keepalive_thread_created = 0;
    }
    
    if (peer_connector_thread_created) {
        pthread_join(peer_connector_thread, NULL);
        peer_connector_thread_created = 0;
    }
    
    p2p_initialized = 0;
    MXD_LOG_INFO("p2p", "P2P stopped");
    return 0;
}

int mxd_add_peer(const char* address, uint16_t port) {
    if (!p2p_initialized || !address) {
        return 1;
    }
    
    pthread_mutex_lock(&manual_peer_mutex);
    
    for (size_t i = 0; i < manual_peer_count; i++) {
        if (manual_peers[i].port == port && 
            strcmp(manual_peers[i].address, address) == 0) {
            manual_peers[i].active = 1;
            pthread_mutex_unlock(&manual_peer_mutex);
            MXD_LOG_INFO("p2p", "Peer %s:%d already exists", address, port);
            return 0;
        }
    }
    
    if (manual_peer_count >= MXD_MAX_PEERS) {
        pthread_mutex_unlock(&manual_peer_mutex);
        MXD_LOG_WARN("p2p", "Manual peer list full");
        return 1;
    }
    
    strncpy(manual_peers[manual_peer_count].address, address, sizeof(manual_peers[0].address) - 1);
    manual_peers[manual_peer_count].address[sizeof(manual_peers[0].address) - 1] = '\0';
    manual_peers[manual_peer_count].port = port;
    manual_peers[manual_peer_count].active = 1;
    manual_peer_count++;
    
    pthread_mutex_unlock(&manual_peer_mutex);
    
    mxd_dht_add_peer(address, port);
    
    MXD_LOG_INFO("p2p", "Added peer %s:%d (total manual peers: %zu)", address, port, manual_peer_count);
    
    const char* enable_peer_connector = getenv("MXD_ENABLE_PEER_CONNECTOR");
    if (!enable_peer_connector || strcmp(enable_peer_connector, "0") != 0) {
        MXD_LOG_DEBUG("p2p", "Attempting immediate connection to newly added peer %s:%d", address, port);
        if (try_establish_persistent_connection(address, port) == 0) {
            MXD_LOG_INFO("p2p", "Successfully established immediate connection to %s:%d", address, port);
        }
    }
    
    return 0;
}

// Get list of connected peers
int mxd_get_peers(mxd_peer_t* peers, size_t* peer_count) {
    if (!peers || !peer_count) {
        MXD_LOG_INFO("p2p", "mxd_get_peers failed: invalid parameters");
        return -1;
    }
    
    size_t max_peers = *peer_count;
    *peer_count = 0;
    
    if (max_peers == 0) {
        return 0;
    }
    
    size_t dht_peer_count = max_peers;
    mxd_dht_node_t dht_nodes[MXD_MAX_PEERS];
    
    if (mxd_dht_get_peers(dht_nodes, &dht_peer_count) == 0) {
        for (size_t i = 0; i < dht_peer_count && i < max_peers; i++) {
            if (dht_nodes[i].active) {
                strncpy(peers[i].address, dht_nodes[i].address, sizeof(peers[i].address) - 1);
                peers[i].address[sizeof(peers[i].address) - 1] = '\0';
                peers[i].port = dht_nodes[i].port;
                peers[i].state = MXD_PEER_CONNECTED;
                peers[i].latency = 1000;
                peers[i].last_seen = time(NULL);
                (*peer_count)++;
            }
        }
        MXD_LOG_INFO("p2p", "Retrieved %zu peers from DHT", *peer_count);
    }
    
    return 0;
}

int mxd_send_message_with_retry(const char* address, uint16_t port, 
                                       mxd_message_type_t type, const void* payload, 
                                       size_t payload_length, int max_retries) {
    int retry_delay_ms = 1000;
    const int max_delay_ms = 60000;
    
    for (int attempt = 0; attempt < max_retries; attempt++) {
        int result = mxd_send_message(address, port, type, payload, payload_length);
        if (result == 0) {
            if (attempt > 0) {
                MXD_LOG_INFO("p2p", "Successfully connected to %s:%d after %d retries", 
                           address, port, attempt);
            }
            return 0;
        }
        
        if (attempt < max_retries - 1) {
            MXD_LOG_WARN("p2p", "Connection attempt %d/%d to %s:%d failed, retrying in %d ms", 
                       attempt + 1, max_retries, address, port, retry_delay_ms);
            usleep(retry_delay_ms * 1000);
            retry_delay_ms = (retry_delay_ms * 2 > max_delay_ms) ? max_delay_ms : retry_delay_ms * 2;
        }
    }
    
    MXD_LOG_ERROR("p2p", "Failed to connect to %s:%d after %d attempts", address, port, max_retries);
    return -1;
}

int mxd_send_message(const char* address, uint16_t port, 
                    mxd_message_type_t type, const void* payload, 
                    size_t payload_length) {
    if (!p2p_initialized || !address || !payload || 
        payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        MXD_LOG_WARN("p2p", "Failed to create socket for sending: %s", strerror(errno));
        return -1;
    }
    
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    int set = 1;
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(set));
#endif
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, address, &peer_addr.sin_addr) <= 0) {
        MXD_LOG_WARN("p2p", "Invalid address: %s", address);
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        MXD_LOG_WARN("p2p", "Failed to connect to %s:%d: %s", address, port, strerror(errno));
        close(sock);
        return -1;
    }
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        close(sock);
        return -1;
    }
    
    mxd_handshake_payload_t handshake;
    if (create_signed_handshake(&handshake, NULL, 0) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to create signed handshake for %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    if (send_on_socket(sock, MXD_MSG_HANDSHAKE, &handshake, sizeof(handshake)) != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to send HANDSHAKE to %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    struct timeval short_timeout;
    short_timeout.tv_sec = 0;
    short_timeout.tv_usec = 250000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &short_timeout, sizeof(short_timeout));
    
    uint8_t header_buffer[76];
    int read_result = read_n(sock, header_buffer, sizeof(header_buffer));
    if (read_result == 0) {
        mxd_message_header_t server_header;
        if (parse_wire_header(header_buffer, &server_header, secrets->network_magic) == 0 &&
            server_header.type == MXD_MSG_HANDSHAKE) {
            
            uint8_t *server_payload = malloc(server_header.length);
            if (server_payload && read_n(sock, server_payload, server_header.length) == 0) {
                MXD_LOG_DEBUG("p2p", "Received server HANDSHAKE from %s:%d", address, port);
                free(server_payload);
            } else {
                if (server_payload) free(server_payload);
            }
        }
    }
    
    struct timeval normal_timeout;
    normal_timeout.tv_sec = 5;
    normal_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &normal_timeout, sizeof(normal_timeout));
    
    mxd_message_header_t header = {
        .magic = secrets->network_magic,
        .type = type,
        .length = payload_length
    };
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        close(sock);
        return -1;
    }
    
    mxd_wire_header_t wire_header;
    header_to_wire(&header, &wire_header);
    
    if (write_n(sock, &wire_header, sizeof(wire_header)) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send v2 header to %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    if (write_n(sock, payload, payload_length) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send payload to %s:%d", address, port);
        close(sock);
        return -1;
    }
    
    close(sock);
    
    update_unified_peer_sent(address, port);
    
    return 0;
}

int mxd_broadcast_message(mxd_message_type_t type, const void* payload, size_t payload_length) {
    if (!p2p_initialized || !payload) {
        consecutive_errors++;
        if (consecutive_errors > 10) {
            return -1;
        }
        return 0;
    }

    if (payload_length > MXD_MAX_MESSAGE_SIZE || type > MXD_MSG_RAPID_TABLE_UPDATE) {
        return -1;
    }

    consecutive_errors = 0;

    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        return -1;
    }
    
    mxd_message_header_t header = {
        .magic = secrets->network_magic,
        .type = type,
        .length = payload_length
    };
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        return -1;
    }

    if (check_rate_limit(type) != 0) {
        return -1;
    }

    mxd_dht_node_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    
    mxd_dht_get_peers(peers, &peer_count);
    
    int success_count = 0;
    
    pthread_mutex_lock(&manual_peer_mutex);
    for (size_t i = 0; i < manual_peer_count; i++) {
        if (manual_peers[i].active) {
            if (mxd_send_message(manual_peers[i].address, manual_peers[i].port, type, payload, payload_length) == 0) {
                success_count++;
            }
        }
    }
    pthread_mutex_unlock(&manual_peer_mutex);
    
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            if (mxd_send_message(peers[i].address, peers[i].port, type, payload, payload_length) == 0) {
                success_count++;
            }
        }
    }
    
    MXD_LOG_DEBUG("p2p", "Broadcast to %d peers", success_count);
    
    return success_count > 0 ? 0 : -1;
}

int mxd_start_peer_discovery(void) {
    if (!p2p_initialized) {
        MXD_LOG_ERROR("p2p", "P2P not initialized");
        return 1;
    }
    
    // Initialize DHT for peer discovery
    if (mxd_init_node(&node_config) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to initialize DHT node");
        return 1;
    }
    
    if (mxd_start_dht(p2p_port) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to start DHT service");
        return 1;
    }
    
    MXD_LOG_INFO("p2p", "Peer discovery started");
    return 0;
}

int mxd_stop_peer_discovery(void) {
    mxd_stop_dht();
    MXD_LOG_INFO("p2p", "Peer discovery stopped");
    return 0;
}

int mxd_get_connection_count(void) {
    if (!p2p_initialized) {
        return 0;
    }
    
    pthread_mutex_lock(&peer_mutex);
    size_t count = active_connection_count;
    pthread_mutex_unlock(&peer_mutex);
    
    return (int)count;
}

int mxd_get_known_peer_count(void) {
    size_t dht_count = MXD_MAX_PEERS;
    mxd_dht_node_t dht_nodes[MXD_MAX_PEERS];
    
    if (mxd_dht_get_peers(dht_nodes, &dht_count) != 0) {
        return 0;
    }
    
    size_t active_count = 0;
    for (size_t i = 0; i < dht_count; i++) {
        if (dht_nodes[i].active) {
            active_count++;
        }
    }
    
    return (int)active_count;
}

int mxd_get_peer_connections(mxd_peer_info_t* peer_info, size_t* count) {
    if (!peer_info || !count || !p2p_initialized) {
        return -1;
    }
    
    size_t max_count = *count;
    *count = 0;
    
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS && *count < max_count; i++) {
        if (active_connections[i].active) {
            strncpy(peer_info[*count].address, active_connections[i].address, 
                   sizeof(peer_info[*count].address) - 1);
            peer_info[*count].address[sizeof(peer_info[*count].address) - 1] = '\0';
            peer_info[*count].port = active_connections[i].port;
            peer_info[*count].connected_at = active_connections[i].connected_at;
            peer_info[*count].last_keepalive_sent = active_connections[i].last_keepalive_sent;
            peer_info[*count].last_keepalive_received = active_connections[i].last_keepalive_received;
            peer_info[*count].keepalive_failures = active_connections[i].keepalive_failures;
            (*count)++;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    
    return 0;
}

int mxd_get_unified_peers(mxd_peer_info_t* peer_info, size_t* count) {
    if (!peer_info || !count) {
        return -1;
    }
    
    if (!p2p_initialized) {
        *count = 0;
        return 0;
    }
    
    size_t max_count = *count;
    *count = 0;
    
    pthread_mutex_lock(&unified_peer_mutex);
    for (size_t i = 0; i < unified_peer_count && *count < max_count; i++) {
        if (unified_peers[i].active) {
            strncpy(peer_info[*count].address, unified_peers[i].address, 
                   sizeof(peer_info[*count].address) - 1);
            peer_info[*count].address[sizeof(peer_info[*count].address) - 1] = '\0';
            peer_info[*count].port = unified_peers[i].port;
            peer_info[*count].connected_at = 0;
            peer_info[*count].last_keepalive_sent = unified_peers[i].last_message_sent;
            peer_info[*count].last_keepalive_received = unified_peers[i].last_message_received;
            peer_info[*count].keepalive_failures = 0;
            (*count)++;
        }
    }
    pthread_mutex_unlock(&unified_peer_mutex);
    
    return 0;
}
