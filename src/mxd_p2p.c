#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#elif defined(__linux__)
#include <endian.h>
#elif defined(_WIN32)
#include <winsock2.h>
#define htobe64(x) htonll(x)
#define be64toh(x) ntohll(x)
#endif
#include "mxd_config.h"
#include "mxd_crypto.h"
#include "mxd_dht.h"
#include "mxd_p2p.h"
#include "mxd_logging.h"
#include "mxd_secrets.h"
#include "mxd_address.h"
#include "mxd_domain_tags.h"
#include "base58.h"
#include "utils/mxd_replay.h"
#include "metrics/mxd_prometheus.h"
#include "mxd_blockchain_db.h"

// Track last genesis push time per peer to avoid flooding
static time_t last_genesis_push_time[MXD_MAX_PEERS] = {0};
static char last_genesis_push_addr[MXD_MAX_PEERS][256] = {{0}};

// Same idea for head pushes — separate slot so head and genesis pushes don't
// share a 30s rate-limit budget.
static time_t last_head_push_time[MXD_MAX_PEERS] = {0};
static char last_head_push_addr[MXD_MAX_PEERS][256] = {{0}};

static struct {
    char address[256];
    uint16_t port;
    int active;
} manual_peers[MXD_MAX_PEERS];
static size_t manual_peer_count = 0;
static pthread_mutex_t manual_peer_mutex = PTHREAD_MUTEX_INITIALIZER;


static int p2p_initialized = 0;
static uint16_t p2p_port = 0;
static uint8_t node_algo_id = MXD_SIGALG_ED25519;
static uint8_t node_public_key[MXD_PUBKEY_MAX_LEN] = {0};
static uint8_t node_private_key[MXD_PRIVKEY_MAX_LEN] = {0};
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
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

// Known self IP addresses (discovered via rejected self-connections during handshake).
// Prevents repeated connection attempts to our own public/NAT IP.
#define MAX_SELF_IPS 10
static char known_self_ips[MAX_SELF_IPS][256];
static int known_self_ip_count = 0;

static void add_known_self_ip(const char *address) {
    for (int i = 0; i < known_self_ip_count; i++) {
        if (strcmp(known_self_ips[i], address) == 0) return;
    }
    if (known_self_ip_count < MAX_SELF_IPS) {
        strncpy(known_self_ips[known_self_ip_count], address, 255);
        known_self_ips[known_self_ip_count][255] = '\0';
        known_self_ip_count++;
        MXD_LOG_INFO("p2p", "Learned own external IP: %s", address);
    }
}

static int is_self_address(const char *address, uint16_t port) {
    if (port != p2p_port) return 0;
    if (strcmp(address, "127.0.0.1") == 0 || strcmp(address, "localhost") == 0) return 1;
    for (int i = 0; i < known_self_ip_count; i++) {
        if (strcmp(known_self_ips[i], address) == 0) return 1;
    }
    return 0;
}

typedef struct {
    int socket;
    char address[256];
    uint16_t port;
    uint16_t peer_listen_port;
    time_t connected_at;
    time_t last_keepalive_sent;
    time_t last_keepalive_received;
    int active;
    int keepalive_failures;
    uint8_t sent_session_token[16];     // Token we sent to peer (for validating incoming messages)
    uint8_t received_session_token[16]; // Token peer sent to us (for sending outgoing messages)
    int has_sent_token;
    int has_received_token;
    int handshake_done;                 // Flag to indicate handshake is already completed (for outbound connections)
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
    uint8_t algo_id;  // Peer's signature algorithm (for diagnostics/display)
} unified_peer_t;

static unified_peer_t unified_peers[MXD_MAX_PEERS];
static size_t unified_peer_count = 0;
static pthread_mutex_t unified_peer_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MXD_KEEPALIVE_INTERVAL 15
#define MXD_KEEPALIVE_TIMEOUT 45
#define MXD_MAX_KEEPALIVE_FAILURES 3
#define MXD_PROTOCOL_VERSION 4

static pthread_t keepalive_thread;
static volatile int keepalive_running = 0;
static int keepalive_thread_created = 0;

static pthread_t peer_connector_thread;
static volatile int peer_connector_running = 0;
static int peer_connector_thread_created = 0;

static int server_thread_created = 0;

typedef struct {
    uint32_t magic;      // Network byte order
    uint8_t version;     // Protocol version
    uint8_t type;        // Fixed size instead of enum
    uint8_t reserved[2]; // Padding for alignment
    uint32_t length;     // Network byte order
    uint8_t checksum[64]; // SHA-512 checksum
    uint8_t session_token[16]; // Session token (protocol v3)
} __attribute__((packed)) mxd_wire_header_t;

typedef struct {
    char node_id[256];                      // Node identifier (wallet address)
    uint32_t protocol_version;              // Protocol version (now v4 for network filtering)
    uint16_t listen_port;                   // Listening port
    uint8_t algo_id;                        // Algorithm ID (1=Ed25519, 2=Dilithium5)
    uint16_t public_key_length;             // Length of public key
    uint8_t public_key[MXD_PUBKEY_MAX_LEN]; // Public key (variable size)
    uint8_t challenge[32];                  // Random challenge nonce
    uint64_t timestamp;                     // Unix timestamp for anti-replay
    uint16_t signature_length;              // Length of signature
    uint8_t signature[MXD_SIG_MAX_LEN];     // Signature (variable size)
    char network_type[32];                  // Network identifier for isolation
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
    wire->version = MXD_PROTOCOL_VERSION;
    wire->type = (uint8_t)header->type;
    wire->reserved[0] = 0;
    wire->reserved[1] = 0;
    wire->length = htonl(header->length);
    memcpy(wire->checksum, header->checksum, 64);
    memcpy(wire->session_token, header->session_token, 16);
}

static void wire_to_header(const mxd_wire_header_t *wire, mxd_message_header_t *header) {
    header->magic = ntohl(wire->magic);
    header->type = (mxd_message_type_t)wire->type;
    header->length = ntohl(wire->length);
    memcpy(header->checksum, wire->checksum, 64);
    memcpy(header->session_token, wire->session_token, 16);
}

static int parse_wire_header(const uint8_t *buffer, mxd_message_header_t *header, uint32_t expected_magic) {
    mxd_wire_header_t *wire = (mxd_wire_header_t*)buffer;
    
    uint32_t magic = ntohl(wire->magic);
    uint8_t version = wire->version;
    uint8_t type = wire->type;
    uint32_t length = ntohl(wire->length);
    
    if (magic != expected_magic) {
        return -1;
    }
    
    if (version != MXD_PROTOCOL_VERSION) {
        MXD_LOG_WARN("p2p", "Protocol version mismatch: expected %u, got %u", MXD_PROTOCOL_VERSION, version);
        return -1;
    }
    
    if (type > MXD_MSG_MAX) {
        return -1;
    }
    
    if (length > MXD_MAX_MESSAGE_SIZE || length == 0) {
        return -1;
    }
    
    if (wire->reserved[0] != 0 || wire->reserved[1] != 0) {
        return -1;
    }
    
    header->magic = magic;
    header->type = (mxd_message_type_t)type;
    header->length = length;
    memcpy(header->checksum, wire->checksum, 64);
    memcpy(header->session_token, wire->session_token, 16);
    
    return 0;
}

static int send_on_connection(peer_connection_t *conn, mxd_message_type_t type, const void *payload, size_t payload_length) {
    if (!conn || !conn->active || !payload || payload_length > MXD_MAX_MESSAGE_SIZE) {
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
    
    if (conn->has_received_token) {
        memcpy(header.session_token, conn->received_session_token, 16);
    } else {
        memset(header.session_token, 0, 16);
    }
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        return -1;
    }
    
    mxd_wire_header_t wire_header;
    header_to_wire(&header, &wire_header);
    
    if (write_n(conn->socket, &wire_header, sizeof(wire_header)) != 0) {
        return -1;
    }
    
    if (write_n(conn->socket, payload, payload_length) != 0) {
        return -1;
    }
    
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
    
    memset(header.session_token, 0, 16);
    
    if (mxd_sha512(payload, payload_length, header.checksum) != 0) {
        return -1;
    }
    
    MXD_LOG_INFO("p2p", "Sending message: type=%d, payload_length=%zu", type, payload_length);
    
    mxd_wire_header_t wire_header;
    header_to_wire(&header, &wire_header);
    
    if (write_n(sock, &wire_header, sizeof(wire_header)) != 0) {
        MXD_LOG_WARN("p2p", "Failed to write header: type=%d, errno=%d (%s)", type, errno, strerror(errno));
        return -1;
    }
    
    if (write_n(sock, payload, payload_length) != 0) {
        MXD_LOG_WARN("p2p", "Failed to write payload: type=%d, length=%zu, errno=%d (%s)", 
                    type, payload_length, errno, strerror(errno));
        return -1;
    }
    
    MXD_LOG_INFO("p2p", "Successfully sent message: type=%d, payload_length=%zu", type, payload_length);
    return 0;
}

// Thread-safe send: atomically finds connection by peer address, validates it's
// active, copies needed state under the lock, then sends outside the lock.
// Returns 0 on success, -1 on failure.
static int send_to_peer_safe(const char *address, uint16_t port,
                             mxd_message_type_t type, const void *payload,
                             size_t payload_length) {
    if (!address || !payload || payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }

    int sock = -1;
    uint8_t session_token[16];
    int has_token = 0;

    pthread_mutex_lock(&peer_mutex);
    // Find by exact port or listen port match
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active &&
            strcmp(active_connections[i].address, address) == 0 &&
            (active_connections[i].port == port || active_connections[i].peer_listen_port == port)) {
            sock = active_connections[i].socket;
            has_token = active_connections[i].has_received_token;
            if (has_token) {
                memcpy(session_token, active_connections[i].received_session_token, 16);
            }
            break;
        }
    }
    // Fallback: address-only match
    if (sock < 0) {
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (active_connections[i].active &&
                strcmp(active_connections[i].address, address) == 0) {
                sock = active_connections[i].socket;
                has_token = active_connections[i].has_received_token;
                if (has_token) {
                    memcpy(session_token, active_connections[i].received_session_token, 16);
                }
                break;
            }
        }
    }
    pthread_mutex_unlock(&peer_mutex);

    if (sock < 0) {
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

    if (has_token) {
        memcpy(header.session_token, session_token, 16);
    } else {
        memset(header.session_token, 0, 16);
    }

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
            unified_peers[slot].algo_id = 0;
            
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
            unified_peers[slot].algo_id = 0;
            
            if (inactive_slot < 0) {
                unified_peer_count++;
            }
        }
    }
    
    pthread_mutex_unlock(&unified_peer_mutex);
}

static void update_unified_peer_algo(const char *address, uint16_t port, uint8_t algo_id) {
    pthread_mutex_lock(&unified_peer_mutex);
    
    for (size_t i = 0; i < unified_peer_count; i++) {
        if (strcmp(unified_peers[i].address, address) == 0 && unified_peers[i].port == port) {
            unified_peers[i].algo_id = algo_id;
            break;
        }
    }
    
    pthread_mutex_unlock(&unified_peer_mutex);
}

static void reset_rate_limit(void) {
    pthread_mutex_lock(&rate_limit_mutex);
    last_message_time = 0;
    messages_this_second = 0;
    last_tx_time = 0;
    tx_this_second = 0;
    consecutive_errors = 0;
    error_simulation_count = 0;
    pthread_mutex_unlock(&rate_limit_mutex);
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
// NOTE: These find functions return a pointer to a static array entry.
// The pointer is always valid memory, but the connection may be closed by
// another thread after the mutex is released. Callers doing I/O should use
// send_on_connection_safe() instead of find + send_on_connection.
static peer_connection_t* find_connection(const char *address, uint16_t port) {
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active &&
            strcmp(active_connections[i].address, address) == 0 &&
            (active_connections[i].port == port || active_connections[i].peer_listen_port == port)) {
            pthread_mutex_unlock(&peer_mutex);
            return &active_connections[i];
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    return NULL;
}

static peer_connection_t* find_connection_by_socket(int sock) {
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && active_connections[i].socket == sock) {
            pthread_mutex_unlock(&peer_mutex);
            return &active_connections[i];
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    return NULL;
}

static peer_connection_t* find_connection_for_peer(const char *address, uint16_t port) {
    pthread_mutex_lock(&peer_mutex);
    // First pass: exact port or listen port match
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active &&
            strcmp(active_connections[i].address, address) == 0 &&
            (active_connections[i].port == port || active_connections[i].peer_listen_port == port)) {
            pthread_mutex_unlock(&peer_mutex);
            return &active_connections[i];
        }
    }
    // Second pass: address-only fallback (handles stale ephemeral ports)
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active &&
            strcmp(active_connections[i].address, address) == 0) {
            pthread_mutex_unlock(&peer_mutex);
            return &active_connections[i];
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    return NULL;
}

static int validate_message(const mxd_message_header_t *header, const void *payload, peer_connection_t *conn) {
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
    if (header->type > MXD_MSG_MAX) {
        MXD_LOG_WARN("p2p", "Invalid message type %d (max: %d)", header->type, MXD_MSG_MAX);
        return -1;
    }
    
    // Additional input validation
    if (header->length == 0) {
        MXD_LOG_WARN("p2p", "Empty message payload");
        return -1;
    }

    // Session token validation (protocol v3)
    // Allow empty token for HANDSHAKE, SESSION_TOKEN, peer discovery, genesis-related messages,
    // block messages, validation signatures, and transaction broadcasts.
    // Blocks and validation signatures are cryptographically signed so don't need session tokens.
    // Transactions are validated by the mempool/UTXO logic when applied.
    // Validate against the token WE SENT (sent_session_token), not the one we received
    if (header->type != MXD_MSG_HANDSHAKE && header->type != MXD_MSG_SESSION_TOKEN &&
        header->type != MXD_MSG_GET_PEERS && header->type != MXD_MSG_PEERS &&
        header->type != MXD_MSG_GENESIS_ANNOUNCE && header->type != MXD_MSG_GENESIS_SIGN_REQUEST &&
        header->type != MXD_MSG_GENESIS_SIGN_RESPONSE && header->type != MXD_MSG_GENESIS_SYNC &&
        header->type != MXD_MSG_BLOCKS && header->type != MXD_MSG_GET_BLOCKS &&
        header->type != MXD_MSG_VALIDATION_SIGNATURE && header->type != MXD_MSG_VALIDATION_CHAIN &&
        header->type != MXD_MSG_GET_VALIDATION_CHAIN &&
        header->type != MXD_MSG_TRANSACTIONS && header->type != MXD_MSG_GET_TRANSACTIONS) {
        if (conn && conn->has_sent_token) {
            if (memcmp(header->session_token, conn->sent_session_token, 16) != 0) {
                MXD_LOG_WARN("p2p", "Session token mismatch for message type %d", header->type);
                return -1;
            }
        } else {
            MXD_LOG_WARN("p2p", "No session token for message type %d", header->type);
            return -1;
        }
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

    pthread_mutex_lock(&rate_limit_mutex);
    
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
            pthread_mutex_unlock(&rate_limit_mutex);
            return -1;
        }
        tx_this_second++;
    } else {
        // Allow exactly 100 messages per second
        if (messages_this_second >= 100) {
            pthread_mutex_unlock(&rate_limit_mutex);
            return -1;
        }
        messages_this_second++;
    }

    pthread_mutex_unlock(&rate_limit_mutex);
    return 0;
}

// Set message handler callback
// Note: This can be called before p2p_initialized to ensure handler is ready
// when connections start arriving
int mxd_set_message_handler(mxd_message_handler_t handler) {
    message_handler = handler;
    MXD_LOG_INFO("p2p", "Message handler %s", handler ? "registered" : "cleared");
    return 0;
}

static void handle_get_peers_message(const char *address, uint16_t port, const void *payload, size_t length) {
    uint16_t peer_listening_port = port;

    if (length >= sizeof(uint16_t)) {
        memcpy(&peer_listening_port, payload, sizeof(uint16_t));
        MXD_LOG_INFO("p2p", "GET_PEERS from %s:%d (listening on port %d)", address, port, peer_listening_port);

        if (mxd_dht_add_peer(address, peer_listening_port, NULL) == 0) {
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

    // Cap peers per message to prevent integer overflow in allocation (C7)
    if (active_count > 100) active_count = 100;

    // New format: [count:4][address:256 + port:2 + network_type_len:1 + network_type:N]...
    // Max size per peer: 256 + 2 + 1 + 32 = 291; max total: 4 + 100*291 = 29,104 bytes
    size_t payload_size = sizeof(uint32_t) + (active_count * (256 + sizeof(uint16_t) + 1 + 32));
    uint8_t *response = malloc(payload_size);
    if (!response) {
        MXD_LOG_ERROR("p2p", "Failed to allocate memory for PEERS response");
        return;
    }

    uint32_t count = htonl((uint32_t)active_count);
    memcpy(response, &count, sizeof(uint32_t));

    size_t offset = sizeof(uint32_t);
    size_t serialized_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            memcpy(response + offset, peers[i].address, 256);
            offset += 256;
            uint16_t port_be = htons(peers[i].port);
            memcpy(response + offset, &port_be, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            // Add network_type (length byte + string)
            uint8_t network_type_len = (uint8_t)strlen(peers[i].network_type);
            response[offset] = network_type_len;
            offset += 1;
            if (network_type_len > 0) {
                memcpy(response + offset, peers[i].network_type, network_type_len);
                offset += network_type_len;
            }
            serialized_count++;
            MXD_LOG_DEBUG("p2p", "Serializing peer %zu: %s:%d (network: %s)", serialized_count, peers[i].address, peers[i].port, peers[i].network_type);
        }
    }

    MXD_LOG_DEBUG("p2p", "PEERS response: count=%zu, serialized=%zu, payload_size=%zu, actual_offset=%zu",
                 active_count, serialized_count, payload_size, offset);

    if (mxd_send_message(address, peer_listening_port, MXD_MSG_PEERS, response, offset) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send PEERS response to %s:%d", address, peer_listening_port);
    } else {
        MXD_LOG_INFO("p2p", "Sent %zu active peers to %s:%d (payload: %zu bytes)", active_count, address, peer_listening_port, offset);
    }

    free(response);
}

static void handle_get_peers_on_socket(int sock, const char *address, uint16_t port, const void *payload, size_t length) {
    uint16_t peer_listening_port = port;

    if (length >= sizeof(uint16_t)) {
        memcpy(&peer_listening_port, payload, sizeof(uint16_t));
        MXD_LOG_INFO("p2p", "GET_PEERS from %s:%d (listening on port %d) on persistent connection", address, port, peer_listening_port);

        if (mxd_dht_add_peer(address, peer_listening_port, NULL) == 0) {
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

    // Cap peers per message to prevent integer overflow in allocation (C7)
    if (active_count > 100) active_count = 100;

    // New format: [count:4][address:256 + port:2 + network_type_len:1 + network_type:N]...
    // Max size per peer: 256 + 2 + 1 + 32 = 291; max total: 4 + 100*291 = 29,104 bytes
    size_t payload_size = sizeof(uint32_t) + (active_count * (256 + sizeof(uint16_t) + 1 + 32));
    uint8_t *response = malloc(payload_size);
    if (!response) {
        MXD_LOG_ERROR("p2p", "Failed to allocate memory for PEERS response");
        return;
    }

    uint32_t count = htonl((uint32_t)active_count);
    memcpy(response, &count, sizeof(uint32_t));

    size_t offset = sizeof(uint32_t);
    size_t serialized_count = 0;
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            memcpy(response + offset, peers[i].address, 256);
            offset += 256;
            uint16_t port_be = htons(peers[i].port);
            memcpy(response + offset, &port_be, sizeof(uint16_t));
            offset += sizeof(uint16_t);
            // Add network_type (length byte + string)
            uint8_t network_type_len = (uint8_t)strlen(peers[i].network_type);
            response[offset] = network_type_len;
            offset += 1;
            if (network_type_len > 0) {
                memcpy(response + offset, peers[i].network_type, network_type_len);
                offset += network_type_len;
            }
            serialized_count++;
            MXD_LOG_DEBUG("p2p", "Serializing peer %zu (socket): %s:%d (network: %s)", serialized_count, peers[i].address, peers[i].port, peers[i].network_type);
        }
    }

    MXD_LOG_DEBUG("p2p", "PEERS response (socket): count=%zu, serialized=%zu, payload_size=%zu, actual_offset=%zu",
                 active_count, serialized_count, payload_size, offset);

    // Atomically check if this socket has a session token
    uint8_t session_token[16];
    int has_token = 0;
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && active_connections[i].socket == sock) {
            has_token = active_connections[i].has_received_token;
            if (has_token) {
                memcpy(session_token, active_connections[i].received_session_token, 16);
            }
            break;
        }
    }
    pthread_mutex_unlock(&peer_mutex);

    // Send using the socket directly (already have the fd)
    const mxd_secrets_t *secrets_peers = mxd_get_secrets();
    int send_result = -1;
    if (secrets_peers) {
        mxd_message_header_t hdr = {
            .magic = secrets_peers->network_magic,
            .type = MXD_MSG_PEERS,
            .length = offset
        };
        if (has_token) {
            memcpy(hdr.session_token, session_token, 16);
        } else {
            memset(hdr.session_token, 0, 16);
        }
        if (mxd_sha512(response, offset, hdr.checksum) == 0) {
            mxd_wire_header_t wire_hdr;
            header_to_wire(&hdr, &wire_hdr);
            if (write_n(sock, &wire_hdr, sizeof(wire_hdr)) == 0 &&
                write_n(sock, response, offset) == 0) {
                send_result = 0;
            }
        }
    }

    if (send_result != 0) {
        MXD_LOG_WARN("p2p", "Failed to send PEERS response to %s:%d", address, peer_listening_port);
    } else {
        MXD_LOG_INFO("p2p", "Sent %zu active peers to %s:%d (payload: %zu bytes)", active_count, address, peer_listening_port, offset);
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
    peer_count = ntohl(peer_count);

    MXD_LOG_DEBUG("p2p", "PEERS message from %s:%d: count=%u, length=%zu",
                 address, port, peer_count, length);

    if (peer_count == 0) {
        MXD_LOG_DEBUG("p2p", "PEERS message from %s:%d has no peers", address, port);
        return;
    }

    if (peer_count > MXD_MAX_PEERS) {
        MXD_LOG_WARN("p2p", "PEERS message from %s:%d: count=%u exceeds max=%d, capping",
                    address, port, peer_count, MXD_MAX_PEERS);
        peer_count = MXD_MAX_PEERS;
    }

    MXD_LOG_INFO("p2p", "Processing %u peers from %s:%d", peer_count, address, port);

    // New format: [count:4][address:256 + port:2 + network_type_len:1 + network_type:N]...
    size_t offset = sizeof(uint32_t);
    size_t peers_added = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        // Check if we have enough data for address + port + network_type_len
        if (offset + 256 + sizeof(uint16_t) + 1 > length) {
            MXD_LOG_WARN("p2p", "PEERS message truncated at peer %u (offset=%zu, length=%zu)", i, offset, length);
            break;
        }

        char peer_addr[257];
        uint16_t peer_port;
        char peer_network_type[32] = {0};

        memcpy(peer_addr, (uint8_t*)payload + offset, 256);
        peer_addr[256] = '\0';
        offset += 256;
        memcpy(&peer_port, (uint8_t*)payload + offset, sizeof(uint16_t));
        peer_port = ntohs(peer_port);
        offset += sizeof(uint16_t);

        // Read network_type (length byte + string)
        uint8_t network_type_len = ((uint8_t*)payload)[offset];
        offset += 1;
        if (network_type_len > 31) {
            MXD_LOG_WARN("p2p", "PEERS message: peer %u has invalid network_type_len=%u, skipping", i, network_type_len);
            continue;
        }
        if (offset + network_type_len > length) {
            MXD_LOG_WARN("p2p", "PEERS message truncated in network_type at peer %u", i);
            break;
        }
        if (network_type_len > 0) {
            memcpy(peer_network_type, (uint8_t*)payload + offset, network_type_len);
            offset += network_type_len;
        }
        peer_network_type[31] = '\0';

        if (is_self_address(peer_addr, peer_port)) {
            MXD_LOG_DEBUG("p2p", "Skipping self-peer %s:%d", peer_addr, peer_port);
            continue;
        }

        // Skip peers with empty network_type when we have filtering enabled
        if (node_config.network_type[0] != '\0' && peer_network_type[0] == '\0') {
            MXD_LOG_DEBUG("p2p", "Skipping peer %s:%d with empty network_type (local requires: %s)",
                          peer_addr, peer_port, node_config.network_type);
            continue;
        }

        // mxd_dht_add_peer will filter by network_type
        if (mxd_dht_add_peer(peer_addr, peer_port, peer_network_type) == 0) {
            peers_added++;
            MXD_LOG_INFO("p2p", "Learned new peer from %s:%d -> %s:%d (network: %s)", address, port, peer_addr, peer_port, peer_network_type);
        } else {
            MXD_LOG_DEBUG("p2p", "Peer %s:%d already known, filtered, or failed to add", peer_addr, peer_port);
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

static inline size_t handshake_wire_size(const mxd_handshake_payload_t *handshake) {
    // Base size: node_id(256) + proto_ver(4) + port(2) + algo(1) + pubkey_len(2) + challenge(32) + timestamp(8) + sig_len(2) + network_type_len(1)
    if (!handshake) {
        return 256 + 4 + 2 + 1 + 2 + MXD_PUBKEY_MAX_LEN + 32 + 8 + 2 + MXD_SIG_MAX_LEN + 1 + 32;
    }
    size_t network_type_len = strlen(handshake->network_type);
    return 256 + 4 + 2 + 1 + 2 + handshake->public_key_length + 32 + 8 + 2 + handshake->signature_length + 1 + network_type_len;
}

static size_t handshake_to_wire(const mxd_handshake_payload_t *handshake, uint8_t *buf, size_t buf_len) {
    if (!handshake || !buf) return 0;
    
    size_t offset = 0;
    
    if (offset + 256 > buf_len) return 0;
    memcpy(buf + offset, handshake->node_id, 256);
    offset += 256;
    
    if (offset + 4 > buf_len) return 0;
    uint32_t protocol_version_net = htonl(handshake->protocol_version);
    memcpy(buf + offset, &protocol_version_net, 4);
    offset += 4;
    
    if (offset + 2 > buf_len) return 0;
    uint16_t listen_port_net = htons(handshake->listen_port);
    memcpy(buf + offset, &listen_port_net, 2);
    offset += 2;
    
    if (offset + 1 > buf_len) return 0;
    buf[offset] = handshake->algo_id;
    offset += 1;
    
    // public_key_length (2 bytes, network order)
    if (offset + 2 > buf_len) return 0;
    uint16_t pubkey_len_net = htons(handshake->public_key_length);
    memcpy(buf + offset, &pubkey_len_net, 2);
    offset += 2;
    
    // public_key (variable length based on public_key_length)
    if (offset + handshake->public_key_length > buf_len) return 0;
    memcpy(buf + offset, handshake->public_key, handshake->public_key_length);
    offset += handshake->public_key_length;
    
    if (offset + 32 > buf_len) return 0;
    memcpy(buf + offset, handshake->challenge, 32);
    offset += 32;
    
    // timestamp (8 bytes, network order)
    if (offset + 8 > buf_len) return 0;
    uint64_t timestamp_net = htobe64(handshake->timestamp);
    memcpy(buf + offset, &timestamp_net, 8);
    offset += 8;
    
    // signature_length (2 bytes, network order)
    if (offset + 2 > buf_len) return 0;
    uint16_t sig_len_net = htons(handshake->signature_length);
    memcpy(buf + offset, &sig_len_net, 2);
    offset += 2;
    
    // signature (variable length based on signature_length)
    if (offset + handshake->signature_length > buf_len) return 0;
    memcpy(buf + offset, handshake->signature, handshake->signature_length);
    offset += handshake->signature_length;

    // network_type (1 byte length + string)
    uint8_t network_type_len = (uint8_t)strlen(handshake->network_type);
    if (offset + 1 + network_type_len > buf_len) return 0;
    buf[offset] = network_type_len;
    offset += 1;
    if (network_type_len > 0) {
        memcpy(buf + offset, handshake->network_type, network_type_len);
        offset += network_type_len;
    }

    return offset;
}

static int wire_to_handshake(const uint8_t *buf, size_t buf_len, mxd_handshake_payload_t *handshake) {
    if (!buf || !handshake) return -1;
    
    size_t offset = 0;
    
    if (offset + 256 > buf_len) return -1;
    memcpy(handshake->node_id, buf + offset, 256);
    offset += 256;
    
    if (offset + 4 > buf_len) return -1;
    uint32_t protocol_version_net;
    memcpy(&protocol_version_net, buf + offset, 4);
    handshake->protocol_version = ntohl(protocol_version_net);
    offset += 4;
    
    if (offset + 2 > buf_len) return -1;
    uint16_t listen_port_net;
    memcpy(&listen_port_net, buf + offset, 2);
    handshake->listen_port = ntohs(listen_port_net);
    offset += 2;
    
    if (offset + 1 > buf_len) return -1;
    handshake->algo_id = buf[offset];
    offset += 1;
    
    // public_key_length (2 bytes, network order)
    if (offset + 2 > buf_len) return -1;
    uint16_t pubkey_len_net;
    memcpy(&pubkey_len_net, buf + offset, 2);
    handshake->public_key_length = ntohs(pubkey_len_net);
    offset += 2;
    
    // public_key (variable length based on public_key_length)
    if (handshake->public_key_length > MXD_PUBKEY_MAX_LEN) return -1;
    if (offset + handshake->public_key_length > buf_len) return -1;
    memcpy(handshake->public_key, buf + offset, handshake->public_key_length);
    offset += handshake->public_key_length;
    
    if (offset + 32 > buf_len) return -1;
    memcpy(handshake->challenge, buf + offset, 32);
    offset += 32;
    
    // timestamp (8 bytes, network order)
    if (offset + 8 > buf_len) return -1;
    uint64_t timestamp_net;
    memcpy(&timestamp_net, buf + offset, 8);
    handshake->timestamp = be64toh(timestamp_net);
    offset += 8;
    
    // signature_length (2 bytes, network order)
    if (offset + 2 > buf_len) return -1;
    uint16_t sig_len_net;
    memcpy(&sig_len_net, buf + offset, 2);
    handshake->signature_length = ntohs(sig_len_net);
    offset += 2;
    
    // signature (variable length based on signature_length)
    if (handshake->signature_length > MXD_SIG_MAX_LEN) return -1;
    if (offset + handshake->signature_length > buf_len) return -1;
    memcpy(handshake->signature, buf + offset, handshake->signature_length);
    offset += handshake->signature_length;

    // network_type (1 byte length + string)
    if (offset + 1 > buf_len) return -1;
    uint8_t network_type_len = buf[offset];
    offset += 1;
    if (network_type_len > 31) return -1;  // Max 31 chars + null terminator
    if (offset + network_type_len > buf_len) return -1;
    memset(handshake->network_type, 0, sizeof(handshake->network_type));
    if (network_type_len > 0) {
        memcpy(handshake->network_type, buf + offset, network_type_len);
        offset += network_type_len;
    }
    handshake->network_type[31] = '\0';

    return 0;
}

static int create_signed_handshake(mxd_handshake_payload_t *handshake, const uint8_t *challenge, size_t challenge_len) {
    memset(handshake, 0, sizeof(mxd_handshake_payload_t));

    strncpy(handshake->node_id, node_config.node_id, sizeof(handshake->node_id) - 1);
    handshake->node_id[sizeof(handshake->node_id) - 1] = '\0';
    handshake->protocol_version = 6;   // v7 cascade (L6-5): handshake bumped to 6 for MXD-P2P-V1 domain-tagged signed payload
    handshake->listen_port = p2p_port;
    handshake->timestamp = (uint64_t)time(NULL);

    // Set network_type from config
    strncpy(handshake->network_type, node_config.network_type, sizeof(handshake->network_type) - 1);
    handshake->network_type[sizeof(handshake->network_type) - 1] = '\0';
    
    handshake->algo_id = node_algo_id;
    size_t pubkey_len = mxd_sig_pubkey_len(node_algo_id);
    handshake->public_key_length = (uint16_t)pubkey_len;  // Store in host order
    memcpy(handshake->public_key, node_public_key, pubkey_len);
    
    if (challenge && challenge_len > 0) {
        memcpy(handshake->challenge, challenge, challenge_len < 32 ? challenge_len : 32);
    } else {
        if (RAND_bytes(handshake->challenge, 32) != 1) {
            MXD_LOG_ERROR("p2p", "Failed to generate challenge nonce");
            return -1;
        }
    }
    
    uint8_t addr32_hs[MXD_ADDR32_LEN];
    if (mxd_derive_address(node_algo_id, node_public_key, pubkey_len, addr32_hs) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to derive address for handshake signing");
        return -1;
    }
    // v7 cascade (L6-5): MXD-P2P-V1 (11) || challenge(32) || ts_be(8) || algo_id(1) || addr32(32)
    uint8_t message_to_sign[MXD_DOMAIN_TAG_P2P_LEN + 32 + 8 + 1 + MXD_ADDR32_LEN];
    size_t soff = 0;
    memcpy(message_to_sign + soff, MXD_DOMAIN_TAG_P2P, MXD_DOMAIN_TAG_P2P_LEN); soff += MXD_DOMAIN_TAG_P2P_LEN;
    memcpy(message_to_sign + soff, handshake->challenge, 32); soff += 32;
    uint64_t timestamp_net = htobe64(handshake->timestamp);
    memcpy(message_to_sign + soff, &timestamp_net, 8); soff += 8;
    message_to_sign[soff++] = node_algo_id;
    memcpy(message_to_sign + soff, addr32_hs, MXD_ADDR32_LEN); soff += MXD_ADDR32_LEN;

    size_t sig_len = 0;
    if (mxd_sig_sign(node_algo_id, handshake->signature, &sig_len, message_to_sign, sizeof(message_to_sign), node_private_key) != 0) {
        MXD_LOG_ERROR("p2p", "Failed to sign handshake");
        return -1;
    }
    
    handshake->signature_length = (uint16_t)sig_len;  // Store in host order
    
    MXD_LOG_DEBUG("p2p", "Created signed handshake: algo=%s, pubkey_len=%u, sig_len=%u", 
                  mxd_sig_alg_name(node_algo_id), handshake->public_key_length, handshake->signature_length);
    return 0;
}

// Push genesis block to a newly connected peer if we have it and they might not
// This helps propagate the genesis block to late joiners
static void push_genesis_to_peer(const char *address, uint16_t port) {
    // Check if we have a genesis block (height >= 1 means we have at least genesis)
    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0 || local_height == 0) {
        return;  // We don't have any blocks yet
    }
    
    // Rate limit: don't push to the same peer more than once every 30 seconds
    time_t now = time(NULL);
    int found_slot = 0;
    for (int i = 0; i < MXD_MAX_PEERS; i++) {
        if (strcmp(last_genesis_push_addr[i], address) == 0) {
            if (now - last_genesis_push_time[i] < 30) {
                MXD_LOG_DEBUG("p2p", "Skipping genesis push to %s:%d (rate limited)", address, port);
                return;
            }
            // Update timestamp and proceed
            last_genesis_push_time[i] = now;
            found_slot = 1;
            break;
        }
        if (!found_slot && last_genesis_push_addr[i][0] == '\0') {
            // Found empty slot, use it
            strncpy(last_genesis_push_addr[i], address, sizeof(last_genesis_push_addr[i]) - 1);
            last_genesis_push_time[i] = now;
            found_slot = 1;
            break;
        }
    }
    
    // Retrieve the genesis block
    mxd_block_t genesis_block;
    memset(&genesis_block, 0, sizeof(genesis_block));
    
    if (mxd_retrieve_block_by_height(0, &genesis_block) != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to retrieve genesis block for push to %s:%d", address, port);
        return;
    }
    
    // Use mxd_broadcast_block to send the genesis block to all peers
    // This will serialize and broadcast the block properly
    MXD_LOG_INFO("p2p", "Pushing genesis block to network after new peer %s:%d connected", address, port);
    
    extern int mxd_broadcast_block(const mxd_block_t *block);
    if (mxd_broadcast_block(&genesis_block) == 0) {
        MXD_LOG_INFO("p2p", "Successfully broadcast genesis block after peer %s:%d connected", address, port);
    } else {
        MXD_LOG_DEBUG("p2p", "Failed to broadcast genesis block after peer %s:%d connected", address, port);
    }

    mxd_free_block(&genesis_block);
}

// Push the current head block to a newly connected peer. Complements
// push_genesis_to_peer: genesis bootstraps fresh nodes; head exchange lets
// already-bootstrapped nodes discover divergent forks at the chain tip so the
// fork-choice rule (mxd_fork_choice.c) can fire and reorg the loser. Without
// this, two nodes that each stored a different block at the same height never
// learn about each other's block and stay forked indefinitely.
static void push_head_to_peer(const char *address, uint16_t port) {
    uint32_t local_height = 0;
    if (mxd_get_blockchain_height(&local_height) != 0) {
        return;
    }
    if (local_height <= 1) {
        // We only have genesis (or nothing). push_genesis_to_peer covers this.
        return;
    }
    uint32_t head_h = local_height - 1;  // current_height is "next to fill"; head is h-1

    // 30s rate-limit per peer (mirrors genesis push).
    time_t now = time(NULL);
    int found_slot = 0;
    for (int i = 0; i < MXD_MAX_PEERS; i++) {
        if (strcmp(last_head_push_addr[i], address) == 0) {
            if (now - last_head_push_time[i] < 30) {
                MXD_LOG_DEBUG("p2p", "Skipping head push to %s:%d (rate limited)", address, port);
                return;
            }
            last_head_push_time[i] = now;
            found_slot = 1;
            break;
        }
        if (!found_slot && last_head_push_addr[i][0] == '\0') {
            strncpy(last_head_push_addr[i], address, sizeof(last_head_push_addr[i]) - 1);
            last_head_push_time[i] = now;
            found_slot = 1;
            break;
        }
    }

    mxd_block_t head_block;
    memset(&head_block, 0, sizeof(head_block));
    if (mxd_retrieve_block_by_height(head_h, &head_block) != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to retrieve head block at h=%u for push to %s:%d",
                      head_h, address, port);
        return;
    }

    MXD_LOG_INFO("p2p", "Pushing head block at h=%u to network after new peer %s:%d connected",
                 head_h, address, port);
    extern int mxd_broadcast_block(const mxd_block_t *block);
    if (mxd_broadcast_block(&head_block) == 0) {
        MXD_LOG_INFO("p2p", "Successfully broadcast head block (h=%u) after peer %s:%d connected",
                     head_h, address, port);
    } else {
        MXD_LOG_DEBUG("p2p", "Failed to broadcast head block (h=%u) after peer %s:%d connected",
                      head_h, address, port);
    }

    mxd_free_block(&head_block);
}

static int handle_handshake_message(const char *address, uint16_t port, 
                                     const void *payload, size_t length,
                                     peer_connection_t *conn) {
    size_t min_size = 256 + 4 + 2 + 1 + 2 + 32 + 8 + 2;
    if (!payload || length < min_size) {
        MXD_LOG_WARN("p2p", "Invalid HANDSHAKE payload from %s:%d (length=%zu, minimum=%zu)", 
                     address, port, length, min_size);
        return -1;
    }
    
    mxd_handshake_payload_t handshake;
    if (wire_to_handshake((const uint8_t *)payload, length, &handshake) != 0) {
        MXD_LOG_WARN("p2p", "Failed to deserialize HANDSHAKE from %s:%d", address, port);
        return -1;
    }
    
    if (handshake.protocol_version != 6) {   // v7 cascade (L6-5): bumped from 5 for MXD-P2P-V1 signed payload
        MXD_LOG_WARN("p2p", "Incompatible protocol version %u from %s:%d (expected v6)",
                   handshake.protocol_version, address, port);
        return -1;
    }

    // Check network_type match - require matching network_type for handshake v5+
    if (node_config.network_type[0] != '\0') {
        // Local node has a network_type configured - require match
        if (handshake.network_type[0] == '\0') {
            MXD_LOG_INFO("p2p", "Rejecting peer %s:%d with empty network_type (local: %s)",
                        address, port, node_config.network_type);
            return -1;
        }
        if (strcmp(handshake.network_type, node_config.network_type) != 0) {
            MXD_LOG_INFO("p2p", "Rejecting peer %s:%d with mismatched network_type: %s (local: %s)",
                        address, port, handshake.network_type, node_config.network_type);
            return -1;
        }
    }

    if (mxd_replay_check_and_record(handshake.challenge, handshake.timestamp) != 0) {
        MXD_LOG_WARN("p2p", "Replay attack detected or timestamp invalid from %s:%d", address, port);
        return -1;
    }
    
    if (handshake.algo_id != MXD_SIGALG_ED25519 && handshake.algo_id != MXD_SIGALG_DILITHIUM5) {
        MXD_LOG_WARN("p2p", "Invalid algorithm ID %u from %s:%d", handshake.algo_id, address, port);
        return -1;
    }
    
    size_t expected_pubkey_len = mxd_sig_pubkey_len(handshake.algo_id);
    if (handshake.public_key_length != expected_pubkey_len) {
        MXD_LOG_WARN("p2p", "Invalid pubkey length %u for algo %u from %s:%d (expected %zu)", 
                   handshake.public_key_length, handshake.algo_id, address, port, expected_pubkey_len);
        return -1;
    }
    
    size_t expected_sig_len = mxd_sig_signature_len(handshake.algo_id);
    if (handshake.signature_length != expected_sig_len) {
        MXD_LOG_WARN("p2p", "Invalid signature length %u for algo %u from %s:%d (expected %zu)", 
                   handshake.signature_length, handshake.algo_id, address, port, expected_sig_len);
        return -1;
    }
    
    if (strcmp(handshake.node_id, node_config.node_id) == 0) {
        add_known_self_ip(address);
        MXD_LOG_DEBUG("p2p", "Rejecting self-connection from %s:%d (node_id: %s)",
                   address, port, handshake.node_id);
        return -1;
    }
    
    uint8_t addr_hash[MXD_ADDR32_LEN];
    if (mxd_derive_address(handshake.algo_id, handshake.public_key, handshake.public_key_length, addr_hash) != 0) {
        MXD_LOG_WARN("p2p", "Failed to derive address from public key for %s:%d", address, port);
        return -1;
    }
    
    char derived_address[64];
    if (mxd_address_to_string(handshake.algo_id, handshake.public_key,
                              handshake.public_key_length, /*mainnet*/1, derived_address,
                              sizeof(derived_address)) != 0) {
        MXD_LOG_WARN("p2p", "Failed to generate address for %s:%d", address, port);
        return -1;
    }
    
    if (strcmp(derived_address, handshake.node_id) != 0) {
        MXD_LOG_WARN("p2p", "Address mismatch for %s:%d: claimed=%s, derived=%s", 
                   address, port, handshake.node_id, derived_address);
        return -1;
    }
    
    // v7 cascade (L6-5): MXD-P2P-V1 (11) || challenge(32) || ts_be(8) || algo_id(1) || addr32(32)
    uint8_t message_to_verify[MXD_DOMAIN_TAG_P2P_LEN + 32 + 8 + 1 + MXD_ADDR32_LEN];
    size_t voff = 0;
    memcpy(message_to_verify + voff, MXD_DOMAIN_TAG_P2P, MXD_DOMAIN_TAG_P2P_LEN); voff += MXD_DOMAIN_TAG_P2P_LEN;
    memcpy(message_to_verify + voff, handshake.challenge, 32); voff += 32;
    uint64_t timestamp_net = htobe64(handshake.timestamp);
    memcpy(message_to_verify + voff, &timestamp_net, 8); voff += 8;
    message_to_verify[voff++] = handshake.algo_id;
    memcpy(message_to_verify + voff, addr_hash, MXD_ADDR32_LEN); voff += MXD_ADDR32_LEN;

    if (mxd_sig_verify(handshake.algo_id, handshake.signature, handshake.signature_length,
                       message_to_verify, sizeof(message_to_verify), handshake.public_key) != 0) {
        MXD_LOG_WARN("p2p", "Signature verification failed for %s:%d (node_id: %s, algo: %s)", 
                   address, port, handshake.node_id, mxd_sig_alg_name(handshake.algo_id));
        return -1;
    }
    
    MXD_LOG_INFO("p2p", "HANDSHAKE from %s:%d (node_id: %s, protocol: %u, listen_port: %u, algo: %s, network: %s) - signature verified",
               address, port, handshake.node_id, handshake.protocol_version,
               handshake.listen_port, mxd_sig_alg_name(handshake.algo_id), handshake.network_type);
    
    if (conn) {
        strncpy(conn->address, address, sizeof(conn->address) - 1);
        conn->address[sizeof(conn->address) - 1] = '\0';
        conn->peer_listen_port = handshake.listen_port;
        conn->active = 1;
        conn->connected_at = time(NULL);
        conn->last_keepalive_received = time(NULL);
        conn->keepalive_failures = 0;
        
        if (RAND_bytes(conn->sent_session_token, 16) != 1) {
            MXD_LOG_ERROR("p2p", "Failed to generate session token for %s:%d", address, port);
            return -1;
        }
        conn->has_sent_token = 1;
        conn->has_received_token = 0;
        
        mxd_handshake_payload_t reply_handshake;
        if (create_signed_handshake(&reply_handshake, NULL, 0) == 0) {
            size_t wire_buf_size = handshake_wire_size(&reply_handshake);
            uint8_t *wire_buf = malloc(wire_buf_size);
            if (!wire_buf) {
                MXD_LOG_ERROR("p2p", "Failed to allocate wire buffer for handshake reply");
                return -1;
            }
            size_t wire_len = handshake_to_wire(&reply_handshake, wire_buf, wire_buf_size);
            if (wire_len > 0 && send_on_socket(conn->socket, MXD_MSG_HANDSHAKE, wire_buf, wire_len) == 0) {
                MXD_LOG_INFO("p2p", "Sent HANDSHAKE reply to %s:%d", address, port);
                
                if (send_on_connection(conn, MXD_MSG_SESSION_TOKEN, conn->sent_session_token, 16) == 0) {
                    MXD_LOG_INFO("p2p", "Sent SESSION_TOKEN to %s:%d", address, port);
                } else {
                    MXD_LOG_ERROR("p2p", "Failed to send SESSION_TOKEN to %s:%d", address, port);
                }
                
                uint16_t my_listen_port = p2p_port;
                if (send_on_connection(conn, MXD_MSG_GET_PEERS, &my_listen_port, sizeof(uint16_t)) == 0) {
                    MXD_LOG_INFO("p2p", "Sent GET_PEERS to %s:%d over TCP after handshake", address, port);
                } else {
                    MXD_LOG_DEBUG("p2p", "Failed to send GET_PEERS to %s:%d over TCP", address, port);
                }
            } else {
                MXD_LOG_WARN("p2p", "Failed to send HANDSHAKE reply to %s:%d", address, port);
            }
            free(wire_buf);
        } else {
            MXD_LOG_ERROR("p2p", "Failed to create HANDSHAKE reply for %s:%d", address, port);
        }
    }
    
    if (mxd_dht_add_peer(address, handshake.listen_port, handshake.network_type) == 0) {
        MXD_LOG_INFO("p2p", "Added peer %s:%d to DHT after handshake (network: %s)",
                   address, handshake.listen_port, handshake.network_type);
    }
    
    update_unified_peer_algo(address, handshake.listen_port, handshake.algo_id);
    
    // Push genesis block to new peer if we have it (helps late joiners get the genesis block)
    push_genesis_to_peer(address, handshake.listen_port);

    // Push current head so divergent forks at the tip are surfaced to the peer.
    // The receiver's mxd_store_block path will fold this into fork-choice via
    // handle_block_at_existing_height; the loser reorgs to the winner.
    push_head_to_peer(address, handshake.listen_port);
    
    return 0;
}

static int handle_incoming_message(const char *address, uint16_t port,
                                 const mxd_message_header_t *header, 
                                 const void *payload) {
    if (!address || !header || !payload) {
        return -1;
    }

    peer_connection_t *conn = find_connection(address, port);
    
    if (validate_message(header, payload, conn) != 0) {
        consecutive_errors++;
        if (consecutive_errors >= 10) {
            return -1;
        }
        return 0;
    }

    consecutive_errors = 0;
    
    update_unified_peer_received(address, port);

    switch (header->type) {
        case MXD_MSG_HANDSHAKE:
            MXD_LOG_DEBUG("p2p", "Ignoring duplicate handshake from %s:%d (already connected)", address, port);
            break;
        case MXD_MSG_SESSION_TOKEN:
            if (conn && header->length == 16) {
                pthread_mutex_lock(&peer_mutex);
                if (conn->active) {
                    memcpy(conn->received_session_token, payload, 16);
                    conn->has_received_token = 1;
                }
                pthread_mutex_unlock(&peer_mutex);
                MXD_LOG_INFO("p2p", "Received SESSION_TOKEN from %s:%d", address, port);
            } else {
                MXD_LOG_WARN("p2p", "Invalid SESSION_TOKEN from %s:%d", address, port);
            }
            break;
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
                MXD_LOG_INFO("p2p", "Dispatching to handler: type=%d len=%u from %s:%u", 
                             header->type, header->length, address, port);
                message_handler(address, port, header->type, payload, header->length);
            } else {
                MXD_LOG_WARN("p2p", "No message handler registered for type=%d from %s:%u", 
                            header->type, address, port);
            }
            break;
    }

    return 0;
}

static void enable_tcp_keepalive(int sock) {
    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable));
#ifdef TCP_KEEPIDLE
    int idle = 15;   // Start probes after 15s idle
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    int intvl = 5;   // Probe every 5s
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    int cnt = 3;     // 3 failed probes = dead
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
}

static int try_establish_persistent_connection(const char *address, uint16_t port) {
    if (is_self_address(address, port)) return -1;

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

    enable_tcp_keepalive(sock);

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
    
    size_t wire_buf_size = handshake_wire_size(&handshake);
    uint8_t *wire_buf = malloc(wire_buf_size);
    if (!wire_buf) {
        MXD_LOG_ERROR("p2p", "Failed to allocate wire buffer for handshake");
        close(sock);
        return -1;
    }
    size_t wire_len = handshake_to_wire(&handshake, wire_buf, wire_buf_size);
    if (wire_len == 0 || send_on_socket(sock, MXD_MSG_HANDSHAKE, wire_buf, wire_len) != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to send HANDSHAKE to %s:%d for persistent connection", address, port);
        free(wire_buf);
        close(sock);
        return -1;
    }
    free(wire_buf);
    
    uint8_t header_buffer[92];
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

    // Explicit size guard before malloc (C8): defense-in-depth against unchecked network length
    if (header.length > MXD_MAX_MESSAGE_SIZE || header.length == 0) {
        MXD_LOG_WARN("p2p", "Refusing malloc of network-provided length %u from %s:%d", header.length, address, port);
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
        free(payload);
        close(sock);
        return -1;
    }
    
    strncpy(active_connections[slot].address, address, sizeof(active_connections[slot].address) - 1);
    active_connections[slot].address[sizeof(active_connections[slot].address) - 1] = '\0';
    active_connections[slot].port = port;
    active_connections[slot].peer_listen_port = port; // For outbound connections, we know the listen port
    active_connections[slot].socket = sock;
    active_connections[slot].active = 1;
    active_connections[slot].connected_at = time(NULL);
    active_connections[slot].last_keepalive_received = time(NULL);
    active_connections[slot].keepalive_failures = 0;
    memset(active_connections[slot].sent_session_token, 0, 16);
    memset(active_connections[slot].received_session_token, 0, 16);
    active_connections[slot].has_sent_token = 0;
    active_connections[slot].has_received_token = 0;
    active_connections[slot].handshake_done = 0;
    active_connection_count++;
    
    pthread_mutex_unlock(&peer_mutex);
    
    // Process the handshake response to set up session tokens
    // This will generate our session token and send it to the peer
    if (handle_handshake_message(address, port, payload, header.length, &active_connections[slot]) != 0) {
        MXD_LOG_INFO("p2p", "Handshake validation failed for outbound connection to %s:%d", address, port);
        pthread_mutex_lock(&peer_mutex);
        active_connections[slot].active = 0;
        active_connection_count--;
        pthread_mutex_unlock(&peer_mutex);
        free(payload);
        close(sock);
        return -1;
    }
    free(payload);

    pthread_mutex_lock(&peer_mutex);

    // Mark handshake as done under the mutex so connection_handler skips the handshake phase.
    // Must be set while holding peer_mutex to avoid a race: between the mutex unlock above
    // and the re-lock here, another thread could read handshake_done=0 and attempt to
    // re-handshake an already-active slot.
    active_connections[slot].handshake_done = 1;

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
            if (is_self_address(dht_peers[i].address, dht_peers[i].port)) continue;

            pthread_mutex_lock(&peer_mutex);
            int already_connected = 0;
            for (size_t j = 0; j < MXD_MAX_PEERS; j++) {
                if (active_connections[j].active &&
                    strcmp(active_connections[j].address, dht_peers[i].address) == 0) {
                    already_connected = 1;  // Match by address only to avoid ephemeral port mismatches
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
        
        mxd_replay_cleanup_expired();
        
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
                MXD_LOG_WARN("p2p", "Incoming connection %s:%d timed out, shutting down socket",
                           active_connections[i].address, active_connections[i].port);
                // Use shutdown() instead of close() to unblock the connection handler's read_n().
                // The connection handler thread owns close() — double-close causes fd reuse bugs
                // that corrupt RocksDB WAL/SST file descriptors.
                shutdown(active_connections[i].socket, SHUT_RDWR);
            }
        }
        
        pthread_mutex_unlock(&peer_mutex);
    }
    
    MXD_LOG_INFO("p2p", "Keepalive thread stopped");
    return NULL;
}

static void* connection_handler(void* arg) {
    peer_connection_t *conn = (peer_connection_t*)arg;
    
    MXD_LOG_INFO("p2p", "Connection handler started for %s:%d (handshake_done=%d)", 
                conn->address, conn->port, conn->handshake_done);
    
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets) {
        MXD_LOG_ERROR("p2p", "Secrets not initialized");
        close(conn->socket);
        conn->active = 0;
        return NULL;
    }
    
    // Skip handshake phase if already completed (for outbound connections)
    if (!conn->handshake_done) {
        mxd_handshake_payload_t handshake;
        if (create_signed_handshake(&handshake, NULL, 0) != 0) {
            MXD_LOG_ERROR("p2p", "Failed to create signed handshake for %s:%d", conn->address, conn->port);
            close(conn->socket);
            conn->active = 0;
            return NULL;
        }
        
        size_t wire_buf_size = handshake_wire_size(&handshake);
        uint8_t *wire_buf = malloc(wire_buf_size);
        if (!wire_buf) {
            MXD_LOG_ERROR("p2p", "Failed to allocate wire buffer for handshake");
            close(conn->socket);
            conn->active = 0;
            return NULL;
        }
        size_t wire_len = handshake_to_wire(&handshake, wire_buf, wire_buf_size);
        if (wire_len == 0 || send_on_socket(conn->socket, MXD_MSG_HANDSHAKE, wire_buf, wire_len) != 0) {
            MXD_LOG_WARN("p2p", "Failed to send HANDSHAKE to %s:%d", conn->address, conn->port);
            free(wire_buf);
            close(conn->socket);
            conn->active = 0;
            return NULL;
        }
        free(wire_buf);
        
        MXD_LOG_INFO("p2p", "Sent HANDSHAKE to %s:%d", conn->address, conn->port);
        
        uint8_t header_buffer[92];
        int read_result = read_n(conn->socket, header_buffer, sizeof(header_buffer));
        if (read_result != 0) {
            MXD_LOG_WARN("p2p", "Failed to read HANDSHAKE from %s:%d (v2 protocol requires HANDSHAKE)", 
                       conn->address, conn->port);
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

        // Explicit size guard before malloc (C8): defense-in-depth against unchecked network length
        if (header.length > MXD_MAX_MESSAGE_SIZE || header.length == 0) {
            MXD_LOG_WARN("p2p", "Refusing malloc of network-provided length %u from %s:%d", header.length, conn->address, conn->port);
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
    } else {
        MXD_LOG_INFO("p2p", "Handshake already done for %s:%d, skipping to message loop", 
                   conn->address, conn->port);
    }
    
    while (conn->active && server_running) {
        uint8_t header_buffer[92];
        
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
        
        MXD_LOG_INFO("p2p", "Parsed header from %s:%d: type=%d, length=%u",
                    conn->address, conn->port, header.type, header.length);

        // Explicit size guard before malloc (C8): defense-in-depth against unchecked network length
        if (header.length > MXD_MAX_MESSAGE_SIZE || header.length == 0) {
            MXD_LOG_WARN("p2p", "Refusing malloc of network-provided length %u from %s:%d", header.length, conn->address, conn->port);
            break;
        }
        uint8_t *payload = malloc(header.length);
        if (!payload) {
            MXD_LOG_ERROR("p2p", "Failed to allocate %u bytes for message", header.length);
            break;
        }

        int payload_read_result = read_n(conn->socket, payload, header.length);
        if (payload_read_result != 0) {
            MXD_LOG_WARN("p2p", "Error reading payload from %s:%d: expected=%u bytes, result=%d, errno=%d (%s)", 
                        conn->address, conn->port, header.length, payload_read_result, errno, strerror(errno));
            free(payload);
            break;
        }
        
        MXD_LOG_INFO("p2p", "Successfully read payload from %s:%d: type=%d, length=%u", 
                    conn->address, conn->port, header.type, header.length);
        
        if (header.type == MXD_MSG_GET_PEERS) {
            handle_get_peers_on_socket(conn->socket, conn->address, conn->port, payload, header.length);
        } else {
            handle_incoming_message(conn->address, conn->port, &header, payload);
        }
        free(payload);
    }
    
    MXD_LOG_INFO("p2p", "Connection handler stopped for %s:%d", conn->address, conn->port);

    pthread_mutex_lock(&peer_mutex);
    if (conn->socket >= 0) {
        close(conn->socket);
        conn->socket = -1;
    }
    if (conn->active) {
        conn->active = 0;
        active_connection_count--;
    }
    pthread_mutex_unlock(&peer_mutex);

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

        // Reject inbound connections from our own external IP early
        if (is_self_address(client_ip, p2p_port)) {
            MXD_LOG_DEBUG("p2p", "Rejecting inbound self-connection from %s:%d", client_ip, client_port);
            close(client_socket);
            pthread_mutex_unlock(&peer_mutex);
            continue;
        }

        int duplicate_found = 0;
        for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
            if (active_connections[i].active &&
                strcmp(active_connections[i].address, client_ip) == 0) {
                duplicate_found = 1;  // Match by address only — one connection per peer
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
        
        enable_tcp_keepalive(client_socket);

        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        time_t now = time(NULL);
        active_connections[slot].socket = client_socket;
        strncpy(active_connections[slot].address, client_ip, sizeof(active_connections[slot].address) - 1);
        active_connections[slot].port = client_port;
        active_connections[slot].peer_listen_port = 0;
        active_connections[slot].connected_at = now;
        active_connections[slot].last_keepalive_sent = now;
        active_connections[slot].last_keepalive_received = now;
        active_connections[slot].keepalive_failures = 0;
        memset(active_connections[slot].sent_session_token, 0, 16);
        memset(active_connections[slot].received_session_token, 0, 16);
        active_connections[slot].has_sent_token = 0;
        active_connections[slot].has_received_token = 0;
        active_connections[slot].handshake_done = 0;  // Inbound connections need handshake
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

int mxd_init_p2p(uint16_t port, uint8_t algo_id, const uint8_t* public_key, const uint8_t* private_key) {
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
    node_algo_id = algo_id;

    // Seed self-IP cache from MXD_PUBLIC_IP env var so we never attempt self-connections
    const char *public_ip = getenv("MXD_PUBLIC_IP");
    if (public_ip && strlen(public_ip) > 0) {
        add_known_self_ip(public_ip);
    }
    size_t pubkey_len = mxd_sig_pubkey_len(algo_id);
    size_t privkey_len = mxd_sig_privkey_len(algo_id);
    memcpy(node_public_key, public_key, pubkey_len);
    memcpy(node_private_key, private_key, privkey_len);
    
    memset(&node_config, 0, sizeof(node_config));
    node_config.port = port;
    
    if (mxd_address_to_string(algo_id, public_key, pubkey_len, /*mainnet*/1,
                              node_config.node_id, sizeof(node_config.node_id)) == 0) {
        MXD_LOG_INFO("p2p", "Derived node_id from wallet address (algo: %s): %s", 
                     mxd_sig_alg_name(algo_id), node_config.node_id);
    } else {
        MXD_LOG_ERROR("p2p", "Failed to generate address string");
        snprintf(node_config.node_id, sizeof(node_config.node_id), "mx_error");
    }
    
    snprintf(node_config.data_dir, sizeof(node_config.data_dir), "data");

    // SECURITY: Populate network_type from global config for network isolation.
    // Without this, testnet and mainnet nodes accept connections from each other.
    {
        mxd_config_t *cfg = mxd_get_config();
        if (cfg && cfg->network_type[0] != '\0') {
            strncpy(node_config.network_type, cfg->network_type, sizeof(node_config.network_type) - 1);
            node_config.network_type[sizeof(node_config.network_type) - 1] = '\0';
            MXD_LOG_INFO("p2p", "Network isolation enabled: %s", node_config.network_type);
        } else {
            MXD_LOG_WARN("p2p", "No network_type configured - network isolation DISABLED");
        }
    }
    
    memset(active_connections, 0, sizeof(active_connections));
    active_connection_count = 0;
    
    memset(manual_peers, 0, sizeof(manual_peers));
    manual_peer_count = 0;
    
    if (mxd_replay_init() != 0) {
        MXD_LOG_ERROR("p2p", "Failed to initialize replay detection");
        return -1;
    }
    
    p2p_initialized = 1;
    MXD_LOG_INFO("p2p", "P2P initialized on port %d with node_id: %s (algo: %s)", 
                 port, node_config.node_id, mxd_sig_alg_name(algo_id));
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
    server_thread_created = 0;
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
    server_thread_created = 1;
    
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
    
    // Use shutdown() to unblock connection handler threads, then let them close() their own sockets.
    // Direct close() here races with connection handlers and causes fd reuse corruption.
    pthread_mutex_lock(&peer_mutex);
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && active_connections[i].socket >= 0) {
            shutdown(active_connections[i].socket, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    
    if (server_thread_created) {
        pthread_join(server_thread, NULL);
        server_thread_created = 0;
    }
    
    if (keepalive_thread_created) {
        pthread_join(keepalive_thread, NULL);
        keepalive_thread_created = 0;
    }
    
    if (peer_connector_thread_created) {
        pthread_join(peer_connector_thread, NULL);
        peer_connector_thread_created = 0;
    }
    
    mxd_replay_cleanup();

    // Zero sensitive key material
    volatile uint8_t *p = node_private_key;
    for (size_t i = 0; i < sizeof(node_private_key); i++) {
        p[i] = 0;
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

    mxd_dht_add_peer(address, port, NULL);

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
    if (is_self_address(address, port)) {
        return -1;
    }

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

static int mxd_send_message_nonblocking(const char* address, uint16_t port,
                    mxd_message_type_t type, const void* payload,
                    size_t payload_length) {
    if (!p2p_initialized || !address || !payload ||
        payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }

    if (send_to_peer_safe(address, port, type, payload, payload_length) != 0) {
        MXD_LOG_DEBUG("p2p", "Failed to send message to %s:%d on persistent connection", address, port);
        return -1;
    }

    update_unified_peer_sent(address, port);

    return 0;
}

int mxd_send_message(const char* address, uint16_t port,
                    mxd_message_type_t type, const void* payload,
                    size_t payload_length) {
    if (!p2p_initialized || !address || !payload ||
        payload_length > MXD_MAX_MESSAGE_SIZE) {
        return -1;
    }

    if (is_self_address(address, port)) {
        return -1;
    }

    // Check if we already have a connection
    peer_connection_t *conn = find_connection_for_peer(address, port);

    if (!conn) {
        if (try_establish_persistent_connection(address, port) != 0) {
            MXD_LOG_WARN("p2p", "Failed to establish persistent connection to %s:%d", address, port);
            return -1;
        }

        for (int i = 0; i < 10; i++) {
            usleep(20000); // 20ms
            conn = find_connection_for_peer(address, port);
            if (conn) break;
        }

        if (!conn) {
            MXD_LOG_WARN("p2p", "Connection to %s:%d not found after establishment", address, port);
            return -1;
        }
    }

    // Wait for session token to be ready (check atomically under lock)
    int token_ready = 0;
    for (int i = 0; i < 100; i++) {
        pthread_mutex_lock(&peer_mutex);
        // Re-find under lock (two-pass like find_connection_for_peer)
        int found = 0;
        // First pass: exact port or listen port match
        for (size_t j = 0; j < MXD_MAX_PEERS; j++) {
            if (active_connections[j].active &&
                strcmp(active_connections[j].address, address) == 0 &&
                (active_connections[j].port == port || active_connections[j].peer_listen_port == port)) {
                if (active_connections[j].has_received_token) {
                    token_ready = 1;
                }
                found = 1;
                break;
            }
        }
        // Second pass: address-only fallback
        if (!found) {
            for (size_t j = 0; j < MXD_MAX_PEERS; j++) {
                if (active_connections[j].active &&
                    strcmp(active_connections[j].address, address) == 0) {
                    if (active_connections[j].has_received_token) {
                        token_ready = 1;
                    }
                    found = 1;
                    break;
                }
            }
        }
        pthread_mutex_unlock(&peer_mutex);

        if (token_ready) break;

        if (!found) {
            MXD_LOG_WARN("p2p", "Connection to %s:%d closed while waiting for token", address, port);
            return -1;
        }

        usleep(40000); // 40ms
    }

    if (!token_ready) {
        MXD_LOG_WARN("p2p", "Session token not ready for %s:%d after 4s timeout", address, port);
        return -1;
    }

    // Use safe send which atomically finds + validates + sends
    if (send_to_peer_safe(address, port, type, payload, payload_length) != 0) {
        MXD_LOG_WARN("p2p", "Failed to send message to %s:%d on persistent connection", address, port);
        return -1;
    }

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

    if (payload_length > MXD_MAX_MESSAGE_SIZE || type > MXD_MSG_MAX) {
        MXD_LOG_ERROR("p2p", "Invalid broadcast: payload_length=%zu (max: %d), type=%d (max: %d)", 
                     payload_length, MXD_MAX_MESSAGE_SIZE, type, MXD_MSG_MAX);
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
            if (mxd_send_message_nonblocking(manual_peers[i].address, manual_peers[i].port, type, payload, payload_length) == 0) {
                success_count++;
            }
        }
    }
    pthread_mutex_unlock(&manual_peer_mutex);
    
    for (size_t i = 0; i < peer_count; i++) {
        if (peers[i].active) {
            if (mxd_send_message_nonblocking(peers[i].address, peers[i].port, type, payload, payload_length) == 0) {
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

int mxd_get_authenticated_connection_count(void) {
    if (!p2p_initialized) {
        return 0;
    }
    
    pthread_mutex_lock(&peer_mutex);
    int count = 0;
    for (size_t i = 0; i < MXD_MAX_PEERS; i++) {
        if (active_connections[i].active && active_connections[i].has_sent_token) {
            count++;
        }
    }
    pthread_mutex_unlock(&peer_mutex);
    
    return count;
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

int mxd_get_node_keys(uint8_t *public_key_out, uint8_t *private_key_out) {
    if (!p2p_initialized) {
        MXD_LOG_ERROR("p2p", "P2P not initialized, cannot retrieve node keys");
        return -1;
    }
    
    size_t pubkey_len = mxd_sig_pubkey_len(node_algo_id);
    size_t privkey_len = mxd_sig_privkey_len(node_algo_id);
    
    if (public_key_out) {
        memcpy(public_key_out, node_public_key, pubkey_len);
    }
    
    if (private_key_out) {
        memcpy(private_key_out, node_private_key, privkey_len);
    }
    
    return 0;
}

int mxd_get_node_algo_id(uint8_t *out_algo_id) {
    if (!p2p_initialized) {
        MXD_LOG_ERROR("p2p", "P2P not initialized, cannot retrieve node algo_id");
        return -1;
    }
    
    if (!out_algo_id) {
        MXD_LOG_ERROR("p2p", "Invalid parameter: out_algo_id is NULL");
        return -1;
    }
    
    *out_algo_id = node_algo_id;
    return 0;
}
