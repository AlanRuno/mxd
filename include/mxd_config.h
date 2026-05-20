#ifndef MXD_CONFIG_H
#define MXD_CONFIG_H

#include <stdint.h>
#include "mxd_types.h"

// Bootstrap node metadata for hybrid cryptography support
typedef struct {
    char address[256];         // IP address or hostname
    uint16_t port;             // Port number
    uint8_t algo_id;           // Algorithm ID (1=Ed25519, 2=Dilithium5, 0=unknown)
    uint8_t public_key[2592];  // Public key (max size for Dilithium5)
    uint16_t public_key_length; // Actual public key length
    uint8_t address20[20];     // Cryptographic address (HASH160 of algo_id || pubkey)
    uint8_t has_crypto_info;   // 1 if algo_id and public_key are available, 0 otherwise
} mxd_bootstrap_node_t;

// HTTP server security configuration
typedef struct {
    char bind_address[64];     // HTTP bind address (default: 127.0.0.1)
    uint16_t port;             // HTTP port (default: 8080)
    int require_auth;          // Require Bearer token authentication
    char api_token[256];       // API authentication token
    int wallet_enabled;        // Enable wallet endpoints (default: false)
    uint32_t rate_limit_per_minute; // Rate limit per IP
    uint32_t timeout_seconds;  // Request timeout
    uint8_t bridge_oracle_pubkeys[10][2592]; // Authorized bridge oracle public keys
    uint16_t bridge_oracle_pubkey_lengths[10]; // Lengths of each oracle public key
    uint8_t bridge_oracle_algo_ids[10];        // Algorithm IDs for each oracle
    uint32_t bridge_oracle_count;              // Number of authorized oracles

    // Bridge security limits (MXD-side enforcement)
    mxd_amount_t bridge_max_mint_per_tx;       // Max MXD per single bridge mint (0 = no limit)
    mxd_amount_t bridge_daily_mint_cap;        // Max MXD minted per day via bridge (0 = no limit)
    uint32_t bridge_min_oracle_signatures;     // Required oracle signatures (N-of-M, default 1)
} mxd_http_config_t;

// Bootstrap security configuration
typedef struct {
    char endpoint[256];        // Bootstrap API endpoint
    int verify_tls;            // Enable TLS verification
    char pinned_keys[10][256]; // Certificate pinned keys
    int pinned_keys_count;     // Number of pinned keys
    char fallback_nodes[10][256]; // Hardcoded fallback nodes
    int fallback_count;        // Number of fallback nodes
    uint32_t min_subnet_diversity; // Minimum unique /24 subnets
} mxd_bootstrap_config_t;

// Mempool security configuration
typedef struct {
    uint32_t max_size;         // Maximum mempool size
    uint32_t max_tx_per_peer;  // Max transactions per peer
    uint64_t max_bytes_per_peer; // Max bytes per peer
    uint32_t min_fee_per_byte; // Minimum fee per byte
    uint32_t max_tx_per_sec_per_peer; // Rate limit per peer
} mxd_mempool_config_t;

// Smart contract security configuration
typedef struct {
    int enabled;                // Enable smart contracts (default: 0/disabled)
    uint64_t gas_limit_default; // Default gas limit
    uint32_t timeout_seconds;   // Execution timeout
    int metering_enabled;       // Enable gas metering
    uint32_t max_memory_pages;  // Maximum WASM memory pages
} mxd_contracts_config_t;

// Consensus security configuration
typedef struct {
    uint32_t blacklist_duration_blocks; // Blacklist duration
    uint32_t min_unique_validators;     // Minimum validators
    uint32_t signature_cache_size;      // Signature cache size
} mxd_consensus_config_t;

// P2P security configuration
typedef struct {
    uint32_t challenge_cache_size;      // Challenge cache size
    uint32_t challenge_ttl_seconds;     // Challenge TTL
    uint32_t session_timeout_seconds;   // Session timeout
    uint32_t timestamp_tolerance_seconds; // Timestamp tolerance
} mxd_p2p_security_config_t;

typedef struct {
    char node_id[64];
    uint16_t port;
    uint16_t metrics_port;     // Metrics/health endpoint port
    char data_dir[256];
    char network_type[32];     // mainnet, testnet
    char node_name[64];        // Node display name
    mxd_amount_t initial_stake; // Initial stake amount in base units
    uint32_t metrics_interval; // Display refresh interval (ms)
    char bootstrap_nodes[10][256];  // Legacy format: "address:port" strings
    mxd_bootstrap_node_t bootstrap_nodes_v2[10];  // Enhanced format with crypto metadata
    int bootstrap_count;
    char node_data[1024];      // Custom node data
    int enable_upnp;           // Enable UPnP port mapping (1=enabled, 0=disabled)
    int bootstrap_refresh_interval;  // Seconds between bootstrap list refreshes (from network_info.update_interval)
    uint8_t preferred_sign_algo;     // Preferred signature algorithm (1=Ed25519, 2=Dilithium5)
    
    // Security configurations
    mxd_http_config_t http;
    mxd_bootstrap_config_t bootstrap;
    mxd_mempool_config_t mempool;
    mxd_contracts_config_t contracts;
    mxd_consensus_config_t consensus;
    mxd_p2p_security_config_t p2p_security;
    
    uint32_t protocol_version;  // Protocol version (v3)
} mxd_config_t;

// Load configuration from file or use built-in defaults.
// If config_file is NULL or file cannot be opened, default configuration will be used.
// Returns 0 on success, -1 on validation failure.
int mxd_load_config(const char* config_file, mxd_config_t* config);

// Fetch bootstrap nodes from network
// Returns 0 on success (including fallback), -1 on critical failure
int mxd_fetch_bootstrap_nodes(mxd_config_t* config);

// Get the global configuration instance
mxd_config_t* mxd_get_config(void);

// Set the global configuration instance
void mxd_set_global_config(mxd_config_t* config);

void mxd_set_default_config(mxd_config_t* config);

#endif // MXD_CONFIG_H
