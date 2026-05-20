#include "../include/mxd_monitoring.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_address.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_config.h"
#include "../include/mxd_secrets.h"
#include "../include/mxd_rocksdb_globals.h"
#include "../include/mxd_mempool.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_rsc.h"
#include "metrics/mxd_prometheus.h"
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <cjson/cJSON.h>
#include <sodium.h>

static mxd_system_metrics_t current_metrics = {0};
static mxd_health_status_t current_health = {0};
static int monitoring_initialized = 0;
static uint16_t metrics_port = 0;
static char prometheus_buffer[4096];
static char health_buffer[1024];
static int server_socket = -1;
static pthread_t server_thread;
static volatile int server_running = 0;

static mxd_config_t* global_config = NULL;

typedef struct {
    char ip[64];
    time_t last_request;
    time_t last_access;  // For LRU eviction
    int request_count;
} rate_limit_entry_t;

#define RATE_LIMIT_TABLE_SIZE 256  // Increased capacity for better coverage
static rate_limit_entry_t rate_limits[RATE_LIMIT_TABLE_SIZE];
static int rate_limit_count = 0;
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;

static int constant_time_compare(const char* a, const char* b, size_t len) {
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

static int check_rate_limit(const char* client_ip) {
    if (!global_config || global_config->http.rate_limit_per_minute == 0) {
        return 1;
    }
    
    pthread_mutex_lock(&rate_limit_mutex);
    
    time_t now = time(NULL);
    int found_idx = -1;
    
    // Search for existing entry
    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, client_ip) == 0) {
            found_idx = i;
            break;
        }
    }
    
    if (found_idx >= 0) {
        // Update existing entry
        rate_limits[found_idx].last_access = now;
        if (now - rate_limits[found_idx].last_request >= 60) {
            rate_limits[found_idx].request_count = 1;
            rate_limits[found_idx].last_request = now;
        } else {
            rate_limits[found_idx].request_count++;
            if (rate_limits[found_idx].request_count > (int)global_config->http.rate_limit_per_minute) {
                pthread_mutex_unlock(&rate_limit_mutex);
                mxd_metrics_increment("mxd_http_rate_limit_violations_total");
                return 0;
            }
        }
    } else {
        // Need to add new entry
        int target_idx;
        
        if (rate_limit_count < RATE_LIMIT_TABLE_SIZE) {
            // Table not full, use next slot
            target_idx = rate_limit_count;
            rate_limit_count++;
        } else {
            // Table full - LRU eviction: find oldest entry by last_access time
            target_idx = 0;
            time_t oldest_access = rate_limits[0].last_access;
            for (int i = 1; i < rate_limit_count; i++) {
                if (rate_limits[i].last_access < oldest_access) {
                    oldest_access = rate_limits[i].last_access;
                    target_idx = i;
                }
            }
            MXD_LOG_DEBUG("monitoring", "Rate limit table full, evicting LRU entry for IP: %s", 
                          rate_limits[target_idx].ip);
        }
        
        // Initialize new entry
        strncpy(rate_limits[target_idx].ip, client_ip, sizeof(rate_limits[target_idx].ip) - 1);
        rate_limits[target_idx].ip[sizeof(rate_limits[target_idx].ip) - 1] = '\0';
        rate_limits[target_idx].last_request = now;
        rate_limits[target_idx].last_access = now;
        rate_limits[target_idx].request_count = 1;
    }
    
    pthread_mutex_unlock(&rate_limit_mutex);
    return 1;
}

static int check_bearer_token(const char* auth_header) {
    if (!global_config || !global_config->http.require_auth) {
        return 1;
    }
    
    // SECURITY FIX: Fail closed when require_auth is true but no token is configured
    // This prevents accidental exposure of wallet endpoints when operators forget to set a token
    if (global_config->http.api_token[0] == '\0') {
        MXD_LOG_WARN("monitoring", "Authentication required but no API token configured - denying access");
        mxd_metrics_increment("mxd_http_auth_failures_total");
        return 0;
    }
    
    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0) {
        mxd_metrics_increment("mxd_http_auth_failures_total");
        return 0;
    }
    
    const char* token = auth_header + 7;
    size_t token_len = strlen(token);
    size_t expected_len = strlen(global_config->http.api_token);
    
    if (token_len != expected_len) {
        mxd_metrics_increment("mxd_http_auth_failures_total");
        return 0;
    }
    
    if (!constant_time_compare(token, global_config->http.api_token, token_len)) {
        mxd_metrics_increment("mxd_http_auth_failures_total");
        return 0;
    }
    
    return 1;
}

static int check_wallet_access(const char* auth_header, const char** error_response, const char** error_content_type, int* error_status) {
    if (global_config && !global_config->http.wallet_enabled) {
        *error_response = "{\"error\":\"Wallet endpoints are disabled\"}";
        *error_content_type = "application/json";
        *error_status = 403;
        mxd_metrics_increment("mxd_http_wallet_requests_total");
        return 0;
    }

    // Skip auth check if require_auth is false
    if (global_config && !global_config->http.require_auth) {
        mxd_metrics_increment("mxd_http_wallet_requests_total");
        return 1;
    }

    if (!check_bearer_token(auth_header)) {
        *error_response = "{\"error\":\"Unauthorized\"}";
        *error_content_type = "application/json";
        *error_status = 401;
        mxd_metrics_increment("mxd_http_wallet_requests_total");
        return 0;
    }
    
    mxd_metrics_increment("mxd_http_wallet_requests_total");
    return 1;
}

static mxd_wallet_t wallet = {0};
static int wallet_initialized = 0;
static char wallet_response_buffer[8192];
static pthread_mutex_t wallet_mutex = PTHREAD_MUTEX_INITIALIZER;

#define MXD_WALLET_MAX_KEYPAIRS (sizeof(wallet.keypairs) / sizeof(wallet.keypairs[0]))
#define MXD_WALLET_FILE_PATH "wallet.json"

static mxd_transaction_history_entry_t transaction_history[1000];
static size_t transaction_history_count = 0;
static pthread_mutex_t history_mutex = PTHREAD_MUTEX_INITIALIZER;

static mxd_hybrid_crypto_metrics_t hybrid_metrics = {0};
static pthread_mutex_t hybrid_metrics_mutex = PTHREAD_MUTEX_INITIALIZER;
static char hybrid_metrics_buffer[2048];

int mxd_init_monitoring(uint16_t http_port) {
    if (monitoring_initialized) {
        return 0;
    }
    
    metrics_port = http_port;
    memset(&current_metrics, 0, sizeof(current_metrics));
    memset(&current_health, 0, sizeof(current_health));
    
    current_health.is_healthy = 1;
    current_health.database_connected = 1;
    current_health.p2p_active = 1;
    current_health.consensus_active = 1;
    strncpy(current_health.status_message, "System operational", sizeof(current_health.status_message) - 1);
    current_health.status_message[sizeof(current_health.status_message) - 1] = '\0';
    current_health.last_check_timestamp = time(NULL);
    
    global_config = mxd_get_config();
    if (!global_config) {
        MXD_LOG_WARN("monitoring", "Failed to get global config, using defaults");
    }
    
    if (mxd_metrics_init() != 0) {
        MXD_LOG_WARN("monitoring", "Failed to initialize metrics registry");
    }
    
    if (mxd_init_wallet() != 0) {
        MXD_LOG_ERROR("monitoring", "Failed to initialize wallet");
        return -1;
    }
    
    monitoring_initialized = 1;
    MXD_LOG_INFO("monitoring", "Monitoring system initialized on port %d", http_port);
    MXD_LOG_INFO("monitoring", "HTTP binding: %s, Auth: %s, Wallet: %s",
        global_config ? global_config->http.bind_address : "0.0.0.0",
        global_config && global_config->http.require_auth ? "enabled" : "disabled",
        global_config && global_config->http.wallet_enabled ? "enabled" : "disabled");
    return 0;
}

void mxd_cleanup_monitoring(void) {
    if (monitoring_initialized) {
        mxd_cleanup_wallet();
        monitoring_initialized = 0;
        MXD_LOG_INFO("monitoring", "Monitoring system cleaned up");
    }
}

int mxd_update_system_metrics(const mxd_system_metrics_t *metrics) {
    if (!monitoring_initialized || !metrics) {
        return -1;
    }
    
    current_metrics = *metrics;
    MXD_LOG_DEBUG("monitoring", "System metrics updated - TPS: %.2f, Peers: %d", 
                  metrics->current_tps, metrics->active_peers);
    return 0;
}

int mxd_get_health_status(mxd_health_status_t *status) {
    if (!monitoring_initialized || !status) {
        return -1;
    }
    
    current_health.last_check_timestamp = time(NULL);
    
    current_health.is_healthy = current_health.database_connected && 
                               current_health.p2p_active && 
                               current_health.consensus_active;
    
    *status = current_health;
    return 0;
}

const char* mxd_get_prometheus_metrics(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(prometheus_buffer, sizeof(prometheus_buffer),
        "# HELP mxd_transactions_total Total number of transactions processed\n"
        "# TYPE mxd_transactions_total counter\n"
        "mxd_transactions_total %lu\n"
        "\n"
        "# HELP mxd_blocks_total Total number of blocks processed\n"
        "# TYPE mxd_blocks_total counter\n"
        "mxd_blocks_total %lu\n"
        "\n"
        "# HELP mxd_tps_current Current transactions per second\n"
        "# TYPE mxd_tps_current gauge\n"
        "mxd_tps_current %.2f\n"
        "\n"
        "# HELP mxd_network_latency_ms Network latency in milliseconds\n"
        "# TYPE mxd_network_latency_ms gauge\n"
        "mxd_network_latency_ms %lu\n"
        "\n"
        "# HELP mxd_peers_active Number of active peers\n"
        "# TYPE mxd_peers_active gauge\n"
        "mxd_peers_active %u\n"
        "\n"
        "# HELP mxd_blockchain_height Current blockchain height\n"
        "# TYPE mxd_blockchain_height gauge\n"
        "mxd_blockchain_height %lu\n"
        "\n"
        "# HELP mxd_consensus_efficiency Consensus efficiency percentage\n"
        "# TYPE mxd_consensus_efficiency gauge\n"
        "mxd_consensus_efficiency %.2f\n"
        "\n"
        "# HELP mxd_memory_usage_bytes Memory usage in bytes\n"
        "# TYPE mxd_memory_usage_bytes gauge\n"
        "mxd_memory_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_disk_usage_bytes Disk usage in bytes\n"
        "# TYPE mxd_disk_usage_bytes gauge\n"
        "mxd_disk_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_cpu_usage_percent CPU usage percentage\n"
        "# TYPE mxd_cpu_usage_percent gauge\n"
        "mxd_cpu_usage_percent %.2f\n",
        current_metrics.total_transactions,
        current_metrics.total_blocks,
        current_metrics.current_tps,
        current_metrics.network_latency_ms,
        current_metrics.active_peers,
        current_metrics.blockchain_height,
        current_metrics.consensus_efficiency,
        current_metrics.memory_usage_bytes,
        current_metrics.disk_usage_bytes,
        current_metrics.cpu_usage_percent
    );
    
    return prometheus_buffer;
}

const char* mxd_get_health_json(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(health_buffer, sizeof(health_buffer),
        "{"
        "\"status\":\"%s\","
        "\"timestamp\":%lu,"
        "\"checks\":{"
        "\"database\":%s,"
        "\"p2p\":%s,"
        "\"consensus\":%s"
        "},"
        "\"message\":\"%s\""
        "}",
        current_health.is_healthy ? "healthy" : "unhealthy",
        current_health.last_check_timestamp,
        current_health.database_connected ? "true" : "false",
        current_health.p2p_active ? "true" : "false",
        current_health.consensus_active ? "true" : "false",
        current_health.status_message
    );
    
    return health_buffer;
}

// Explorer API: Get network status
static char status_buffer[4096];
const char* mxd_get_status_json(void) {
    uint32_t height = 0;
    mxd_get_blockchain_height(&height);

    // Get latest block hash and calculate statistics
    char latest_hash_hex[129] = "";
    uint64_t total_transactions = 0;
    double avg_block_time = 0.0;
    double current_tps = 0.0;
    uint32_t validator_count = 0;
    uint32_t difficulty = 1;
    uint64_t total_supply = 0;

    // Get validator count from rapid table
    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (table) {
        validator_count = (uint32_t)table->count;
    }

    if (height > 0) {
        // Get latest block for hash and stats
        mxd_block_t latest_block = {0};
        if (mxd_get_block_by_height(height - 1, &latest_block) == 0) {
            for (int i = 0; i < 64; i++) {
                snprintf(latest_hash_hex + i*2, 3, "%02x", latest_block.block_hash[i]);
            }
            difficulty = latest_block.difficulty;
            total_supply = latest_block.total_supply;
            mxd_free_block(&latest_block);
        }

        // Calculate statistics from recent blocks (last 100 or all if less)
        uint32_t sample_size = (height > 100) ? 100 : height;
        uint64_t first_timestamp = 0;
        uint64_t last_timestamp = 0;
        uint64_t recent_tx_count = 0;
        uint32_t blocks_retrieved = 0;

        for (uint32_t i = 0; i < sample_size; i++) {
            uint32_t block_height = height - 1 - i;
            mxd_block_t block = {0};
            if (mxd_get_block_by_height(block_height, &block) == 0) {
                total_transactions += block.transaction_count;
                recent_tx_count += block.transaction_count;

                if (blocks_retrieved == 0) {
                    last_timestamp = block.timestamp;
                }
                first_timestamp = block.timestamp;
                blocks_retrieved++;
                mxd_free_block(&block);
            }
            if (block_height == 0) break;
        }

        // Calculate average block time (in seconds)
        if (blocks_retrieved > 1 && last_timestamp > first_timestamp) {
            avg_block_time = (double)(last_timestamp - first_timestamp) / (double)(blocks_retrieved - 1);
        }

        // Calculate TPS from recent blocks
        if (blocks_retrieved > 1 && last_timestamp > first_timestamp) {
            uint64_t time_span = last_timestamp - first_timestamp;
            if (time_span > 0) {
                current_tps = (double)recent_tx_count / (double)time_span;
            }
        }

        // Count total transactions from all blocks (approximate for large chains)
        // For now we counted recent 100, for older blocks we estimate
        if (height > 100) {
            // Get a sample from middle of chain to estimate average tx per block
            uint32_t mid_height = height / 2;
            uint64_t mid_tx_sum = 0;
            uint32_t mid_sample = 10;
            for (uint32_t i = 0; i < mid_sample && mid_height + i < height; i++) {
                mxd_block_t block = {0};
                if (mxd_get_block_by_height(mid_height + i, &block) == 0) {
                    mid_tx_sum += block.transaction_count;
                    mxd_free_block(&block);
                }
            }
            double avg_tx_per_block = (double)mid_tx_sum / (double)mid_sample;
            total_transactions = (uint64_t)(avg_tx_per_block * height);
        }
    }

    snprintf(status_buffer, sizeof(status_buffer),
        "{"
        "\"height\":%u,"
        "\"latest_hash\":\"%s\","
        "\"total_transactions\":%llu,"
        "\"validator_count\":%u,"
        "\"difficulty\":%u,"
        "\"total_supply\":%llu,"
        "\"avg_block_time\":%.2f,"
        "\"current_tps\":%.4f"
        "}",
        height,
        latest_hash_hex,
        (unsigned long long)total_transactions,
        validator_count,
        difficulty,
        (unsigned long long)total_supply,
        avg_block_time,
        current_tps
    );

    return status_buffer;
}

// Explorer API: Get block by height
static char *last_block_json_buf = NULL;

static void mon_hex_encode(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) snprintf(out + i*2, 3, "%02x", bytes[i]);
}

// A2 helper: surface BSC-side bridge context for bridge_mint transactions.
// The data is committed on-chain inside the v3 payload but is invisible to
// explorers because v3 bridge mints are structurally parseable as v2 coinbases
// (and the v2 path wins first), so the payload.bridge is never extracted.
// Aditive — does not replace any existing v2/v3 field.
static void mon_add_bridge_data_json(cJSON *tx_obj, const mxd_bridge_payload_t *bridge) {
    if (!tx_obj || !bridge) return;
    cJSON *bd = cJSON_AddObjectToObject(tx_obj, "bridge_data");
    if (!bd) return;

    char hex[129];

    // source_chain_id: BE u32 in first 4 bytes of the 32-byte field
    uint32_t chain_id_be;
    memcpy(&chain_id_be, bridge->source_chain_id, sizeof(uint32_t));
    uint32_t chain_id = ntohl(chain_id_be);
    cJSON_AddNumberToObject(bd, "source_chain_id", chain_id);
    const char *chain_name = (chain_id == 56) ? "bsc_mainnet_56"
                           : (chain_id == 97) ? "bsc_testnet_97"
                           : "unknown";
    cJSON_AddStringToObject(bd, "source_chain_name", chain_name);

    // bsc_tx_hash: 32 bytes = 64 hex chars, "0x" prefix for BSC convention
    char bsc_tx_hash_prefixed[67];
    bsc_tx_hash_prefixed[0] = '0';
    bsc_tx_hash_prefixed[1] = 'x';
    mon_hex_encode(bridge->source_tx_hash, 32, bsc_tx_hash_prefixed + 2);
    bsc_tx_hash_prefixed[66] = '\0';
    cJSON_AddStringToObject(bd, "bsc_tx_hash", bsc_tx_hash_prefixed);

    cJSON_AddNumberToObject(bd, "source_block_number", (double)bridge->source_block_number);

    // bridge_contract: 64-byte hash, 128 hex
    mon_hex_encode(bridge->bridge_contract, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(bd, "bridge_contract", hex);

    // mxd_chain_id: BE u32 in first 4 bytes, hex form (e.g. "4d580002")
    mon_hex_encode(bridge->mxd_chain_id, 4, hex); hex[8] = 0;
    cJSON_AddStringToObject(bd, "mxd_chain_id", hex);

    cJSON_AddNumberToObject(bd, "oracle_count", (double)bridge->oracle_count);
}

const char* mxd_get_block_json(uint32_t height) {
    if (last_block_json_buf) { free(last_block_json_buf); last_block_json_buf = NULL; }
    mxd_block_t block = {0};

    if (mxd_get_block_by_height(height, &block) != 0) {
        last_block_json_buf = strdup("{\"error\":\"Block not found\"}");
        return last_block_json_buf;
    }

    cJSON *root = cJSON_CreateObject();
    char hex[129];

    cJSON_AddNumberToObject(root, "height", block.height);
    mon_hex_encode(block.block_hash, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(root, "hash", hex);
    mon_hex_encode(block.prev_block_hash, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(root, "prev_hash", hex);
    mon_hex_encode(block.merkle_root, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(root, "merkle_root", hex);
    cJSON_AddNumberToObject(root, "timestamp", (double)block.timestamp);
    mon_hex_encode(block.proposer_id, 32, hex); hex[64] = 0;   // v6: addr32 (64 hex chars)
    cJSON_AddStringToObject(root, "proposer", hex);
    cJSON_AddNumberToObject(root, "version", block.version);
    cJSON_AddNumberToObject(root, "difficulty", block.difficulty);
    cJSON_AddNumberToObject(root, "nonce", (double)block.nonce);
    cJSON_AddNumberToObject(root, "validation_count", block.validation_count);
    cJSON_AddNumberToObject(root, "rapid_membership_count", block.rapid_membership_count);
    cJSON_AddNumberToObject(root, "transaction_count", block.transaction_count);
    cJSON_AddNumberToObject(root, "total_supply", (double)block.total_supply);

    if (block.version >= 5) {
        // v6: next_proposer is 32-byte addr32 (was 20 bytes in v5).
        size_t np_len = (block.version >= 6) ? 32 : 20;
        mon_hex_encode(block.next_proposer, np_len, hex); hex[np_len * 2] = 0;
        cJSON_AddStringToObject(root, "next_proposer", hex);
    }

    // Transactions
    cJSON *tx_array = cJSON_AddArrayToObject(root, "transactions");
    for (uint32_t t = 0; t < block.transaction_count && block.transactions; t++) {
        const uint8_t *data = block.transactions[t].data;
        size_t len = block.transactions[t].length;
        if (!data || len == 0) continue;

        mxd_transaction_t tx;
        memset(&tx, 0, sizeof(tx));
        if (mxd_deserialize_transaction(data, len, &tx) == 0) {
            /* tx_hash is populated from the wire (MXD-04 §10.1 pre-parse dedup hint). */
            cJSON *tx_obj = cJSON_CreateObject();
            mon_hex_encode(tx.tx_hash, 64, hex); hex[128] = 0;
            cJSON_AddStringToObject(tx_obj, "hash", hex);
            cJSON_AddNumberToObject(tx_obj, "version", tx.version);
            cJSON_AddBoolToObject(tx_obj, "is_coinbase", tx.is_coinbase);
            cJSON_AddNumberToObject(tx_obj, "timestamp", (double)tx.timestamp);
            cJSON_AddNumberToObject(tx_obj, "input_count", tx.input_count);
            cJSON_AddNumberToObject(tx_obj, "output_count", tx.output_count);
            if (tx.voluntary_tip > 0)
                cJSON_AddNumberToObject(tx_obj, "voluntary_tip", (double)tx.voluntary_tip);

            cJSON *inputs = cJSON_AddArrayToObject(tx_obj, "inputs");
            for (uint32_t i = 0; i < tx.input_count && tx.inputs; i++) {
                cJSON *in_obj = cJSON_CreateObject();
                mon_hex_encode(tx.inputs[i].prev_tx_hash, 64, hex); hex[128] = 0;
                cJSON_AddStringToObject(in_obj, "prev_tx_hash", hex);
                cJSON_AddNumberToObject(in_obj, "output_index", tx.inputs[i].output_index);
                cJSON_AddNumberToObject(in_obj, "amount", (double)tx.inputs[i].amount);
                cJSON_AddItemToArray(inputs, in_obj);
            }

            cJSON *outputs = cJSON_AddArrayToObject(tx_obj, "outputs");
            for (uint32_t i = 0; i < tx.output_count && tx.outputs; i++) {
                cJSON *out_obj = cJSON_CreateObject();
                mon_hex_encode(tx.outputs[i].recipient_addr, 32, hex); hex[64] = 0;
                cJSON_AddStringToObject(out_obj, "recipient", hex);
                cJSON_AddNumberToObject(out_obj, "amount", (double)tx.outputs[i].amount);
                cJSON_AddItemToArray(outputs, out_obj);
            }

            // A2: v3 bridge_mint txs are structurally parseable as v2 coinbases
            // so the v2 path wins here without ever touching payload.bridge. We
            // re-deserialize as v3 (additive, side-effect-free) just to surface
            // the BSC-side context for audit/explorer.
            if (tx.version == 3) {
                mxd_transaction_v3_t tx3_for_bridge;
                memset(&tx3_for_bridge, 0, sizeof(tx3_for_bridge));
                if (mxd_deserialize_transaction_v3_from_block(data, len, &tx3_for_bridge) == 0) {
                    if (tx3_for_bridge.type == MXD_TX_TYPE_BRIDGE_MINT &&
                        tx3_for_bridge.payload.bridge) {
                        mon_add_bridge_data_json(tx_obj, tx3_for_bridge.payload.bridge);
                    }
                    mxd_free_transaction_v3(&tx3_for_bridge);
                }
            }

            cJSON_AddItemToArray(tx_array, tx_obj);
            mxd_free_transaction(&tx);
        } else {
            mxd_transaction_v3_t tx3;
            memset(&tx3, 0, sizeof(tx3));
            if (mxd_deserialize_transaction_v3_from_block(data, len, &tx3) == 0) {
                cJSON *tx_obj = cJSON_CreateObject();
                mon_hex_encode(tx3.tx_hash, 64, hex); hex[128] = 0;
                cJSON_AddStringToObject(tx_obj, "hash", hex);
                cJSON_AddNumberToObject(tx_obj, "version", tx3.version);
                cJSON_AddNumberToObject(tx_obj, "type", tx3.type);
                cJSON_AddNumberToObject(tx_obj, "timestamp", (double)tx3.timestamp);

                cJSON *outputs = cJSON_AddArrayToObject(tx_obj, "outputs");
                for (uint32_t i = 0; i < tx3.output_count && tx3.outputs; i++) {
                    cJSON *out_obj = cJSON_CreateObject();
                    mon_hex_encode(tx3.outputs[i].recipient_addr, 32, hex); hex[64] = 0;
                    cJSON_AddStringToObject(out_obj, "recipient", hex);
                    cJSON_AddNumberToObject(out_obj, "amount", (double)tx3.outputs[i].amount);
                    cJSON_AddItemToArray(outputs, out_obj);
                }

                // A2: also from this branch (in case v2 deser fails for some
                // future bridge tx variant).
                if (tx3.type == MXD_TX_TYPE_BRIDGE_MINT && tx3.payload.bridge) {
                    mon_add_bridge_data_json(tx_obj, tx3.payload.bridge);
                }

                cJSON_AddItemToArray(tx_array, tx_obj);
                mxd_free_transaction_v3(&tx3);
            }
        }
    }

    last_block_json_buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    mxd_free_block(&block);
    return last_block_json_buf;
}

// Explorer API: Get latest blocks
static char blocks_buffer[32768];
const char* mxd_get_latest_blocks_json(int limit) {
    if (limit <= 0) limit = 10;
    if (limit > 50) limit = 50;  // Cap at 50

    uint32_t height = 0;
    mxd_get_blockchain_height(&height);

    if (height == 0) {
        snprintf(blocks_buffer, sizeof(blocks_buffer), "{\"blocks\":[]}");
        return blocks_buffer;
    }

    char* ptr = blocks_buffer;
    size_t remaining = sizeof(blocks_buffer);
    int written = snprintf(ptr, remaining, "{\"blocks\":[");
    ptr += written;
    remaining -= written;

    int count = 0;
    for (uint32_t h = height - 1; count < limit && h < height; h--, count++) {
        mxd_block_t block = {0};
        if (mxd_get_block_by_height(h, &block) != 0) {
            break;
        }

        // Convert to hex
        char hash_hex[129] = "";
        char proposer_hex[41] = "";
        for (int i = 0; i < 64; i++) {
            snprintf(hash_hex + i*2, 3, "%02x", block.block_hash[i]);
        }
        for (int i = 0; i < 20; i++) {
            snprintf(proposer_hex + i*2, 3, "%02x", block.proposer_id[i]);
        }

        if (count > 0) {
            written = snprintf(ptr, remaining, ",");
            ptr += written;
            remaining -= written;
        }

        written = snprintf(ptr, remaining,
            "{"
            "\"height\":%u,"
            "\"hash\":\"%s\","
            "\"timestamp\":%llu,"
            "\"proposer\":\"%s\","
            "\"version\":%u,"
            "\"validation_count\":%u,"
            "\"transaction_count\":%u"
            "}",
            block.height,
            hash_hex,
            (unsigned long long)block.timestamp,
            proposer_hex,
            block.version,
            block.validation_count,
            block.transaction_count
        );
        ptr += written;
        remaining -= written;

        mxd_free_block(&block);

        if (h == 0) break;  // Prevent underflow
    }

    snprintf(ptr, remaining, "]}");
    return blocks_buffer;
}

// Explorer API: Get rapid stake table validators
static char validators_buffer[65536];
const char* mxd_get_validators_json(void) {
    const mxd_rapid_table_t *table = mxd_get_rapid_table();

    if (!table || table->count == 0) {
        snprintf(validators_buffer, sizeof(validators_buffer),
            "{\"validators\":[],\"count\":0,\"last_update\":0}");
        return validators_buffer;
    }

    char* ptr = validators_buffer;
    size_t remaining = sizeof(validators_buffer);
    int written = snprintf(ptr, remaining,
        "{\"validators\":[");
    ptr += written;
    remaining -= written;

    for (size_t i = 0; i < table->count && remaining > 512; i++) {
        mxd_node_stake_t *node = table->nodes[i];
        if (!node) continue;

        // Convert address to hex (v6: addr32)
        char addr_hex[65] = "";
        for (int j = 0; j < 32; j++) {
            snprintf(addr_hex + j*2, 3, "%02x", node->node_address[j]);
        }

        if (i > 0) {
            written = snprintf(ptr, remaining, ",");
            ptr += written;
            remaining -= written;
        }

        written = snprintf(ptr, remaining,
            "{"
            "\"address\":\"%s\","
            "\"node_id\":\"%s\","
            "\"rank\":%u,"
            "\"rank_score\":%u,"
            "\"active\":%d,"
            "\"position\":%u,"
            "\"stake\":%llu,"
            "\"metrics\":{"
            "\"avg_response_time\":%llu,"
            "\"response_count\":%u,"
            "\"message_success\":%u,"
            "\"message_total\":%u,"
            "\"reliability_score\":%.4f,"
            "\"performance_score\":%.4f,"
            "\"last_update\":%llu,"
            "\"tip_share\":%llu,"
            "\"peer_count\":%zu"
            "}"
            "}",
            addr_hex,
            node->node_id,
            node->rapid_table_position,
            node->rank,
            node->active ? 1 : 0,
            node->rapid_table_position,
            (unsigned long long)node->stake_amount,
            (unsigned long long)node->metrics.avg_response_time,
            node->metrics.response_count,
            node->metrics.message_success,
            node->metrics.message_total,
            node->metrics.reliability_score,
            node->metrics.performance_score,
            (unsigned long long)node->metrics.last_update,
            (unsigned long long)node->metrics.tip_share,
            node->metrics.peer_count
        );
        ptr += written;
        remaining -= written;
    }

    snprintf(ptr, remaining,
        "],\"count\":%zu,\"last_update\":%llu}",
        table->count,
        (unsigned long long)table->last_update
    );

    return validators_buffer;
}

int mxd_init_wallet(void) {
    if (wallet_initialized) {
        MXD_LOG_INFO("wallet", "Wallet already initialized");
        return 0;
    }
    
    MXD_LOG_INFO("wallet", "Starting wallet initialization...");
    memset(&wallet, 0, sizeof(wallet));
    
    if (!mxd_get_rocksdb_db()) {
        MXD_LOG_ERROR("wallet", "UTXO database not initialized - must be initialized before wallet");
        return -1;
    }
    MXD_LOG_INFO("wallet", "UTXO database already initialized");
    
    wallet_initialized = 1;
    MXD_LOG_INFO("wallet", "Wallet system initialized");
    return 0;
}

void mxd_cleanup_wallet(void) {
    if (wallet_initialized) {
        pthread_mutex_lock(&wallet_mutex);
        
        for (size_t i = 0; i < wallet.keypair_count; i++) {
            if (wallet.keypairs[i].public_key) {
                free(wallet.keypairs[i].public_key);
                wallet.keypairs[i].public_key = NULL;
            }
            if (wallet.keypairs[i].private_key) {
                free(wallet.keypairs[i].private_key);
                wallet.keypairs[i].private_key = NULL;
            }
            wallet.keypairs[i].public_key_length = 0;
            wallet.keypairs[i].private_key_length = 0;
        }
        
        memset(&wallet, 0, sizeof(wallet));
        wallet_initialized = 0;
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_INFO("wallet", "Wallet system cleaned up");
    }
}

const char* mxd_get_wallet_html(void) {
    static const char* wallet_html = 
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "    <meta charset=\"UTF-8\">\n"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "    <title>MXD Web3 Wallet</title>\n"
        "    <style>\n"
        "        * { margin: 0; padding: 0; box-sizing: border-box; }\n"
        "        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }\n"
        "        .container { max-width: 1200px; margin: 0 auto; }\n"
        "        .header { text-align: center; color: white; margin-bottom: 30px; }\n"
        "        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }\n"
        "        .header p { font-size: 1.1rem; opacity: 0.9; }\n"
        "        .wallet-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }\n"
        "        .card { background: white; border-radius: 15px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }\n"
        "        .card h2 { color: #333; margin-bottom: 20px; font-size: 1.5rem; }\n"
        "        .form-group { margin-bottom: 15px; }\n"
        "        .form-group label { display: block; margin-bottom: 5px; color: #555; font-weight: 500; }\n"
        "        .form-group input, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #e1e5e9; border-radius: 8px; font-size: 14px; transition: border-color 0.3s; }\n"
        "        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: #667eea; }\n"
        "        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: transform 0.2s; }\n"
        "        .btn:hover { transform: translateY(-2px); }\n"
        "        .btn:active { transform: translateY(0); }\n"
        "        .address-item { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid #667eea; }\n"
        "        .address-item .address { font-family: monospace; font-size: 12px; color: #666; word-break: break-all; }\n"
        "        .address-item .balance { font-weight: bold; color: #333; margin-top: 5px; }\n"
        "        .status { padding: 10px; border-radius: 8px; margin-top: 15px; }\n"
        "        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }\n"
        "        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }\n"
        "        .status.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }\n"
        "        @media (max-width: 768px) { .wallet-grid { grid-template-columns: 1fr; } .header h1 { font-size: 2rem; } }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <div class=\"container\">\n"
        "        <div class=\"header\">\n"
        "            <h1>MXD Web3 Wallet</h1>\n"
        "            <p>Manage your MXD addresses, check balances, and send transactions</p>\n"
        "        </div>\n"
        "        <div class=\"wallet-grid\">\n"
        "            <div class=\"card\">\n"
        "                <h2>Generate New Address</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"algorithm\">Algorithm:</label>\n"
        "                    <select id=\"algorithm\" style=\"width: 100%; padding: 12px; border: 2px solid #e1e5e9; border-radius: 8px; font-size: 14px;\">\n"
        "                        <option value=\"ed25519\">Ed25519 (Classical)</option>\n"
        "                        <option value=\"dilithium5\">Dilithium5 (Post-Quantum)</option>\n"
        "                    </select>\n"
        "                </div>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"passphrase\">Passphrase (optional):</label>\n"
        "                    <input type=\"password\" id=\"passphrase\" placeholder=\"Enter passphrase for key derivation\">\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"generateAddress()\">Generate Address</button>\n"
        "                <div id=\"generateStatus\"></div>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>Check Balance</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"balanceAddress\">Address:</label>\n"
        "                    <input type=\"text\" id=\"balanceAddress\" placeholder=\"Enter MXD address\">\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"checkBalance()\">Check Balance</button>\n"
        "                <div id=\"balanceStatus\"></div>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>Send Transaction</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"sendFrom\">From Address:</label>\n"
        "                    <input type=\"text\" id=\"sendFrom\" placeholder=\"Your address\">\n"
        "                </div>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"sendTo\">To Address:</label>\n"
        "                    <input type=\"text\" id=\"sendTo\" placeholder=\"Recipient address\">\n"
        "                </div>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"sendAmount\">Amount:</label>\n"
        "                    <input type=\"number\" id=\"sendAmount\" placeholder=\"Amount to send\" step=\"0.00000001\">\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"sendTransaction()\">Send Transaction</button>\n"
        "                <div id=\"sendStatus\"></div>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>My Addresses</h2>\n"
        "                <div id=\"addressList\">\n"
        "                    <p style=\"color: #666; text-align: center; padding: 20px;\">No addresses generated yet</p>\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"refreshAddresses()\">Refresh Balances</button>\n"
        "                <button class=\"btn\" onclick=\"listAddresses()\" style=\"margin-left: 10px;\">List All Addresses</button>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>Wallet Management</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label>Export Wallet (Argon2id Encrypted)</label>\n"
        "                    <input type=\"password\" id=\"exportPassword\" placeholder=\"Enter password for encryption\">\n"
        "                    <button class=\"btn\" onclick=\"exportWallet()\" style=\"margin-top: 10px;\">Export Wallet</button>\n"
        "                    <div id=\"exportStatus\"></div>\n"
        "                </div>\n"
        "                <div class=\"form-group\" style=\"margin-top: 20px;\">\n"
        "                    <label>Import Wallet</label>\n"
        "                    <textarea id=\"importData\" placeholder=\"Paste encrypted wallet data here\" rows=\"3\" style=\"font-family: monospace; font-size: 12px;\"></textarea>\n"
        "                    <input type=\"password\" id=\"importPassword\" placeholder=\"Enter decryption password\" style=\"margin-top: 10px;\">\n"
        "                    <button class=\"btn\" onclick=\"importWallet()\" style=\"margin-top: 10px;\">Import Wallet</button>\n"
        "                    <div id=\"importStatus\"></div>\n"
        "                </div>\n"
        "                <div class=\"form-group\" style=\"margin-top: 20px;\">\n"
        "                    <label>Transaction History</label>\n"
        "                    <button class=\"btn\" onclick=\"viewHistory()\">View Transaction History</button>\n"
        "                    <div id=\"historyStatus\"></div>\n"
        "                </div>\n"
        "            </div>\n"
        "        </div>\n"
        "    </div>\n"
        "    <script>\n"
        "        let addresses = [];\n"
        "        function showStatus(elementId, message, type) {\n"
        "            const element = document.getElementById(elementId);\n"
        "            element.innerHTML = '<div class=\"status ' + type + '\">' + message + '</div>';\n"
        "        }\n"
        "        async function generateAddress() {\n"
        "            const algorithm = document.getElementById('algorithm').value;\n"
        "            const passphrase = document.getElementById('passphrase').value;\n"
        "            showStatus('generateStatus', 'Generating ' + algorithm + ' address...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/generate?algo=' + algorithm, {\n"
        "                    method: 'POST',\n"
        "                    headers: { 'Content-Type': 'application/json' },\n"
        "                    body: JSON.stringify({ passphrase: passphrase })\n"
        "                });\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    addresses.push({address: data.address, algo: data.algo});\n"
        "                    showStatus('generateStatus', 'Address generated (' + data.algo + '): ' + data.address, 'success');\n"
        "                    updateAddressList();\n"
        "                    document.getElementById('passphrase').value = '';\n"
        "                } else {\n"
        "                    showStatus('generateStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('generateStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function checkBalance() {\n"
        "            const address = document.getElementById('balanceAddress').value;\n"
        "            if (!address) {\n"
        "                showStatus('balanceStatus', 'Please enter an address', 'error');\n"
        "                return;\n"
        "            }\n"
        "            showStatus('balanceStatus', 'Checking balance...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/balance?address=' + encodeURIComponent(address));\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    showStatus('balanceStatus', 'Balance: ' + data.balance + ' MXD', 'success');\n"
        "                } else {\n"
        "                    showStatus('balanceStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('balanceStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function sendTransaction() {\n"
        "            const from = document.getElementById('sendFrom').value;\n"
        "            const to = document.getElementById('sendTo').value;\n"
        "            const amount = document.getElementById('sendAmount').value;\n"
        "            if (!from || !to || !amount) {\n"
        "                showStatus('sendStatus', 'Please fill in all fields', 'error');\n"
        "                return;\n"
        "            }\n"
        "            showStatus('sendStatus', 'Creating transaction...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/send', {\n"
        "                    method: 'POST',\n"
        "                    headers: { 'Content-Type': 'application/json' },\n"
        "                    body: JSON.stringify({ from: from, to: to, amount: amount })\n"
        "                });\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    showStatus('sendStatus', 'Transaction sent! TX ID: ' + data.txid, 'success');\n"
        "                    document.getElementById('sendFrom').value = '';\n"
        "                    document.getElementById('sendTo').value = '';\n"
        "                    document.getElementById('sendAmount').value = '';\n"
        "                } else {\n"
        "                    showStatus('sendStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('sendStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function refreshAddresses() {\n"
        "            updateAddressList();\n"
        "        }\n"
        "        async function listAddresses() {\n"
        "            try {\n"
        "                const response = await fetch('/wallet/addresses');\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    addresses = data.addresses;\n"
        "                    updateAddressList();\n"
        "                }\n"
        "            } catch (error) {\n"
        "                console.error('Failed to list addresses:', error);\n"
        "            }\n"
        "        }\n"
        "        async function updateAddressList() {\n"
        "            const listElement = document.getElementById('addressList');\n"
        "            if (addresses.length === 0) {\n"
        "                listElement.innerHTML = '<p style=\"color: #666; text-align: center; padding: 20px;\">No addresses generated yet</p>';\n"
        "                return;\n"
        "            }\n"
        "            let html = '';\n"
        "            for (const addrObj of addresses) {\n"
        "                const address = addrObj.address || addrObj;\n"
        "                const algo = addrObj.algo_name || addrObj.algo || 'Unknown';\n"
        "                try {\n"
        "                    const response = await fetch('/wallet/balance?address=' + encodeURIComponent(address));\n"
        "                    const data = await response.json();\n"
        "                    const balance = data.success ? data.balance : 'Error';\n"
        "                    html += '<div class=\"address-item\"><div class=\"address\">' + address + ' <span style=\"color: #667eea; font-weight: bold;\">[' + algo + ']</span></div><div class=\"balance\">Balance: ' + balance + ' MXD</div></div>';\n"
        "                } catch (error) {\n"
        "                    html += '<div class=\"address-item\"><div class=\"address\">' + address + ' <span style=\"color: #667eea; font-weight: bold;\">[' + algo + ']</span></div><div class=\"balance\">Balance: Error loading</div></div>';\n"
        "                }\n"
        "            }\n"
        "            listElement.innerHTML = html;\n"
        "        }\n"
        "        async function exportWallet() {\n"
        "            const password = document.getElementById('exportPassword').value;\n"
        "            if (!password) {\n"
        "                showStatus('exportStatus', 'Please enter a password', 'error');\n"
        "                return;\n"
        "            }\n"
        "            showStatus('exportStatus', 'Exporting wallet with Argon2id encryption...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/export', {\n"
        "                    method: 'POST',\n"
        "                    headers: { 'Content-Type': 'application/json' },\n"
        "                    body: JSON.stringify({ password: password })\n"
        "                });\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    const blob = new Blob([data.encrypted_data], { type: 'text/plain' });\n"
        "                    const url = window.URL.createObjectURL(blob);\n"
        "                    const a = document.createElement('a');\n"
        "                    a.href = url;\n"
        "                    a.download = 'mxd_wallet_' + Date.now() + '.enc';\n"
        "                    a.click();\n"
        "                    window.URL.revokeObjectURL(url);\n"
        "                    showStatus('exportStatus', 'Wallet exported successfully! File downloaded.', 'success');\n"
        "                    document.getElementById('exportPassword').value = '';\n"
        "                } else {\n"
        "                    showStatus('exportStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('exportStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function importWallet() {\n"
        "            const encryptedData = document.getElementById('importData').value;\n"
        "            const password = document.getElementById('importPassword').value;\n"
        "            if (!encryptedData || !password) {\n"
        "                showStatus('importStatus', 'Please provide encrypted data and password', 'error');\n"
        "                return;\n"
        "            }\n"
        "            showStatus('importStatus', 'Importing wallet with Argon2id decryption...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/import', {\n"
        "                    method: 'POST',\n"
        "                    headers: { 'Content-Type': 'application/json' },\n"
        "                    body: JSON.stringify({ encrypted_data: encryptedData, password: password })\n"
        "                });\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    showStatus('importStatus', 'Wallet imported! ' + data.imported + ' addresses added (total: ' + data.total + ')', 'success');\n"
        "                    document.getElementById('importData').value = '';\n"
        "                    document.getElementById('importPassword').value = '';\n"
        "                    listAddresses();\n"
        "                } else {\n"
        "                    showStatus('importStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('importStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function viewHistory() {\n"
        "            try {\n"
        "                const response = await fetch('/wallet/history');\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    let html = '<h3>Transaction History</h3>';\n"
        "                    if (data.transactions.length === 0) {\n"
        "                        html += '<p>No transactions yet</p>';\n"
        "                    } else {\n"
        "                        for (const tx of data.transactions) {\n"
        "                            html += '<div class=\"address-item\"><small>' + tx.txid.substring(0, 16) + '...</small><br>';\n"
        "                            html += 'From: ' + tx.from + '<br>To: ' + tx.to + '<br>Amount: ' + tx.amount + ' MXD</div>';\n"
        "                        }\n"
        "                    }\n"
        "                    showStatus('historyStatus', html, 'info');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('historyStatus', 'Error loading history: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        window.onload = function() {\n"
        "            listAddresses();\n"
        "        };\n"
        "    </script>\n"
        "</body>\n"
        "</html>";
    
    return wallet_html;
}

const char* mxd_handle_wallet_generate_with_algo(uint8_t algo_id) {
    if (!wallet_initialized) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Wallet not initialized\"}");
        return wallet_response_buffer;
    }
    
    if (algo_id != MXD_SIGALG_ED25519 && algo_id != MXD_SIGALG_DILITHIUM5) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid algorithm. Use 'ed25519' or 'dilithium5'\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    if (wallet.keypair_count >= MXD_WALLET_MAX_KEYPAIRS) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Maximum number of addresses reached\"}");
        return wallet_response_buffer;
    }
    
    mxd_wallet_keypair_t* keypair = &wallet.keypairs[wallet.keypair_count];
    
    uint8_t public_key[MXD_PUBKEY_MAX_LEN];
    uint8_t private_key[MXD_PRIVKEY_MAX_LEN];
    char address[64];
    char passphrase[256];
    
    if (mxd_generate_passphrase(passphrase, sizeof(passphrase)) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to generate passphrase\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_sig_keygen(algo_id, public_key, private_key) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to generate keypair\"}");
        return wallet_response_buffer;
    }
    
    size_t pubkey_len = mxd_sig_pubkey_len(algo_id);
    if (mxd_address_to_string(algo_id, public_key, pubkey_len, /*mainnet*/1, address, sizeof(address)) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to generate address\"}");
        return wallet_response_buffer;
    }
    
    size_t privkey_len = mxd_sig_privkey_len(algo_id);
    
    keypair->public_key = (uint8_t*)malloc(pubkey_len);
    keypair->private_key = (uint8_t*)malloc(privkey_len);
    if (!keypair->public_key || !keypair->private_key) {
        if (keypair->public_key) free(keypair->public_key);
        if (keypair->private_key) free(keypair->private_key);
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Memory allocation failed\"}");
        return wallet_response_buffer;
    }
    
    strncpy(keypair->address, address, sizeof(keypair->address) - 1);
    keypair->algo_id = algo_id;
    keypair->public_key_length = (uint16_t)pubkey_len;
    keypair->private_key_length = (uint16_t)privkey_len;
    memcpy(keypair->public_key, public_key, pubkey_len);
    memcpy(keypair->private_key, private_key, privkey_len);
    strncpy(keypair->passphrase, passphrase, sizeof(keypair->passphrase) - 1);
    
    wallet.keypair_count++;
    
    pthread_mutex_unlock(&wallet_mutex);
    
    const char* algo_name = (algo_id == MXD_SIGALG_ED25519) ? "ed25519" : "dilithium5";
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"address\":\"%s\",\"algo\":\"%s\"}", address, algo_name);
    return wallet_response_buffer;
}

const char* mxd_handle_wallet_generate(void) {
    return mxd_handle_wallet_generate_with_algo(MXD_SIGALG_ED25519);
}

const char* mxd_handle_wallet_balance(const char* address) {
    if (!wallet_initialized || !address) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid request\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_validate_address(address) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid address format\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    uint8_t* public_key = NULL;
    uint8_t algo_id = 0;
    uint16_t public_key_length = 0;
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        if (strcmp(wallet.keypairs[i].address, address) == 0) {
            public_key = wallet.keypairs[i].public_key;
            algo_id = wallet.keypairs[i].algo_id;
            public_key_length = wallet.keypairs[i].public_key_length;
            break;
        }
    }
    
    pthread_mutex_unlock(&wallet_mutex);
    
    if (!public_key) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Address not found in wallet\"}");
        return wallet_response_buffer;
    }
    
    uint8_t addr32[MXD_ADDR32_LEN];
    if (mxd_derive_address(algo_id, public_key, public_key_length, addr32) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to derive address\"}");
        return wallet_response_buffer;
    }
    double balance = mxd_get_balance(addr32);

    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"balance\":%.8f}", balance);
    return wallet_response_buffer;
}

const char* mxd_handle_wallet_send(const char* recipient, const char* amount) {
    if (!wallet_initialized || !recipient || !amount) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid request parameters\"}");
        return wallet_response_buffer;
    }
    
    double amount_value = strtod(amount, NULL);
    if (amount_value <= 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid amount\"}");
        return wallet_response_buffer;
    }
    
    // Parse the recipient address to get the 32-byte addr32 per MXD-01 v1.1.x §4
    uint8_t algo_id;
    uint8_t recipient_addr32[32];
    if (mxd_parse_address(recipient, &algo_id, recipient_addr32) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid recipient address\"}");
        return wallet_response_buffer;
    }

    mxd_transaction_t tx;
    if (mxd_create_transaction(&tx) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to create transaction\"}");
        return wallet_response_buffer;
    }

    if (mxd_add_tx_output(&tx, recipient_addr32, (mxd_amount_t)amount_value) != 0) {
        mxd_free_transaction(&tx);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to add transaction output\"}");
        return wallet_response_buffer;
    }
    
    uint8_t tx_hash[64];
    if (mxd_calculate_tx_hash(&tx, tx_hash) != 0) {
        mxd_free_transaction(&tx);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to calculate transaction hash\"}");
        return wallet_response_buffer;
    }
    
    char tx_hash_str[129];
    for (int i = 0; i < 64; i++) {
        snprintf(tx_hash_str + (i * 2), 3, "%02x", tx_hash[i]);
    }
    tx_hash_str[128] = '\0';
    
    mxd_free_transaction(&tx);
    
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"txid\":\"%s\"}", tx_hash_str);
    return wallet_response_buffer;
}

const char* mxd_handle_wallet_list_addresses(void) {
    if (!wallet_initialized) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Wallet not initialized\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "success", 1);
    cJSON* addresses = cJSON_CreateArray();
    
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        cJSON* addr_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(addr_obj, "address", wallet.keypairs[i].address);
        cJSON_AddNumberToObject(addr_obj, "algo_id", wallet.keypairs[i].algo_id);
        cJSON_AddStringToObject(addr_obj, "algo_name", 
            wallet.keypairs[i].algo_id == 1 ? "Ed25519" : "Dilithium5");
        cJSON_AddItemToArray(addresses, addr_obj);
    }
    
    cJSON_AddItemToObject(root, "addresses", addresses);
    
    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    strncpy(wallet_response_buffer, json_str, sizeof(wallet_response_buffer) - 1);
    free(json_str);
    
    pthread_mutex_unlock(&wallet_mutex);
    
    return wallet_response_buffer;
}

int mxd_add_transaction_to_history(const char* txid, const char* from_addr, 
                                    const char* to_addr, mxd_amount_t amount, 
                                    uint64_t timestamp, uint8_t algo_id) {
    if (!txid || !from_addr || !to_addr) {
        return -1;
    }
    
    pthread_mutex_lock(&history_mutex);
    
    if (transaction_history_count >= 1000) {
        memmove(&transaction_history[0], &transaction_history[1], 
                sizeof(mxd_transaction_history_entry_t) * 999);
        transaction_history_count = 999;
    }
    
    mxd_transaction_history_entry_t* entry = &transaction_history[transaction_history_count];
    strncpy(entry->txid, txid, sizeof(entry->txid) - 1);
    strncpy(entry->from_address, from_addr, sizeof(entry->from_address) - 1);
    strncpy(entry->to_address, to_addr, sizeof(entry->to_address) - 1);
    entry->amount = amount;
    entry->timestamp = timestamp;
    entry->algo_id = algo_id;
    strncpy(entry->status, "confirmed", sizeof(entry->status) - 1);
    
    transaction_history_count++;
    
    pthread_mutex_unlock(&history_mutex);
    
    return 0;
}

const char* mxd_handle_wallet_transaction_history(const char* address) {
    if (!wallet_initialized) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Wallet not initialized\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&history_mutex);
    
    cJSON* root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "success", 1);
    cJSON* transactions = cJSON_CreateArray();
    
    for (size_t i = 0; i < transaction_history_count; i++) {
        if (!address || 
            strcmp(transaction_history[i].from_address, address) == 0 ||
            strcmp(transaction_history[i].to_address, address) == 0) {
            
            cJSON* tx_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(tx_obj, "txid", transaction_history[i].txid);
            cJSON_AddStringToObject(tx_obj, "from", transaction_history[i].from_address);
            cJSON_AddStringToObject(tx_obj, "to", transaction_history[i].to_address);
            cJSON_AddNumberToObject(tx_obj, "amount", transaction_history[i].amount);
            cJSON_AddNumberToObject(tx_obj, "timestamp", transaction_history[i].timestamp);
            cJSON_AddNumberToObject(tx_obj, "algo_id", transaction_history[i].algo_id);
            cJSON_AddStringToObject(tx_obj, "status", transaction_history[i].status);
            cJSON_AddItemToArray(transactions, tx_obj);
        }
    }
    
    cJSON_AddItemToObject(root, "transactions", transactions);
    
    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    strncpy(wallet_response_buffer, json_str, sizeof(wallet_response_buffer) - 1);
    free(json_str);
    
    pthread_mutex_unlock(&history_mutex);
    
    return wallet_response_buffer;
}

int mxd_update_hybrid_crypto_metrics(const mxd_hybrid_crypto_metrics_t* metrics) {
    if (!metrics) {
        return -1;
    }
    
    pthread_mutex_lock(&hybrid_metrics_mutex);
    hybrid_metrics = *metrics;
    pthread_mutex_unlock(&hybrid_metrics_mutex);
    
    return 0;
}

const char* mxd_get_hybrid_crypto_metrics_json(void) {
    pthread_mutex_lock(&hybrid_metrics_mutex);
    
    snprintf(hybrid_metrics_buffer, sizeof(hybrid_metrics_buffer),
        "{"
        "\"ed25519_addresses\":%u,"
        "\"dilithium5_addresses\":%u,"
        "\"ed25519_transactions\":%u,"
        "\"dilithium5_transactions\":%u,"
        "\"ed25519_volume\":%lu,"
        "\"dilithium5_volume\":%lu,"
        "\"total_addresses\":%u,"
        "\"total_transactions\":%u,"
        "\"total_volume\":%lu"
        "}",
        hybrid_metrics.ed25519_addresses,
        hybrid_metrics.dilithium5_addresses,
        hybrid_metrics.ed25519_transactions,
        hybrid_metrics.dilithium5_transactions,
        hybrid_metrics.ed25519_volume,
        hybrid_metrics.dilithium5_volume,
        hybrid_metrics.ed25519_addresses + hybrid_metrics.dilithium5_addresses,
        hybrid_metrics.ed25519_transactions + hybrid_metrics.dilithium5_transactions,
        hybrid_metrics.ed25519_volume + hybrid_metrics.dilithium5_volume
    );
    
    pthread_mutex_unlock(&hybrid_metrics_mutex);
    
    return hybrid_metrics_buffer;
}

int mxd_save_wallet_to_file(const char* filepath) {
    if (!wallet_initialized || !filepath) {
        return -1;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    cJSON* root = cJSON_CreateObject();
    cJSON* addresses = cJSON_CreateArray();
    
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        cJSON* addr_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(addr_obj, "address", wallet.keypairs[i].address);
        cJSON_AddNumberToObject(addr_obj, "algo_id", wallet.keypairs[i].algo_id);
        
        char pubkey_hex[MXD_PUBKEY_MAX_LEN * 2 + 1];
        for (size_t j = 0; j < wallet.keypairs[i].public_key_length; j++) {
            snprintf(pubkey_hex + (j * 2), 3, "%02x", wallet.keypairs[i].public_key[j]);
        }
        pubkey_hex[wallet.keypairs[i].public_key_length * 2] = '\0';
        cJSON_AddStringToObject(addr_obj, "public_key", pubkey_hex);
        
        char privkey_hex[MXD_PRIVKEY_MAX_LEN * 2 + 1];
        for (size_t j = 0; j < wallet.keypairs[i].private_key_length; j++) {
            snprintf(privkey_hex + (j * 2), 3, "%02x", wallet.keypairs[i].private_key[j]);
        }
        privkey_hex[wallet.keypairs[i].private_key_length * 2] = '\0';
        cJSON_AddStringToObject(addr_obj, "private_key", privkey_hex);
        
        cJSON_AddStringToObject(addr_obj, "passphrase", wallet.keypairs[i].passphrase);
        
        cJSON_AddItemToArray(addresses, addr_obj);
    }
    
    cJSON_AddItemToObject(root, "addresses", addresses);
    cJSON_AddNumberToObject(root, "version", 2);
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));
    
    char* json_str = cJSON_Print(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_ERROR("wallet", "Failed to serialize wallet to JSON");
        return -2;
    }

    // SECURITY FIX (C-08): Encrypt wallet data using XChaCha20-Poly1305.
    // Key is derived from database_encryption_key via Argon2.
    const mxd_secrets_t *secrets = mxd_get_secrets();
    if (!secrets || secrets->database_encryption_key[0] == '\0') {
        free(json_str);
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_ERROR("wallet", "Cannot save wallet: database_encryption_key not configured");
        return -4;
    }

    // Derive encryption key using Argon2id
    uint8_t wallet_salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(wallet_salt, sizeof(wallet_salt));

    uint8_t enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (crypto_pwhash(enc_key, sizeof(enc_key),
                      secrets->database_encryption_key,
                      strlen(secrets->database_encryption_key),
                      wallet_salt,
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free(json_str);
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_ERROR("wallet", "Key derivation failed for wallet encryption");
        return -5;
    }

    size_t json_len = strlen(json_str);
    size_t ciphertext_len = json_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    uint8_t *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        sodium_memzero(enc_key, sizeof(enc_key));
        free(json_str);
        pthread_mutex_unlock(&wallet_mutex);
        return -1;
    }

    unsigned long long actual_ct_len;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, &actual_ct_len,
        (const uint8_t *)json_str, json_len,
        NULL, 0,  // no additional data
        NULL,     // nsec (unused)
        nonce, enc_key);

    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(json_str, json_len);
    free(json_str);

    // File format: "MXDWv2" (6) || salt (16) || nonce (24) || ciphertext
    static const char wallet_magic[] = "MXDWv2";
    FILE* fp = fopen(filepath, "wb");
    if (!fp) {
        free(ciphertext);
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_ERROR("wallet", "Failed to open wallet file '%s' for writing", filepath);
        return -1;
    }

    int write_ok = 1;
    if (fwrite(wallet_magic, 1, 6, fp) != 6) write_ok = 0;
    if (write_ok && fwrite(wallet_salt, 1, sizeof(wallet_salt), fp) != sizeof(wallet_salt)) write_ok = 0;
    if (write_ok && fwrite(nonce, 1, sizeof(nonce), fp) != sizeof(nonce)) write_ok = 0;
    if (write_ok && fwrite(ciphertext, 1, (size_t)actual_ct_len, fp) != (size_t)actual_ct_len) write_ok = 0;

    if (fflush(fp) != 0) {
        MXD_LOG_WARN("wallet", "fflush failed for '%s'", filepath);
    }

    fclose(fp);
    free(ciphertext);

    if (!write_ok) {
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_ERROR("wallet", "Failed to write encrypted wallet data to '%s'", filepath);
        return -3;
    }
    
    pthread_mutex_unlock(&wallet_mutex);
    
    MXD_LOG_INFO("wallet", "Wallet saved to %s", filepath);
    return 0;
}

int mxd_load_wallet_from_file(const char* filepath) {
    if (!wallet_initialized || !filepath) {
        return -1;
    }

    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        MXD_LOG_ERROR("wallet", "Failed to open wallet file: %s", filepath);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize < 6) {
        fclose(fp);
        MXD_LOG_ERROR("wallet", "Wallet file too small: %s", filepath);
        return -1;
    }

    // Read magic bytes to detect format
    char magic[6];
    if (fread(magic, 1, 6, fp) != 6) {
        fclose(fp);
        return -1;
    }

    char *json_str = NULL;

    if (memcmp(magic, "MXDWv2", 6) == 0) {
        // SECURITY FIX (C-08): Encrypted wallet format
        // Format: "MXDWv2" (6) || salt (16) || nonce (24) || ciphertext
        const size_t header_size = 6 + crypto_pwhash_SALTBYTES +
                                   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if ((size_t)fsize < header_size + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            fclose(fp);
            MXD_LOG_ERROR("wallet", "Encrypted wallet file too small");
            return -1;
        }

        uint8_t wallet_salt[crypto_pwhash_SALTBYTES];
        uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        if (fread(wallet_salt, 1, sizeof(wallet_salt), fp) != sizeof(wallet_salt) ||
            fread(nonce, 1, sizeof(nonce), fp) != sizeof(nonce)) {
            fclose(fp);
            return -1;
        }

        size_t ct_len = (size_t)fsize - header_size;
        uint8_t *ciphertext = malloc(ct_len);
        if (!ciphertext) { fclose(fp); return -1; }

        if (fread(ciphertext, 1, ct_len, fp) != ct_len) {
            free(ciphertext);
            fclose(fp);
            return -1;
        }
        fclose(fp);

        // Derive decryption key
        const mxd_secrets_t *secrets = mxd_get_secrets();
        if (!secrets || secrets->database_encryption_key[0] == '\0') {
            free(ciphertext);
            MXD_LOG_ERROR("wallet", "Cannot load wallet: database_encryption_key not configured");
            return -1;
        }

        uint8_t enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
        if (crypto_pwhash(enc_key, sizeof(enc_key),
                          secrets->database_encryption_key,
                          strlen(secrets->database_encryption_key),
                          wallet_salt,
                          crypto_pwhash_OPSLIMIT_MODERATE,
                          crypto_pwhash_MEMLIMIT_MODERATE,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) {
            free(ciphertext);
            MXD_LOG_ERROR("wallet", "Key derivation failed for wallet decryption");
            return -1;
        }

        size_t plaintext_len = ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        json_str = malloc(plaintext_len + 1);
        if (!json_str) {
            sodium_memzero(enc_key, sizeof(enc_key));
            free(ciphertext);
            return -1;
        }

        unsigned long long actual_pt_len;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                (uint8_t *)json_str, &actual_pt_len,
                NULL, // nsec (unused)
                ciphertext, ct_len,
                NULL, 0, // no additional data
                nonce, enc_key) != 0) {
            sodium_memzero(enc_key, sizeof(enc_key));
            free(ciphertext);
            free(json_str);
            MXD_LOG_ERROR("wallet", "Wallet decryption failed (wrong key or corrupted file)");
            return -1;
        }

        sodium_memzero(enc_key, sizeof(enc_key));
        free(ciphertext);
        json_str[actual_pt_len] = '\0';
    } else {
        // Legacy unencrypted format (plaintext JSON)
        fseek(fp, 0, SEEK_SET);
        json_str = (char*)malloc(fsize + 1);
        if (!json_str) { fclose(fp); return -1; }
        fread(json_str, 1, fsize, fp);
        fclose(fp);
        json_str[fsize] = '\0';
        MXD_LOG_WARN("wallet", "Loaded unencrypted wallet file - will be encrypted on next save");
    }
    
    cJSON* root = cJSON_Parse(json_str);
    free(json_str);
    
    if (!root) {
        MXD_LOG_ERROR("wallet", "Failed to parse wallet JSON");
        return -1;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        if (wallet.keypairs[i].public_key) free(wallet.keypairs[i].public_key);
        if (wallet.keypairs[i].private_key) free(wallet.keypairs[i].private_key);
    }
    memset(&wallet, 0, sizeof(wallet));
    
    cJSON* addresses = cJSON_GetObjectItem(root, "addresses");
    if (addresses && cJSON_IsArray(addresses)) {
        int count = cJSON_GetArraySize(addresses);
        for (int i = 0; i < count && i < 10; i++) {
            cJSON* addr_obj = cJSON_GetArrayItem(addresses, i);
            
            cJSON* address = cJSON_GetObjectItem(addr_obj, "address");
            cJSON* algo_id = cJSON_GetObjectItem(addr_obj, "algo_id");
            cJSON* pubkey = cJSON_GetObjectItem(addr_obj, "public_key");
            cJSON* privkey = cJSON_GetObjectItem(addr_obj, "private_key");
            cJSON* passphrase = cJSON_GetObjectItem(addr_obj, "passphrase");
            
            if (address && algo_id && pubkey && privkey) {
                mxd_wallet_keypair_t* kp = &wallet.keypairs[wallet.keypair_count];
                
                strncpy(kp->address, address->valuestring, sizeof(kp->address) - 1);
                kp->algo_id = (uint8_t)algo_id->valueint;
                
                size_t pubkey_len = strlen(pubkey->valuestring) / 2;
                kp->public_key = (uint8_t*)malloc(pubkey_len);
                kp->public_key_length = (uint16_t)pubkey_len;
                for (size_t j = 0; j < pubkey_len; j++) {
                    sscanf(pubkey->valuestring + (j * 2), "%2hhx", &kp->public_key[j]);
                }
                
                size_t privkey_len = strlen(privkey->valuestring) / 2;
                kp->private_key = (uint8_t*)malloc(privkey_len);
                kp->private_key_length = (uint16_t)privkey_len;
                for (size_t j = 0; j < privkey_len; j++) {
                    sscanf(privkey->valuestring + (j * 2), "%2hhx", &kp->private_key[j]);
                }
                
                if (passphrase && cJSON_IsString(passphrase)) {
                    strncpy(kp->passphrase, passphrase->valuestring, sizeof(kp->passphrase) - 1);
                }
                
                wallet.keypair_count++;
            }
        }
    }
    
    cJSON_Delete(root);
    pthread_mutex_unlock(&wallet_mutex);
    
    MXD_LOG_INFO("wallet", "Wallet loaded from %s with %zu addresses", filepath, wallet.keypair_count);
    return 0;
}

const char* mxd_handle_wallet_export(const char* password) {
    if (!wallet_initialized || !password || strlen(password) == 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid password\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddNumberToObject(root, "keypair_count", wallet.keypair_count);
    cJSON* keypairs = cJSON_CreateArray();
    
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        cJSON* kp = cJSON_CreateObject();
        cJSON_AddNumberToObject(kp, "algo_id", wallet.keypairs[i].algo_id);
        
        char pubkey_hex[MXD_PUBKEY_MAX_LEN * 2 + 1];
        for (size_t j = 0; j < wallet.keypairs[i].public_key_length; j++) {
            snprintf(pubkey_hex + (j * 2), 3, "%02x", wallet.keypairs[i].public_key[j]);
        }
        cJSON_AddStringToObject(kp, "public_key", pubkey_hex);
        
        char privkey_hex[MXD_PRIVKEY_MAX_LEN * 2 + 1];
        for (size_t j = 0; j < wallet.keypairs[i].private_key_length; j++) {
            snprintf(privkey_hex + (j * 2), 3, "%02x", wallet.keypairs[i].private_key[j]);
        }
        cJSON_AddStringToObject(kp, "private_key", privkey_hex);
        cJSON_AddStringToObject(kp, "address", wallet.keypairs[i].address);
        
        cJSON_AddItemToArray(keypairs, kp);
    }
    cJSON_AddItemToObject(root, "keypairs", keypairs);
    
    char* json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    
    if (!json_str) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to serialize wallet\"}");
        return wallet_response_buffer;
    }
    
    size_t json_len = strlen(json_str);
    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));
    
    uint8_t key[crypto_secretbox_KEYBYTES];
    if (mxd_argon2(password, salt, key, sizeof(key)) != 0) {
        free(json_str);
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Key derivation failed\"}");
        return wallet_response_buffer;
    }
    
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    size_t ciphertext_len = crypto_secretbox_MACBYTES + json_len;
    uint8_t* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        free(json_str);
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Memory allocation failed\"}");
        return wallet_response_buffer;
    }
    
    crypto_secretbox_easy(ciphertext, (const uint8_t*)json_str, json_len, nonce, key);
    
    sodium_memzero(key, sizeof(key));
    sodium_memzero(json_str, json_len);
    free(json_str);
    
    size_t encrypted_blob_len = sizeof(salt) + sizeof(nonce) + ciphertext_len;
    uint8_t* encrypted_blob = malloc(encrypted_blob_len);
    if (!encrypted_blob) {
        free(ciphertext);
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Memory allocation failed\"}");
        return wallet_response_buffer;
    }
    
    memcpy(encrypted_blob, salt, sizeof(salt));
    memcpy(encrypted_blob + sizeof(salt), nonce, sizeof(nonce));
    memcpy(encrypted_blob + sizeof(salt) + sizeof(nonce), ciphertext, ciphertext_len);
    free(ciphertext);
    
    size_t b64_len = ((encrypted_blob_len + 2) / 3) * 4 + 1;
    char* base64_output = malloc(b64_len);
    if (!base64_output) {
        free(encrypted_blob);
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Memory allocation failed\"}");
        return wallet_response_buffer;
    }
    
    if (sodium_bin2base64(base64_output, b64_len, encrypted_blob, encrypted_blob_len, 
                          sodium_base64_VARIANT_ORIGINAL) == NULL) {
        free(base64_output);
        free(encrypted_blob);
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Base64 encoding failed\"}");
        return wallet_response_buffer;
    }
    free(encrypted_blob);
    
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"encrypted_data\":\"%s\"}", base64_output);
    free(base64_output);
    
    pthread_mutex_unlock(&wallet_mutex);
    
    MXD_LOG_INFO("wallet", "Wallet exported successfully");
    return wallet_response_buffer;
}

const char* mxd_handle_wallet_import(const char* encrypted_data, const char* password) {
    if (!wallet_initialized || !encrypted_data || !password || strlen(password) == 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid parameters\"}");
        return wallet_response_buffer;
    }
    
    size_t encrypted_blob_len = strlen(encrypted_data) * 3 / 4 + 10;
    uint8_t* encrypted_blob = malloc(encrypted_blob_len);
    if (!encrypted_blob) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Memory allocation failed\"}");
        return wallet_response_buffer;
    }
    
    size_t bin_len;
    if (sodium_base642bin(encrypted_blob, encrypted_blob_len, encrypted_data, strlen(encrypted_data),
                          NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0) {
        free(encrypted_blob);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid base64 data\"}");
        return wallet_response_buffer;
    }
    
    if (bin_len < crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        free(encrypted_blob);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid encrypted data format\"}");
        return wallet_response_buffer;
    }
    
    uint8_t* salt = encrypted_blob;
    uint8_t* nonce = encrypted_blob + crypto_pwhash_SALTBYTES;
    uint8_t* ciphertext = encrypted_blob + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = bin_len - crypto_pwhash_SALTBYTES - crypto_secretbox_NONCEBYTES;
    
    uint8_t key[crypto_secretbox_KEYBYTES];
    if (mxd_argon2(password, salt, key, sizeof(key)) != 0) {
        free(encrypted_blob);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Key derivation failed\"}");
        return wallet_response_buffer;
    }
    
    size_t plaintext_len = ciphertext_len - crypto_secretbox_MACBYTES;
    uint8_t* plaintext = malloc(plaintext_len + 1);
    if (!plaintext) {
        sodium_memzero(key, sizeof(key));
        free(encrypted_blob);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Memory allocation failed\"}");
        return wallet_response_buffer;
    }
    
    if (crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, key) != 0) {
        sodium_memzero(key, sizeof(key));
        free(plaintext);
        free(encrypted_blob);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Decryption failed - wrong password or corrupted data\"}");
        return wallet_response_buffer;
    }
    
    sodium_memzero(key, sizeof(key));
    free(encrypted_blob);
    
    plaintext[plaintext_len] = '\0';
    
    cJSON* root = cJSON_Parse((const char*)plaintext);
    sodium_memzero(plaintext, plaintext_len);
    free(plaintext);
    
    if (!root) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid wallet data format\"}");
        return wallet_response_buffer;
    }
    
    cJSON* version = cJSON_GetObjectItem(root, "version");
    cJSON* keypairs = cJSON_GetObjectItem(root, "keypairs");
    
    if (!version || !cJSON_IsNumber(version) || version->valueint != 1 || 
        !keypairs || !cJSON_IsArray(keypairs)) {
        cJSON_Delete(root);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Unsupported wallet format\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    size_t old_count = wallet.keypair_count;
    int imported_count = 0;
    
    cJSON* kp_item = NULL;
    cJSON_ArrayForEach(kp_item, keypairs) {
        if (wallet.keypair_count >= MXD_WALLET_MAX_KEYPAIRS) {
            MXD_LOG_WARN("wallet", "Maximum keypair limit reached during import");
            break;
        }
        
        cJSON* algo_id = cJSON_GetObjectItem(kp_item, "algo_id");
        cJSON* public_key = cJSON_GetObjectItem(kp_item, "public_key");
        cJSON* private_key = cJSON_GetObjectItem(kp_item, "private_key");
        cJSON* address = cJSON_GetObjectItem(kp_item, "address");
        
        if (!algo_id || !cJSON_IsNumber(algo_id) ||
            !public_key || !cJSON_IsString(public_key) ||
            !private_key || !cJSON_IsString(private_key) ||
            !address || !cJSON_IsString(address)) {
            MXD_LOG_WARN("wallet", "Skipping invalid keypair entry during import");
            continue;
        }
        
        uint8_t kp_algo_id = (uint8_t)algo_id->valueint;
        if (kp_algo_id != MXD_SIGALG_ED25519 && kp_algo_id != MXD_SIGALG_DILITHIUM5) {
            MXD_LOG_WARN("wallet", "Skipping keypair with invalid algo_id: %u", kp_algo_id);
            continue;
        }
        
        const char* pubkey_hex = public_key->valuestring;
        size_t pubkey_hex_len = strlen(pubkey_hex);
        if (pubkey_hex_len % 2 != 0) {
            MXD_LOG_WARN("wallet", "Skipping keypair with odd-length public key hex");
            continue;
        }
        
        const char* privkey_hex = private_key->valuestring;
        size_t privkey_hex_len = strlen(privkey_hex);
        if (privkey_hex_len % 2 != 0) {
            MXD_LOG_WARN("wallet", "Skipping keypair with odd-length private key hex");
            continue;
        }
        
        size_t pub_bytes = pubkey_hex_len / 2;
        size_t priv_bytes = privkey_hex_len / 2;
        
        if (pub_bytes > MXD_PUBKEY_MAX_LEN || priv_bytes > MXD_PRIVKEY_MAX_LEN) {
            MXD_LOG_WARN("wallet", "Skipping keypair with oversized keys (pub: %zu, priv: %zu)", 
                         pub_bytes, priv_bytes);
            continue;
        }
        
        size_t expected_pubkey_len = mxd_sig_pubkey_len(kp_algo_id);
        size_t expected_privkey_len = mxd_sig_privkey_len(kp_algo_id);
        if (pub_bytes != expected_pubkey_len || priv_bytes != expected_privkey_len) {
            MXD_LOG_WARN("wallet", "Skipping keypair with incorrect key lengths for algo %u (expected pub: %zu, priv: %zu, got pub: %zu, priv: %zu)",
                         kp_algo_id, expected_pubkey_len, expected_privkey_len, pub_bytes, priv_bytes);
            continue;
        }
        
        mxd_wallet_keypair_t* new_kp = &wallet.keypairs[wallet.keypair_count];
        new_kp->algo_id = kp_algo_id;
        new_kp->public_key_length = pub_bytes;
        new_kp->private_key_length = priv_bytes;
        
        new_kp->public_key = malloc(pub_bytes);
        new_kp->private_key = malloc(priv_bytes);
        if (!new_kp->public_key || !new_kp->private_key) {
            if (new_kp->public_key) free(new_kp->public_key);
            if (new_kp->private_key) free(new_kp->private_key);
            new_kp->public_key = NULL;
            new_kp->private_key = NULL;
            MXD_LOG_WARN("wallet", "Memory allocation failed for keypair during import");
            continue;
        }
        
        for (size_t i = 0; i < pub_bytes; i++) {
            char byte_str[3] = {pubkey_hex[i*2], pubkey_hex[i*2+1], '\0'};
            new_kp->public_key[i] = (uint8_t)strtol(byte_str, NULL, 16);
        }
        
        for (size_t i = 0; i < priv_bytes; i++) {
            char byte_str[3] = {privkey_hex[i*2], privkey_hex[i*2+1], '\0'};
            new_kp->private_key[i] = (uint8_t)strtol(byte_str, NULL, 16);
        }
        
        strncpy(new_kp->address, address->valuestring, sizeof(new_kp->address) - 1);
        new_kp->address[sizeof(new_kp->address) - 1] = '\0';
        
        wallet.keypair_count++;
        imported_count++;
    }
    
    cJSON_Delete(root);
    
    if (imported_count > 0) {
        if (mxd_save_wallet_to_file(MXD_WALLET_FILE_PATH) != 0) {
            MXD_LOG_WARN("wallet", "Failed to persist imported wallet to disk");
        }
    }
    
    pthread_mutex_unlock(&wallet_mutex);
    
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"imported\":%d,\"total\":%zu}", 
        imported_count, wallet.keypair_count);
    
    MXD_LOG_INFO("wallet", "Imported %d keypairs (total: %zu)", imported_count, wallet.keypair_count);
    return wallet_response_buffer;
}

static void handle_http_request(int client_socket) {
    char buffer[131072];  // 128KB — fits 5-of-5 Dilithium5 bridge_mint (~72 KB JSON+hex)
    size_t total_read = 0;

    // Read initial data (headers + possibly partial body)
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }
    total_read = (size_t)bytes_read;
    buffer[total_read] = '\0';

    // Check Content-Length and read remaining body if needed
    char *cl_header = strstr(buffer, "Content-Length:");
    if (!cl_header) cl_header = strstr(buffer, "content-length:");
    if (cl_header) {
        size_t content_length = (size_t)atol(cl_header + 15);
        char *body_start = strstr(buffer, "\r\n\r\n");
        if (body_start && content_length > 0) {
            body_start += 4;
            size_t header_size = (size_t)(body_start - buffer);
            size_t body_received = total_read - header_size;

            // Keep reading until we have the full body
            while (body_received < content_length && total_read < sizeof(buffer) - 1) {
                bytes_read = recv(client_socket, buffer + total_read, sizeof(buffer) - 1 - total_read, 0);
                if (bytes_read <= 0) break;
                total_read += (size_t)bytes_read;
                body_received += (size_t)bytes_read;
                buffer[total_read] = '\0';
            }
        }
    }
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    if (!check_rate_limit(client_ip)) {
        const char* rate_limit_response = 
            "HTTP/1.1 429 Too Many Requests\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 60\r\n"
            "Retry-After: 60\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{\"error\":\"Rate limit exceeded\",\"retry_after_seconds\":60}";
        send(client_socket, rate_limit_response, strlen(rate_limit_response), 0);
        close(client_socket);
        return;
    }
    
    char method[16], path[256], version[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, version) != 3) {
        close(client_socket);
        return;
    }
    
    // Save the body pointer BEFORE strtok destroys the buffer.
    // 128KB body buffer needed for /bridge/submit with 5-of-5 Dilithium5
    // sigs (~72 KB hex+JSON wrap). AUTHORIZE_BRIDGE with 3-of-5 only needs
    // ~44 KB but bumping once to 128 KB covers both endpoints. Previously
    // 32 KB then 64 KB which truncated /bridge/submit on mainnet launch
    // 2026-05-18 (first deposit at BSC block 99088258 stalled with
    // "Invalid JSON" 400 after coordinator collected 5/5 sigs).
    char* saved_body = strstr(buffer, "\r\n\r\n");
    char body_copy[131072] = {0};
    if (saved_body) {
        saved_body += 4;
        strncpy(body_copy, saved_body, sizeof(body_copy) - 1);
    }
    
    char* auth_header = NULL;
    char* line = strtok(buffer, "\r\n");
    while (line != NULL) {
        if (strncasecmp(line, "Authorization:", 14) == 0) {
            auth_header = line + 14;
            while (*auth_header == ' ') auth_header++;
            break;
        }
        line = strtok(NULL, "\r\n");
    }
    
    const char* response_body = NULL;
    const char* content_type = "text/plain";
    int status_code = 404;
    int is_wallet_endpoint = 0;
    
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/health") == 0) {
            response_body = mxd_get_health_json();
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/metrics") == 0) {
            // Metrics expose internal state (CPU, memory, peers) — require auth
            if (!check_bearer_token(auth_header)) {
                response_body = "{\"error\":\"Authentication required\"}";
                content_type = "application/json";
                status_code = 401;
            } else {
                response_body = mxd_get_prometheus_metrics();
                content_type = "text/plain";
                status_code = 200;
            }
        } else if (strcmp(path, "/wallet") == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                response_body = mxd_get_wallet_html();
                content_type = "text/html";
                status_code = 200;
            }
        } else if (strncmp(path, "/wallet/balance?address=", 24) == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
            char* address = path + 24;
            char decoded_address[256];
            int j = 0;
            for (int i = 0; address[i] && j < sizeof(decoded_address) - 1; i++) {
                if (address[i] == '%' && address[i+1] && address[i+2]) {
                    char hex[3] = {address[i+1], address[i+2], '\0'};
                    decoded_address[j++] = (char)strtol(hex, NULL, 16);
                    i += 2;
                } else {
                    decoded_address[j++] = address[i];
                }
            }
            decoded_address[j] = '\0';
            response_body = mxd_handle_wallet_balance(decoded_address);
            content_type = "application/json";
            status_code = 200;
            }
        } else if (strcmp(path, "/wallet/addresses") == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                response_body = mxd_handle_wallet_list_addresses();
                content_type = "application/json";
                status_code = 200;
            }
        } else if (strncmp(path, "/wallet/history", 15) == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                const char* address = NULL;
                if (strncmp(path, "/wallet/history?address=", 24) == 0) {
                    address = path + 24;
                }
                response_body = mxd_handle_wallet_transaction_history(address);
                content_type = "application/json";
                status_code = 200;
            }
        } else if (strcmp(path, "/metrics/hybrid") == 0) {
            response_body = mxd_get_hybrid_crypto_metrics_json();
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/status") == 0) {
            // Explorer API: Network status
            response_body = mxd_get_status_json();
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/chain_id") == 0) {
            // MXD chain identifier = SHA-256(genesis_block_hash)
            extern int mxd_get_chain_id(uint8_t chain_id[32]);
            static char chain_id_buf[128];
            uint8_t cid[32];
            if (mxd_get_chain_id(cid) == 0) {
                char hex[65] = {0};
                mon_hex_encode(cid, 32, hex); hex[64] = 0;
                snprintf(chain_id_buf, sizeof(chain_id_buf), "{\"chain_id\":\"%s\"}", hex);
            } else {
                snprintf(chain_id_buf, sizeof(chain_id_buf),
                    "{\"chain_id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}");
            }
            response_body = chain_id_buf;
            content_type = "application/json";
            status_code = 200;
        } else if (strncmp(path, "/utxos/", 7) == 0) {
            // List UTXOs for an address (needed for wallet transaction construction).
            // Address is 64 hex chars per MXD-01 v1.1.x addr32.
            const char *addr_hex = path + 7;
            if (strlen(addr_hex) == 64) {
                uint8_t addr32[MXD_ADDR32_LEN];
                for (int i = 0; i < MXD_ADDR32_LEN; i++) {
                    char byte_hex[3] = { addr_hex[i*2], addr_hex[i*2+1], '\0' };
                    addr32[i] = (uint8_t)strtoul(byte_hex, NULL, 16);
                }
                mxd_utxo_t *utxos = NULL;
                size_t utxo_count = 0;
                if (mxd_get_utxos_by_pubkey_hash(addr32, &utxos, &utxo_count) == 0 && utxo_count > 0) {
                    cJSON *root = cJSON_CreateObject();
                    cJSON_AddStringToObject(root, "address", addr_hex);
                    cJSON *arr = cJSON_AddArrayToObject(root, "utxos");
                    for (size_t i = 0; i < utxo_count; i++) {
                        if (utxos[i].is_spent) { mxd_free_utxo(&utxos[i]); continue; }
                        cJSON *u = cJSON_CreateObject();
                        char txh[129] = {0};
                        mon_hex_encode(utxos[i].tx_hash, 64, txh); txh[128] = 0;
                        cJSON_AddStringToObject(u, "tx_hash", txh);
                        cJSON_AddNumberToObject(u, "output_index", utxos[i].output_index);
                        cJSON_AddNumberToObject(u, "amount", (double)utxos[i].amount);
                        cJSON_AddNumberToObject(u, "amount_mxd", (double)utxos[i].amount / 100000000.0);
                        cJSON_AddItemToArray(arr, u);
                        mxd_free_utxo(&utxos[i]);
                    }
                    free(utxos);
                    response_body = cJSON_PrintUnformatted(root);
                    cJSON_Delete(root);
                } else {
                    response_body = strdup("{\"address\":\"" "addr" "\",\"utxos\":[]}");
                    // Build proper response
                    char *buf = malloc(128);
                    snprintf(buf, 128, "{\"address\":\"%s\",\"utxos\":[]}", addr_hex);
                    response_body = buf;
                }
            } else {
                response_body = strdup("{\"error\":\"Invalid address\"}");
            }
            content_type = "application/json";
            status_code = 200;
        } else if (strncmp(path, "/balance/", 9) == 0) {
            // Public balance lookup by hex address (no auth required).
            // Address is 64 hex chars per MXD-01 v1.1.x addr32.
            static char balance_buf[1024];
            const char *addr_hex = path + 9;
            if (strlen(addr_hex) == 64) {
                uint8_t addr32[MXD_ADDR32_LEN];
                for (int i = 0; i < MXD_ADDR32_LEN; i++) {
                    char byte_hex[3] = { addr_hex[i*2], addr_hex[i*2+1], '\0' };
                    addr32[i] = (uint8_t)strtoul(byte_hex, NULL, 16);
                }
                mxd_utxo_t *utxos = NULL;
                size_t utxo_count = 0;
                uint64_t balance = 0;
                size_t unspent_count = 0;
                size_t spent_count = 0;
                uint64_t total_received = 0;
                if (mxd_get_utxos_by_pubkey_hash(addr32, &utxos, &utxo_count) == 0) {
                    for (size_t i = 0; i < utxo_count; i++) {
                        total_received += utxos[i].amount;
                        if (!utxos[i].is_spent) {
                            balance += utxos[i].amount;
                            unspent_count++;
                        } else {
                            spent_count++;
                        }
                        mxd_free_utxo(&utxos[i]);
                    }
                    free(utxos);
                }
                snprintf(balance_buf, sizeof(balance_buf),
                    "{\"address\":\"%s\",\"balance\":%llu,\"balance_mxd\":%.8f,"
                    "\"utxo_count\":%zu,\"unspent_count\":%zu,\"spent_count\":%zu,"
                    "\"total_received\":%llu,\"total_received_mxd\":%.8f,"
                    "\"transaction_count\":%zu}",
                    addr_hex, (unsigned long long)balance, (double)balance / 100000000.0,
                    utxo_count, unspent_count, spent_count,
                    (unsigned long long)total_received, (double)total_received / 100000000.0,
                    utxo_count);
            } else {
                snprintf(balance_buf, sizeof(balance_buf),
                    "{\"error\":\"Invalid address (expected 40 hex chars)\"}");
            }
            response_body = balance_buf;
            content_type = "application/json";
            status_code = 200;
        } else if (strncmp(path, "/block/", 7) == 0) {
            // Explorer API: Get block by height
            uint32_t block_height = (uint32_t)atoi(path + 7);
            response_body = mxd_get_block_json(block_height);
            content_type = "application/json";
            status_code = 200;
        } else if (strncmp(path, "/blocks/latest", 14) == 0) {
            // Explorer API: Get latest blocks
            int limit = 10;
            char* limit_param = strstr(path, "limit=");
            if (limit_param) {
                limit = atoi(limit_param + 6);
            }
            response_body = mxd_get_latest_blocks_json(limit);
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/validators") == 0) {
            // Explorer API: Get rapid stake table validators
            response_body = mxd_get_validators_json();
            content_type = "application/json";
            status_code = 200;
        }
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/bridge/authorize") == 0) {
            // Authorize a bridge contract hash (admin only, requires API token)
            // Body: {"contract_hash": "128 hex chars"}
            extern rocksdb_t* mxd_get_rocksdb_db(void);
            extern rocksdb_writeoptions_t* mxd_get_rocksdb_writeoptions(void);
            if (body_copy[0] != '\0') {
                cJSON *aj = cJSON_Parse(body_copy);
                if (aj) {
                    cJSON *ch = cJSON_GetObjectItem(aj, "contract_hash");
                    if (ch && cJSON_IsString(ch) && strlen(ch->valuestring) == 128) {
                        uint8_t key[76];
                        memcpy(key, "bridge_auth:", 12);
                        // hex decode
                        for (int i = 0; i < 64; i++) {
                            char hex[3] = { ch->valuestring[i*2], ch->valuestring[i*2+1], '\0' };
                            key[12+i] = (uint8_t)strtoul(hex, NULL, 16);
                        }
                        char *err = NULL;
                        rocksdb_put(mxd_get_rocksdb_db(), mxd_get_rocksdb_writeoptions(),
                                    (const char*)key, 76, "1", 1, &err);
                        if (err) {
                            response_body = strdup("{\"error\":\"Database write failed\"}");
                            free(err);
                            status_code = 500;
                        } else {
                            response_body = strdup("{\"success\":true,\"message\":\"Bridge contract authorized\"}");
                            status_code = 200;
                        }
                    } else {
                        response_body = strdup("{\"error\":\"Invalid contract_hash (expected 128 hex chars)\"}");
                        status_code = 400;
                    }
                    cJSON_Delete(aj);
                } else {
                    response_body = strdup("{\"error\":\"Invalid JSON\"}");
                    status_code = 400;
                }
            } else {
                response_body = strdup("{\"error\":\"Empty body\"}");
                status_code = 400;
            }
            content_type = "application/json";
        } else if (strcmp(path, "/transaction") == 0) {
            // Accept pre-signed serialized transactions
            extern char* handle_transaction_submit(const char *post_data, int *status_code);
            if (body_copy[0] != '\0') {
                response_body = handle_transaction_submit(body_copy, &status_code);
                content_type = "application/json";
            } else {
                response_body = strdup("{\"error\":\"Empty request body\"}");
                content_type = "application/json";
                status_code = 400;
            }
        } else if (strcmp(path, "/bridge/submit") == 0) {
            // Forward bridge mint submissions to the HTTP API handler
            extern char* handle_bridge_submit(const char *post_data, int *status_code);
            if (body_copy[0] != '\0') {
                response_body = handle_bridge_submit(body_copy, &status_code);
                content_type = "application/json";
            } else {
                response_body = strdup("{\"error\":\"Empty request body\"}");
                content_type = "application/json";
                status_code = 400;
            }
        } else if (strcmp(path, "/admin/submit") == 0) {
            // Pre-signed admin tx (bridge authorize/revoke or oracle set update)
            // carrying 3-of-5 oracle signatures. Handler is in mxd_http_api.c.
            extern char* handle_admin_submit(const char *post_data, int *status_code);
            if (body_copy[0] != '\0') {
                response_body = handle_admin_submit(body_copy, &status_code);
                content_type = "application/json";
            } else {
                response_body = strdup("{\"error\":\"Empty request body\"}");
                content_type = "application/json";
                status_code = 400;
            }
        } else if (strcmp(path, "/wallet/generate") == 0 || strncmp(path, "/wallet/generate?", 17) == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                uint8_t algo_id = MXD_SIGALG_ED25519;
                if (strncmp(path, "/wallet/generate?algo=", 22) == 0) {
                    char* algo_str = path + 22;
                    if (strncmp(algo_str, "dilithium5", 10) == 0) {
                        algo_id = MXD_SIGALG_DILITHIUM5;
                    } else if (strncmp(algo_str, "ed25519", 7) == 0) {
                        algo_id = MXD_SIGALG_ED25519;
                    }
                }
                response_body = mxd_handle_wallet_generate_with_algo(algo_id);
                content_type = "application/json";
                status_code = 200;
            }
        } else if (strcmp(path, "/wallet/send") == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                if (body_copy[0] != '\0') {
                    cJSON* json = cJSON_Parse(body_copy);
                    if (json) {
                        cJSON* to = cJSON_GetObjectItem(json, "to");
                        cJSON* amount = cJSON_GetObjectItem(json, "amount");
                        if (to && amount && cJSON_IsString(to) && cJSON_IsString(amount)) {
                            response_body = mxd_handle_wallet_send(to->valuestring, amount->valuestring);
                            content_type = "application/json";
                            status_code = 200;
                        }
                        cJSON_Delete(json);
                    }
                }
                if (!response_body) {
                    response_body = "{\"success\":false,\"error\":\"Invalid request body\"}";
                    content_type = "application/json";
                    status_code = 400;
                }
            }
        } else if (strcmp(path, "/wallet/export") == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                if (body_copy[0] != '\0') {
                    cJSON* json = cJSON_Parse(body_copy);
                    if (json) {
                        cJSON* password = cJSON_GetObjectItem(json, "password");
                        if (password && cJSON_IsString(password)) {
                            response_body = mxd_handle_wallet_export(password->valuestring);
                            content_type = "application/json";
                            status_code = 200;
                        }
                        cJSON_Delete(json);
                    }
                }
                if (!response_body) {
                    response_body = "{\"success\":false,\"error\":\"Invalid request body\"}";
                    content_type = "application/json";
                    status_code = 400;
                }
            }
        } else if (strcmp(path, "/wallet/import") == 0) {
            if (!check_wallet_access(auth_header, &response_body, &content_type, &status_code)) {
            } else {
                if (body_copy[0] != '\0') {
                    cJSON* json = cJSON_Parse(body_copy);
                    if (json) {
                        cJSON* encrypted_data = cJSON_GetObjectItem(json, "encrypted_data");
                        cJSON* password = cJSON_GetObjectItem(json, "password");
                        if (encrypted_data && password && cJSON_IsString(encrypted_data) && cJSON_IsString(password)) {
                            response_body = mxd_handle_wallet_import(encrypted_data->valuestring, password->valuestring);
                            content_type = "application/json";
                            status_code = 200;
                        }
                        cJSON_Delete(json);
                    }
                }
                if (!response_body) {
                    response_body = "{\"success\":false,\"error\":\"Invalid request body\"}";
                    content_type = "application/json";
                    status_code = 400;
                }
            }
        }
    }
    
    if (!response_body) {
        response_body = "Not Found";
        status_code = 404;
    }
    
    char response[16384];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "X-XSS-Protection: 1; mode=block\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
        "\r\n"
        "%s",
        status_code,
        status_code == 200 ? "OK" : (status_code == 400 ? "Bad Request" : (status_code == 401 ? "Unauthorized" : (status_code == 403 ? "Forbidden" : (status_code == 429 ? "Too Many Requests" : "Not Found")))),
        content_type,
        strlen(response_body),
        response_body);
    
    send(client_socket, response, response_len, 0);
    close(client_socket);
}

static void* server_thread_func(void* arg) {
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running && errno != EINTR) {
                MXD_LOG_ERROR("monitoring", "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        handle_http_request(client_socket);
    }
    return NULL;
}

int mxd_start_metrics_server(void) {
    if (!monitoring_initialized) {
        return -1;
    }
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        MXD_LOG_WARN("monitoring", "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    
    const char* bind_addr = (global_config && global_config->http.bind_address[0]) 
        ? global_config->http.bind_address : "0.0.0.0";
    
    if (inet_pton(AF_INET, bind_addr, &server_addr.sin_addr) <= 0) {
        MXD_LOG_WARN("monitoring", "Invalid bind address %s, using 0.0.0.0", bind_addr);
        inet_pton(AF_INET, "0.0.0.0", &server_addr.sin_addr);
    }
    
    server_addr.sin_port = htons(metrics_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to bind to port %d: %s", metrics_port, strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    if (listen(server_socket, 5) < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to listen on socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    server_running = 1;
    pthread_attr_t server_attr;
    pthread_attr_init(&server_attr);
    pthread_attr_setstacksize(&server_attr, 512 * 1024); // 512KB stack
    if (pthread_create(&server_thread, &server_attr, server_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("monitoring", "Failed to create server thread: %s", strerror(errno));
        pthread_attr_destroy(&server_attr);
        close(server_socket);
        server_socket = -1;
        server_running = 0;
        return -1;
    }
    pthread_attr_destroy(&server_attr);
    
    MXD_LOG_INFO("monitoring", "Metrics server started on port %d", metrics_port);
    MXD_LOG_INFO("monitoring", "Endpoints: /metrics (Prometheus), /health (JSON)");
    return 0;
}

int mxd_stop_metrics_server(void) {
    if (!monitoring_initialized || !server_running) {
        return -1;
    }
    
    server_running = 0;
    
    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
    
    pthread_join(server_thread, NULL);
    
    MXD_LOG_INFO("monitoring", "Metrics server stopped");
    return 0;
}
