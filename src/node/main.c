#include "../include/mxd_logging.h"
#include "../include/mxd_http_api.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include "../include/mxd_config.h"
#include "../include/mxd_metrics.h"
#include "../include/mxd_dht.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_monitoring.h"
#include "../include/mxd_address.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_ntp.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_mempool.h"
#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_contracts_db.h"
#include "../include/mxd_blockchain_sync.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_serialize.h"
#include "metrics_display.h"
#include "memory_utils.h"

extern void mxd_genesis_message_handler(const char *address, uint16_t port,
                                        mxd_message_type_t type,
                                        const void *payload,
                                        size_t payload_length);

extern void mxd_validation_message_handler(const char *address, uint16_t port,
                                           mxd_message_type_t type,
                                           const void *payload,
                                           size_t payload_length);

// Handle incoming P2P transaction: deserialize and add to local mempool.
// Uses the canonical mxd_deserialize_transaction (per MXD-04 v1.1.x wire format
// with chain_id u32, addr32 outputs, tx_hash[64] broadcast hint, no is_coinbase
// byte). The hand-rolled parser previously here was for the pre-v1.1.x format
// and silently dropped or corrupted every peer-propagated user tx (audit C-1).
static void handle_p2p_transaction(const void *payload, size_t payload_length) {
    if (!payload || payload_length == 0) return;

    mxd_transaction_t tx;
    memset(&tx, 0, sizeof(mxd_transaction_t));

    if (mxd_deserialize_transaction((const uint8_t *)payload, payload_length, &tx) != 0) {
        MXD_LOG_DEBUG("node", "P2P transaction deserialize failed (len=%zu)", payload_length);
        return;
    }

    // Add to local mempool (will silently fail if already present)
    if (mxd_add_to_mempool(&tx, MXD_PRIORITY_MEDIUM) == 0) {
        char hash_hex[17] = {0};
        for (int i = 0; i < 8; i++) snprintf(hash_hex + i*2, 3, "%02x", tx.tx_hash[i]);
        MXD_LOG_DEBUG("node", "Added P2P transaction %s... to mempool", hash_hex);
    }

    mxd_free_transaction(&tx);
}

static void mxd_message_multiplexer(const char *address, uint16_t port,
                                     mxd_message_type_t type,
                                     const void *payload,
                                     size_t payload_length) {
    switch (type) {
        case MXD_MSG_GENESIS_ANNOUNCE:
        case MXD_MSG_GENESIS_SIGN_REQUEST:
        case MXD_MSG_GENESIS_SIGN_RESPONSE:
        case MXD_MSG_GENESIS_SYNC:
            mxd_genesis_message_handler(address, port, type, payload, payload_length);
            break;

        case MXD_MSG_TRANSACTIONS:
            handle_p2p_transaction(payload, payload_length);
            break;

        case MXD_MSG_VALIDATION_SIGNATURE:
        case MXD_MSG_VALIDATION_CHAIN:
        case MXD_MSG_GET_VALIDATION_CHAIN:
        case MXD_MSG_BLOCKS:
        case MXD_MSG_GET_BLOCKS:
        case MXD_MSG_BLOCK_VALIDATION:
            mxd_validation_message_handler(address, port, type, payload, payload_length);
            break;

        default:
            MXD_LOG_WARN("node", "Unhandled message type: %d from %s:%u", type, address, port);
            break;
    }
}

static volatile int keep_running = 1;
static mxd_config_t current_config;
static mxd_node_metrics_t node_metrics;
static mxd_node_stake_t node_stake;
static mxd_rapid_table_t rapid_table;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

// Accessor function for rapid table (used by HTTP API)
const mxd_rapid_table_t* mxd_get_rapid_table(void) {
    return &rapid_table;
}
static int genesis_initialized = 0;
static uint64_t last_genesis_announce = 0;
static volatile int consensus_running = 1;
static volatile int rapid_table_ready = 0;  // Set after rapid table rebuild from genesis
static uint8_t node_algo_id = 0;
static uint8_t node_pubkey[MXD_PUBKEY_MAX_LEN] = {0};
static uint8_t node_privkey[MXD_PRIVKEY_MAX_LEN] = {0};
static uint8_t node_address[MXD_ADDR32_LEN] = {0};  // widened to 32 bytes (Task 3.2)

void handle_signal(int signum) {
    (void)signum;
    // Only set the flag — do NOT call pthread_join, malloc, or logging
    // from a signal handler (not async-signal-safe, causes deadlocks).
    // The main loop checks keep_running and runs cleanup on exit.
    keep_running = 0;
    consensus_running = 0;
}

static void *consensus_thread_func(void *arg) {
    (void)arg;
    // Reconcile validation chains once every ~30s (150 ticks * 200ms).
    // Catches up nodes that fell behind on validation_chain gossip — see
    // mxd_reconcile_validation_chains.
    uint32_t reconcile_counter = 0;
    while (consensus_running && keep_running) {
        uint32_t blockchain_height = 0;
        mxd_get_blockchain_height(&blockchain_height);

        if (genesis_initialized && blockchain_height > 0 && rapid_table_ready) {
            pthread_mutex_lock(&metrics_mutex);
            int tick_result = mxd_consensus_tick(&rapid_table, node_address,
                                                  node_pubkey, node_privkey, node_algo_id);
            pthread_mutex_unlock(&metrics_mutex);

            if (tick_result == 1) {
                MXD_LOG_INFO("node", "Block finalized by consensus tick");
            }

            if (++reconcile_counter >= 150) {
                reconcile_counter = 0;
                mxd_reconcile_validation_chains(20);
            }
        }

        usleep(200000);  // 200ms — consensus tick fires ~5x/second
    }
    return NULL;
}

/* ======================================================================
 * Phase 4 — Auto-JOIN trigger.
 *
 * Periodically checks whether this node should submit a validator JOIN
 * request. Triggers iff ALL of the following hold:
 *   - chain is past genesis (blockchain_height >= 1)
 *   - rapid_table is initialized and ready
 *   - self is NOT in the active validator set
 *   - on-chain balance for self_addr >= total_supply / 1000 (0.10 % stake)
 *
 * On match: calls mxd_submit_validator_join_request which signs the 52-byte
 * canonical message, adds to the local request pool, and broadcasts via
 * MXD_MSG_VALIDATOR_JOIN_REQUEST (the Phase 1+2 P2P plumbing). The pool
 * already feeds the block proposer at mxd_rsc.c, so once any proposer
 * receives the gossip the JOIN will land in rapid_membership_entries of
 * its next proposed block.
 *
 * Anti-spam: after a successful submission we set submitted_at to suppress
 * repeated submissions until either (a) we observe ourselves in the active
 * set (success) or (b) 5 minutes elapse (the timestamp window enforced by
 * mxd_validate_join_request, after which the original signature expires
 * and re-submission is required).
 * ====================================================================== */

#include "../../include/mxd_validator_management.h"
#include "../include/mxd_protocol_version.h"
#include "../../include/mxd_utxo.h"

static int auto_join_running = 1;

static void *auto_join_thread_func(void *arg) {
    (void)arg;
    uint64_t last_submit_ms = 0;
    /* Brief warm-up: wait for the node to settle (sync from peers, finalize
     * the genesis block locally, initialize the rapid table). 30 seconds
     * is generous — the consensus thread typically converges much faster. */
    sleep(30);
    while (auto_join_running && keep_running) {
        sleep(60); /* 60s polling cadence */

        uint32_t blockchain_height = 0;
        mxd_get_blockchain_height(&blockchain_height);
        if (blockchain_height < 1 || !rapid_table_ready) continue;

        /* Skip if our addr32 is all-zero — the node-keys load failed earlier
         * and there is nothing to sign with. */
        uint8_t zero[32] = {0};
        if (memcmp(node_address, zero, 32) == 0) continue;

        /* Already in the active set? */
        pthread_mutex_lock(&metrics_mutex);
        int in_set = 0;
        for (size_t i = 0; i < rapid_table.count; i++) {
            if (rapid_table.nodes[i] &&
                memcmp(rapid_table.nodes[i]->node_address, node_address, 32) == 0) {
                in_set = 1; break;
            }
        }
        pthread_mutex_unlock(&metrics_mutex);
        if (in_set) {
            /* Stable state — already a validator. Reset the JOIN cooldown so
             * a future drop-out can retry quickly. */
            last_submit_ms = 0;

            /* v8+: while we're in the set, scan OTHER validators for ones
             * whose balance has fallen below the §4.4 stake threshold and
             * sign+broadcast an EVICT. This is the auto-EVICT trigger,
             * integrated into the proven-working auto-join thread instead of
             * a separate thread. Gated on v8 activation. */
            if (mxd_get_required_protocol_version(blockchain_height,
                                                  mxd_get_network_type()) >= MXD_PROTOCOL_VERSION_8) {
                mxd_block_t lb = {0};
                if (mxd_retrieve_block_by_height(blockchain_height - 1, &lb) == 0) {
                    mxd_amount_t s = lb.total_supply;
                    mxd_free_block(&lb);
                    if (s > 0) {
                        mxd_amount_t threshold = s / 1000ULL;
                        /* Snapshot OTHER validators' addr32 under lock. */
                        uint8_t targets[64][32];
                        size_t tc = 0;
                        pthread_mutex_lock(&metrics_mutex);
                        for (size_t k = 0; k < rapid_table.count && tc < 64; k++) {
                            if (!rapid_table.nodes[k]) continue;
                            if (memcmp(rapid_table.nodes[k]->node_address, node_address, 32) == 0) continue;
                            memcpy(targets[tc++], rapid_table.nodes[k]->node_address, 32);
                        }
                        pthread_mutex_unlock(&metrics_mutex);
                        size_t pkl = mxd_sig_pubkey_len(node_algo_id);
                        for (size_t k = 0; k < tc; k++) {
                            mxd_amount_t bal = mxd_get_balance(targets[k]);
                            if (bal >= threshold) continue;
                            MXD_LOG_INFO("auto-evict",
                                         "Submitting EVICT for target %02x%02x..%02x%02x (balance %llu < threshold %llu)",
                                         targets[k][0], targets[k][1], targets[k][30], targets[k][31],
                                         (unsigned long long)bal, (unsigned long long)threshold);
                            mxd_submit_validator_evict_with_pubkey(targets[k], node_address,
                                                                    node_algo_id, node_pubkey,
                                                                    (uint16_t)pkl, node_privkey);
                        }
                    }
                }
            }
            continue;
        }

        /* Cooldown: don't resubmit within the 5-min signature-validity window. */
        uint64_t now_ms = mxd_now_ms();
        if (last_submit_ms != 0 && (now_ms - last_submit_ms) < 300000ULL) continue;

        /* Look up current total_supply by reading the latest finalized block. */
        mxd_block_t latest_block = {0};
        if (mxd_retrieve_block_by_height(blockchain_height - 1, &latest_block) != 0) {
            /* Brand-new chain may not have blocks yet; retry next tick. */
            continue;
        }
        mxd_amount_t supply = latest_block.total_supply;
        mxd_free_block(&latest_block);
        if (supply == 0) continue;

        /* Stake check: balance must meet 0.10 % of total_supply. */
        mxd_amount_t my_balance = mxd_get_balance(node_address);
        mxd_amount_t threshold = supply / 1000ULL;
        if (my_balance < threshold) {
            MXD_LOG_INFO("auto-join",
                         "Skipping JOIN: balance %llu < threshold %llu (0.10%% of supply %llu)",
                         (unsigned long long)my_balance,
                         (unsigned long long)threshold,
                         (unsigned long long)supply);
            continue;
        }

        /* Eligible — submit. */
        size_t pk_len = mxd_sig_pubkey_len(node_algo_id);
        MXD_LOG_INFO("auto-join",
                     "Submitting validator JOIN (balance %llu MXD-base, threshold %llu, supply %llu)",
                     (unsigned long long)my_balance,
                     (unsigned long long)threshold,
                     (unsigned long long)supply);
        if (mxd_submit_validator_join_request(node_address, node_pubkey,
                                              (uint16_t)pk_len, node_algo_id,
                                              node_privkey) == 0) {
            last_submit_ms = now_ms;
        }
    }
    return NULL;
}

/* v8+: auto-EVICT trigger thread. Each active validator scans every OTHER
 * validator in the rapid_table; if any has balance < total_supply/1000, sign
 * and broadcast an EVICT request. Cadence + warm-up mirror the JOIN thread
 * (60s poll, 30s warm-up). Per-(evictor, target) 5-min cooldown to avoid
 * spamming the gossip layer with the same EVICT every tick. */
static int auto_evict_running = 1;
static pthread_t auto_evict_tid;

#define MAX_EVICT_COOLDOWN_ENTRIES 64
typedef struct {
    uint8_t target_addr[32];
    uint64_t last_submit_ms;
} auto_evict_cooldown_t;

static void *auto_evict_thread_func(void *arg) {
    (void)arg;
    auto_evict_cooldown_t cooldowns[MAX_EVICT_COOLDOWN_ENTRIES];
    memset(cooldowns, 0, sizeof(cooldowns));
    size_t cooldown_count = 0;

    sleep(30);  /* warm-up */
    while (auto_evict_running && keep_running) {
        sleep(60);

        uint32_t blockchain_height = 0;
        mxd_get_blockchain_height(&blockchain_height);
        if (blockchain_height < 1 || !rapid_table_ready) continue;

        /* v8 activation gate */
        if (mxd_get_required_protocol_version(blockchain_height,
                                              mxd_get_network_type()) < MXD_PROTOCOL_VERSION_8) {
            continue;
        }

        /* Local node must be an active validator to submit EVICTs. */
        uint8_t zero[32] = {0};
        if (memcmp(node_address, zero, 32) == 0) continue;
        pthread_mutex_lock(&metrics_mutex);
        int local_in_set = 0;
        for (size_t i = 0; i < rapid_table.count; i++) {
            if (rapid_table.nodes[i] &&
                memcmp(rapid_table.nodes[i]->node_address, node_address, 32) == 0) {
                local_in_set = 1; break;
            }
        }
        pthread_mutex_unlock(&metrics_mutex);
        if (!local_in_set) continue;

        /* Read total_supply from latest finalized block. */
        mxd_block_t latest_block = {0};
        if (mxd_retrieve_block_by_height(blockchain_height - 1, &latest_block) != 0) {
            continue;
        }
        mxd_amount_t supply = latest_block.total_supply;
        mxd_free_block(&latest_block);
        if (supply == 0) continue;
        mxd_amount_t threshold = supply / 1000ULL;

        /* Snapshot the addresses to inspect (under lock) then release. */
        uint8_t targets[64][32];
        size_t target_count = 0;
        pthread_mutex_lock(&metrics_mutex);
        for (size_t i = 0; i < rapid_table.count && target_count < 64; i++) {
            if (!rapid_table.nodes[i]) continue;
            /* Skip self — graceful self-EVICT is allowed via the API but the
             * auto-trigger only acts on OTHERS, so a validator with a
             * fluctuating balance doesn't accidentally evict itself. */
            if (memcmp(rapid_table.nodes[i]->node_address, node_address, 32) == 0) continue;
            memcpy(targets[target_count++], rapid_table.nodes[i]->node_address, 32);
        }
        pthread_mutex_unlock(&metrics_mutex);

        uint64_t now_ms = mxd_now_ms();
        size_t pk_len = mxd_sig_pubkey_len(node_algo_id);
        for (size_t i = 0; i < target_count; i++) {
            mxd_amount_t target_balance = mxd_get_balance(targets[i]);
            if (target_balance >= threshold) continue;

            /* Per-target cooldown. */
            int skip = 0;
            for (size_t j = 0; j < cooldown_count; j++) {
                if (memcmp(cooldowns[j].target_addr, targets[i], 32) == 0) {
                    if (now_ms - cooldowns[j].last_submit_ms < 300000ULL) {
                        skip = 1;
                    } else {
                        cooldowns[j].last_submit_ms = now_ms;
                    }
                    break;
                }
            }
            if (skip) continue;
            if (cooldown_count < MAX_EVICT_COOLDOWN_ENTRIES) {
                memcpy(cooldowns[cooldown_count].target_addr, targets[i], 32);
                cooldowns[cooldown_count].last_submit_ms = now_ms;
                cooldown_count++;
            }

            MXD_LOG_INFO("auto-evict",
                         "Submitting EVICT for target %02x%02x...%02x%02x (balance %llu < threshold %llu)",
                         targets[i][0], targets[i][1], targets[i][30], targets[i][31],
                         (unsigned long long)target_balance, (unsigned long long)threshold);
            mxd_submit_validator_evict_with_pubkey(targets[i], node_address, node_algo_id,
                                                    node_pubkey, (uint16_t)pk_len, node_privkey);
        }
    }
    return NULL;
}

void* upnp_nat_thread(void* arg) {
    MXD_LOG_INFO("node", "Starting UPnP NAT traversal in background thread...");
    if (mxd_dht_enable_nat_traversal() == 0) {
        MXD_LOG_INFO("node", "UPnP NAT traversal enabled successfully");
    } else {
        MXD_LOG_INFO("node", "UPnP NAT traversal failed, node may not accept incoming connections through NAT");
    }
    return NULL;
}

void* metrics_collector(void* arg) {
    uint64_t consecutive_errors = 0;
    uint64_t last_success_time = time(NULL);
    
    while (keep_running) {
        uint64_t current_time = time(NULL);
        uint64_t response_time = mxd_get_network_latency();
        
        // Update peer count
        size_t peer_count = MXD_MAX_PEERS;
        mxd_peer_t peers[MXD_MAX_PEERS];
        
        int should_warn_errors = 0;
        int should_warn_tps = 0;
        double tps_value = 0.0;
        uint64_t error_count_snapshot = 0;
        
        pthread_mutex_lock(&metrics_mutex);
        
        if (mxd_get_peers(peers, &peer_count) == 0) {
            node_metrics.peer_count = peer_count;
        }
        
        if (response_time < 3000) {  // Performance requirement: latency < 3s
            mxd_update_metrics(&node_metrics, response_time);
            consecutive_errors = 0;
            last_success_time = current_time;
            
            // Record successful message
            mxd_record_message_result(&node_metrics, 1);
        } else {
            consecutive_errors++;
            if (consecutive_errors > 10) {  // Performance requirement: max 10 consecutive errors
                should_warn_errors = 1;
                error_count_snapshot = consecutive_errors;
            }
            // Record failed message
            mxd_record_message_result(&node_metrics, 0);
        }
        
        // Update stake info
        node_stake.metrics = node_metrics;
        node_stake.stake_amount = current_config.initial_stake;
        strncpy(node_stake.node_id, current_config.node_id, sizeof(node_stake.node_id) - 1);
        
        // Calculate TPS
        double time_diff = (double)(current_time - last_success_time);
        if (time_diff > 0) {
            double tps = node_metrics.message_success / time_diff;
            if (tps < 10.0) {  // Performance requirement: ≥10 TPS
                should_warn_tps = 1;
                tps_value = tps;
            }
        }
        
        pthread_mutex_unlock(&metrics_mutex);
        
        if (should_warn_errors) {
            MXD_LOG_WARN("node", "High consecutive error count: %lu", error_count_snapshot);
        }
        if (should_warn_tps) {
            MXD_LOG_WARN("node", "Low TPS: %.2f", tps_value);
        }
        
        usleep(current_config.metrics_interval * 1000);  // Convert ms to μs
    }
    return NULL;
}

int main(int argc, char** argv) {
    // Initialize logging with console output enabled
    mxd_log_config_t log_config = {
        .level = MXD_LOG_INFO,
        .output_file = NULL,
        .enable_console = 1,
        .enable_json = 0
    };
    mxd_init_logging(&log_config);
    
    MXD_LOG_INFO("node", "MXD Node starting...");
    
    #ifdef GIT_COMMIT_HASH
    MXD_LOG_INFO("node", "Build version: %s", GIT_COMMIT_HASH);
    #else
    MXD_LOG_INFO("node", "Build version: unknown (GIT_COMMIT_HASH not defined)");
    #endif
    
    log_memory_usage("startup");
    
    char default_config_path[PATH_MAX];
    const char* config_path = NULL;
    uint16_t override_port = 0;
    uint16_t http_api_port = 0;
    int is_bootstrap = 0;
    uint8_t override_algo_id = 0;
    int algo_specified = 0;
    
    // Handle command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            int port = atoi(argv[++i]);
            if (port < 1024 || port > 65535) {
                MXD_LOG_ERROR("node", "Port must be between 1024 and 65535");
                return 1;
            }
            override_port = (uint16_t)port;
        } else if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
            const char* algo_name = argv[++i];
            if (strcmp(algo_name, "ed25519") == 0) {
                override_algo_id = MXD_SIGALG_ED25519;
                algo_specified = 1;
                MXD_LOG_INFO("node", "Using Ed25519 signature algorithm");
            } else if (strcmp(algo_name, "dilithium5") == 0) {
                override_algo_id = MXD_SIGALG_DILITHIUM5;
                algo_specified = 1;
                MXD_LOG_INFO("node", "Using Dilithium5 signature algorithm");
            } else {
                MXD_LOG_ERROR("node", "Invalid algorithm: %s (must be 'ed25519' or 'dilithium5')", algo_name);
                return 1;
            }
        } else if (strcmp(argv[i], "--bootstrap") == 0) {
            is_bootstrap = 1;
            MXD_LOG_INFO("node", "Running in bootstrap mode");
        } else if (strcmp(argv[i], "--http-api") == 0 && i + 1 < argc) {
            int port = atoi(argv[++i]);
            if (port < 1024 || port > 65535) {
                MXD_LOG_ERROR("node", "HTTP API port must be between 1024 and 65535");
                return 1;
            }
            http_api_port = (uint16_t)port;
            MXD_LOG_INFO("node", "HTTP API will be enabled on port %d", http_api_port);
        } else if (argv[i][0] != '-' && !config_path) {
            config_path = argv[i];
        } else {
            MXD_LOG_ERROR("node", "Usage: %s [config_file] [--config <file>] [--port <number>] [--algo <ed25519|dilithium5>] [--bootstrap] [--http-api <port>]", argv[0]);
            return 1;
        }
    }
    
    // Set default config path if not specified
    if (!config_path) {
        // Get the directory of the executable
        char* last_slash = strrchr(argv[0], '/');
        if (last_slash != NULL) {
            size_t dir_length = last_slash - argv[0] + 1;
            strncpy(default_config_path, argv[0], dir_length);
            default_config_path[dir_length] = '\0';
            strncat(default_config_path, "default_config.json", 
                    PATH_MAX - strlen(default_config_path) - 1);
        } else {
            strncpy(default_config_path, "./default_config.json", PATH_MAX - 1);
            default_config_path[PATH_MAX - 1] = '\0';
        }
        config_path = default_config_path;
        MXD_LOG_INFO("node", "No config file specified, using default configuration: %s", config_path);
    }

    // Set up signal handlers using sigaction (without SA_RESTART so that
    // sleep/usleep are interrupted, allowing prompt shutdown)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // No SA_RESTART — sleep/accept/read get interrupted
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
    
    // Load configuration
    MXD_LOG_INFO("node", "Loading configuration from: %s", config_path);
    if (mxd_load_config(config_path, &current_config) != 0) {
        MXD_LOG_ERROR("node", "Failed to load configuration from %s", config_path);
        return 1;
    }
    MXD_LOG_INFO("node", "Configuration loaded successfully");

    // Set global config pointer so mxd_get_config() works for genesis creation
    mxd_set_global_config(&current_config);

    log_memory_usage("after_config");

    memset(&node_stake, 0, sizeof(node_stake));
    strncpy(node_stake.node_id, current_config.node_id, sizeof(node_stake.node_id) - 1);
    node_stake.stake_amount = current_config.initial_stake;
    node_stake.active = 0;
    node_stake.rank = 0;
    
    // Override port if specified on command line
    if (override_port > 0) {
        current_config.port = override_port;
        MXD_LOG_INFO("node", "Port overridden from command line: %d", override_port);
    }
    
    // Initialize metrics
    MXD_LOG_INFO("node", "Initializing metrics...");
    if (mxd_init_metrics(&node_metrics) != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize metrics");
        return 1;
    }
    MXD_LOG_INFO("node", "Metrics initialized successfully");
    log_memory_usage("after_metrics");
    
    MXD_LOG_INFO("node", "Initializing rapid table...");
    if (mxd_init_rapid_table(&rapid_table, 100) != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize rapid table");
        return 1;
    }
    MXD_LOG_INFO("node", "Rapid table initialized successfully");
    log_memory_usage("after_rapid_table");
    
    // Ensure data directory exists before initializing databases
    struct stat st = {0};
    if (stat(current_config.data_dir, &st) == -1) {
        MXD_LOG_INFO("node", "Creating data directory: %s", current_config.data_dir);
        if (mkdir(current_config.data_dir, 0755) == -1) {
            MXD_LOG_ERROR("node", "Failed to create data directory %s: %s", 
                         current_config.data_dir, strerror(errno));
            return 1;
        }
    }
    
    // Initialize UTXO database (required before monitoring/wallet initialization)
    MXD_LOG_INFO("node", "Initializing UTXO database...");
    char utxo_db_path[PATH_MAX];
    snprintf(utxo_db_path, sizeof(utxo_db_path), "%s/utxo.db", current_config.data_dir);
    if (mxd_init_utxo_db(utxo_db_path) != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize UTXO database at %s", utxo_db_path);
        return 1;
    }
    MXD_LOG_INFO("node", "UTXO database initialized successfully");
    log_memory_usage("after_utxo_db");

    // Initialize transaction validation (gates mxd_validate_transaction's early check).
    // Depends on UTXO DB being ready, so must come after mxd_init_utxo_db.
    if (mxd_init_transaction_validation() != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize transaction validation");
        return 1;
    }
    MXD_LOG_INFO("node", "Transaction validation initialized successfully");

    // Initialize contracts database
    MXD_LOG_INFO("node", "Initializing contracts system...");
    if (mxd_init_contracts() != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize contracts system");
        return 1;
    }
    MXD_LOG_INFO("node", "Contracts system initialized successfully");
    log_memory_usage("after_contracts");

    // Initialize mempool
    MXD_LOG_INFO("node", "Initializing mempool...");
    if (mxd_init_mempool() != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize mempool");
        return 1;
    }
    MXD_LOG_INFO("node", "Mempool initialized successfully");
    log_memory_usage("after_mempool");

    // Initialize monitoring system
    MXD_LOG_INFO("node", "Initializing monitoring system on port %d...", current_config.metrics_port);
    if (mxd_init_monitoring(current_config.metrics_port) != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize monitoring");
        return 1;
    }
    MXD_LOG_INFO("node", "Monitoring system initialized successfully");
    log_memory_usage("after_monitoring");
    
    // Start metrics server
    if (mxd_start_metrics_server() != 0) {
        MXD_LOG_ERROR("node", "Failed to start metrics server");
        mxd_cleanup_monitoring();
        return 1;
    }
    
    // Display initial peer count
    size_t peer_count = MXD_MAX_PEERS;
    mxd_peer_t peers[MXD_MAX_PEERS];
    if (mxd_get_peers(peers, &peer_count) == 0) {
        MXD_LOG_INFO("node", "Connected peers: %zu", peer_count);
    }
    
    // Initialize DHT node
    log_memory_usage("before_dht_init");
    if (mxd_init_node(&current_config) != 0) {
        MXD_LOG_ERROR("node", "Failed to initialize DHT node");
        return 1;
    }
    log_memory_usage("after_dht_init");
    
    // Register message handler BEFORE starting DHT to ensure all messages are handled
    mxd_set_message_handler(mxd_message_multiplexer);
    MXD_LOG_INFO("node", "Message multiplexer registered (genesis + validation handlers)");
    
    // Start DHT service
    if (mxd_start_dht(current_config.port) != 0) {
        MXD_LOG_ERROR("node", "Failed to start DHT service");
        return 1;
    }
    log_memory_usage("after_dht_start");
    
    // Start metrics collector thread BEFORE UPnP to ensure display loop runs
    pthread_t collector_thread;
    pthread_attr_t collector_attr;
    pthread_attr_init(&collector_attr);
    pthread_attr_setstacksize(&collector_attr, 512 * 1024); // 512KB stack (reduced from 8MB default)
    if (pthread_create(&collector_thread, &collector_attr, metrics_collector, NULL) != 0) {
        MXD_LOG_ERROR("node", "Failed to start metrics collector");
        pthread_attr_destroy(&collector_attr);
        mxd_stop_dht();
        return 1;
    }
    pthread_attr_destroy(&collector_attr);
    MXD_LOG_INFO("node", "Metrics collector thread started");
    
    if (current_config.enable_upnp) {
        pthread_t nat_thread;
        pthread_attr_t nat_attr;
        pthread_attr_init(&nat_attr);
        pthread_attr_setstacksize(&nat_attr, 512 * 1024); // 512KB stack
        if (pthread_create(&nat_thread, &nat_attr, upnp_nat_thread, NULL) == 0) {
            pthread_detach(nat_thread);
            pthread_attr_destroy(&nat_attr);
            MXD_LOG_INFO("node", "UPnP NAT traversal thread started in background");
        } else {
            pthread_attr_destroy(&nat_attr);
            MXD_LOG_WARN("node", "Failed to start UPnP NAT traversal thread");
        }
    } else {
        MXD_LOG_INFO("node", "UPnP disabled in configuration");
    }
    
    if (is_bootstrap) {
        MXD_LOG_INFO("node", "Attempting to register as bootstrap node...");
        if (mxd_register_bootstrap_node(&current_config) == 0) {
            MXD_LOG_INFO("node", "Successfully registered as bootstrap node");
        } else {
            MXD_LOG_ERROR("node", "Failed to register as bootstrap node, terminating");
            mxd_stop_metrics_server();
            mxd_cleanup_monitoring();
            mxd_stop_dht();
            return 1;
        }
    }
    
    // Check for HTTP API port from environment variable if not specified on command line
    if (http_api_port == 0) {
        const char *env_port = getenv("MXD_HTTP_API_PORT");
        if (env_port) {
            int port = atoi(env_port);
            if (port >= 1024 && port <= 65535) {
                http_api_port = (uint16_t)port;
                MXD_LOG_INFO("node", "HTTP API port from environment: %d", http_api_port);
            }
        }
    }
    
    // Start HTTP API server if port is specified
    if (http_api_port > 0) {
        if (mxd_http_api_start(http_api_port) == 0) {
            MXD_LOG_INFO("node", "HTTP API server started on port %d", http_api_port);
        } else {
            MXD_LOG_WARN("node", "Failed to start HTTP API server on port %d", http_api_port);
        }
    }
    
    // Get the actual node algo_id from P2P (based on persisted keys)
    node_algo_id = MXD_SIGALG_ED25519; // Default fallback
    if (mxd_get_node_algo_id(&node_algo_id) != 0) {
        MXD_LOG_WARN("node", "Failed to retrieve node algo_id from P2P, using default Ed25519");
    }
    
    uint8_t requested_algo_id = algo_specified ? override_algo_id : 
                                 (current_config.preferred_sign_algo ? current_config.preferred_sign_algo : MXD_SIGALG_ED25519);
    
    if (requested_algo_id != node_algo_id) {
        MXD_LOG_WARN("node", "CLI/config requested %s but persisted node keys are %s", 
                     mxd_sig_alg_name(requested_algo_id), mxd_sig_alg_name(node_algo_id));
        MXD_LOG_WARN("node", "Using persisted algo_id %s. To change, delete data/node_keypair.bin and restart", 
                     mxd_sig_alg_name(node_algo_id));
    }
    
    MXD_LOG_INFO("node", "Using signature algorithm: %s (from persisted keys)", 
                 mxd_sig_alg_name(node_algo_id));
    
    memset(node_pubkey, 0, sizeof(node_pubkey));
    memset(node_privkey, 0, sizeof(node_privkey));
    memset(node_address, 0, sizeof(node_address));

    if (mxd_get_node_keys(node_pubkey, node_privkey) == 0) {
        size_t pubkey_len = mxd_sig_pubkey_len(node_algo_id);
        if (mxd_derive_address(node_algo_id, node_pubkey, pubkey_len, node_address) == 0) {
            char address_str[64] = {0};
            if (mxd_address_to_string(node_algo_id, node_pubkey, pubkey_len, /*mainnet*/1, address_str, sizeof(address_str)) == 0) {
                MXD_LOG_INFO("node", "Genesis coordination initialized with node address: %s (algo=%s)", 
                             address_str, mxd_sig_alg_name(node_algo_id));
            }
            
            if (mxd_init_genesis_coordination(node_address, node_pubkey, node_privkey, node_algo_id) == 0) {
                genesis_initialized = 1;
            } else {
                MXD_LOG_WARN("node", "Failed to initialize genesis coordination");
            }
        } else {
            MXD_LOG_WARN("node", "Failed to derive node address from public key");
        }
    } else {
        MXD_LOG_WARN("node", "Failed to retrieve node keys from P2P");
    }
    
    // Start dedicated consensus thread — runs mxd_consensus_tick() at ~5Hz
    // independent of the display loop and slow sync operations
    pthread_t consensus_tid;
    if (pthread_create(&consensus_tid, NULL, consensus_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("node", "Failed to start consensus thread");
        return 1;
    }
    MXD_LOG_INFO("node", "Consensus thread started (200ms tick interval)");

    // Phase 4 — Auto-JOIN trigger thread (60s polling, signs+broadcasts a
    // validator JOIN request when self meets the 0.10 %-of-supply stake
    // threshold and is not already in the active set).
    pthread_t auto_join_tid;
    if (pthread_create(&auto_join_tid, NULL, auto_join_thread_func, NULL) != 0) {
        MXD_LOG_WARN("node", "Failed to start auto-join thread (validator JOIN must be triggered manually)");
    } else {
        MXD_LOG_INFO("node", "Auto-join thread started (60s polling, 30s warm-up)");
    }

    /* v8+: auto-EVICT thread. DISABLED pending crash debug — the thread's
     * rapid_table scan was racing with the consensus tick's table writes
     * (suspected; not confirmed). Re-enable once locking is corrected. */
#if 0
    if (pthread_create(&auto_evict_tid, NULL, auto_evict_thread_func, NULL) != 0) {
        MXD_LOG_WARN("node", "Failed to start auto-evict thread");
    } else {
        MXD_LOG_INFO("node", "Auto-evict thread started (60s polling, 30s warm-up, v8 gated)");
    }
#else
    (void)auto_evict_tid;
    MXD_LOG_INFO("node", "Auto-evict thread DISABLED (crash debug — see CONSENSUS_V5 v8 appendix)");
#endif

    MXD_LOG_INFO("node", "Node started successfully, entering display loop");

    // Main display loop
    while (keep_running) {
        mxd_node_metrics_t local_metrics;
        mxd_node_stake_t local_stake;
        uint32_t blockchain_height = 0;
        uint8_t latest_block_hash[64] = {0};
        int has_block = 0;
        
        mxd_node_stake_t *snapshot_nodes[100];
        mxd_node_stake_t snapshot_storage[100];
        size_t snapshot_count = 0;
        
        mxd_get_blockchain_height(&blockchain_height);
        int is_genesis_mode = (genesis_initialized && blockchain_height == 0);
        int is_locked = mxd_is_genesis_locked();
        
        pthread_mutex_lock(&metrics_mutex);
        
        local_metrics = node_metrics;
        local_stake = node_stake;
        local_stake.metrics = local_metrics;
        local_stake.active = mxd_validate_performance(&local_metrics);
        local_stake.rank = (int)(local_metrics.performance_score * 100);
        
        if (rapid_table.count < 10) {
            int found = 0;
            for (size_t i = 0; i < rapid_table.count; i++) {
                if (rapid_table.nodes[i] && strcmp(rapid_table.nodes[i]->node_id, node_stake.node_id) == 0) {
                    found = 1;
                    *rapid_table.nodes[i] = node_stake;
                    break;
                }
            }
            if (!found) {
                int should_add = 1;
                
                if (is_genesis_mode && is_locked) {
                    MXD_LOG_DEBUG("node", "Genesis coordination locked, rejecting new member %s", node_stake.node_id);
                    should_add = 0;
                }
                
                if (should_add && !is_genesis_mode) {
                    double total_stake = 0.0;
                    for (size_t i = 0; i < rapid_table.count; i++) {
                        if (rapid_table.nodes[i]) {
                            total_stake += rapid_table.nodes[i]->stake_amount;
                        }
                    }
                    total_stake += node_stake.stake_amount;
                    
                    if (mxd_validate_node_stake(&node_stake, total_stake) != 0) {
                        MXD_LOG_DEBUG("node", "Node %s does not meet stake requirement", node_stake.node_id);
                        should_add = 0;
                    }
                    
                    if (should_add) {
                        uint64_t current_time = mxd_now_ms();
                        if (mxd_validate_node_performance(&node_stake, current_time) != 0) {
                            MXD_LOG_DEBUG("node", "Node %s does not meet performance requirements", node_stake.node_id);
                            should_add = 0;
                        }
                    }
                }
                
                if (should_add) {
                    // Allocate heap memory for the node - rapid table takes ownership
                    // and will free it later (e.g., in mxd_rebuild_rapid_table_from_blockchain)
                    mxd_node_stake_t *heap_node = malloc(sizeof(mxd_node_stake_t));
                    if (heap_node) {
                        memcpy(heap_node, &node_stake, sizeof(mxd_node_stake_t));
                        if (mxd_add_to_rapid_table(&rapid_table, heap_node, current_config.node_id) != 0) {
                            free(heap_node);
                        }
                    }
                }
            }
        }
        
        pthread_mutex_unlock(&metrics_mutex);
        
        mxd_get_blockchain_height(&blockchain_height);
        
        static uint32_t last_blockchain_height = 0;
        static int rapid_table_rebuilt = 0;
        
        if (genesis_initialized && blockchain_height == 0) {
            uint64_t current_time = time(NULL);
            
            // During genesis, broadcast announces and sync to rapid table regardless of
            // authenticated peer count. Genesis announces are received via regular P2P
            // messages, not persistent authenticated connections.
            int connected_peers = mxd_get_connection_count();
            int pending_count = mxd_get_pending_genesis_count();
            
            if (current_time - last_genesis_announce >= 3) {
                mxd_broadcast_genesis_announce();
                last_genesis_announce = current_time;
            }
            
            // Always sync pending genesis members to rapid table during genesis
            // This is critical because genesis announces come via regular P2P, not
            // authenticated persistent connections
            pthread_mutex_lock(&metrics_mutex);
            mxd_sync_pending_genesis_to_rapid_table(&rapid_table, current_config.node_id);
            pthread_mutex_unlock(&metrics_mutex);
            
            if (pending_count >= 3) {
                MXD_LOG_INFO("node", "Have %d pending genesis members, attempting genesis coordination", pending_count);
                mxd_try_coordinate_genesis_block();
            } else if (connected_peers > 0) {
                MXD_LOG_DEBUG("node", "Waiting for more genesis members: %d/3 (connected peers: %d)",
                             pending_count, connected_peers);
            }
        }
        
        if (genesis_initialized && !rapid_table_rebuilt && blockchain_height > 0) {
            pthread_mutex_lock(&metrics_mutex);
            if (mxd_rebuild_rapid_table_after_genesis(&rapid_table, current_config.node_id) == 0) {
                MXD_LOG_INFO("node", "Rapid table rebuilt from genesis block, now has %zu nodes", rapid_table.count);
                if (rapid_table.count > 0) {
                    rapid_table_rebuilt = 1;
                    rapid_table_ready = 1;  // Allow consensus thread to start proposing
                } else {
                    MXD_LOG_WARN("node", "Rapid table rebuild returned 0 nodes (genesis block may not have arrived yet), will retry");
                }
            } else {
                MXD_LOG_WARN("node", "Failed to rebuild rapid table from genesis block");
            }
            pthread_mutex_unlock(&metrics_mutex);
        }
        
        // Consensus tick now runs in dedicated thread (consensus_thread_func)
        // at ~5Hz, independent of this display loop.

        last_blockchain_height = blockchain_height;

        // Periodic blockchain sync check - ensures we catch up if behind the network
        static uint64_t last_sync_check = 0;
        uint64_t now_sync = time(NULL);
        if (genesis_initialized && blockchain_height > 0 && now_sync - last_sync_check >= 5) {
            last_sync_check = now_sync;
            MXD_LOG_INFO("node", "Checking blockchain sync status...");
            if (mxd_sync_blockchain() == 0) {
                // Update height after sync
                mxd_get_blockchain_height(&blockchain_height);
            }
        }

        pthread_mutex_lock(&metrics_mutex);
        
        snapshot_count = rapid_table.count < 100 ? rapid_table.count : 100;
        for (size_t i = 0; i < snapshot_count; i++) {
            if (rapid_table.nodes[i]) {
                snapshot_storage[i] = *rapid_table.nodes[i];
                snapshot_nodes[i] = &snapshot_storage[i];
            } else {
                snapshot_nodes[i] = NULL;
            }
        }
        
        pthread_mutex_unlock(&metrics_mutex);
        
        mxd_get_blockchain_height(&blockchain_height);
        
        mxd_block_t latest_block;
        if (blockchain_height > 0 && mxd_retrieve_block_by_height(blockchain_height, &latest_block) == 0) {
            memcpy(latest_block_hash, latest_block.block_hash, 64);
            mxd_free_validation_chain(&latest_block);
            has_block = 1;
        }
        
        mxd_rapid_table_t snapshot_table = {
            .nodes = snapshot_nodes,
            .count = snapshot_count,
            .capacity = 100,
            .last_update = 0
        };
        
        display_node_metrics(&local_metrics, &local_stake, &current_config, &snapshot_table,
                           blockchain_height, has_block ? latest_block_hash : NULL);
        sleep(1);
    }
    
    // Cleanup sequence:
    // 1. Stop P2P listener so no new messages trigger DB writes
    // 2. Set flags and wait for in-flight operations to drain
    // 3. Close databases (now safe — no threads are writing)
    // 4. Clean up remaining services and threads
    MXD_LOG_INFO("node", "Shutting down...");
    consensus_running = 0;

    // Stop P2P and DHT first to prevent new incoming messages from
    // triggering DB writes (mxd_handle_blocks_response → mxd_apply_transaction_to_utxo)
    mxd_stop_dht();

    // Wait for any in-flight DB operations to complete.
    // P2P handler threads don't check keep_running, but with the listener
    // closed above, no new work arrives. Existing handlers finish within ~1s.
    MXD_LOG_INFO("node", "Waiting for in-flight operations to drain...");
    usleep(2000000);  // 2 seconds — generous margin for in-flight writes

    // Now safe to close databases — no threads are writing
    mxd_contracts_db_close();
    mxd_close_blockchain_db();
    mxd_close_utxo_db();
    MXD_LOG_INFO("node", "Databases closed safely");

    // Stop remaining services
    mxd_http_api_stop();
    mxd_stop_metrics_server();
    mxd_cleanup_monitoring();
    mxd_free_rapid_table(&rapid_table);

    // Non-blocking thread cleanup: detach instead of join to avoid hanging
    pthread_detach(consensus_tid);
    pthread_detach(collector_thread);

    MXD_LOG_INFO("node", "Node terminated successfully");
    mxd_cleanup_logging();
    return 0;
}
