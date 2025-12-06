#include "../include/mxd_logging.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include "../include/mxd_config.h"
#include "../include/mxd_metrics.h"
#include "../include/mxd_dht.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_monitoring.h"
#include "metrics_display.h"
#include "memory_utils.h"

static volatile int keep_running = 1;
static mxd_config_t current_config;
static mxd_node_metrics_t node_metrics;
static mxd_node_stake_t node_stake;
static mxd_rapid_table_t rapid_table;
static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

void handle_signal(int signum) {
    MXD_LOG_INFO("node", "Received signal %d, terminating node %s...", 
           signum, current_config.node_id);
    keep_running = 0;
    mxd_stop_metrics_server();
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
    int is_bootstrap = 0;
    
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
        } else if (strcmp(argv[i], "--bootstrap") == 0) {
            is_bootstrap = 1;
            MXD_LOG_INFO("node", "Running in bootstrap mode");
        } else if (argv[i][0] != '-' && !config_path) {
            config_path = argv[i];
        } else {
            MXD_LOG_ERROR("node", "Usage: %s [config_file] [--config <file>] [--port <number>] [--bootstrap]", argv[0]);
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
            strcat(default_config_path, "default_config.json");
        } else {
            strcpy(default_config_path, "./default_config.json");
        }
        config_path = default_config_path;
        MXD_LOG_INFO("node", "No config file specified, using default configuration: %s", config_path);
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    
    // Load configuration
    MXD_LOG_INFO("node", "Loading configuration from: %s", config_path);
    if (mxd_load_config(config_path, &current_config) != 0) {
        MXD_LOG_ERROR("node", "Failed to load configuration from %s", config_path);
        return 1;
    }
    MXD_LOG_INFO("node", "Configuration loaded successfully");
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
        
        pthread_mutex_lock(&metrics_mutex);
        
        local_metrics = node_metrics;
        local_stake = node_stake;
        local_stake.metrics = local_metrics;
        local_stake.active = mxd_validate_performance(&local_metrics);
        local_stake.rank = (int)(local_metrics.performance_score * 100);
        
        if (rapid_table.count == 0 || rapid_table.count < 10) {
            int found = 0;
            for (size_t i = 0; i < rapid_table.count; i++) {
                if (rapid_table.nodes[i] && strcmp(rapid_table.nodes[i]->node_id, node_stake.node_id) == 0) {
                    found = 1;
                    *rapid_table.nodes[i] = node_stake;
                    break;
                }
            }
            if (!found) {
                mxd_add_to_rapid_table(&rapid_table, &node_stake, current_config.node_id);
            }
        }
        
        if (blockchain_height == 0 && rapid_table.count >= 3) {
            mxd_try_create_genesis_block(&rapid_table, NULL, NULL, NULL);
        }
        
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
    
    // Cleanup
    pthread_join(collector_thread, NULL);
    mxd_stop_metrics_server();
    mxd_cleanup_monitoring();
    mxd_stop_dht();
    mxd_free_rapid_table(&rapid_table);
    MXD_LOG_INFO("node", "Node terminated successfully");
    mxd_cleanup_logging();
    return 0;
}
