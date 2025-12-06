#include "mxd_logging.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include "mxd_dht.h"
#include "mxd_config.h"
#include "mxd_logging.h"

static volatile int keep_running = 1;
static mxd_config_t current_config;

void handle_signal(int signum) {
    MXD_LOG_INFO("dht", "Received signal %d, shutting down node %s...", 
           signum, current_config.node_id);
    keep_running = 0;
}

int run_network_tests(const char* config_file) {
    mxd_log_config_t log_config = {
        .level = MXD_LOG_INFO,
        .output_file = NULL,
        .enable_console = 1,
        .enable_json = 0
    };
    mxd_init_logging(&log_config);
    
    MXD_LOG_INFO("dht", "Starting network tests with config: %s", config_file);
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    
    // Load configuration
    if (mxd_load_config(config_file, &current_config) != 0) {
        MXD_LOG_ERROR("dht", "Failed to load configuration: %s", strerror(errno));
        return 1;
    }
    
    MXD_LOG_INFO("dht", "Configuration loaded: node_id=%s, port=%d, data_dir=%s",
           current_config.node_id, current_config.port, current_config.data_dir);
    
    // Verify data directory exists
    struct stat st = {0};
    if (stat(current_config.data_dir, &st) == -1) {
        MXD_LOG_INFO("dht", "Creating data directory: %s", current_config.data_dir);
        if (mkdir(current_config.data_dir, 0755) == -1) {
            MXD_LOG_ERROR("dht", "Failed to create data directory: %s", strerror(errno));
            return 1;
        }
    }
    
    // Initialize DHT node
    if (mxd_init_node(&current_config) != 0) {
        MXD_LOG_ERROR("dht", "Failed to initialize DHT node");
        return 1;
    }
    
    MXD_LOG_INFO("dht", "DHT node initialized successfully");
    
    // Start DHT service
    if (mxd_start_dht(current_config.port) != 0) {
        MXD_LOG_ERROR("dht", "Failed to start DHT service");
        return 1;
    }
    
    MXD_LOG_INFO("dht", "DHT service started on port %d", current_config.port);
    
    // Main node loop
    while (keep_running) {
        MXD_LOG_DEBUG("dht", "Node %s alive on port %d", 
               current_config.node_id, current_config.port);
        sleep(5);
    }
    
    MXD_LOG_INFO("dht", "Shutting down node %s...", current_config.node_id);
    mxd_stop_dht();
    return 0;
}
