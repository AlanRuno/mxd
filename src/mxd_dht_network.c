#include <stdio.h>
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

static volatile int keep_running = 1;
static mxd_config_t current_config;

void handle_signal(int signum) {
    printf("\nReceived signal %d, shutting down node %s...\n", 
           signum, current_config.node_id);
    fflush(stdout);
    keep_running = 0;
}

int run_network_tests(const char* config_file) {
    printf("Starting network tests with config: %s\n", config_file);
    fflush(stdout);
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);
    
    // Load configuration
    if (mxd_load_config(config_file, &current_config) != 0) {
        printf("Failed to load configuration: %s\n", strerror(errno));
        return 1;
    }
    
    printf("Configuration loaded: node_id=%s, port=%d, data_dir=%s\n",
           current_config.node_id, current_config.port, current_config.data_dir);
    fflush(stdout);
    
    // Verify data directory exists
    struct stat st = {0};
    if (stat(current_config.data_dir, &st) == -1) {
        printf("Creating data directory: %s\n", current_config.data_dir);
        if (mkdir(current_config.data_dir, 0755) == -1) {
            printf("Failed to create data directory: %s\n", strerror(errno));
            return 1;
        }
    }
    
    // Initialize DHT node
    if (mxd_init_node(&current_config) != 0) {
        printf("Failed to initialize DHT node\n");
        return 1;
    }
    
    printf("DHT node initialized successfully\n");
    fflush(stdout);
    
    // Start DHT service
    if (mxd_start_dht(current_config.port) != 0) {
        printf("Failed to start DHT service\n");
        return 1;
    }
    
    printf("DHT service started on port %d\n", current_config.port);
    fflush(stdout);
    
    // Main node loop
    while (keep_running) {
        printf("Node %s alive on port %d\n", 
               current_config.node_id, current_config.port);
        fflush(stdout);
        sleep(5);
    }
    
    printf("Shutting down node %s...\n", current_config.node_id);
    fflush(stdout);
    mxd_stop_dht();
    return 0;
}
