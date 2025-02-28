#ifndef MXD_CONFIG_H
#define MXD_CONFIG_H

#include <stdint.h>

typedef struct {
    char node_id[64];
    uint16_t port;
    char data_dir[256];
    char network_type[32];     // mainnet, testnet
    char node_name[64];        // Node display name
    double initial_stake;      // Initial stake amount
    uint32_t metrics_interval; // Display refresh interval (ms)
    char bootstrap_nodes[10][256];
    int bootstrap_count;
    char node_data[1024];      // Custom node data
} mxd_config_t;

// Load configuration from file or use built-in defaults.
// If config_file is NULL or file cannot be opened, default configuration will be used.
// Returns 0 on success, -1 on validation failure.
int mxd_load_config(const char* config_file, mxd_config_t* config);

// Fetch bootstrap nodes from network
// Returns 0 on success (including fallback), -1 on critical failure
int mxd_fetch_bootstrap_nodes(mxd_config_t* config);

#endif // MXD_CONFIG_H
