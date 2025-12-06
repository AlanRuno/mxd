#ifndef MXD_DHT_H
#define MXD_DHT_H

#include <stdint.h>
#include <stddef.h>
#include "mxd_config.h"

#define MXD_NODE_ID_SIZE 32
#define MXD_MAX_PEERS 256
#define MXD_BUCKET_SIZE 20

// DHT types
typedef struct {
    uint8_t id[MXD_NODE_ID_SIZE];
} mxd_node_id_t;

typedef struct {
    mxd_node_id_t id;
    char address[256];
    uint16_t port;
    int active;
} mxd_dht_node_t;

typedef struct {
    size_t size;
    mxd_dht_node_t nodes[MXD_BUCKET_SIZE];
} mxd_bucket_t;

// DHT functions
void mxd_generate_node_id(uint8_t* node_id);
void mxd_init_bucket(mxd_bucket_t* bucket);
int mxd_init_node(const void* config);
int mxd_init_dht(const uint8_t* public_key);
int mxd_start_dht(uint16_t port);
int mxd_stop_dht(void);
int mxd_dht_find_nodes(const mxd_node_id_t* target, mxd_dht_node_t* nodes, size_t* count);
int mxd_dht_enable_nat_traversal(void);
int mxd_dht_disable_nat_traversal(void);
uint64_t mxd_get_network_latency(void);  // Get current network latency
int mxd_dht_get_peers(mxd_dht_node_t* nodes, size_t* count);  // Get discovered peers
int mxd_dht_add_peer(const char* address, uint16_t port);  // Add a peer to the DHT
int mxd_register_bootstrap_node(const mxd_config_t* config);  // Register as bootstrap node

// Test functions
int test_node_id(void);
int test_buckets(void);
int run_network_tests(const char* config_file);

#endif // MXD_DHT_H
