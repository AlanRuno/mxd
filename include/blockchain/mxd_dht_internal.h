#ifndef MXD_DHT_INTERNAL_H
#define MXD_DHT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "../mxd_dht.h"

// Kademlia constants
#define K_PARAM 20          // Size of k-buckets
#define ALPHA 3             // Number of parallel lookups
#define BUCKET_COUNT 160    // Number of k-buckets (one per bit)
#define REFRESH_INTERVAL 60 // Bucket refresh interval in seconds

// DHT message types
typedef enum {
    DHT_PING = 1,
    DHT_PONG,
    DHT_FIND_NODE,
    DHT_FIND_NODE_REPLY,
    DHT_STORE,
    DHT_FIND_VALUE,
    DHT_FIND_VALUE_REPLY
} mxd_dht_message_type_t;

// DHT message header
typedef struct {
    uint32_t magic;     // "MXD\0"
    uint8_t version;    // Protocol version
    uint8_t type;       // Message type
    mxd_node_id_t sender_id;
    uint8_t signature[64];  // Message signature
} mxd_dht_message_header_t;

// DHT value storage
typedef struct {
    uint8_t key[20];       // SHA-1 hash of original key
    uint8_t *value;        // Stored value
    size_t value_length;   // Length of value
    time_t expiry;         // Expiration time
} mxd_stored_value_t;

// DHT state
typedef struct {
    int socket;
    uint16_t port;
    pthread_t main_thread;
    pthread_t refresh_thread;
    volatile int running;
    mxd_routing_table_t routing_table;
    pthread_mutex_t table_mutex;
    uint8_t nat_traversal;
    mxd_dht_stats_t stats;
    mxd_stored_value_t *stored_values;
    size_t value_count;
    size_t value_capacity;
    pthread_mutex_t storage_mutex;
} mxd_dht_state_t;

extern mxd_dht_state_t dht_state;

#endif // MXD_DHT_INTERNAL_H
