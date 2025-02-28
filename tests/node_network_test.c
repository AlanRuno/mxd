#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "mxd_p2p.h"
#include "mxd_config.h"
#include "test_utils.h"

#define TEST_PORT_1 12345
#define TEST_PORT_2 12346
#define MAX_LATENCY_MS 3000  // 3 second maximum latency requirement

static void test_node_network(void) {
    TEST_START("Node Network Test");
    
    // Generate test public keys for two nodes
    uint8_t public_key_1[32] = {0};
    uint8_t public_key_2[32] = {0};
    for (int i = 0; i < 32; i++) {
        public_key_1[i] = i;
        public_key_2[i] = i + 32;
    }
    
    // Initialize first node
    TEST_ASSERT(mxd_init_p2p(TEST_PORT_1, public_key_1) == 0, "Node 1 P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node 1 P2P startup");
    
    // Initialize second node with latency tracking
    uint64_t start_time = get_current_time_ms();
    TEST_ASSERT(mxd_init_p2p(TEST_PORT_2, public_key_2) == 0, "Node 2 P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node 2 P2P startup");
    uint64_t end_time = get_current_time_ms();
    uint64_t init_latency = end_time - start_time;
    printf("  Node initialization latency: %lums\n", init_latency);
    TEST_ASSERT(init_latency <= MAX_LATENCY_MS, "Node initialization must complete within 3 seconds");
    
    // Test node connection
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_add_peer("127.0.0.1", TEST_PORT_1) == 0, "Node connection successful");
    end_time = get_current_time_ms();
    uint64_t connect_latency = end_time - start_time;
    printf("  Node connection latency: %lums\n", connect_latency);
    TEST_ASSERT(connect_latency <= MAX_LATENCY_MS, "Node connection must complete within 3 seconds");
    
    // Test message exchange
    const char* test_msg = "test_message";
    size_t msg_len = strlen(test_msg);
    
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_broadcast_message(MXD_MSG_PEERS, test_msg, msg_len) == 0, "Message broadcast successful");
    end_time = get_current_time_ms();
    uint64_t broadcast_latency = end_time - start_time;
    printf("  Message broadcast latency: %lums\n", broadcast_latency);
    TEST_ASSERT(broadcast_latency <= MAX_LATENCY_MS, "Message broadcast must complete within 3 seconds");
    
    // Test peer discovery
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_start_peer_discovery() == 0, "Peer discovery started");
    end_time = get_current_time_ms();
    uint64_t discovery_latency = end_time - start_time;
    printf("  Peer discovery latency: %lums\n", discovery_latency);
    TEST_ASSERT(discovery_latency <= MAX_LATENCY_MS, "Peer discovery must complete within 3 seconds");
    
    // Cleanup
    mxd_stop_p2p();  // Stop second node
    mxd_init_p2p(TEST_PORT_1, public_key_1);  // Switch back to first node
    mxd_stop_p2p();  // Stop first node
    
    TEST_END("Node Network Test");
}

int main(void) {
    test_node_network();
    return 0;
}
