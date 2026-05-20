#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mxd_config.h"
#include "test_utils.h"

void test_bootstrap_node_fetching(void) {
    mxd_config_t config;
    TEST_START("Bootstrap Node Fetching");
    
    // Test config loading
    TEST_ASSERT(mxd_load_config("test_config.json", &config) == 0, "Config loading successful");
    TEST_ASSERT(config.bootstrap_count > 0, "Has bootstrap nodes");
    
    // Verify node format and port range
    char hostname[256];
    int port;
    int valid_nodes = 0;
    
    for (int i = 0; i < config.bootstrap_count; i++) {
        char* node = config.bootstrap_nodes[i];
        TEST_ASSERT(sscanf(node, "%[^:]:%d", hostname, &port) == 2, 
                   "Node format valid: %s", node);
        TEST_ASSERT(port >= 1024 && port <= 65535, 
                   "Port in valid range: %d", port);
        TEST_ASSERT(strlen(hostname) > 0, "Hostname not empty");
        valid_nodes++;
    }
    
    TEST_ASSERT(valid_nodes == config.bootstrap_count, 
               "All nodes valid (%d/%d)", valid_nodes, config.bootstrap_count);
    
    TEST_END("Bootstrap Node Fetching");
}

int main(int argc, char** argv) {
    TEST_START("Config Tests");
    
    test_bootstrap_node_fetching();
    
    TEST_END("Config Tests");
    return 0;
}
