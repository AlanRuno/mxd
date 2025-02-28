#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mxd_config.h"
#include "test_utils.h"

int test_node_arguments(const char* node_path) {
    printf("Starting node argument tests...\n");
    fflush(stdout);

    // Test port override
    TEST_START("Port Override");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s --port 8888", node_path);
    FILE* fp = popen(cmd, "r");
    if (fp) {
        char buf[1024];
        int found_override = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "Port overridden from command line: 8888")) {
                found_override = 1;
                break;
            }
        }
        pclose(fp);
        TEST_ASSERT(found_override, "Port override message found");
    }
    TEST_END("Port Override");

    // Test invalid port (too low)
    TEST_START("Invalid Port (Low)");
    snprintf(cmd, sizeof(cmd), "%s --port 80", node_path);
    fp = popen(cmd, "r");
    if (fp) {
        char buf[1024];
        int found_error = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "Error: Port must be between 1024 and 65535")) {
                found_error = 1;
                break;
            }
        }
        pclose(fp);
        TEST_ASSERT(found_error, "Low port error message found");
    }
    TEST_END("Invalid Port (Low)");

    // Test invalid port (too high)
    TEST_START("Invalid Port (High)");
    snprintf(cmd, sizeof(cmd), "%s --port 70000", node_path);
    fp = popen(cmd, "r");
    if (fp) {
        char buf[1024];
        int found_error = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "Error: Port must be between 1024 and 65535")) {
                found_error = 1;
                break;
            }
        }
        pclose(fp);
        TEST_ASSERT(found_error, "High port error message found");
    }
    TEST_END("Invalid Port (High)");

    // Test DHT node discovery with overridden port
    TEST_START("DHT Node Discovery");
    snprintf(cmd, sizeof(cmd), "%s --port 8888", node_path);
    fp = popen(cmd, "r");
    if (fp) {
        char buf[1024];
        int found_dht = 0;
        int found_peers = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "DHT service started on port 8888")) {
                found_dht = 1;
            }
            if (strstr(buf, "Connected peers: 1")) {
                found_peers = 1;
            }
        }
        pclose(fp);
        TEST_ASSERT(found_dht, "DHT service started on correct port");
        TEST_ASSERT(found_peers, "Node connected to peers");
    }
    TEST_END("DHT Node Discovery");

    // Test bootstrap node connections
    TEST_START("Bootstrap Node Connection");
    snprintf(cmd, sizeof(cmd), "%s --port 8888", node_path);
    fp = popen(cmd, "r");
    if (fp) {
        char buf[1024];
        int found_bootstrap = 0;
        uint64_t latency = 0;
        int error_count = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "Connecting to bootstrap node")) {
                found_bootstrap = 1;
            }
            if (strstr(buf, "Debug: Metrics - TPS=")) {
                // Extract latency from metrics
                char* latency_str = strstr(buf, "Latency=");
                if (latency_str) {
                    sscanf(latency_str + 8, "%lu", &latency);
                }
            }
            if (strstr(buf, "Warning: High consecutive error count:")) {
                error_count++;
            }
        }
        pclose(fp);
        TEST_ASSERT(found_bootstrap, "Connected to bootstrap nodes");
        TEST_ASSERT(latency <= 3000, "Latency within 3s limit");
        TEST_ASSERT(error_count <= 10, "Error count within limit");
    }
    TEST_END("Bootstrap Node Connection");

    // Test peer count display
    TEST_START("Peer Count Display");
    snprintf(cmd, sizeof(cmd), "%s --port 8888", node_path);
    fp = popen(cmd, "r");
    if (fp) {
        char buf[1024];
        int found_peer_count = 0;
        while (fgets(buf, sizeof(buf), fp)) {
            if (strstr(buf, "Connected Peers:")) {
                found_peer_count = 1;
                break;
            }
        }
        pclose(fp);
        TEST_ASSERT(found_peer_count, "Peer count display found");
    }
    TEST_END("Peer Count Display");

    printf("Node argument tests completed\n");
    fflush(stdout);
    return 0;
}

int main(int argc, char** argv) {
    TEST_START("Node Tests");
    fflush(stdout);

    // Get path to mxd_node executable
    char node_path[256];
    snprintf(node_path, sizeof(node_path), "%s/../lib/mxd_node", argv[0]);

    // Run argument tests
    if (test_node_arguments(node_path) != 0) {
        printf("Node argument tests failed\n");
        return 1;
    }

    TEST_END("Node Tests");
    return 0;
}
