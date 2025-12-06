#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include "mxd_p2p.h"
#include "mxd_config.h"
#include "test_utils.h"

#define TEST_PORT_1 12345
#define TEST_PORT_2 12346
#define MAX_LATENCY_MS 3000

static void test_node_network(void) {
    TEST_START("Node Network Test");
    
    uint8_t public_key[256] = {0};
    uint8_t private_key[128] = {0};
    for (int i = 0; i < 256; i++) {
        public_key[i] = i % 256;
    }
    for (int i = 0; i < 128; i++) {
        private_key[i] = (i * 2) % 256;
    }
    
    pid_t daemon_pid = fork();
    if (daemon_pid < 0) {
        TEST_ASSERT(0, "Failed to fork daemon process");
        return;
    }
    
    if (daemon_pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", TEST_PORT_1);
        
        const char* daemon_paths[] = {
            "./lib/mxd_test_node_daemon",
            "../lib/mxd_test_node_daemon",
            "./mxd_test_node_daemon",
            NULL
        };
        
        for (int i = 0; daemon_paths[i] != NULL; i++) {
            execl(daemon_paths[i], "mxd_test_node_daemon", port_str, NULL);
        }
        
        fprintf(stderr, "Failed to exec daemon: %s\n", strerror(errno));
        exit(1);
    }
    
    printf("  Started test node daemon (PID %d) on port %d\n", daemon_pid, TEST_PORT_1);
    
    usleep(500000);
    
    uint64_t start_time = get_current_time_ms();
    TEST_ASSERT(mxd_init_p2p(TEST_PORT_2, public_key, private_key) == 0, "Node P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "Node P2P startup");
    uint64_t end_time = get_current_time_ms();
    uint64_t init_latency = end_time - start_time;
    printf("  Node initialization latency: %lums\n", init_latency);
    TEST_ASSERT(init_latency <= MAX_LATENCY_MS, "Node initialization must complete within 3 seconds");
    
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_add_peer("127.0.0.1", TEST_PORT_1) == 0, "Node connection successful");
    end_time = get_current_time_ms();
    uint64_t connect_latency = end_time - start_time;
    printf("  Node connection latency: %lums\n", connect_latency);
    TEST_ASSERT(connect_latency <= MAX_LATENCY_MS, "Node connection must complete within 3 seconds");
    
    int max_wait = 30;
    int connected = 0;
    for (int i = 0; i < max_wait; i++) {
        if (mxd_get_connection_count() > 0) {
            connected = 1;
            printf("  Connection established after %d00ms\n", i);
            break;
        }
        usleep(100000);
    }
    TEST_ASSERT(connected, "Connection established to test daemon");
    
    const char* test_msg = "test_message";
    size_t msg_len = strlen(test_msg);
    
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_broadcast_message(MXD_MSG_PEERS, test_msg, msg_len) == 0, "Message broadcast successful");
    end_time = get_current_time_ms();
    uint64_t broadcast_latency = end_time - start_time;
    printf("  Message broadcast latency: %lums\n", broadcast_latency);
    TEST_ASSERT(broadcast_latency <= MAX_LATENCY_MS, "Message broadcast must complete within 3 seconds");
    
    start_time = get_current_time_ms();
    TEST_ASSERT(mxd_start_peer_discovery() == 0, "Peer discovery started");
    end_time = get_current_time_ms();
    uint64_t discovery_latency = end_time - start_time;
    printf("  Peer discovery latency: %lums\n", discovery_latency);
    TEST_ASSERT(discovery_latency <= MAX_LATENCY_MS, "Peer discovery must complete within 3 seconds");
    
    mxd_stop_p2p();
    
    printf("  Stopping test node daemon\n");
    kill(daemon_pid, SIGTERM);
    int status;
    waitpid(daemon_pid, &status, 0);
    
    TEST_END("Node Network Test");
}

int main(void) {
    test_node_network();
    return 0;
}
