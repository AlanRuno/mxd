#include "../include/mxd_address.h"
#include "../include/mxd_config.h"
#include "../include/mxd_p2p.h"
#include "test_utils.h"

#include <string.h>
#include <time.h>

static void test_node_setup(void) {
    TEST_START("Basic Node Setup");
    
    // Generate address
    char passphrase[256];
    uint8_t property_key[64];
    uint8_t public_key[256];
    uint8_t private_key[128];
    char address[42];
    
    TEST_ASSERT(mxd_generate_passphrase(passphrase, sizeof(passphrase)) == 0,
                "Passphrase generation");
    TEST_ASSERT(mxd_derive_property_key(passphrase, "1234", property_key) == 0,
                "Property key derivation");
    TEST_ASSERT(mxd_generate_keypair(property_key, public_key, private_key) == 0,
                "Keypair generation");
    TEST_ASSERT(mxd_generate_address(public_key, address, sizeof(address)) == 0,
                "Address generation");
    TEST_ASSERT(mxd_validate_address(address) == 0, "Address validation");
    
    // Configure node
    mxd_config_t config;
    memset(&config, 0, sizeof(config));
    strncpy(config.node_name, "test_node", sizeof(config.node_name));
    strncpy(config.node_data, "test_data", sizeof(config.node_data));
    config.port = 12345;
    
    // Initialize P2P with latency tracking
    uint64_t start_time = get_current_time_ms();
    TEST_ASSERT(mxd_init_p2p(config.port, public_key, private_key) == 0, "P2P initialization");
    TEST_ASSERT(mxd_start_p2p() == 0, "P2P startup");
    uint64_t end_time = get_current_time_ms();
    uint64_t latency = end_time - start_time;
    printf("  P2P Initialization latency: %lums\n", latency);
    TEST_ASSERT(latency <= 3000, "P2P initialization must complete within 3 seconds");
    
    // Verify configuration
    TEST_VALUE("Node name", "%s", config.node_name);
    TEST_VALUE("Node data", "%s", config.node_data);
    TEST_VALUE("Port", "%d", config.port);
    TEST_ARRAY("Public key", public_key, sizeof(public_key));
    
    mxd_stop_p2p();
    TEST_END("Basic Node Setup");
}

int main(void) {
    test_node_setup();
    return 0;
}
