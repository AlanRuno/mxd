#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "mxd_dht.h"
#include "mxd_config.h"

int main(int argc, char** argv) {
    printf("Starting DHT tests...\n");
    fflush(stdout);

    int network_mode = 0;
    const char* config_file = NULL;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--network") == 0) {
            network_mode = 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    if (network_mode) {
        if (!config_file) {
            printf("Error: --config required in network mode\n");
            return 1;
        }
        printf("Running network tests with config: %s\n", config_file);
        fflush(stdout);
        return run_network_tests(config_file);
    }

    // Run basic DHT tests
    uint8_t node_id[32];
    mxd_generate_node_id(node_id);
    printf("Generated node ID: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", node_id[i]);
    }
    printf("\n");
    fflush(stdout);

    mxd_bucket_t bucket;
    mxd_init_bucket(&bucket);
    printf("Initialized k-bucket\n");
    fflush(stdout);

    // Key-generation algorithm selector (used only when data/node_keys.v2 is absent).
    // Default must be Dilithium5; setter accepts only 1 (Ed25519) or 2 (Dilithium5).
    if (mxd_dht_get_keygen_algo() != 2) {
        printf("FAIL: default keygen algo is %u, expected 2 (Dilithium5)\n", mxd_dht_get_keygen_algo());
        return 1;
    }
    if (mxd_dht_set_keygen_algo(0) == 0 || mxd_dht_set_keygen_algo(3) == 0) {
        printf("FAIL: setter accepted an invalid algo_id\n");
        return 1;
    }
    if (mxd_dht_set_keygen_algo(1) != 0 || mxd_dht_get_keygen_algo() != 1) {
        printf("FAIL: setter did not switch to Ed25519\n");
        return 1;
    }
    if (mxd_dht_set_keygen_algo(2) != 0 || mxd_dht_get_keygen_algo() != 2) {
        printf("FAIL: setter did not switch back to Dilithium5\n");
        return 1;
    }
    printf("Keygen algorithm selector OK (default Dilithium5)\n");
    fflush(stdout);

    return 0;
}
