# Add test utilities
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Add test executables
add_executable(mxd_crypto_tests
    test_crypto.c
)

add_executable(mxd_address_tests
    test_address.c
)

add_executable(mxd_blockchain_tests
    test_blockchain.c
)

add_executable(mxd_rsc_tests
    test_rsc.c
)

add_executable(mxd_transaction_tests
    test_transaction.c
)

add_executable(mxd_utxo_tests
    test_utxo.c
)

add_executable(mxd_mempool_tests
    test_mempool.c
)

target_link_libraries(mxd_crypto_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    -Wl,--whole-archive
    ${WASM3_LIBRARIES}
    ${UVWASI_LIBRARIES}
    ${LIBUV_LIBRARIES}
    -Wl,--no-whole-archive
    m
    pthread
    dl
    rt)

target_link_libraries(mxd_address_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_blockchain_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_rsc_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_transaction_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_utxo_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

target_link_libraries(mxd_mempool_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_executable(mxd_p2p_tests
    test_p2p.c
)

target_link_libraries(mxd_p2p_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_executable(mxd_smart_contracts_tests
    test_smart_contracts.c
)

target_link_libraries(mxd_smart_contracts_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    -Wl,--whole-archive
    ${WASM3_LIBRARIES}
    ${UVWASI_LIBRARIES}
    ${LIBUV_LIBRARIES}
    -Wl,--no-whole-archive
    m
    pthread
    dl
    rt)

add_test(NAME crypto_tests COMMAND mxd_crypto_tests)
add_test(NAME address_tests COMMAND mxd_address_tests)
add_test(NAME blockchain_tests COMMAND mxd_blockchain_tests)
add_test(NAME rsc_tests COMMAND mxd_rsc_tests)
add_test(NAME transaction_tests COMMAND mxd_transaction_tests)
add_test(NAME utxo_tests COMMAND mxd_utxo_tests)
add_test(NAME mempool_tests COMMAND mxd_mempool_tests)
add_test(NAME p2p_tests COMMAND mxd_p2p_tests)
set_tests_properties(p2p_tests PROPERTIES TIMEOUT 120)
add_test(NAME smart_contracts_tests COMMAND mxd_smart_contracts_tests)

add_executable(mxd_checkpoints_tests
    test_checkpoints.c
)

target_link_libraries(mxd_checkpoints_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME checkpoints_tests COMMAND mxd_checkpoints_tests)

add_executable(mxd_data_quantization_tests
    test_data_quantization.c
)

target_link_libraries(mxd_data_quantization_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME data_quantization_tests COMMAND mxd_data_quantization_tests)

add_executable(mxd_voluntary_tip_tests
    test_voluntary_tip.c
)

target_link_libraries(mxd_voluntary_tip_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME voluntary_tip_tests COMMAND mxd_voluntary_tip_tests)

add_executable(mxd_ntp_tests
    test_ntp.c
)

target_link_libraries(mxd_ntp_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME ntp_tests COMMAND mxd_ntp_tests)

add_executable(mxd_metrics_tests
    test_metrics.c
)

target_link_libraries(mxd_metrics_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME metrics_tests COMMAND mxd_metrics_tests)

add_executable(mxd_metrics_performance_tests
    test_metrics_performance.c
)

target_link_libraries(mxd_metrics_performance_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME metrics_performance_tests COMMAND mxd_metrics_performance_tests)

add_executable(mxd_enhanced_consensus_tests
    test_enhanced_consensus.c
)

target_link_libraries(mxd_enhanced_consensus_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
)

add_test(NAME enhanced_consensus_tests COMMAND mxd_enhanced_consensus_tests)

add_executable(mxd_dht_tests
    test_dht.c
)

target_link_libraries(mxd_dht_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME dht_tests COMMAND mxd_dht_tests)
set_tests_properties(dht_tests PROPERTIES TIMEOUT 120)

# Basic node setup test
add_executable(mxd_basic_node_setup_test
    basic_node_setup_test.c
)

target_link_libraries(mxd_basic_node_setup_test
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME basic_node_setup_tests COMMAND mxd_basic_node_setup_test)
set_tests_properties(basic_node_setup_tests PROPERTIES TIMEOUT 120)

# Node network test
add_executable(mxd_node_network_test
    node_network_test.c
)

target_link_libraries(mxd_node_network_test
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME node_network_tests COMMAND mxd_node_network_test)
set_tests_properties(node_network_tests PROPERTIES TIMEOUT 120)

# Blockchain data test
add_executable(mxd_blockchain_data_test
    blockchain_data_test.c
)

target_link_libraries(mxd_blockchain_data_test
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME blockchain_data_tests COMMAND mxd_blockchain_data_test)
set_tests_properties(blockchain_data_tests PROPERTIES TIMEOUT 120)

# Mining validation test
add_executable(mxd_mining_validation_test
    mining_validation_test.c
)

target_link_libraries(mxd_mining_validation_test
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME mining_validation_tests COMMAND mxd_mining_validation_test)
set_tests_properties(mining_validation_tests PROPERTIES TIMEOUT 120)

# Integration test
add_executable(mxd_integration_test
    integration_test.c
)

target_link_libraries(mxd_integration_test
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME integration_tests COMMAND mxd_integration_test)
set_tests_properties(integration_tests PROPERTIES TIMEOUT 120)

# Validation Chain Network test
add_executable(mxd_validation_chain_test
    test_validation_chain.c
)

target_link_libraries(mxd_validation_chain_test
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    pthread
)

add_test(NAME validation_chain_tests COMMAND mxd_validation_chain_test)
set_tests_properties(validation_chain_tests PROPERTIES TIMEOUT 120)
