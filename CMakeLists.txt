cmake_minimum_required(VERSION 3.10)
project(mxd_library)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")

# Get git commit hash for version tracking
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(GIT_COMMIT_HASH)
    add_definitions(-DGIT_COMMIT_HASH="${GIT_COMMIT_HASH}")
endif()

# Windows-specific configuration
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
    set(BUILD_SHARED_LIBS ON)
    if(DEFINED ENV{MINGW_PREFIX})
        set(CMAKE_INSTALL_PREFIX $ENV{MINGW_PREFIX})
    else()
        set(CMAKE_INSTALL_PREFIX "/mingw64")
    endif()
endif()

# Find OpenSSL and Libsodium
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Include Libsodium
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

option(MXD_WITH_WASI "Build with WASI/uvwasi support" ON)


# Use pkg-config to find libraries
pkg_check_modules(CJSON REQUIRED libcjson)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(LIBUV REQUIRED libuv)
pkg_check_modules(MINIUPNPC REQUIRED miniupnpc)
if(MXD_WITH_WASI)
  pkg_check_modules(UVWASI QUIET uvwasi)
endif()
pkg_check_modules(WASM3 REQUIRED wasm3)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)

# Enable WASM3 gas metering for Phase 3 security implementation
add_definitions(-DM3_COMPILE_WITH_METERING=1)

# Find RocksDB using find_library instead of pkg-config
find_path(ROCKSDB_INCLUDE_DIR rocksdb/c.h PATHS /usr/include /usr/local/include)
find_library(ROCKSDB_LIBRARY rocksdb PATHS /usr/lib /usr/local/lib)

if(NOT ROCKSDB_INCLUDE_DIR OR NOT ROCKSDB_LIBRARY)
    message(FATAL_ERROR "RocksDB library not found")
endif()

include_directories(
    ${LIBUV_INCLUDE_DIRS}
    ${WASM3_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${MINIUPNPC_INCLUDE_DIRS}
    ${ROCKSDB_INCLUDE_DIR}
    ${MICROHTTPD_INCLUDE_DIRS}
)
if(MXD_WITH_WASI AND UVWASI_FOUND)
    include_directories(${UVWASI_INCLUDE_DIRS})
endif()

# Find other required libraries
find_library(UV_LIBRARY uv PATHS /usr/local/lib /usr/lib)
find_path(UV_INCLUDE_DIR uv.h PATHS /usr/local/include /usr/include)

if(NOT UV_LIBRARY OR NOT UV_INCLUDE_DIR)
    message(FATAL_ERROR "libuv library not found")
endif()

if(MXD_WITH_WASI)
    find_library(UVWASI_LIBRARY uvwasi PATHS /usr/local/lib /usr/lib)
    find_path(UVWASI_INCLUDE_DIR uvwasi/uvwasi.h PATHS /usr/local/include /usr/include)
    if(NOT UVWASI_LIBRARY OR NOT UVWASI_INCLUDE_DIR)
        set(MXD_WITH_WASI OFF)
    endif()
endif()

include_directories(${WASM3_INCLUDE_DIR})

# Set output directories
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Create project structure
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)

# Add library target
add_library(mxd SHARED
    src/mxd_amount.c
    src/mxd_crypto.c
    src/mxd_address.c
    src/base58.c
    src/mxd_chain.c
    src/blockchain/mxd_blockchain.c
    src/blockchain/mxd_blockchain_validation.c
    src/blockchain/mxd_rsc.c
    src/blockchain/mxd_validator_management.c
    src/blockchain/mxd_fork_choice.c
    src/blockchain/mxd_block_delta.c
    src/mxd_transaction.c
    src/mxd_utxo.c
    src/mxd_mempool.c
    src/mxd_block_proposer.c
    src/mxd_p2p.c
    src/mxd_p2p_validation.c
    src/mxd_p2p_peer.c
    src/mxd_genesis_handler.c
    src/mxd_validation_handler.c
    src/mxd_get_utxo.c
    src/mxd_rocksdb_globals.c
    src/mxd_smart_contracts.c
    src/mxd_contracts_db.c
    src/mxd_wasm_validator.c
    src/mxd_gas_metering.c
    src/mxd_merkle_trie.c
    src/mxd_protocol_version.c
    src/mxd_domain_tags.c
    src/checkpoints/mxd_checkpoints.c
    src/quantization/mxd_data_quantization.c
    src/mxd_ntp.c
    src/mxd_metrics.c
    src/mxd_dht.c
    src/mxd_logging.c
    src/mxd_secrets.c
    src/mxd_monitoring.c
    src/mxd_backup.c
    src/mxd_load_testing.c
    src/mxd_bip39.c
    src/mxd_slip10.c
    src/mxd_pq01.c
    src/mxd_wallet.c)


# Link libraries
if(WIN32)
    target_link_libraries(mxd 
        ${OPENSSL_LIBRARIES}
        sodium
        gmp
        ${LIBUV_LIBRARIES}
        ${WASM3_LIBRARIES}
        ${ROCKSDB_LIBRARY}
        ws2_32
        iphlpapi
        userenv)
else()
    target_link_libraries(mxd 
        ${OPENSSL_LIBRARIES}
        sodium
        -static-libgcc
        -static-libstdc++
        gmp
        -Wl,--whole-archive
        ${LIBUV_LIBRARIES}
        ${WASM3_LIBRARIES}
        ${CJSON_LIBRARIES}
        ${CURL_LIBRARIES}
        ${MINIUPNPC_LIBRARIES}
        ${ROCKSDB_LIBRARY}
        ${MICROHTTPD_LIBRARIES}
        -Wl,--no-whole-archive
        m
        pthread)
    
    # Platform-specific libraries (not available on macOS)
    if(NOT APPLE)
        target_link_libraries(mxd dl rt)
    endif()
endif()

if(MXD_WITH_WASI)
    target_link_libraries(mxd ${UVWASI_LIBRARIES})
endif()

# Include directories
target_include_directories(mxd PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
# liboqs is now required for hybrid cryptography support (Ed25519 + Dilithium5)
pkg_check_modules(LIBOQS REQUIRED liboqs)
target_include_directories(mxd PRIVATE ${LIBOQS_INCLUDE_DIRS})
target_link_libraries(mxd ${LIBOQS_LIBRARIES} mldsa)


# Install rules
install(TARGETS mxd
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/mxd
    FILES_MATCHING PATTERN "*.h"
)

# Enable testing
enable_testing()
add_subdirectory(tests)

# Add network test source files
target_sources(mxd PRIVATE
    src/mxd_dht_network.c
)

# Add library sources
target_sources(mxd PRIVATE
    src/mxd_config.c
    src/mxd_blockchain_sync.c
    src/mxd_blockchain_db.c
    src/node/metrics_display.c
    src/utils/mxd_http.c
    src/utils/mxd_cert_pinning.c
    src/utils/mxd_replay.c
    src/metrics/mxd_prometheus.c
    src/mxd_http_api.c)

# Add main node executable
add_executable(mxd_node src/node/main.c)
target_link_libraries(mxd_node PRIVATE mxd)
install(TARGETS mxd_node
    RUNTIME DESTINATION bin)

# Install default configuration file alongside the executable
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/node/default_config.json
    DESTINATION bin)

# pq-crystals ML-DSA-87 reference (for MXD-PQ-01 deterministic keygen).
# DILITHIUM_MODE=5 selects Dilithium5 = ML-DSA-87 (FIPS 204 highest security level).
add_library(mldsa STATIC
  vendor/ml-dsa-pqcrystals/ref/sign.c
  vendor/ml-dsa-pqcrystals/ref/poly.c
  vendor/ml-dsa-pqcrystals/ref/polyvec.c
  vendor/ml-dsa-pqcrystals/ref/ntt.c
  vendor/ml-dsa-pqcrystals/ref/reduce.c
  vendor/ml-dsa-pqcrystals/ref/rounding.c
  vendor/ml-dsa-pqcrystals/ref/packing.c
  vendor/ml-dsa-pqcrystals/ref/symmetric-shake.c
  vendor/ml-dsa-pqcrystals/ref/fips202.c)
target_compile_definitions(mldsa PRIVATE DILITHIUM_MODE=5)
target_include_directories(mldsa PUBLIC vendor/ml-dsa-pqcrystals/ref)

# Note: Removed invalid LINK_FLAGS that opened --whole-archive without closing it
# The mxd_node executable doesn't need whole-archive linking

# Add enterprise features test executable
add_executable(mxd_enterprise_features_tests
    tests/test_enterprise_features.c
)

# Use Threads::Threads for cross-platform pthread support
find_package(Threads REQUIRED)

target_link_libraries(mxd_enterprise_features_tests
    mxd
    ${OPENSSL_LIBRARIES}
    sodium
    Threads::Threads
)

# Add test for enterprise features
add_test(NAME enterprise_features_tests COMMAND mxd_enterprise_features_tests)

# Test-vector generator tool (Phase 9 — MXD-NN spec compliance)
add_executable(gen_test_vectors tools/gen_test_vectors.c)
target_link_libraries(gen_test_vectors mxd mldsa ${OPENSSL_LIBRARIES} sodium)
