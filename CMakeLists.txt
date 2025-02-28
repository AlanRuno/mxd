cmake_minimum_required(VERSION 3.10)
project(mxd_library)

set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3 -O0")

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

# Use pkg-config to find libraries
pkg_check_modules(CJSON REQUIRED libcjson)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(LIBUV REQUIRED libuv)
pkg_check_modules(UVWASI REQUIRED uvwasi)
pkg_check_modules(WASM3 REQUIRED wasm3)

include_directories(
    ${LIBUV_INCLUDE_DIRS}
    ${UVWASI_INCLUDE_DIRS}
    ${WASM3_INCLUDE_DIRS}
    ${CJSON_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
)

# Find other required libraries
find_library(UVWASI_LIBRARY uvwasi PATHS /usr/local/lib)
find_library(UV_LIBRARY uv PATHS /usr/local/lib)
find_path(UVWASI_INCLUDE_DIR uvwasi/uvwasi.h PATHS /usr/local/include)
find_path(UV_INCLUDE_DIR uv.h PATHS /usr/local/include)

if(NOT UVWASI_LIBRARY OR NOT UVWASI_INCLUDE_DIR)
    message(FATAL_ERROR "uvwasi library not found")
endif()

if(NOT UV_LIBRARY OR NOT UV_INCLUDE_DIR)
    message(FATAL_ERROR "libuv library not found")
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
    src/mxd_crypto.c
    src/mxd_address.c
    src/base58.c
    src/blockchain/mxd_blockchain.c
    src/blockchain/mxd_rsc.c
    src/mxd_transaction.c
    src/mxd_utxo.c
    src/mxd_mempool.c
    src/mxd_p2p.c
    src/mxd_smart_contracts.c
    src/checkpoints/mxd_checkpoints.c
    src/quantization/mxd_data_quantization.c
    src/mxd_ntp.c
    src/mxd_metrics.c
    src/mxd_dht.c)


# Link libraries
if(WIN32)
    target_link_libraries(mxd 
        ${OPENSSL_LIBRARIES}
        sodium
        gmp
        ${LIBUV_LIBRARIES}
        ${UVWASI_LIBRARIES}
        ${WASM3_LIBRARIES}
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
        ${UVWASI_LIBRARIES}
        ${WASM3_LIBRARIES}
        ${CJSON_LIBRARIES}
        ${CURL_LIBRARIES}
        -Wl,--no-whole-archive
        m
        pthread
        dl
        rt)
endif()

# Include directories
target_include_directories(mxd PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

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
    src/node/metrics_display.c
    src/utils/mxd_http.c)

# Add main node executable
add_executable(mxd_node src/node/main.c)
target_link_libraries(mxd_node PRIVATE mxd)
install(TARGETS mxd_node
    RUNTIME DESTINATION bin)

# Install default configuration file alongside the executable
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/node/default_config.json
    DESTINATION bin)

# Ensure whole-archive linking
set_target_properties(mxd_node PROPERTIES
    LINK_FLAGS "-Wl,--whole-archive"
    LINK_WHAT_YOU_USE TRUE)
