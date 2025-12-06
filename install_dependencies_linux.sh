#!/bin/bash

set -e

FORCE_BUILD=false

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get the full path to ldconfig
get_ldconfig_path() {
    # First try the normal command
    if command -v ldconfig >/dev/null 2>&1; then
        command -v ldconfig
        return 0
    fi
    
    # If normal command fails, check common locations
    for path in /sbin/ldconfig /usr/sbin/ldconfig /usr/bin/ldconfig /bin/ldconfig; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    # If not found in common locations, try to find it
    ldconfig_path=$(which ldconfig 2>/dev/null)
    if [ -n "$ldconfig_path" ] && [ -x "$ldconfig_path" ]; then
        echo "$ldconfig_path"
        return 0
    fi
    
    return 1
}

ensure_ldconfig_available() {
    # First try the normal ldconfig command
    if command -v ldconfig >/dev/null 2>&1; then
        return 0
    fi
    
    # If normal command fails, try to find the full path
    if get_ldconfig_path >/dev/null; then
        return 0
    fi
    
    # If still not found, try to install it
    log "ldconfig not found, installing libc-bin package..."
    sudo apt-get update
    sudo apt-get install -y libc-bin
    
    # After installation, check again
    if command -v ldconfig >/dev/null 2>&1 || get_ldconfig_path >/dev/null; then
        return 0
    fi
    
    log "Error: Failed to find ldconfig. Using alternative methods to check libraries."
    return 1
}

check_library_installed() {
    local lib=$1
    # First try the normal ldconfig command
    if command -v ldconfig >/dev/null 2>&1; then
        ldconfig -p | grep "$lib" >/dev/null 2>&1
        return $?
    else
        # If normal command fails, try to find the full path
        local ldconfig_path=$(get_ldconfig_path)
        if [ -n "$ldconfig_path" ]; then
            "$ldconfig_path" -p | grep "$lib" >/dev/null 2>&1
            return $?
        else
            # Alternative method: check if the library exists in common library paths
            find /usr/lib /usr/local/lib /lib /lib64 -name "$lib*" 2>/dev/null | grep -q "$lib"
            return $?
        fi
    fi
}

verify_pkgconfig() {
    local pkg=$1
    local min_version=$2
    if ! pkg-config --exists "$pkg"; then
        log "Error: $pkg.pc not found in pkg-config search path"
        log "Search paths: $(pkg-config --variable pc_path pkg-config)"
        log "Installed .pc files: $(find /usr/local/lib/pkgconfig -name '*.pc' 2>/dev/null)"
        return 1
    fi
    if [ -n "$min_version" ] && ! pkg-config --atleast-version="$min_version" "$pkg"; then
        log "Error: $pkg version $(pkg-config --modversion "$pkg") is less than required $min_version"
        return 1
    fi
    log "Successfully verified $pkg$([ -n "$min_version" ] && echo " >= $min_version")"
    return 0
}

check_wasm3_installed() {
    # Check for library files and headers
    if [[ "$OSTYPE" == "darwin"* ]]; then
        ([ -f "/usr/local/lib/libm3.dylib" ] || [ -f "/usr/local/lib/libm3.a" ]) && \
        [ -f "/usr/local/include/wasm3.h" ] && \
        [ -f "/usr/local/lib/cmake/wasm3/wasm3Config.cmake" ]
    else
        # Check for library using ldconfig or find
        if command -v ldconfig >/dev/null 2>&1; then
            (ldconfig -p | grep -E "libm3\.(so|a)" >/dev/null 2>&1) && \
            [ -f "/usr/local/include/wasm3.h" ] && \
            [ -f "/usr/local/lib/cmake/wasm3/wasm3Config.cmake" ]
        else
            # If normal command fails, try to find the full path
            local ldconfig_path=$(get_ldconfig_path)
            if [ -n "$ldconfig_path" ]; then
                ("$ldconfig_path" -p | grep -E "libm3\.(so|a)" >/dev/null 2>&1) && \
                [ -f "/usr/local/include/wasm3.h" ] && \
                [ -f "/usr/local/lib/cmake/wasm3/wasm3Config.cmake" ]
            else
                (find /usr/local/lib -name "libm3.so*" -o -name "libm3.a" 2>/dev/null | grep -q "libm3") && \
                [ -f "/usr/local/include/wasm3.h" ] && \
                [ -f "/usr/local/lib/cmake/wasm3/wasm3Config.cmake" ]
            fi
        fi
    fi
}

check_libuv_installed() {
    check_library_installed "libuv.so" && [ -f "/usr/local/include/uv.h" ]
}

check_uvwasi_installed() {
    check_library_installed "libuvwasi.so" && [ -f "/usr/local/include/uvwasi/uvwasi.h" ]
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force_build)
                FORCE_BUILD=true
                shift
                ;;
            *)
                log "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

verify_system_deps() {
    local errors=0
    for lib in libssl.so libsodium.so libgmp.so; do
        if ! check_library_installed "$lib"; then
            log "Error: $lib not found"
            errors=$((errors + 1))
        fi
    done
    return $errors
}

install_system_deps() {
    sudo apt-get update
    sudo apt-get install -y build-essential cmake pkg-config libssl-dev libsodium-dev libgmp-dev libc-bin libcjson-dev libcurl4-openssl-dev librocksdb-dev libminiupnpc-dev
    
    # Run ldconfig if available
    if command -v ldconfig >/dev/null 2>&1; then
        sudo ldconfig
    else
        # Only use full path as fallback
        local ldconfig_path=$(get_ldconfig_path)
        if [ -n "$ldconfig_path" ]; then
            sudo "$ldconfig_path"
        fi
    fi
    
    if ! verify_system_deps; then
        log "Error: Some system dependencies are still missing"
        exit 1
    fi
}

create_wasm3_cmake_config() {
    sudo tee /usr/local/lib/cmake/wasm3/wasm3Config.cmake > /dev/null << 'EOF'
if(NOT TARGET wasm3::m3)
    add_library(wasm3::m3 UNKNOWN IMPORTED)
    set_target_properties(wasm3::m3 PROPERTIES
        IMPORTED_LOCATION "/usr/local/lib/libm3${CMAKE_SHARED_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
    )
endif()
set(WASM3_FOUND TRUE)
EOF
}

install_wasm3() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding wasm3..."
        sudo rm -rf /usr/local/lib/libm3.so* /usr/local/include/wasm3*
    elif check_wasm3_installed; then
        log "wasm3 is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing wasm3..."
    # Clean up existing wasm3 directory if it exists
    rm -rf wasm3
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    # Modify wasm3's CMake to support shared library and install targets
    # Create a new CMakeLists.txt in source directory
    # Patch CMake files to build shared library
    sed -i 's/add_library(m3 STATIC/add_library(m3 SHARED/' source/CMakeLists.txt
    sed -i 's/STATIC/SHARED/' source/CMakeLists.txt
    
    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add source files
file(GLOB M3_SOURCES source/*.c)

# Add library target
add_library(m3 SHARED ${M3_SOURCES})

# Find dependencies
find_library(UVWASI_LIB uvwasi REQUIRED)
find_library(UV_LIB uv REQUIRED)

# Link dependencies
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB} m pthread dl)

# Set library properties
set_target_properties(m3 PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    OUTPUT_NAME m3
    C_VISIBILITY_PRESET default
    VISIBILITY_INLINES_HIDDEN OFF
    LINK_FLAGS "-Wl,-rpath,/usr/local/lib"
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE)

# Add include directories
target_include_directories(m3 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/source>
    $<INSTALL_INTERFACE:include>)

# Install headers to wasm3 subdirectory
file(GLOB HEADER_FILES source/*.h)
install(FILES ${HEADER_FILES} DESTINATION include/wasm3)

# Install library
install(TARGETS m3 EXPORT wasm3Targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Add executable target
add_executable(wasm3 platforms/app/main.c)
target_link_libraries(wasm3 PRIVATE m3)

# Install executable
install(TARGETS wasm3 RUNTIME DESTINATION bin)

# Generate and install pkg-config file
message(STATUS "Generating pkg-config file...")
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)

if(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc)
    message(FATAL_ERROR "Failed to generate wasm3.pc")
endif()

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION lib/pkgconfig)

# Generate and install CMake config files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    VERSION 1.0.0
    COMPATIBILITY SameMajorVersion)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    @ONLY)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/wasm3ConfigVersion.cmake"
    DESTINATION lib/cmake/wasm3)

install(EXPORT wasm3Targets
    FILE wasm3Targets.cmake
    NAMESPACE wasm3::
    DESTINATION lib/cmake/wasm3)
EOL

    # Create CMake config file template
    cat > source/wasm3Config.cmake.in << 'EOL'
@PACKAGE_INIT@

include(CMakeFindDependencyMacro)
find_dependency(uvwasi)
find_dependency(uv)

include("${CMAKE_CURRENT_LIST_DIR}/wasm3Targets.cmake")

set(WASM3_INCLUDE_DIR "@CMAKE_INSTALL_PREFIX@/include")
set(WASM3_LIBRARY_DIR "@CMAKE_INSTALL_PREFIX@/lib")
set(WASM3_LIBRARIES m3)
EOL

    # Create pkg-config file
    mkdir -p source
    echo "Creating source directory and copying pkg-config file..."
    # Get the directory where the installation scripts are located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cp "${SCRIPT_DIR}/wasm3.pc.in" source/wasm3.pc.in || {
        echo "Failed to copy wasm3.pc.in. Debug info:"
        echo "Current directory: $(pwd)"
        echo "Script directory: ${SCRIPT_DIR}"
        echo "Source exists: $(test -f "${SCRIPT_DIR}/wasm3.pc.in" && echo "Yes" || echo "No")"
        echo "Target directory exists: $(test -d source && echo "Yes" || echo "No")"
        exit 1
    }
    
    # Build and install
    mkdir -p build && cd build
    CFLAGS="-fPIC -fvisibility=default" \
    CXXFLAGS="-fPIC -fvisibility=default" \
    LDFLAGS="-L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" \
          -DCMAKE_INSTALL_RPATH="/usr/local/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON \
          -DCMAKE_SHARED_LINKER_FLAGS="-Wl,--no-undefined -Wl,--as-needed" \
          -DCMAKE_EXE_LINKER_FLAGS="-Wl,--no-undefined -Wl,--as-needed" \
          ..
    make
    sudo make install
    # Run ldconfig if available
    if command -v ldconfig >/dev/null 2>&1; then
        sudo ldconfig
    else
        # Only use full path as fallback
        local ldconfig_path=$(get_ldconfig_path)
        if [ -n "$ldconfig_path" ]; then
            sudo "$ldconfig_path"
        fi
    fi
    cd ../..
    rm -rf wasm3
    
    # Verify wasm3 installation
    if ! verify_pkgconfig wasm3 "1.0.0"; then
        log "Error: wasm3 pkg-config verification failed"
        exit 1
    fi
}

install_libuv() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding libuv..."
        sudo rm -rf /usr/local/lib/libuv.so* /usr/local/include/uv*
    elif check_libuv_installed; then
        log "libuv is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing libuv..."
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" -DCMAKE_INSTALL_RPATH="/usr/local/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON -DLIBUV_BUILD_SHARED=ON -DUVWASI_BUILD_SHARED=ON ..
    make
    sudo make install
    cd ../..
    rm -rf libuv
    
    # Verify libuv installation
    if ! verify_pkgconfig libuv "1.0.0"; then
        log "Error: libuv pkg-config verification failed"
        exit 1
    fi
}

install_uvwasi() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding uvwasi..."
        sudo rm -rf /usr/local/lib/libuvwasi.so* /usr/local/include/uvwasi*
    elif check_uvwasi_installed; then
        log "uvwasi is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing uvwasi..."
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" -DCMAKE_INSTALL_RPATH="/usr/local/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON -DLIBUV_BUILD_SHARED=ON -DUVWASI_BUILD_SHARED=ON ..
    make
    sudo make install
    cd ../..
    rm -rf uvwasi
    
    # Verify uvwasi installation
    if ! verify_pkgconfig uvwasi "0.0.20"; then
        log "Error: uvwasi pkg-config verification failed"
        exit 1
    fi
}

verify_installation() {
    local errors=0
    
    # Check system dependencies
    for cmd in cmake gcc g++; do
        if ! check_command $cmd; then
            log "Error: $cmd not found"
            errors=$((errors + 1))
        fi
    done

    # Check libraries
    for lib in libssl.so libsodium.so libgmp.so; do
        if ! check_library_installed "$lib"; then
            log "Error: $lib not found"
            errors=$((errors + 1))
        fi
    done
    
    # Verify pkg-config files
    local pkgconfig_errors=0
    for pkg in wasm3 uvwasi libuv; do
        if ! verify_pkgconfig "$pkg"; then
            pkgconfig_errors=$((pkgconfig_errors + 1))
        fi
    done
    
    if [ "$pkgconfig_errors" -gt 0 ]; then
        log "Error: Some pkg-config files are missing or invalid"
        return 1
    fi

    return $errors
}

main() {
    log "Starting installation..."
    parse_args "$@"
    
    # Ensure ldconfig is available
    ensure_ldconfig_available
    
    install_system_deps
    install_libuv
    install_uvwasi
    install_wasm3
    
    # Run ldconfig if available
    if command -v ldconfig >/dev/null 2>&1; then
        sudo ldconfig
    else
        # Only use full path as fallback
        local ldconfig_path=$(get_ldconfig_path)
        if [ -n "$ldconfig_path" ]; then
            sudo "$ldconfig_path"
        fi
    fi

    if verify_installation; then
        log "Installation completed successfully"
    else
        log "Installation completed with errors"
        exit 1
    fi
}

main "$@"
