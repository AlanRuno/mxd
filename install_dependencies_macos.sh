#!/bin/bash

set -e

FORCE_BUILD=false
ARCH=$(uname -m)
BREW_PREFIX=$(brew --prefix)

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_library_installed() {
    local lib=$1
    find "${BREW_PREFIX}/lib" -name "lib${lib}.dylib*" >/dev/null 2>&1
}

verify_directory_permissions() {
    local dir="$1"
    local fallback_dir=""
    
    # Try Homebrew paths first
    if [[ "$dir" == "/usr/local/"* ]]; then
        fallback_dir="${BREW_PREFIX}/opt/$(basename "$dir")"
        if [ -w "$fallback_dir" ] || mkdir -p "$fallback_dir" 2>/dev/null; then
            log "Using Homebrew fallback path: $fallback_dir"
            echo "$fallback_dir"
            return 0
        fi
    fi
    
    # Try user's home directory next
    fallback_dir="$HOME/.local/$(basename "$dir")"
    if [ -w "$fallback_dir" ] || mkdir -p "$fallback_dir" 2>/dev/null; then
        log "Using home directory fallback path: $fallback_dir"
        echo "$fallback_dir"
        return 0
    fi
    
    # Try original directory as last resort
    if [ -w "$dir" ] || mkdir -p "$dir" 2>/dev/null; then
        log "Using original path: $dir"
        echo "$dir"
        return 0
    fi
    
    log "Error: Cannot find writable directory for $dir"
    return 1
}

install_pkgconfig_manually() {
    local pc_file="${BREW_PREFIX}/lib/pkgconfig/wasm3.pc"
    local version="1.0.0"
    
    # Create pkgconfig directory if needed
    verify_directory_permissions "$(dirname "$pc_file")"
    
    # Generate pkg-config file
    cat > "$pc_file" << EOL
prefix=${BREW_PREFIX}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: wasm3
Description: High performance WebAssembly interpreter
Version: ${version}
Requires: libuv uvwasi
Libs: -L\${libdir} -lm3
Cflags: -I\${includedir}
EOL
    log "Manually created pkg-config file at $pc_file"
}

setup_pkgconfig_paths() {
    local verified_paths=()
    
    # Try standard locations in order of preference
    local standard_paths=(
        "${BREW_PREFIX}/opt/pkgconfig"
        "${BREW_PREFIX}/lib/pkgconfig"
        "${BREW_PREFIX}/share/pkgconfig"
        "$HOME/.local/lib/pkgconfig"
    )
    
    # Verify each path and collect working ones
    for dir in "${standard_paths[@]}"; do
        local actual_dir
        if actual_dir=$(verify_directory_permissions "$dir"); then
            verified_paths+=("$actual_dir")
            log "Added pkg-config path: $actual_dir"
        fi
    done
    
    # Add system paths for searching but not writing
    verified_paths+=(
        "/usr/local/lib/pkgconfig"
        "/usr/local/share/pkgconfig"
        "/usr/lib/pkgconfig"
    )
    
    # Set PKG_CONFIG_PATH with verified directories
    if [ ${#verified_paths[@]} -eq 0 ]; then
        log "Error: No writable pkg-config paths found"
        return 1
    fi
    
    export PKG_CONFIG_PATH=$(IFS=:; echo "${verified_paths[*]}"):${PKG_CONFIG_PATH:-}
    log "PKG_CONFIG_PATH set to: $PKG_CONFIG_PATH"
    return 0
}

verify_pkgconfig() {
    local pkg=$1
    local min_version=$2
    if ! pkg-config --exists "$pkg"; then
        log "Error: $pkg.pc not found in pkg-config search path"
        log "Search paths: $(pkg-config --variable pc_path pkg-config)"
        log "Debug information:"
        for dir in "${pkgconfig_paths[@]}"; do
            log "Checking $dir:"
            ls -la "$dir"/*.pc 2>/dev/null || log "  No .pc files found"
        done
        return 1
    fi
    if [ -n "$min_version" ] && ! pkg-config --atleast-version="$min_version" "$pkg"; then
        log "Error: $pkg version $(pkg-config --modversion "$pkg") is less than required $min_version"
        return 1
    fi
    log "Successfully verified $pkg$([ -n "$min_version" ] && echo " >= $min_version")"
    return 0
}

verify_system_deps() {
    local errors=0
    for lib in libssl libsodium libgmp; do
        if ! find "${BREW_PREFIX}/lib" -name "${lib}.dylib*" >/dev/null 2>&1; then
            log "Error: ${lib} not found"
            errors=$((errors + 1))
        fi
    done
    return $errors
}

install_system_deps() {
    if ! check_command brew; then
        log "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install cmake openssl libsodium gmp pkg-config
    
    if ! verify_system_deps; then
        log "Error: Some system dependencies are still missing"
        exit 1
    fi
}

check_wasm3_installed() {
    # Check for library files and headers
    [ -f "${BREW_PREFIX}/lib/libm3.dylib" ] && \
    [ -f "${BREW_PREFIX}/include/wasm3.h" ] && \
    [ -f "${BREW_PREFIX}/lib/cmake/wasm3/wasm3Config.cmake" ]
}

check_libuv_installed() {
    check_library_installed "libuv" && [ -f "${BREW_PREFIX}/include/uv.h" ]
}

check_uvwasi_installed() {
    check_library_installed "libuvwasi" && [ -f "${BREW_PREFIX}/include/uvwasi/uvwasi.h" ]
}

install_wasm3() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding wasm3..."
        rm -rf "${BREW_PREFIX}/lib/libm3.dylib*" "${BREW_PREFIX}/include/wasm3*"
    elif check_wasm3_installed; then
        log "wasm3 is already installed, skipping"
        return 0
    fi
    
    log "Installing wasm3..."
    # Clean up existing wasm3 directory if it exists
    rm -rf wasm3
    
    # Set up pkg-config paths and verify permissions
    setup_pkgconfig_paths
    
    git clone https://github.com/wasm3/wasm3
    cd wasm3
    mkdir -p build && cd build
    
    # Create pkg-config file and directory
    mkdir -p source
    mkdir -p "${BREW_PREFIX}/lib/pkgconfig"
    echo "Creating source directory and copying pkg-config file..."
    cp ../../wasm3.pc.in source/wasm3.pc.in || {
        echo "Failed to copy wasm3.pc.in. Debug info:"
        echo "Current directory: $(pwd)"
        echo "Source exists: $(test -f ../../wasm3.pc.in && echo "Yes" || echo "No")"
        echo "Target directory exists: $(test -d source && echo "Yes" || echo "No")"
        exit 1
    }
    
    # Create main CMakeLists.txt
    cat > CMakeLists.txt << 'EOL'
cmake_minimum_required(VERSION 3.12)
project(wasm3)

include(GNUInstallDirs)

option(BUILD_WASM3_LIBS "Build wasm3 libraries" ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)

# Add source files
file(GLOB M3_SOURCES ../source/*.c)
add_library(m3 ${M3_SOURCES})
target_include_directories(m3 PUBLIC ../source)

# Add executable target
add_executable(wasm3 ../platforms/app/main.c)
target_link_libraries(wasm3 PRIVATE m3)

# Configure pkg-config file
configure_file(
    ../source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)

# Install targets
install(TARGETS m3 wasm3
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Install headers
install(DIRECTORY ../source/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wasm3
    FILES_MATCHING PATTERN "*.h")

# Install pkg-config file
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
EOL

    # Configure for macOS
    # Use home directory for installation
    local install_dir="$HOME/.local"
    mkdir -p "$install_dir"/{lib,include,lib/pkgconfig}
    
    # Create pkg-config file manually first
    cat > "$install_dir/lib/pkgconfig/wasm3.pc" << EOL
prefix=$install_dir
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: wasm3
Description: High performance WebAssembly interpreter
Version: 1.0.0
Requires: libuv uvwasi
Libs: -L\${libdir} -lm3
Cflags: -I\${includedir}
EOL
    
    # Configure with correct installation paths
    cmake -DCMAKE_INSTALL_PREFIX="$install_dir" \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include \
          -DPKGCONFIG_INSTALL_DIR="$install_dir/lib/pkgconfig" \
          -DCMAKE_C_FLAGS="-fPIC" \
          -DCMAKE_INSTALL_RPATH="$install_dir/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_NAME_DIR="$install_dir/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    
    # Try CMake installation first
    if ! make install || ! verify_pkgconfig wasm3 "1.0.0"; then
        log "CMake pkg-config installation failed, trying manual installation..."
        install_pkgconfig_manually
    fi
    
    # Final verification
    if ! verify_pkgconfig wasm3; then
        log "Error: pkg-config installation failed after all attempts"
        log "Debug information:"
        pkg-config --debug --exists wasm3 2>&1 || true
        exit 1
    fi
    
    cd ../..
    rm -rf wasm3
}

install_libuv() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding libuv..."
        rm -rf "${BREW_PREFIX}/lib/libuv.dylib*" "${BREW_PREFIX}/include/uv*"
    elif check_libuv_installed; then
        log "libuv is already installed, skipping"
        return 0
    fi
    
    log "Installing libuv..."
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    
    cmake -DCMAKE_INSTALL_PREFIX="${BREW_PREFIX}" \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_INSTALL_NAME_DIR="${BREW_PREFIX}/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    
    # Try installation with fallback paths
    local install_dir="$HOME/.local"
    mkdir -p "$install_dir"/{lib,include,lib/pkgconfig}
    
    # Configure with correct installation paths
    cmake -DCMAKE_INSTALL_PREFIX="$install_dir" \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include \
          -DCMAKE_INSTALL_RPATH="$install_dir/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_BUILD_TYPE=Release \
          ..
    make install
    
    # Update pkg-config path to include the new location
    export PKG_CONFIG_PATH="$install_dir/lib/pkgconfig:$PKG_CONFIG_PATH"
    log "Installed to $install_dir"
    
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
        rm -rf "${BREW_PREFIX}/lib/libuvwasi.dylib*" "${BREW_PREFIX}/include/uvwasi*"
    elif check_uvwasi_installed; then
        log "uvwasi is already installed, skipping"
        return 0
    fi
    
    log "Installing uvwasi..."
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    
    cmake -DCMAKE_INSTALL_PREFIX="${BREW_PREFIX}" \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_INSTALL_NAME_DIR="${BREW_PREFIX}/lib" \
          -DCMAKE_MACOSX_RPATH=ON \
          ..
    
    make
    
    # Try installation with fallback paths
    local install_dir="$HOME/.local"
    mkdir -p "$install_dir"/{lib,include,lib/pkgconfig}
    
    # Configure with correct installation paths
    cmake -DCMAKE_INSTALL_PREFIX="$install_dir" \
          -DCMAKE_INSTALL_LIBDIR=lib \
          -DCMAKE_INSTALL_INCLUDEDIR=include \
          -DCMAKE_INSTALL_RPATH="$install_dir/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_BUILD_TYPE=Release \
          ..
    make install
    
    # Update pkg-config path to include the new location
    export PKG_CONFIG_PATH="$install_dir/lib/pkgconfig:$PKG_CONFIG_PATH"
    log "Installed to $install_dir"
    
    cd ../..
    rm -rf uvwasi
    
    # Verify uvwasi installation
    if ! verify_pkgconfig uvwasi "0.0.20"; then
        log "Error: uvwasi pkg-config verification failed"
        exit 1
    fi
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

main() {
    parse_args "$@"
    
    log "Installing for macOS (${ARCH})"
    install_system_deps
    install_libuv
    install_uvwasi
    install_wasm3
    
    log "All dependencies installed successfully"
}

main "$@"
