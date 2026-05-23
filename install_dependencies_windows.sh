#!/bin/bash

set -e

FORCE_BUILD=false

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

MINGW_PREFIX="/mingw64"
export PATH="${MINGW_PREFIX}/bin:${PATH}"

check_library_installed() {
    local lib=$1
    find "${MINGW_PREFIX}/lib" -name "lib${lib}.dll*" >/dev/null 2>&1
}

check_wasm3_installed() {
    # Check for library files and headers
    [ -f "${MINGW_PREFIX}/bin/libm3.dll" ] && \
    [ -f "${MINGW_PREFIX}/include/wasm3/wasm3.h" ] && \
    [ -f "${MINGW_PREFIX}/lib/cmake/wasm3/wasm3Config.cmake" ]
}

check_libuv_installed() {
    check_library_installed "libuv" && [ -f "${MINGW_PREFIX}/include/uv.h" ]
}

check_uvwasi_installed() {
    check_library_installed "libuvwasi" && [ -f "${MINGW_PREFIX}/include/uvwasi/uvwasi.h" ]
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
    for lib in libssl libsodium libgmp; do
        if ! check_library_installed "$lib"; then
            log "Error: ${lib} not found"
            errors=$((errors + 1))
        fi
    done
    return $errors
}

install_system_deps() {
    if ! check_command pacman; then
        log "Error: MSYS2 is required. Please install from https://www.msys2.org"
        exit 1
    fi
    
    pacman -Syu --noconfirm
    pacman -S --noconfirm \
        git \
        mingw-w64-x86_64-toolchain \
        mingw-w64-x86_64-cmake \
        mingw-w64-x86_64-pkg-config \
        mingw-w64-x86_64-openssl \
        mingw-w64-x86_64-libsodium \
        mingw-w64-x86_64-gmp \
        mingw-w64-x86_64-cjson \
        mingw-w64-x86_64-curl \
        mingw-w64-x86_64-miniupnpc \
        mingw-w64-x86_64-rocksdb
    
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
        rm -rf ${MINGW_PREFIX}/bin/libm3.dll* ${MINGW_PREFIX}/lib/libm3.dll.a ${MINGW_PREFIX}/include/wasm3*
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

# Link dependencies (Windows-specific - no pthread, dl, or m needed)
target_link_libraries(m3 PUBLIC ${UVWASI_LIB} ${UV_LIB})

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
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)

# Generate and install pkg-config file
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/source/wasm3.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/wasm3.pc
    @ONLY)
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

    # Create pkg-config file template
    cat > source/wasm3.pc.in << 'EOL'
prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=${prefix}/lib
includedir=${prefix}/include

Name: wasm3
Description: High performance WebAssembly interpreter
Version: 1.0.0
Libs: -L${libdir} -lm3
Cflags: -I${includedir}
EOL
    
    # Build and install
    mkdir -p build && cd build
    PKG_CONFIG_PATH="${MINGW_PREFIX}/lib/pkgconfig" \
    cmake -DCMAKE_INSTALL_PREFIX="${MINGW_PREFIX}" \
          -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=ON \
          -DCMAKE_C_FLAGS="-fPIC" \
          -DCMAKE_INSTALL_RPATH="${MINGW_PREFIX}/lib" \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -DCMAKE_INSTALL_NAME_DIR="${MINGW_PREFIX}/lib" \
          -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON \
          -DCMAKE_SHARED_LIBRARY_PREFIX="lib" \
          ..
    ninja
    ninja install
    cd ../..
    rm -rf wasm3
}

install_libuv() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding libuv..."
        rm -rf ${MINGW_PREFIX}/lib/libuv.dll* ${MINGW_PREFIX}/include/uv*
    elif check_libuv_installed; then
        log "libuv is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing libuv..."
    # Clean up existing libuv directory if it exists
    rm -rf libuv
    git clone https://github.com/libuv/libuv
    cd libuv
    mkdir -p build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=${MINGW_PREFIX} -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" -DCMAKE_INSTALL_RPATH="/usr/local/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON -DLIBUV_BUILD_SHARED=ON -DUVWASI_BUILD_SHARED=ON ..
    ninja
    ninja install
    cd ../..
    rm -rf libuv
}

install_uvwasi() {
    if [ "$FORCE_BUILD" = "true" ]; then
        log "Force rebuilding uvwasi..."
        rm -rf ${MINGW_PREFIX}/lib/libuvwasi.dll* ${MINGW_PREFIX}/include/uvwasi*
    elif check_uvwasi_installed; then
        log "uvwasi is already installed, skipping (use --force_build to override)"
        return 0
    fi
    log "Installing uvwasi..."
    # Clean up existing uvwasi directory if it exists
    rm -rf uvwasi
    git clone https://github.com/nodejs/uvwasi
    cd uvwasi
    mkdir -p build && cd build
    cmake -DCMAKE_INSTALL_PREFIX=${MINGW_PREFIX} -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_C_FLAGS="-fPIC -fvisibility=default" -DCMAKE_INSTALL_RPATH="/usr/local/lib" -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_INSTALL_RPATH_USE_LINK_PATH=ON -DLIBUV_BUILD_SHARED=ON -DUVWASI_BUILD_SHARED=ON ..
    ninja
    ninja install
    cd ../..
    rm -rf uvwasi
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

    # Check libraries - Windows/MSYS2 specific
    for lib in libssl libsodium libgmp; do
        if ! check_library_installed "$lib"; then
            log "Error: ${lib} not found in ${MINGW_PREFIX}/lib"
            errors=$((errors + 1))
        fi
    done
    
    # Verify custom-built dependencies
    if ! check_library_installed "libuv"; then
        log "Error: libuv not found in ${MINGW_PREFIX}/lib"
        errors=$((errors + 1))
    fi
    
    if ! check_library_installed "libuvwasi"; then
        log "Error: libuvwasi not found in ${MINGW_PREFIX}/lib"
        errors=$((errors + 1))
    fi
    
    # Verify wasm3 installation
    if ! [ -f "${MINGW_PREFIX}/bin/libm3.dll" ]; then
        log "Error: wasm3 library not found"
        errors=$((errors + 1))
    fi
    
    # Verify wasm3 pkg-config installation
    if ! PKG_CONFIG_PATH="${MINGW_PREFIX}/lib/pkgconfig" pkg-config --exists wasm3; then
        log "Error: wasm3.pc not found by pkg-config"
        errors=$((errors + 1))
    fi

    return $errors
}

main() {
    log "Starting installation..."
    parse_args "$@"
    
    install_system_deps
    install_libuv
    install_uvwasi
    install_wasm3
    # No ldconfig needed on Windows

    if verify_installation; then
        log "Installation completed successfully"
    else
        log "Installation completed with errors"
        exit 1
    fi
}

main "$@"
