# 🛠️ Building MXD Library

## System Requirements

### 💻 Hardware Requirements
- CPU: x86_64, aarch64, armv7a, riscv64, powerpc64le, or loongarch64
- RAM: Minimum 2GB (4GB recommended)
- Storage: 500MB free space

### 🔧 Required Tools
- CMake 3.10+
- C11 compatible compiler
- OpenSSL 3.0+
- libsodium
- GMP (GNU Multiple Precision Arithmetic Library)
- wasm3
- uvwasi and libuv

### 🐧 Platform-Specific Setup

#### Ubuntu/Debian
```bash
# Update package lists
sudo apt-get update

# Install build tools
sudo apt-get install -y build-essential cmake pkg-config

# Install core dependencies
sudo apt-get install -y \
    libssl-dev \        # OpenSSL for cryptography
    libsodium-dev \     # libsodium for Dilithium5
    libgmp-dev \        # GMP for Base58 encoding
    libuv1-dev         # libuv for WebAssembly runtime

# Install optional dependencies
sudo apt-get install -y \
    clang \             # Alternative compiler
    lldb \              # Debugging support
    valgrind \          # Memory analysis
    gcovr              # Code coverage

# Set up environment variables
export OPENSSL_ROOT_DIR=/usr
export SODIUM_ROOT_DIR=/usr
export GMP_ROOT_DIR=/usr
```

#### 🔧 Compiler Requirements
- GCC 7.5+ or Clang 6.0+
- C11 standard support
- Position Independent Code (-fPIC)
- OpenMP support (optional)

#### 🍎 macOS
```bash
# Install Xcode Command Line Tools (if not installed)
xcode-select --install

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install build tools
brew install \
    cmake \            # Build system
    ninja \            # Build system (optional)
    pkg-config \       # Package configuration
    llvm              # Modern compiler toolchain

# Install core dependencies
brew install \
    openssl \          # Cryptography
    libsodium \        # Post-quantum crypto
    gmp \              # Arbitrary precision math
    libuv              # Async I/O for WASM

# Install optional development tools
brew install \
    clang-format \     # Code formatting
    valgrind \         # Memory analysis
    gcovr \            # Code coverage
    doxygen           # Documentation

# Set up environment variables
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
export SODIUM_ROOT_DIR=$(brew --prefix libsodium)
export GMP_ROOT_DIR=$(brew --prefix gmp)
export LLVM_DIR=$(brew --prefix llvm)

# Add LLVM to PATH (if using LLVM's clang)
export PATH="$(brew --prefix llvm)/bin:$PATH"
```

#### 🛠️ Build Options
```bash
# Debug build with all symbols
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build with specific compiler
cmake -DCMAKE_C_COMPILER=clang ..

#### 🪟 Windows
```powershell
# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install dependencies (x64)
.\vcpkg install --triplet x64-windows `
    openssl `    # Cryptography
    libsodium `  # Post-quantum crypto
    gmp `        # Arbitrary precision math
    libuv        # Async I/O for WASM

# Set up environment variables
$env:OPENSSL_ROOT_DIR = "C:/vcpkg/installed/x64-windows"
$env:SODIUM_ROOT_DIR = "C:/vcpkg/installed/x64-windows"
$env:GMP_ROOT_DIR = "C:/vcpkg/installed/x64-windows"

# Configure Visual Studio environment
call "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

### 🔍 Advanced Build Configuration

#### Performance Optimization
```cmake
# Enable Link Time Optimization
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

# Enable hardware-specific optimizations
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")

# Enable parallel compilation
set(CMAKE_BUILD_PARALLEL_LEVEL 8)
```

#### Debug Configuration
```cmake
# Enable address sanitizer
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")

# Enable undefined behavior sanitizer
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=undefined")

# Enable thread sanitizer
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
```

### 🔧 Troubleshooting Guide

#### Common Build Issues

1. CMake Configuration Fails
```bash
# Ensure all dependencies are installed
cmake --debug-find ..

# Set specific compiler version
cmake -DCMAKE_C_COMPILER=/usr/bin/gcc-11 ..
```

2. Linker Errors
```bash
# Link against static libraries
cmake -DBUILD_SHARED_LIBS=OFF ..

# Add library search paths
cmake -DCMAKE_PREFIX_PATH="/usr/local/lib;/opt/lib" ..
```

3. Runtime Issues
```bash
# Run with memory checker
valgrind --leak-check=full ./tests/test_main

# Enable debug logging
export MXD_LOG_LEVEL=DEBUG
```

### 📊 Performance Tuning

#### Profile-Guided Optimization
```bash
# Generate profile data
cmake -DCMAKE_C_FLAGS="-fprofile-generate" ..
make
./tests/test_main

# Use profile data
cmake -DCMAKE_C_FLAGS="-fprofile-use" ..
make
```

#### Memory Optimization
```bash
# Configure memory pools
export MXD_MEMPOOL_SIZE=10000
export MXD_MAX_UTXO_CACHE=5000

# Set garbage collection threshold
export MXD_GC_THRESHOLD=1000
```

## Build Steps

1. Clone the repository:
```bash
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib
```

2. Create build directory:
```bash
mkdir build
cd build
```

3. Configure with CMake:
```bash
# Unix-like systems
cmake ..

# Windows with vcpkg
cmake -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake ..
```

4. Build the library:
```bash
cmake --build .
```

5. Run tests:
```bash
ctest --output-on-failure
```

## Installation

### System-wide Installation
```bash
sudo cmake --install .
```

### Custom Installation Directory
```bash
cmake --install . --prefix /path/to/install
```

## Troubleshooting

### Common Issues

1. OpenSSL Not Found
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# macOS
brew install openssl
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
```

2. libsodium Not Found
```bash
# Ubuntu/Debian
sudo apt-get install libsodium-dev

# macOS
brew install libsodium
```

3. GMP Not Found
```bash
# Ubuntu/Debian
sudo apt-get install libgmp-dev

# macOS
brew install gmp
```

### Build Verification
After building, verify the installation:
```bash
# Run all tests
make test

# Run specific test
./tests/test_crypto
./tests/test_address
```
