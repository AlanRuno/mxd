# 🌟 MXD Universal Dynamic Library

A cross-platform dynamic library implementing cryptographic, blockchain, and networking functionalities with ISO compliance and post-quantum security. This library serves as the foundation for the Mexican Denarius (MXD) cryptocurrency, designed to revolutionize digital financial transactions with a focus on efficiency, security, and scalability.

## 🌐 Cryptocurrency Overview

MXD (Mexican Denarius) represents a groundbreaking advancement in digital finance, designed to revolutionize financial transactions through innovative technology and accessibility:

### 🎯 Core Features & Vision
- **Zero Mandatory Fees**: Revolutionary transaction model with optional voluntary tips
- **Advanced Consensus**: Communication speed-based mechanism ensuring optimal efficiency
- **Deployment Timeline**: 
  - Current: Pre-launch phase on BNB Smart Chain
  - 2025: Main network deployment with full feature set
- **Financial Empowerment**: Focused on simplifying digital transactions and increasing accessibility

### 💫 Technical Innovation
- **Consensus Mechanism**: Utilizes network communication speed metrics for efficient block validation
- **Transaction Model**: UTXO-based system with voluntary tip structure
- **Security**: Post-quantum cryptographic implementations with Dilithium5
- **Network Efficiency**: Optimized P2P communication with DHT-based node discovery

## 🚀 Features

### 🔐 Core Cryptographic Features
- SHA-512 & RIPEMD-160 hashing (ISO/IEC 10118-3)
- Argon2 key derivation (ISO/IEC 11889)
- Dilithium5 post-quantum signatures (ISO/IEC 18033-3) with matrix calculations
- Elliptic curve cryptography (secp256k1) for robust transaction security
- Base58Check address encoding

### 💎 Blockchain & Consensus
- Advanced communication speed-based consensus mechanism
- Network Time Protocol (NTP) synchronization for precise timing
- Collaborative real-time consensus protocol
- Transaction management with UTXO model and voluntary tip system
- Memory pool for transaction staging
- P2P networking with DHT-based discovery
- Eco-friendly design with minimal energy consumption

### 📜 Smart Contracts & Extensions
- WebAssembly (WASM) runtime using wasm3
- Contract deployment and execution
- Gas metering and limits
- State management and validation
- Secure storage with Merkle trees

## 📚 Documentation

Detailed documentation is available in the `docs` directory:
- [Module Documentation](docs/MODULES.md)
- [Build Instructions](docs/BUILD.md)
- [Integration Guide](docs/INTEGRATION.md)
- [MXD Whitepaper (English)](https://mxd.com.mx/WhitePaper_En.pdf)

The library's architecture is designed for optimal performance and security in cryptocurrency operations, with a focus on rapid transaction processing and network efficiency. Our modular design separates concerns into distinct components:

### 📦 Module Organization
- **Crypto Module**: Implements hashing (SHA-512, RIPEMD-160) and signing operations
- **Address Management**: Handles wallet address generation and validation
- **Blockchain Core**: Manages consensus mechanism and block validation
- **Transaction Processing**: Implements UTXO model with voluntary tip system
- **P2P Networking**: Handles node discovery and communication
- **Smart Contracts**: Manages WASM-based contract execution
- **Checkpoints**: Provides blockchain synchronization points
- **Data Quantization**: Optimizes data storage and transmission

## 🛠️ Quick Start

### Node Configuration
The node can be started with or without a configuration file:
```bash
# Start with custom config
./mxd_node custom_config.json

# Start with default config
./mxd_node
```
The default configuration file (`default_config.json`) is automatically loaded from the same directory as the executable if no configuration file is specified.

### Prerequisites

⚠️ **Important**: Before proceeding with any build or test operations, you must first install all dependencies:

```bash
./install_dependencies.sh [--force_build]
```

This step is mandatory and ensures all required libraries and tools are properly configured.

The script automatically detects your operating system and runs the appropriate installation script:
- Linux: Uses apt-get and builds from source
- macOS: Uses Homebrew and builds from source (supports both Intel and Apple Silicon)
- Windows: Uses MSYS2/MinGW and builds from source

Options:
- `--force_build`: Force rebuild and installation of libraries even if they are already installed

These scripts will automatically install:
#### System Dependencies
- build-essential (Ubuntu/Debian)
- cmake
- libssl-dev
- libsodium-dev
- libgmp-dev

#### Required Libraries
- wasm3 (WebAssembly Runtime)
- libuv (Event-driven Library)
- uvwasi (WASI Implementation)

The script supports both Ubuntu/Debian and macOS systems.

For manual installation instructions, see below:

#### System Dependencies (Manual Installation)
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libsodium-dev libgmp-dev

# macOS
brew install cmake openssl libsodium gmp
```

#### Required Libraries (Manual Installation)
The following libraries need to be built and installed:

1. wasm3 (WebAssembly Runtime):
```bash
git clone https://github.com/wasm3/wasm3
cd wasm3 && mkdir build && cd build
cmake -DBUILD_WASM3_LIBS=ON ..
make && sudo make install
```

2. libuv (Event-driven Library):
```bash
git clone https://github.com/libuv/libuv
cd libuv && mkdir build && cd build
cmake ..
make && sudo make install
```

3. uvwasi (WASI Implementation):
```bash
git clone https://github.com/nodejs/uvwasi
cd uvwasi && mkdir build && cd build
cmake ..
make && sudo make install
```

After installing all dependencies, update the library cache:
```bash
sudo ldconfig
```

### Build Steps
```bash
# Clone repository
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make

# Run tests (requires completed dependency installation)
make test
```

### 🧪 Testing Information
The test suite includes:
- Unit tests for all core modules
- Integration tests for blockchain operations
- Performance tests for cryptographic operations
- Network simulation tests for consensus mechanism
- Smart contract execution tests

Expected test duration: 3-5 minutes on standard hardware
Memory requirement: Minimum 4GB RAM recommended
Note: Some tests require network connectivity for P2P simulations

## 💡 Basic Usage

### Generate MXD Address
```c
#include <mxd_address.h>

char address[42];
uint8_t public_key[256];
mxd_generate_address(public_key, address, sizeof(address));
```

### Create Transaction
```c
#include <mxd_transaction.h>

mxd_transaction_t tx;
mxd_create_transaction(&tx);
mxd_add_tx_output(&tx, recipient_key, 1.0);
mxd_sign_tx_input(&tx, 0, private_key);
```

### Deploy Smart Contract
```c
#include <mxd_smart_contracts.h>

mxd_contract_state_t state;
mxd_deploy_contract(wasm_code, wasm_size, &state);
```

## 🤝 Contributing
Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links
- [Issue Tracker](https://github.com/AlanRuno/mxdlib/issues)
- [Release Notes](https://github.com/AlanRuno/mxdlib/releases)
