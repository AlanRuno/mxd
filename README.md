# MXD - Mexican Denarius

A UTXO-based blockchain with Rapid Stake Consensus (RSC), hybrid post-quantum cryptography, and zero mandatory transaction fees. Written in C.

## Overview

MXD is a layer-1 cryptocurrency designed for efficient, secure, and accessible digital transactions. The network runs Protocol v4, which embeds on-chain validator scoring directly into block headers for transparent, deterministic proposer selection.

Key design choices:

- **UTXO transaction model** with voluntary tips (no mandatory fees)
- **Hybrid cryptography**: Ed25519 (default) + Dilithium5 (post-quantum), selectable per node at runtime via `algo_id`
- **Rapid Stake Consensus (RSC)**: round-robin block proposal with score-weighted fallback and validation chain signatures from 50%+ of the Rapid Table
- **RocksDB** storage for blocks, UTXOs, and address indexes
- **Bridge support**: native BNB-to-MXD bridge with v3 bridge mint transactions

The project builds into two artifacts: `libmxd.so` (shared library) and `mxd_node` (standalone node binary).

## Features

- Zero mandatory fees -- users may attach voluntary tips
- Hybrid Ed25519 / Dilithium5 signatures on the same network
- Protocol v4 on-chain validator scoring (stake 30%, proposals 25%, participation 25%, latency 20%)
- Deterministic total supply tracking per block
- WASM3-based smart contracts (basic support, disabled by default)
- HTTP JSON API for wallets, explorers, and bridge integrations
- P2P networking with DHT-based node discovery
- Cross-platform: Linux, macOS, Windows (MSYS2)

## Building

### Prerequisites

```bash
# Automated (recommended)
./install_dependencies.sh [--force_build]

# Manual -- Ubuntu/Debian
sudo apt-get install -y build-essential cmake libssl-dev libsodium-dev libgmp-dev
```

Additional libraries built from source by the install script: **wasm3**, **libuv**, **uvwasi**, **RocksDB**.

### Compile

```bash
git clone https://github.com/AlanRuno/mxdlib.git
cd mxdlib
mkdir build && cd build
cmake ..
cmake --build . --parallel
```

This produces `lib/libmxd.so` and `lib/mxd_node`.

## Running

```bash
# Start with defaults (loads default_config.json)
./mxd_node

# Custom config and algorithm override
./mxd_node --config testnet.json --algo dilithium5

# Override port / register as bootstrap
./mxd_node --port 9000 --bootstrap
```

Configuration is via a JSON file. Key fields: `node_id`, `network_type`, `port`, `data_dir`, `initial_stake`, `preferred_sign_algo` (1 = Ed25519, 2 = Dilithium5), `bootstrap_nodes`. See the `default_config.json` file for all options.

### Testnet

Currently deployed on 5 GCP nodes (`mxd-test-node-testing-0` through `4`) in `us-central1-a`. HTTP API listens on port **8080**, P2P on port **8000**.

## API Endpoints (summary)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/status` | Node status and chain height |
| GET | `/block/{height}` | Block by height |
| GET | `/tx/{hash}` | Transaction by hash |
| GET | `/balance/{address}` | Address balance (UTXO sum) |
| POST | `/tx/submit` | Submit a signed transaction |
| POST | `/bridge/submit` | Submit a bridge mint transaction |
| GET | `/validators` | Current validator set and scores |
| GET | `/mempool` | Pending transactions |

See source (`mxd_http_api.c`) for the full endpoint list and request/response formats.

## Bridge Support

MXD includes a native bridge endpoint (`/bridge/submit`) for cross-chain transfers between BNB and MXD. Bridge mint transactions use the v3 transaction format and are validated against the bridge oracle before inclusion in a block.

Detailed documentation:

- [Bridge Transactions](docs/BRIDGE_TRANSACTIONS.md)
- [Bridge Deployment](docs/BRIDGE_DEPLOYMENT.md)
- [Bridge System Technical Documentation](docs/MXD_Bridge_System_Technical_Documentation.html)

## Documentation

The `docs/` directory contains detailed guides:

- [Build Instructions](docs/BUILD.md)
- [Hybrid Cryptography Guide](docs/HYBRID_CRYPTO.md)
- [Module Documentation](docs/MODULES.md)
- [Integration Guide](docs/INTEGRATION.md)
- [Serialization Spec v4](docs/serialization_spec_v4.md)
- [Smart Contracts Roadmap](docs/SMART_CONTRACTS_ROADMAP.md)
- [Security Guidelines](docs/SECURITY_GUIDELINES.md)
- [Platform Quirks](docs/PLATFORM_QUIRKS.md)
- [Determinism](docs/DETERMINISM.md)
- [MXD Whitepaper (English)](https://mxd.com.mx/WhitePaper_En.pdf)

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
