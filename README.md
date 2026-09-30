# MXD - Mexican Denarius

Post-quantum payment and settlement infrastructure built in Mexico. A UTXO-based layer-1 ledger with Rapid Stake Consensus (RSC), hybrid post-quantum cryptography, and zero mandatory transaction fees. Written in C.

## Overview

MXD is a layer-1 settlement network designed for efficient, secure, and accessible digital payments. Mainnet has been live since 2026-05-18 and runs protocol v7; protocol v8 activates at block height 100. Validator rankings are embedded in block headers for transparent, deterministic proposer selection.

MXD is infrastructure, not a crypto-asset offering: the network exists so that institutions, businesses, and developers can clear and settle transactions and tokenize assets and processes on a ledger that is already resistant to quantum attacks. The native unit (MXD) is the network's internal unit of account for metering and settling activity.

Key design choices:

- **UTXO transaction model** with voluntary tips (no mandatory fees)
- **Hybrid cryptography**: Ed25519 (default) + Dilithium5 (post-quantum), selectable per node at runtime via `algo_id`
- **Rapid Stake Consensus (RSC)**: round-robin block proposal with score-weighted fallback and validation-chain signatures from at least ceil(2N/3) of the Rapid Table
- **RocksDB** storage for blocks, UTXOs, and address indexes
- **Bridge support**: one-way inbound bridge from BNB Smart Chain (BNB → MXD) with v3 bridge mint transactions

The project builds into two artifacts: `libmxd.so` (shared library) and `mxd_node` (standalone node binary).

## Features

- Zero mandatory fees -- users may attach voluntary tips
- Hybrid Ed25519 / Dilithium5 signatures on the same network
- On-chain validator ranking (rank score, stake, reliability and performance metrics, exposed by `GET /validators`)
- Deterministic total supply tracking per block
- WASM3-based smart contracts (basic support, disabled by default)
- HTTP JSON API for wallets, explorers, and bridge integrations
- P2P networking with DHT-based node discovery
- Cross-platform: Linux, macOS, Windows (MSYS2)

## Quick start

Easiest path for new operators — downloads a prebuilt release, verifies SHA256, runs:

```bash
git clone --depth 1 https://github.com/AlanRuno/mxd.git
cd mxd
./letsgo testnet                # default: download prebuilt + run
./letsgo testnet --docker       # alternative: pull + run Docker image
./letsgo testnet --from-source  # legacy: compile everything from source (~10-20 min)
```

The prebuilt path is fully self-contained — no `apt install` of system libraries
required. Works on any Linux with glibc ≥ 2.35 (Ubuntu 22.04+, Debian 12+,
Fedora 36+, Rocky 9+, Arch, Alpine 3.18+ with gcompat).

### Running on Windows

Two paths:

- **WSL2 (recommended, easiest)** — double-click `letsgo-wsl.bat`. It will
  install WSL2 + Ubuntu-22.04 automatically if not already present (first run
  requires admin + reboot), then run the prebuilt Linux node inside WSL.
  Requirements: Windows 10 21H2+ or Windows 11.
- **MSYS2/MinGW64 (compile from source)** — run `letsgo.bat` in a system that
  already has MSYS2 installed. Produces a Windows-native binary, but takes
  10-20 min on first run and depends on MSYS2 DLLs at runtime.

For most Windows users WSL2 is dramatically simpler. Use the MSYS2 path only
if WSL is unavailable in your environment.

## Building from source

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
git clone https://github.com/AlanRuno/mxd.git
cd mxd
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

### Networks

| Network | `chain_id` | Status (2026-09-30) |
|---------|-----------|---------------------|
| Mainnet | `0x4D580001` | Live since 2026-05-18. Five validators operated by Runo Networks; public read API on port **8080**, P2P on port **8000**. Explorer and wallet: https://mxd.network |
| Testnet | `0x4D580002` | Public fleet offline. Run your own nodes with the testnet configuration if you need one. |

The node takes its chain id from the `MXD_CHAIN_ID` environment variable (`mainnet` by default, `testnet` for a testnet node).

## API Endpoints (summary)

Public routes served by the node's HTTP server (mainnet validators expose them on port 8080):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness and component checks |
| GET | `/status` | Chain height, latest hash, supply, validator count |
| GET | `/chain_id` | Configured chain id |
| GET | `/validators` | Current validator set, rank scores and metrics |
| GET | `/utxos/{addr32_hex}` | Unspent outputs of an address (64-hex addr32) |
| GET | `/balance/{addr32_hex}` | Balance and UTXO counters of an address |
| GET | `/metrics` | Prometheus metrics |
| POST | `/transaction` | Submit a signed transaction as `{"signed_tx": "<hex wire bytes>"}` (MXD-04 §10.1) |
| POST | `/bridge/submit` | Submit a bridge mint transaction carrying the oracle attestations (MXD-API-01) |
| POST | `/admin/submit` | Submit a pre-signed admin transaction (3-of-5 oracle quorum) |

Transactions are signed client-side; the node never receives private keys. Administrative
routes require a bearer token or a signature quorum, and the in-node wallet routes
(`/wallet/*`) are disabled on mainnet. See `src/mxd_monitoring.c` and `src/mxd_http_api.c`
for the full list and the request/response formats.

## Bridge Support

MXD includes a native bridge endpoint (`/bridge/submit`) for the network's **one-way, inbound** bridge: assets move from BNB Smart Chain into MXD (BNB → MXD), never the other way. Bridge mint transactions use the v3 transaction format and are validated against the bridge oracle before inclusion in a block.

Live deployment (BNB Smart Chain mainnet, chain id 56):

| Component | Value |
|-----------|-------|
| Bridge contract | `MXDBridgeV3` at `0xCae102064d8E9e13d5b48F38bAc53d1155B331B4` (source: `contracts/contracts/MXDBridgeV3.sol`) |
| Token burned on deposit | Denarius MXD (BNBMXD) `0xdf1f7AdF59a178BA83f6140a4930cf3BEB7b73BF`, 9 decimals |
| Contract governance | K-of-N EIP-712 operator signatures (domain `MXDBridge` / `3`) |
| Mint attestation | 3-of-5 Dilithium5 oracle quorum, see [MAINNET_ORACLE_SET.md](docs/MAINNET_ORACLE_SET.md) and [MXD-API-01](docs/standards/MXD-API-01-bridge-oracle-attestation.md) |

Earlier bridge contracts are retired; only the address above is valid.

## Documentation

The `docs/` directory contains detailed guides:

- [Standards index](docs/standards/MXD-00-index.md): MXD-01 address format, MXD-02 key derivation, MXD-03 signing, MXD-04 transaction format and sighash, MXD-05 wallet at rest, MXD-06 P2P handshake, MXD-API-01 bridge oracle attestation, MXD-CONS-01/02 consensus signatures and fork choice, MXD-PQ-00 post-quantum wallet profile, each with JSON test vectors
- [Mainnet oracle set](docs/MAINNET_ORACLE_SET.md)
- [Security policy](SECURITY.md) and [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [MXD Whitepaper (English)](https://mxd.com.mx/WhitePaper_En.pdf)

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE) for details.
