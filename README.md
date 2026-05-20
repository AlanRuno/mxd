# MXD — Mexican Denarius

[![CI](https://github.com/AlanRuno/mxd/actions/workflows/ci.yml/badge.svg)](https://github.com/AlanRuno/mxd/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AlanRuno/mxd)](https://github.com/AlanRuno/mxd/releases)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Issues](https://img.shields.io/github/issues/AlanRuno/mxd)](https://github.com/AlanRuno/mxd/issues)
[![Discussions](https://img.shields.io/github/discussions/AlanRuno/mxd)](https://github.com/AlanRuno/mxd/discussions)

> *"Firm roots, strong coin: MXD — Planting the seeds for digital economy in Mexico."*

**Mexican Denarius (MXD)** is a hybrid classical/post-quantum Layer-1 blockchain
with a one-way bridge to BNB Smart Chain. The project name comes from "deni"
("containing ten"), the Latin root of denarius, hat-tipping the decimal base
behind every monetary system. Both Ed25519 (classical, fast) and ML-DSA-87 /
Dilithium5 (FIPS 204, quantum-resistant) signature schemes are first-class
citizens at the address, transaction, and consensus layers.

This repository contains the reference C implementation of the chain, the
BSC-side bridge contract, the spec documents (`docs/standards/MXD-*`), and
operator utilities. The chain is live on mainnet; see the [protocol specs](docs/standards/MXD-00-index.md)
for wire formats and address derivation rules.

## About the project

MXD is built to be a fee-free, energy-efficient digital currency that hands
control of value transfer back to its users. The economic and product context
— mission, voluntary-tip-driven incentive model, optional fiscal-integration
roadmap, and the broader vision for a digital economy in Mexico — is laid out
in the project [white paper](https://mxd.com.mx/WhitePaper_En.pdf). This
repository is the technical implementation of that vision: the chain, the
bridge, the cryptography, and the conformance specs.

The work began in 2020 under the **Cripto Águila** (Crypto Eagle) team and is
operated today by [Runo Networks](https://runonetworks.com).

## Status

| Component        | State                                              |
|------------------|----------------------------------------------------|
| Chain core       | Mainnet live — 5 validator quorum, round-robin BFT |
| Address format   | MXD-01 v1.1 (addr32, dual-algo Ed25519 + Dilithium5) |
| Bridge BSC → MXD | Live (one-way). Contract: `0xCae102064d8E9e13d5b48F38bAc53d1155B331B4` |
| Bridge MXD → BSC | **Disabled.** No code path exercised on mainnet.   |
| Oracle quorum    | 3-of-5 Dilithium5 K-of-N attestation per mint      |

## Architecture at a glance

- **Consensus.** Round-robin proposer with K-of-N validator chain signatures.
  Empty heartbeat blocks every ~5s when idle. Reorg via fork-choice score.
- **Transactions.** UTXO model, 64-bit base units (`1 MXD = 100,000,000` base units).
  v3 transactions carry typed payloads for bridge mints and admin operations.
- **Fee model.** Network-mandated transaction fees are **zero**: validators
  only enforce `inputs >= outputs`. Senders MAY attach a voluntary tip
  (`voluntary_tip` u64 field) that is distributed to the validators
  participating in block closure, rewarding faster responders proportionally
  more. The chain does not impose, deduct, or split off an implicit fee.
- **Signing.** Per-output algo_id selects Ed25519 (algo 1) or Dilithium5 (algo 2).
  All addresses are 32 bytes with a version byte for network + algorithm.
- **Bridge.** Users deposit BNBMXD on BSC; an oracle set of 5 Dilithium5 keys
  attests N-of-M to the deposit; the MXD node validates every signature and
  mints the equivalent MXD via a coinbase-shaped `bridge_mint` v3 tx. Replay
  protection is enforced at the consensus layer by an on-chain
  `bridge_tx:<source_tx_hash>` index.
- **Admin operations.** `AUTHORIZE_BRIDGE`, `REVOKE_BRIDGE`, `UPDATE_ORACLE_SET`
  admin transactions require 3-of-5 oracle Dilithium5 signatures over a
  canonical message. See [MXD-API-01](docs/standards/MXD-API-01-bridge-oracle-attestation.md).

## Specifications

All wire formats, signature schemes, address derivation, and protocol invariants
live in [`docs/standards/`](docs/standards/):

| Spec      | Topic                                                  |
|-----------|--------------------------------------------------------|
| MXD-00    | Index of standards                                     |
| MXD-01    | Address format (addr32, dual-algo)                     |
| MXD-02    | Mnemonic + HD derivation (BIP-39 + per-algo paths)     |
| MXD-03    | Signing and verification (Ed25519 + Dilithium5)        |
| MXD-04    | Transaction format and sighash                         |
| MXD-05    | Wallet-at-rest encryption                              |
| MXD-06    | P2P handshake                                          |
| MXD-API-01 | Bridge oracle attestation (K-of-N canonical message)  |

Each spec ships with `*-test-vectors.json` for cross-implementation conformance.

## Building

Dependencies are installed via the platform-specific scripts at the repo root:

```bash
./install_dependencies_linux.sh    # or _macos.sh / _windows.sh
```

Then a standard CMake out-of-source build:

```bash
mkdir build && cd build
cmake ..
cmake --build . --parallel
```

Outputs land in `build/lib/`:

- `libmxd.so` — shared library with the chain core, transaction codec, consensus, bridge, etc.
- `mxd_node` — validator/node binary linking against `libmxd.so`

For development workflow, build options, and test conventions, see
[`CONTRIBUTING.md`](CONTRIBUTING.md). The configuration loader and its defaults
live in `src/mxd_config.c`.

## Smart contracts

The BSC-side bridge contracts are in [`contracts/contracts/`](contracts/contracts/):

- `BNBMXD.sol` — fixed-supply ERC-20 representation of MXD on BSC mainnet
- `MXDBridgeV3.sol` — the live one-way bridge contract
- `TestBNBMXD.sol` — testnet token (BSC testnet only)
- `MXDBridge.sol` — V1/V2 historical reference (not deployed on mainnet)

Build and test with Hardhat:

```bash
cd contracts
npm install
npx hardhat test
npx hardhat compile
```

For mainnet deploys, set `BSC_MAINNET_RPC_URL` (your own RPC endpoint) and
`DEPLOYER_PRIVATE_KEY` in your environment — see [`contracts/hardhat.config.js`](contracts/hardhat.config.js).

## Tools

[`tools/`](tools/) contains the three utilities that are useful to anyone
building against or auditing MXD:

- `mxd_sign.c` — standalone CLI for the FIPS 204 ML-DSA-87 sign/verify path.
  Useful for any client implementing the spec without linking libmxd
  (alternative-language ports, independent signature verifiers, etc.).
- `gen_test_vectors.c` — regenerates the `docs/standards/MXD-*-test-vectors.json`
  golden files from the C reference implementation. Run this after modifying
  any wire-format or signing code to keep the cross-implementation conformance
  fixtures in sync.
- `generate_node_key.py` — generates a fresh `node_keys.v2` validator identity
  file (106 bytes, Ed25519). Required when bringing up a new validator.

Operator-side tooling (admin-tx signing, bridge-auth registry maintenance,
historical migration utilities) is not redistributed here — those are tightly
coupled to the canonical operator's deployment and are not useful in isolation.
The wire format for admin transactions is fully specified in
[MXD-API-01](docs/standards/MXD-API-01-bridge-oracle-attestation.md), so any
party can implement an admin-tx signer from the spec alone.

## Running a validator

External validators are welcome. The current set of 5 mainnet validators is
maintained by Runo Networks; expansion requires an `UPDATE_VALIDATOR_SET` admin
transaction (3-of-5 oracle quorum). To prepare:

1. Build `mxd_node` and `libmxd.so` from this repo.
2. Generate a validator identity: `python3 tools/generate_node_key.py --out data/node_keys.v2`
3. Configure your node from the sample in `src/mxd_config.c` — point at your
   data directory and set your external IP. The node will bootstrap from
   `https://mxd.network/bootstrap/main` automatically (mainnet) or
   `https://mxd.network/bootstrap/test` (testnet), falling back to the
   hardcoded `bootstrap{1,2,3}.mxd.network:8000` seeds if the HTTP fetch
   fails. See `mxd_fetch_bootstrap_nodes` in `src/mxd_config.c` for the
   full discovery flow.
4. Reach out via Issues or Discussions to be added to the active validator set.

## Oracle set (mainnet)

See [`docs/MAINNET_ORACLE_SET.md`](docs/MAINNET_ORACLE_SET.md) for the 5
Dilithium5 public keys + derived addresses of the on-chain mainnet oracle set.
These keys are also published on-chain via the `UPDATE_ORACLE_SET` admin tx.

## Security

Found a vulnerability? See [`SECURITY.md`](SECURITY.md) for the responsible
disclosure policy.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for build instructions, test
conventions, PR guidelines, and commit message style.

## License

AGPL-3.0-only. See [`LICENSE`](LICENSE).

The AGPL was chosen deliberately: any deployment that exposes the chain or
bridge to users over a network must publish its source modifications. This
keeps the protocol auditable as the network grows and prevents proprietary
forks from running closed-source.

## Acknowledgments

- The **Cripto Águila** (Crypto Eagle) team for the founding vision, the
  whitepaper, and four years of research that led to this release.
- ML-DSA-87 / Dilithium5: NIST FIPS 204 (CRYSTALS-Dilithium team).
- RocksDB, libmicrohttpd, cJSON, OpenSSL — the standard library dependencies.
- The BSC team for the underlying BNB Smart Chain that hosts the bridge.

Mainnet is operated by [Runo Networks](https://runonetworks.com). Read the
project white paper at [mxd.com.mx](https://mxd.com.mx/WhitePaper_En.pdf).
