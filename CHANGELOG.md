# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The project ships specifications (`docs/standards/MXD-*`) and a reference C
implementation. Wire-format and consensus rules follow their own per-spec
versioning (see each `MXD-XX` document's change log). Repository-level
versions track the C library and tooling as a whole.

## [Unreleased]

---

## [0.1.0] — Initial public release

### Added

- Chain core C library (`libmxd`) and validator binary (`mxd_node`).
- BSC-side bridge contracts: `MXDBridgeV3.sol` (one-way BSC → MXD, K-of-N
  Dilithium5 oracle attestation), plus the `BNBMXD` token and the historical
  `MXDBridge` / `TestBNBMXD` references.
- Protocol specifications:
  - **MXD-00** — index of standards
  - **MXD-01** — address format (addr32, dual-algorithm Ed25519 + Dilithium5)
  - **MXD-02** — mnemonic and HD derivation (BIP-39 + per-algo paths)
  - **MXD-03** — signing and verification (Ed25519 + Dilithium5)
  - **MXD-04** — transaction format and sighash
  - **MXD-05** — wallet-at-rest encryption
  - **MXD-06** — P2P handshake
  - **MXD-API-01** — bridge oracle attestation (K-of-N canonical message)
  - **MXD-CONS-01** — validator consensus signatures
  - **MXD-CONS-02** — fork choice and reorganization
  - **MXD-PQ-00** — post-quantum-ready wallet profile
- JSON test vectors for every spec, suitable for cross-implementation
  conformance testing.
- Operator/implementer utilities in `tools/`:
  - `mxd_sign.c` — standalone Dilithium5 (FIPS 204 ML-DSA-87) sign/verify CLI.
  - `gen_test_vectors.c` — regenerate the `MXD-*-test-vectors.json` fixtures
    from the reference implementation.
  - `generate_node_key.py` — generate a fresh `node_keys.v2` validator identity.
- Mainnet oracle set published in `docs/MAINNET_ORACLE_SET.md` (5 Dilithium5
  public keys + derived addresses).
- C unit test suite (`tests/`) with fuzzing and sanitizer harnesses.
- Docker build (`Dockerfile`) and platform-specific dependency installers.

### Security

- Bridge mint pipeline ships with defense-in-depth across the oracle DB
  (atomic row claim, `dest_tx_hash` exclusion filter, stuck-processing
  recovery), the libmxd queue (`source_tx_hash` dedup), the consensus
  validator (`bridge_tx:<source_tx_hash>` replay guard), and the API surface
  (audit-trail `bridge_data` in `/block/N` JSON responses). Any single-layer
  bypass is structurally caught by the next layer.
- Admin operations (`AUTHORIZE_BRIDGE`, `REVOKE_BRIDGE`, `UPDATE_ORACLE_SET`)
  require a 3-of-5 Dilithium5 oracle quorum over a canonical message format
  that prevents cross-operation replay.

### License

AGPL-3.0-only.

[Unreleased]: https://github.com/AlanRuno/mxd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AlanRuno/mxd/releases/tag/v0.1.0
