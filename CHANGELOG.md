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

## [0.2.0] — Permissionless validator membership (JOIN + EVICT)

### Added

- **Protocol version 8** with per-network `v8_activation_height` gate.
  Mainnet defaults to `UINT32_MAX` (no activation); operators MUST set a
  coordinated future activation height before deploying the v8 binary.
- **Peer-driven validator EVICT** — an active validator that observes a
  peer's on-chain balance has fallen below the §4.4 stake threshold
  signs an MXD-VAL-V1 EVICT (84-byte canonical bytes: domain || 0x02 ||
  target_addr32 || evictor_addr32 || timestamp_be) and broadcasts it on
  the new `MXD_MSG_VALIDATOR_EVICT_REQUEST` (P2P type 20) gossip
  channel. The 173-byte Ed25519 / ~7.3 KB Dilithium5 wire format
  carries the evictor's pubkey inline for self-contained verifiability.
- **Auto-EVICT trigger** integrated into the existing
  `auto_join_thread_func` (no new thread). When the local node is in
  the rapid_table AND v8 is active, every 60-second poll scans OTHER
  validators for balances below the threshold and signs an EVICT for
  each.
- **Block field `rapid_eviction_entries[]`** (v8+ blocks). Serialized
  alongside `rapid_membership_entries[]`; pre-v8 blocks omit the field
  for backwards compatibility.
- **Validator membership-management apply paths** lifted from the
  formerly-dead `mxd_process_validation_chain` into the three real
  block-storage paths (`mxd_blockchain_sync.c` unsolicited + bulk-sync,
  `mxd_rsc.c` proposer's own block). Both JOIN and EVICT now take
  effect on every peer's in-memory rapid_table immediately after block
  finalize, with no process restart required.
- **MXD-CONS-01 v1.2.0** — promotes `op_type=0x02` EVICT from Reserved
  to Active. Adds §4.0.2 (84-byte canonical bytes), §4.2.2
  (verification + 5-min grace period for newly-joined validators),
  §4.3.1 (173-byte gossip wire format), §4.4.2 (auto-trigger
  integration), §4.5.2 (proposer drain with dedup-by-target and
  4-validator floor for K=⅔ quorum preservation), §4.6.2 + §4.6.3
  (eviction apply + ordering rule — membership first, scoring middle,
  evictions last), §4.7.2 (storage-path EVICT signature verification).
- **`MXD-CONS-01-validator-management-test-vectors.json`** —
  deterministic test vectors covering JOIN positive, EXIT
  (deprecated) reference, EVICT positive (84-byte canonical + 173-byte
  wire payload), and cross-replay negatives proving the `op_type` byte
  defends against JOIN↔EXIT and JOIN↔EVICT signature reuse.
- **`vendor/ml-dsa-pqcrystals/`** — the FIPS 204 ML-DSA-87 reference
  implementation that the chain links against. Previously missing from
  v0.1.0 despite being referenced by `CMakeLists.txt`; v0.2.0 includes
  it so the build is self-contained.
- **Release tooling** documented in the repository README.

### Fixed

- **Use-after-free of `g_active_val_block`** in the v5 skip-timeout
  path. The proposer's validation-tracking globals (`g_active_val_ctx`,
  `g_active_val_block`, `g_active_val_table`) were not cleared before
  `mxd_stop_block_proposal()` freed the block, allowing the next
  consensus tick's skip-timeout scan to read freed memory. Latent
  v5-era race that EVICT activity exposed by extending the time
  between block-close and first signature.
- **JOIN/EVICT request pool clearing after block-apply**.
  `mxd_clear_processed_requests` existed in source since the original
  Phase 1 plumbing but (a) had no EVICT logic and (b) was never called
  from any production path. Without it, the per-(evictor, target)
  dedup in `mxd_submit_validator_evict_with_pubkey` retained stale
  pool entries after the proposer drained them, silently no-op'ing
  every subsequent EVICT for the same target. v0.2.0 extends the
  clear-helper to cover EVICT and invokes it at all three apply call
  sites, so JOIN↔EVICT cycles for the same validator address can repeat
  indefinitely without process restart.

### Changed

- **`mxd_node_stake_t::added_at_block_time_ms`** (new field) tracks
  when each validator was last added to the rapid_table. Input to the
  §4.2.2 grace-period rule on EVICT requests.
- **Dockerfile + `tools/mxd_sign.c` build comments** use `/opt/mxd`
  paths consistently (previously referenced `/opt/mxdlib`, the
  internal working-tree path).

### Validated

- Two consecutive smoke batteries on a 6-node testnet (~50 min each)
  exercised the full JOIN → idle-soak → EVICT → idle-soak → liveness
  cycle. Zero crashes, repeatable JOIN↔EVICT cycles for the same
  validator address without restart, memory flat within ±0.3 MB over
  30-minute idle windows. `scripts/release/smoke_evict_cycle.sh` in
  the private working tree is the re-runnable regression suite.
- libmxd.so SHA `cee5ed5e68526646` is the validated v0.2.0 build.

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
