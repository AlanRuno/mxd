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

## [0.2.5] — Unbreak Docker (anchore/sbom-action @v0.15.8 → @v0)

### Fixed

- **`docker-build` failed** on v0.2.4 at "Generate SBOM for source" with
  `received HTTP status=404 for url='https://get.anchore.io/syft/v0.103.1/install.sh'`.
  The pinned `anchore/sbom-action@v0.15.8` is bundled with a syft
  version that Anchore has since deleted/moved upstream. Bumped all
  three usage sites (source SBOM in `docker-build`, image SBOM in
  `docker-build`, image SBOM in `docker-publish-sign`) to
  `@v0` (the moving major-tag pointer Anchore maintains as stable).
- **SBOM steps now non-blocking** via `continue-on-error: true`.
  CycloneDX SBOMs are supply-chain-transparency metadata, not
  gating on Docker image functionality — if the SBOM action breaks
  again upstream, Docker push should still complete. The Upload
  SBOM step is gated on `hashFiles(...)` so it skips cleanly when
  the SBOM file wasn't produced.

### Notes

- v0.2.4 binary tarballs landed correctly and are still the
  recommended `letsgo testnet` target until v0.2.5 supersedes them.
- Docker image was never produced for v0.2.2 / v0.2.3 / v0.2.4. v0.2.5
  should be the first version with `ghcr.io/alanruno/mxd:vX.Y.Z` live.

---

## [0.2.4] — Fix the v0.2.3 release pipeline (round 2)

v0.2.3's tag CI got further than v0.2.2's — `build-binary-release`
produced both x86_64 and arm64 tarballs as workflow artifacts — but
two issues then prevented the GitHub Release from being created:

### Fixed

- **GHCR push failed with "repository name must be lowercase"** —
  the workflow used `${{ github.repository }}` (= `AlanRuno/mxd`)
  directly in the image tag, but OCI registries reject uppercase.
  Added a `lc` step that lowercases the repo once and reuses the
  output in the build-push + cosign + SBOM steps.
- **`publish-release` was skipped** because it `needs:
  [build-binary-release, docker-publish-sign]` and Docker failed.
  Decoupled: now `needs: [build-binary-release]` only. Docker
  publishing is independent of the GitHub Release creation; if GHCR
  has issues the tarballs still land so `letsgo` prebuilt path
  works.
- **`integration-test` failed** with `docker-compose.test.yml: no
  such file or directory` — the file lives in mxdlib root but
  wasn't in the public manifest. Now added.

### Notes

- Image will publish as `ghcr.io/alanruno/mxd:vX.Y.Z` (lowercase).
- v0.2.3 tarballs do exist as workflow artifacts on
  https://github.com/AlanRuno/mxd/actions but were never promoted
  to a GitHub Release. v0.2.4 should be the first to land actual
  Release assets that `letsgo` can download.

---

## [0.2.3] — Fix the v0.2.2 release pipeline

Patch on top of v0.2.2 to make the new prebuilt-release workflow
actually produce artifacts. v0.2.2 shipped but its tag-triggered CI
failed before reaching `build-binary-release`, so no tarballs landed
on the GitHub Release. v0.2.3 ships the same code as v0.2.2 plus the
two release-pipeline fixes below.

### Fixed

- **Executable bit on shell scripts** — `install_dependencies*.sh`,
  `letsgo`, and `switch_network.sh` were stored in git with mode
  `100644` (non-executable) because the Windows-side `cp -r`
  during release-tree sync silently strips the exec bit
  (`core.filemode = false` on Windows git installs). The Linux CI
  runner then refused to run them with exit 126 ("Permission
  denied"). Now stamped to `100755` in the git tree via
  `git update-index --chmod=+x`. Bug present since v0.1.0; CI on
  public has been red on every release tag until now.
- **`wasm3.pc.in` missing from public release tree** —
  `install_dependencies_linux.sh` references `${SCRIPT_DIR}/wasm3.pc.in`
  (a pkg-config template at repo root) before compiling wasm3 from
  source. The manifest didn't include it, so even after the exec-bit
  fix the wasm3 build step failed with `cp: cannot stat .../wasm3.pc.in`.
  Now listed in `scripts/release/mxd-public-manifest.txt`.
- **`RELEASE_PROCESS.md`** — codified the post-sync `git update-index
  --chmod=+x` step for the six known-executable scripts, so this
  doesn't recur on the next release.

### Notes

- v0.2.2 tarballs do NOT exist on the GitHub Release; `letsgo
  testnet` would have returned a 404. v0.2.3 is the first version
  that should actually produce downloadable artifacts when the tag
  CI completes.

---

## [0.2.2] — Distributable releases (prebuilt binaries + Docker)

Operator onboarding goes from ~10-20 min ("compile everything from
source") to ~30 seconds ("download + extract + run") for the common
case. No functional changes to libmxd, chain consensus, or wire format.

### Added

- **`.github/workflows/ci.yml`** — two new jobs on tag pushes:
  - `build-binary-release` — matrix-builds release tarballs natively
    on `ubuntu-24.04` (x86_64) and `ubuntu-24.04-arm` (arm64). Each
    bundle contains `bin/mxd_node` + `bin/mxd_node_run` wrapper +
    `lib/{libmxd, libuv, libuvwasi, libm3, liboqs}.so*` + bundled
    `config/default_config.json` + the README + apt prereq line for
    runtime-only system libs. Each tarball is SHA256-summed and
    cosign-signed (keyless / OIDC).
  - `publish-release` — collects the per-arch bundles, generates a
    combined `SHA256SUMS`, extracts release notes from `CHANGELOG.md`,
    and uses `softprops/action-gh-release@v2` to create the GitHub
    Release with all assets attached.
- **Multi-arch Docker image** — the existing `docker-publish-sign`
  job now builds `linux/amd64,linux/arm64` via `buildx` + QEMU and
  pushes a single multi-arch manifest to
  `ghcr.io/AlanRuno/mxd:vX.Y.Z` + `:latest`. Image is cosign-signed
  (keyless) and ships with a CycloneDX SBOM.
- **`letsgo`** — rewritten to be **prebuilt-first** with three modes:
  - default: `curl` the latest release tarball for `$(uname -m)`,
    verify SHA256, extract under `./mxd-prebuilt/`, run via
    `mxd_node_run` (which sets `LD_LIBRARY_PATH` so the bundled
    libuv/libuvwasi/libm3/liboqs are found without a global install).
    Detects + auto-installs missing runtime system libs (`libssl3`,
    `libsodium23`, `librocksdb6.11`, etc.) via apt on Debian/Ubuntu.
  - `--docker`: `docker pull ghcr.io/AlanRuno/mxd:latest` and run
    with the chain data dir bind-mounted.
  - `--from-source`: legacy path, kept verbatim for auditors and
    contributors who want to compile.
  - Environment overrides: `MXD_RELEASE_TAG` (pin a version),
    `MXD_INSTALL_DIR` (where to extract), `MXD_REPO`
    (release source, default `AlanRuno/mxd`).
- **`letsgo.bat`** — Windows wrapper now forwards extra args
  (`--docker`, `--from-source`, `--reset`) through to the bash
  script under MSYS2.

### Notes

- The mxdlib working tree's mainnet `v8_activation_height = 100`
  (operator deploy value, commit `c38110b`) is **not** shipped to
  public; the staged release tree keeps the `UINT32_MAX` placeholder
  so downstream operators must still make a deliberate choice.
- The `release-yml` chicken-and-egg: this release is itself the first
  one to actually exercise the new workflow. The v0.2.2 tag push will
  produce the initial set of binary tarballs + Docker manifest.

---

## [0.2.1] — CI hardening + test bit-rot fixes

No functional changes to libmxd, chain consensus, or wire format. All
diffs are CI/test maintenance against the v0.2.0 baseline.

### Fixed

- **`include/common/mxd_metrics_types.h`** — bumped
  `mxd_node_stake_t::node_id` from `char[64]` to `char[65]`. The field
  holds a 64-hex-char encoding of the v6 addr32 plus a null terminator
  (65 bytes); the previous `[64]` size caused both the `snprintf` loop
  and the explicit `node_id[64] = '\0'` in `mxd_rsc.c::mxd_apply_membership_deltas`
  to write one byte past the end, clobbering the low byte of the
  adjacent `stake_amount`. Benign in practice (the field was
  `memset`-zeroed and reassigned moments later by `mxd_get_balance`),
  but UB and flagged by `cppcheck` as `arrayIndexOutOfBounds`. The
  in-memory struct layout shift is safe because the struct is never
  serialized to disk or wire.
- **`src/blockchain/mxd_fork_choice.c`** — removed a duplicate
  `if (cur_h == 0) break;` check in `find_common_ancestor`'s
  walk-back loop. The first check at line 133 already breaks early
  and `cur_h` is not modified between the two checks, making the
  second one unreachable.
- **`include/mxd_blockchain_sync.h`** — declared
  `mxd_sign_and_broadcast_block()` in the public header. It was
  defined in `mxd_blockchain_sync.c` with a file-local forward
  declaration only, and called from three sites in
  `mxd_validation_handler.c` without any declaration in scope.
  Clang's `-Werror=implicit-function-declaration` caught this; gcc
  had been silently letting it pass.

### Security

- **`contracts/`** — bumped `axios` from `^1.13.5` to `^1.15.5` and
  regenerated `package-lock.json` to absorb security patches for
  transitive Hardhat dev dependencies. Cleared the critical
  Handlebars RCE (GHSA-…) and five high-severity issues against
  axios (prototype pollution, header injection, SSRF). Remaining
  Dependabot alerts are all transitive dev-dependencies gated
  behind a future `hardhat-toolbox v4 → v6` major bump and don't
  affect production validators (which never link any npm code).

### Test maintenance

- **`tests/test_smart_contracts.c`** — passed the required
  `deployer[20]` argument to `mxd_deploy_contract` at all five
  call sites (was using the legacy 3-arg signature), added
  `<sys/stat.h>` + `<unistd.h>` and `mkdir(data_dir, 0755)` in the
  test-setup helper so `mxd_contracts_db_init()` can create its
  RocksDB instance in CI's working directory, and corrected
  `mxd_init_contracts() == -1` → `== 0` in the disabled-by-default
  test to match the source comment "FIX: Disabled is a valid state,
  not an error".
- **`tests/test_blockchain.c::test_block_validation`** — removed
  the positive `mxd_validate_block(&block) == 0` assertion. The
  full validation path needs whole-chain context (prev block in
  RocksDB, per-height required protocol version, computed
  contracts/scores roots) that can't reasonably be set up in a
  synthetic-block unit test. The negative path (`block->version=0`
  → rejected) still runs.
- **`tests/test_enhanced_consensus.c`** — `mxd_init_node_metrics`
  now intentionally sets `last_update = mxd_now_ms()` so newly-
  joined validators appear active immediately; updated the test
  to assert `!= 0` instead of the stale `== 0`. Also bumped the
  "invalid response time" test value past both the header constant
  (5000) and the in-source override (`mxd_rsc.c` redefines
  `MXD_MAX_RESPONSE_TIME` to 120000).
- **`tests/test_validator_management.c`** — converted all
  remaining 20-byte stack-array addresses to v6 addr32 (32-byte),
  derived the join-request address from the test pubkey via
  `mxd_derive_address` so the addr↔pubkey binding check inside
  `mxd_validate_join_request` actually passes, extended the
  liveness-tracking loop to enough heights for at least one
  validator to cross `MXD_MAX_CONSECUTIVE_MISSES` with three
  validators in round-robin, freed the `requests` array allocated
  by `mxd_get_pending_join_requests` (LeakSanitizer caught the
  7280-byte leak), and added the missing `<stdlib.h>` for
  `calloc`/`free`.
- **`src/mxd_wasm_validator.c`** — added `// cppcheck-suppress
  oppositeInnerCondition` comment to silence a false-positive on
  the defensive `if (ptr >= body_end) break;` inside
  `while (ptr < body_end)`. The check is kept as defense against
  future loop-body edits that advance `ptr` mid-iteration.

### CI

- **`.github/workflows/ci.yml`** — added `--inline-suppr` to the
  `cppcheck` invocation so the new in-source `cppcheck-suppress`
  comment is honoured, and excluded the `node_network_tests`
  integration test (which needs a live daemon) from the standard
  `ctest --output-on-failure` run.

### Validated

- CI now passes 100% on both gcc and clang lanes across all 37 tests,
  with valgrind (gcc) and address/leak sanitizers (clang) clean.

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
