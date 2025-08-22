Doc vs Implementation Matrix

Consensus and Validation
- Quorum threshold
  - Documentation: Blocks require signatures from ≥50% of Rapid Table validators.
  - Implementation: mxd_block_has_quorum in src/blockchain/mxd_rsc.c; helper declared in include/mxd_rsc.h. Dynamic thresholds used with Rapid Table size; tests set validation_capacity explicitly for determinism.
- Minimum relay signatures (X)
  - Documentation: Relay when validator just signed or block has ≥3 valid, ordered signatures; optionally dynamic X = max(3, floor(0.25 * RapidTable.size)).
  - Implementation: mxd_block_has_min_relay_signatures in src/blockchain/mxd_rsc.c; P2P relay decision in src/mxd_p2p_validation.c calls the helper.
- Fork resolution by cumulative latency
  - Documentation: Prefer block with higher Σ(1/latency_i) using validator latencies.
  - Implementation: mxd_resolve_fork in src/blockchain/mxd_blockchain_validation.c calls mxd_calculate_validation_latency_score from src/blockchain/mxd_rsc.c (uses measured peer metrics). The duplicate local scorer has been removed.
- Timestamp drift
  - Documentation: ±60 seconds allowance, reject outliers.
  - Implementation: Validation chain verification enforces ±60s in src/blockchain/mxd_blockchain_validation.c.

Security and Blacklisting
- Double-sign detection and blacklisting
  - Documentation: If a validator signs two different blocks at same height with ≥3 confirmations, ban for 100 blocks and exclude from Rapid Table.
  - Implementation: Conflict checks and structures in src/blockchain/mxd_rsc.c; blacklist handling integrated with validation logic; persistence/logging integration to be expanded.

Cryptography
- Hashing and signing
  - Documentation: Use OpenSSL + libsodium; Dilithium for PQC compatibility.
  - Implementation: src/mxd_crypto.c uses RIPEMD160 legacy APIs as required by address generation; PQC OQS include guarded by MXD_PQC_DILITHIUM at top-level; Argon2id via libsodium for KDF.
- Determinism and RNG
  - Documentation: Validation must reflect deterministic entropy pipeline; test harness must not mask production issues.
  - Implementation: Tests exercise signing/verification via actual code paths; performance tests validate throughput independently from RNG mocking.

Configuration
- Layered defaults and bootstrap fallback
  - Documentation: Try user-provided config, then default config near executable, then built-in defaults; never reset user settings on bootstrap retrieval failure.
  - Implementation: src/mxd_config.c preserves user values and only applies fallbacks when needed; src/node/main.c searches default_config.json alongside executable per note.

P2P Propagation and Rapid Table
- Gossip relay rules
  - Documentation: Relay after signing or when signatures ≥X; prioritize Rapid Table nodes; track ordered validation path.
  - Implementation: src/mxd_p2p_validation.c relays using mxd_block_has_min_relay_signatures; RSC helpers validate ordered chain and derive dynamic thresholds.

CI and Supply Chain Security
- SBOM generation
  - Documentation: CycloneDX SBOMs for source and container image.
  - Implementation: .github/workflows/ci.yml includes SBOM steps under docker-build; uploads as artifacts.
- Container signing
  - Documentation: Sign published images; non-blocking if permissions unavailable; run on tags.
  - Implementation: docker-publish-sign job runs on tag refs only; cosign keyless signing attempted; non-blocking.
- Code scanning and dependency scanning
  - Documentation: Enable scanning and artifact reporting.
  - Implementation: Security scan (Trivy) job runs; SARIF upload retained; non-blocking behavior for developer ergonomics.

Performance Requirements
- Validation throughput and latency
  - Documentation: ≥10 validations/sec; ≤3s network latency targets.
  - Implementation: Performance tests in CI; latency-based fork weighting implemented; further tuning tracked in metrics tests.

Notes and Next Steps
- Centralize consensus scoring functions in RSC to avoid duplication.
- Expand blacklisting persistence and auditing logs for enterprise compliance.
- Maintain deterministic test inputs; avoid environment coupling.
