# Security Policy

## Reporting a vulnerability

If you find a security issue in MXD (chain core, consensus, bridge contract,
oracle attestation, or any component in this repository), **do not** open a
public issue. Use one of these private channels:

### Preferred: GitHub Private Security Advisories

Open a private report at:

**https://github.com/AlanRuno/mxd/security/advisories/new**

Or use the **Security → Report a vulnerability** button on the repository
page. This routes your report to the maintainers privately and lets us
coordinate a fix and disclosure timeline with you without leaking the issue
to the public until a fix is ready. Requires a GitHub account.

### Alternative: encrypted email

If you cannot use GitHub for any reason, email **security@runonetworks.com**.
For end-to-end encrypted email, request the maintainers' current PGP key
through the GitHub advisory channel above first; PGP keys are not embedded
in this repository to avoid stale-key risk.

### What to include

1. A description of the issue and the impact you believe it has.
2. Steps to reproduce, ideally a minimal proof-of-concept.
3. The commit hash and platform you tested against.
4. Whether you'd like to be credited and how.

We will acknowledge receipt within 72 hours and aim to provide an initial
assessment within 7 days. For confirmed high-severity issues, we coordinate
a disclosure timeline with you — typically 30-90 days depending on the fix
complexity and active mitigation availability.

## Scope

In scope:
- This repository (`AlanRuno/mxd`): chain core C library, validator binary,
  bridge Solidity contracts, oracle attestation specs, operator tools.
- Mainnet endpoints exposed by the canonical Runo Networks validator set.
- The deployed `MXDBridgeV3` contract on BSC mainnet at
  `0xCae102064d8E9e13d5b48F38bAc53d1155B331B4`.

Out of scope:
- Third-party wallets, third-party explorers, third-party bridge frontends.
- Self-hosted validators (please report to whoever runs them).
- DoS / amplification against unauthenticated endpoints (we already rate-limit;
  if you find a *novel* amplification path with a leverage factor > 10x,
  that IS in scope).
- Social engineering of operators.

## Deployed components (reference for reports)

| Component | Deployed value | Source in this repository |
|-----------|----------------|---------------------------|
| MXD mainnet | `chain_id 0x4D580001`, protocol v7 (v8 activates at height 100), five validators operated by Runo Networks. Public read API and `POST /transaction` on port 8080; `/wallet/*` disabled; admin routes gated by bearer token or signature quorum. | `src/`, `include/mxd_protocol_version.h`, `docs/standards/` |
| Bridge contract | `MXDBridgeV3` at `0xCae102064d8E9e13d5b48F38bAc53d1155B331B4` (BSC, chain id 56), launched 2026-05-18, immutable. EIP-712 domain `MXDBridge` / `3`. Admin actions need K-of-N operator signatures; the current `threshold()` and `operatorCount()` are readable on-chain. | `contracts/contracts/MXDBridgeV3.sol` (the deployed bytecode predates the `safeTransfer` fix listed in the changelog) |
| Bridged token | Denarius MXD (BNBMXD) `0xdf1f7AdF59a178BA83f6140a4930cf3BEB7b73BF`, 9 decimals, ownership renounced; deposited tokens are burned. | Not in this repository (pre-existing ERC-20) |
| Mint attestation | 3-of-5 Dilithium5 oracle quorum, verified by every node during block validation. | `docs/MAINNET_ORACLE_SET.md`, `docs/standards/MXD-API-01-bridge-oracle-attestation.md` |

Earlier bridge contracts are retired. Findings against them are out of scope unless they
also affect `MXDBridgeV3`.

## Severity guidelines

| Severity | Examples |
|----------|----------|
| Critical | Consensus break, unauthorized mint, bridge double-spend, oracle quorum bypass, validator-key extraction from running node. |
| High | Replay across networks, signature forgery for a non-quorum, denial of service against the full validator set, mutable wire format inconsistency. |
| Medium | UI deceit (wallet shows wrong balance/address), state inconsistencies that auto-heal, recoverable resource exhaustion. |
| Low | Build issues, doc errors, log injection without further impact. |

## Rewards

There is no formal bug bounty program at this time. We will publicly credit
reporters of valid findings (with their permission) and may offer discretionary
rewards for high-impact reports — discussed case-by-case after the fix lands.

## Acknowledgments

We thank the following researchers for responsibly disclosed findings:

- **ibnu76** (2026-09-04) — `MXDBridgeV3.recoverToken` used a raw `IERC20.transfer`
  whose `false` return value was ignored; fixed with `SafeERC20.safeTransfer` plus
  regression tests (2026-09-29).

## Hardening philosophy

MXD ships with defense-in-depth on every critical path:
- **Bridge mints**: replay protected at queue (`source_tx_hash` dedup), oracle
  DB (`FOR UPDATE SKIP LOCKED`), and consensus (`bridge_tx:` RocksDB index).
- **Oracle attestation**: K-of-N Dilithium5 quorum, every node independently
  verifies every signature against the on-chain oracle set during block
  validation.
- **Admin operations**: 3-of-5 oracle quorum required for any bridge auth /
  oracle-set update, canonical message format prevents cross-op replay.

If a layer fails, the next one catches it. Reports that bypass *one* layer are
useful; reports that bypass *all* layers of a critical path are urgent.
