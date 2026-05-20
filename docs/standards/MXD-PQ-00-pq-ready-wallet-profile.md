# MXD-PQ-00: Post-Quantum Ready Wallet Profile

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.0.3 |
| **Created** | 2026-04-27 |
| **Updated** | 2026-04-28 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01, MXD-02, MXD-03, MXD-04, MXD-PQ-01 |

## 1. Abstract

This document defines a **conformance profile** — a stricter superset of MXD-00..04 conformance — that a wallet MUST satisfy to be marketed as "post-quantum" or "PQ-ready" by its publisher or by the MXD project. The profile binds wallets to use Dilithium5 / ML-DSA-87 (per MXD-PQ-01) by default for new accounts, restricts Ed25519 (per MXD-02) to legacy / migration uses, and acknowledges a public deprecation calendar for the classical algorithm.

This profile is **non-binding** for MXD-00..04 conformance. A wallet implementing only Ed25519 (MXD-02) is fully conformant with the base specs; it just cannot claim "PQ-ready". The profile exists so that the post-quantum claim, when made, is grounded in a verifiable specification rather than marketing language.

## 2. Motivation

MXD's external positioning includes the phrase "post-quantum cryptography" (see project README and `docs/HYBRID_CRYPTO.md`). The MXD-00..04 base specs deliberately make Ed25519 mandatory and Dilithium5 reserved, because the realistic ecosystem of integrators (MetaMask, exchanges, hardware wallets) cannot ship Dilithium5 today. This is the right choice for the base specs.

But it creates a gap: a wallet can be fully MXD-conformant while being entirely classical, and an external reviewer cannot, from MXD-00..04 alone, verify any specific post-quantum property of the system.

This profile closes the gap. A wallet claiming PQ-readiness MUST implement the rules in §4 and acknowledge the timeline in §5.

## 3. Terminology

| Term | Meaning |
|---|---|
| `PQ-Ready wallet` | A wallet conforming to this profile in addition to MXD-00..04. |
| `Classical address` | An MXD-01 address with `algo_id = 0x01` (Ed25519). Version byte `0x32` mainnet, `0x3A` testnet. |
| `PQ address` | An MXD-01 address with `algo_id = 0x02` (Dilithium5/ML-DSA-87). Version byte `0x33` mainnet, `0x3B` testnet. |
| `Composite address` | An MXD-01 address with `algo_id = 0x03` (Composite-Ed25519-MLDSA87). Version byte `0x34` mainnet, `0x3C` testnet. Reserved; the composite scheme is not yet specified. |
| `flag-day` | A future block height or calendar date at which a deprecation step takes effect. |

## 4. Profile rules

A PQ-Ready wallet MUST:

### 4.1 Default algorithm

- New addresses MUST be PQ addresses (`algo_id = 0x02`) by default. The user-facing "create account" flow MUST produce a PQ address without requiring the user to explicitly select an algorithm.
- The wallet MAY expose composite addresses (`algo_id = 0x03`) as a future option once that scheme is specified. Until then, the default is the PQ-only path of MXD-PQ-01.

### 4.2 HD derivation

- HD derivation for PQ addresses MUST follow MXD-PQ-01.
- The wallet MUST NOT derive PQ keys via the experimental placeholder of MXD-03 §5.3 (which MXD-PQ-01 supersedes).

### 4.3 Classical address handling

- Classical addresses MAY be supported for **read-only** display (balance, transaction history).
- Classical addresses MAY be supported for **spend-out** operations (sending funds *from* a classical address *to* a PQ address) — this is the migration path.
- Classical addresses MUST NOT be created as new accounts. The wallet's address-generation code path is for PQ addresses only.
- If the wallet imports an existing mnemonic that has previously been used to create classical addresses (e.g., an MXD-02 wallet from before this profile existed), the wallet SHOULD prompt the user to migrate to PQ addresses and SHOULD NOT silently re-derive classical addresses for ongoing use.
- **Detection of prior classical-address use.** To trigger the migration prompt above, a PQ-Ready wallet importing a mnemonic MUST derive at least the MXD-02 (Ed25519) tree at `account = 0` from the imported mnemonic, compute the resulting `addr32` and mainnet address per MXD-01, and query the chain for balance and transaction history at that address. Non-zero on-chain history at the derived address triggers the migration prompt. Wallets MAY extend the lookup to higher account indices per their UX policy; the minimum conformance bar is `account = 0`. Wallets that decline to perform any chain lookup at import time (e.g., fully air-gapped UX) MUST instead surface a one-time prompt asking the user whether they have ever used this mnemonic with a pre-PQ-Ready MXD wallet, and treat an affirmative answer as the migration trigger.

### 4.4 Domain separation

- All cross-context signed payloads MUST use the MXD-03 §7 domain-tag contract. (This is also required by base MXD-03; it is restated here because it is load-bearing for the PQ claim.)

### 4.5 Length validation

- All algorithm-dispatch points MUST apply the length-validation rules of MXD-03 §6 for both Ed25519 and Dilithium5 paths. (Likewise restated.)

### 4.6 User-facing labelling

- The wallet UI MUST display, at minimum once during onboarding, that the user's funds are protected by post-quantum cryptography (Dilithium5 / ML-DSA-87). The exact wording is the wallet's choice; the requirement is that the user is informed.
- The wallet MUST NOT label classical (Ed25519) addresses as "post-quantum" anywhere in its UI. Mislabeling a classical address as PQ in any wallet that claims this profile is a profile violation.

### 4.7 Backup and recovery

- Backup material is the BIP-39 mnemonic (and, if used, the BIP-39 passphrase). MXD-PQ-01-derived keys are recoverable from the same mnemonic that recovers MXD-02 keys.
- The wallet MUST NOT instruct users to back up the 4896-byte ML-DSA-87 private key as a recovery artifact; it is recoverable from the mnemonic and the canonical derivation path.

## 5. Deprecation calendar for classical addresses

This calendar is a public commitment of the MXD project under this profile. It is intentionally aggressive enough to push the ecosystem toward PQ adoption and conservative enough to give existing classical-key holders time to migrate.

| Date | Event | Implication for PQ-Ready wallets |
|---|---|---|
| **2030-01-01** | New classical-address generation deprecated on mainnet | A PQ-Ready wallet MUST NOT generate any new classical address after this date. Existing classical addresses remain spend-out usable. The wallet UI SHOULD display a warning when a user views a classical-address balance, prompting migration. |
| **TBD by governance** | Classical-address UTXOs no longer spendable on mainnet (hard fork) | A PQ-Ready wallet SHOULD warn users at every spend-out operation from a classical address that the address class has a finite remaining lifetime. The exact flag-day is set by a governance process the MXD project commits to running before then. |

The `2030-01-01` date is a forward commitment, not a current restriction. PQ-Ready wallets shipping today are conformant if they implement the rules of §4 and acknowledge §5; they do not need to enforce the 2030 cutoff in code until the date approaches.

The `TBD by governance` final date will be set under a successor minor version of this profile, with at least 24 months of lead time before the flag-day. Wallets MUST be updated to enforce the final date before it arrives.

## 6. Conformance assertions

A wallet claiming "MXD PQ-Ready" SHOULD include, in its public release notes or its repository's README, a one-paragraph self-assessment naming:

1. Which version of MXD-PQ-00 it conforms to (e.g., "v1.0.x").
2. Which version of MXD-PQ-01 (Dilithium5 HD) and MXD-01..04 it implements.
3. Any deviations from §4 that are temporarily out of compliance, with a target date for resolution.

This is recommended-not-required because no certification body audits these claims today. As the ecosystem matures (e.g., a future MXD certification process), the conformance assertion may become normative.

## 7. Relationship to other profiles

- **MXD-00 thin-wallet profile** (informative, in MXD-00 §"Conformance levels"): PQ-Ready is *not* a thin wallet. A thin wallet is Ed25519-only by definition; a PQ-Ready wallet is Dilithium5-default. The two are mutually exclusive.
- **Composite signatures (`algo_id = 0x03`)**: when the composite scheme is specified (future spec), this profile will be revised to permit (or require) composite addresses as the default. Until then, PQ-Ready means PQ-only at the wallet layer.
- **Consensus-layer PQ**: out of scope for this profile (see MXD-CONS-01 reservation in MXD-00). A PQ-Ready *wallet* does not imply a PQ-secure *chain*. Honest publishers SHOULD acknowledge this distinction when marketing their PQ-Ready wallet.

## 8. Security considerations

- **PQ-Ready does not mean quantum-secure today.** It means the wallet's keys and signatures are believed quantum-resistant under current cryptanalysis (lattice-based assumptions for ML-DSA-87). If lattice cryptanalysis advances, PQ addresses become vulnerable; the profile expects future revisions to track NIST PQC selections.
- **PQ-Ready does not mean quantum-secure when a CRQC arrives.** A cryptographically-relevant quantum computer (CRQC) targeting Ed25519 would drain every classical-address whose pubkey has been revealed (i.e., every classical-address that has ever signed a transaction). PQ-Ready wallets that follow §4.3 prevent that loss for *new* funds; they cannot retroactively protect users who have already spent from classical addresses.
- **The profile is honest about the consensus gap.** Validators may still operate Ed25519 (per `default_config.json`). A CRQC against Ed25519 could rewrite history regardless of wallet-layer protection. Closing this gap is the MXD-CONS-01 work; until it lands, the PQ-Ready label applies to wallet-layer protection only.
- **Hardware-wallet ecosystem readiness.** As of 2026, mainstream hardware wallets (Ledger, Trezor) cannot sign ML-DSA-87 transactions: secure-element flash budgets, signing-buffer sizes, transaction-display UX flows, and firmware-update mechanisms are all sized for classical-signature payloads. A 4627-byte ML-DSA-87 signature alone exceeds the typical secure-element scratch buffer; the 2592-byte public key strains user-confirmation displays. PQ-Ready means *"the spec describes how to do this"*, not *"every device today can do this."* Publishers SHOULD scope their PQ-Ready claim to the form factors they have actually validated (software wallet, server-side custody, future hardware-wallet generations) rather than implying universal hardware support. A claim of "PQ-Ready hardware wallet" requires evidence that the device's signing path has been exercised end-to-end against MXD-PQ-01 and MXD-04 v1.1.x test vectors on real hardware, not on emulators.

## 9. References

- **MXD-01**: Address Format.
- **MXD-02**: Mnemonic & HD Key Derivation (Ed25519).
- **MXD-03**: Signing & Verification.
- **MXD-04**: Transaction Format & Sighash.
- **MXD-PQ-01**: Dilithium5 / ML-DSA-87 HD Derivation.
- **NIST PQC**: `https://csrc.nist.gov/projects/post-quantum-cryptography` — origin of ML-DSA standardization.

## 10. Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-27 | 1.0.0 | Initial draft. Establishes the PQ-Ready Wallet Profile and the 2030-01-01 deprecation milestone for classical-address generation. |
| 2026-04-27 | 1.0.1 | Second-audit revisions: **N5** (§4.3 import-detection clarification — MUST derive MXD-02 tree at account=0 and query chain for balance/history; air-gapped fallback documented). **N6** (new §8 bullet on hardware-wallet ecosystem readiness — PQ-Ready ≠ HW-ready; publishers SHOULD scope claims to validated form factors). |
| 2026-04-27 | 1.0.2 | Third-audit cosmetic revision **T3**: §6 conformance-assertion example updated from `v1.0.0` (stale after v1.0.1) to `v1.0.x` (genericized so future patch bumps don't re-stale the example). Editorial only. |
| 2026-04-24 | 1.0.3 | FIPS 204 size cascade (editorial): §4.7 private-key backup warning 4864 → 4896 bytes; §8 hardware-wallet note 4595 → 4627 bytes for signature size. No wire-format change. |
