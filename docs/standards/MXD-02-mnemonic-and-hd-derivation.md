# MXD-02: Mnemonic and Hierarchical Deterministic Key Derivation

| Field | Value |
|---|---|
| **Status** | Draft |
| **Version** | 1.1.0 |
| **Created** | 2026-04-26 |
| **Updated** | 2026-04-27 |
| **Author(s)** | MXD Project |
| **Requires** | MXD-01 |

## 1. Abstract

This document defines how an MXD wallet derives Ed25519 keypairs from a BIP-39 mnemonic. The derivation chain is:

```
mnemonic (+ optional passphrase)
   → BIP-39 seed
   → SLIP-10 ed25519 master key
   → child at m/44'/19800'/account'/0'
   → 32-byte Ed25519 private + 32-byte public key
   → MXD-01 address with algo_id = 0x01
```

The MXD-specific "PIN" concept of legacy implementations is absorbed into the BIP-39 25th-word passphrase. There is no MXD-specific layer on top of BIP-39 + SLIP-10 in this spec.

For Dilithium5 / ML-DSA-87 HD derivation, see **MXD-PQ-01** (a separate spec with a distinct master constant; the two key trees are cryptographically independent).

## 2. Terminology

| Term | Meaning |
|---|---|
| `mnemonic` | A space-joined sequence of BIP-39 wordlist words, NFKD-normalized. |
| `passphrase` | Optional BIP-39 25th-word secret. May be the empty string. NFKD-normalized. |
| `BIP-39 seed` | 64-byte output of BIP-39's PBKDF2 derivation. See §4. |
| `SLIP-10 master key` | The (priv32, chain32) pair produced by SLIP-10 ed25519 from the BIP-39 seed. See §5. |
| `derivation path` | A SLIP-10 / BIP-44 sequence of indices. MXD's canonical path is defined in §7. |
| `account` | A non-negative integer ≤ 2^31−1. The third hardened index of MXD's derivation path. |
| `coin_type` | The SLIP-44 numeric identifier of MXD. **Provisional** value `19800` until SLIP-44 registration completes. See §7.2. |

## 3. Mnemonic generation

MXD wallets use BIP-39 mnemonics without modification.

### 3.1 Wordlist

- Conformant wallets MUST support the **English** BIP-39 wordlist.
- Conformant wallets MAY additionally support any other official BIP-39 wordlist.
- A mnemonic in a non-English wordlist produces a **different** BIP-39 seed than the same conceptual sequence in English. Cross-wallet portability therefore requires both wallets to use the same wordlist. Wallets that support multiple wordlists SHOULD clearly label which wordlist is in use when displaying the mnemonic.

### 3.2 Entropy

- 128 bits (12 words) MUST be supported.
- 256 bits (24 words) MAY be supported.
- Other entropy lengths permitted by BIP-39 (160, 192, 224 bits) are out of scope for MXD-02 v1.

### 3.3 Mnemonic generation algorithm

Per BIP-39, sections "Generating the mnemonic" and "From entropy to mnemonic":

```
entropy        := CSPRNG(128 or 256 bits)
checksum_bits  := first (entropy_bits / 32) bits of SHA-256(entropy)
total_bits     := entropy ‖ checksum_bits
mnemonic       := for each 11-bit chunk of total_bits, look up BIP-39 wordlist
```

This is the **one** place in MXD where SHA-256 is normatively used, and only because it is fixed by the BIP-39 specification we inherit. The MXD SHA-512 policy from MXD-01 does not apply to externally-defined steps. Reviewers performing a "no SHA-256" sweep across MXD code SHOULD whitelist this single carve-out and treat any other SHA-256 occurrence as a violation.

### 3.4 Mnemonic validation

A wallet importing a mnemonic MUST verify the checksum bits per BIP-39 before deriving any keys, and reject any mnemonic that fails.

## 4. Seed derivation

Per BIP-39:

```
seed := PBKDF2(
    password   = NFKD(mnemonic),                  // UTF-8 bytes after NFKD normalization
    salt       = "mnemonic" ‖ NFKD(passphrase),   // ASCII "mnemonic" || passphrase bytes
    iterations = 2048,
    PRF        = HMAC-SHA-512,
    dkLen      = 64
)
```

If no passphrase is provided, `passphrase = ""` (empty string). Both `mnemonic` and `passphrase` MUST be NFKD-normalized (Unicode Normalization Form D) before encoding to UTF-8 bytes.

This is the same construction used by Bitcoin, Ethereum, Solana, and every BIP-39-compliant wallet. Existing libraries can be used unmodified.

The MXD-specific "PIN" of pre-MXD-02 wallets is absorbed by setting `passphrase` to the user's PIN string. **See §13 for important security caveats about low-entropy passphrases.**

## 5. SLIP-10 master key

Per SLIP-10, "Master key generation":

```
I               := HMAC-SHA-512( key = "ed25519 seed", data = seed )
master_priv32   := I[0..31]
master_chain32  := I[32..63]
```

The 12-byte ASCII string `"ed25519 seed"` is fixed by SLIP-10 and MUST be used verbatim. (MXD-PQ-01 uses the distinct constant `"ml-dsa seed"` for its independent key tree; see MXD-PQ-01 §3.)

## 6. Hardened child derivation

SLIP-10 ed25519 supports only **hardened** derivation. Every level uses an index ≥ 2^31. There is no non-hardened path.

For each hardened index `i` (where the top bit is set, i.e., `i = i_normal + 2^31`):

```
data            := 0x00 ‖ parent_priv32 ‖ ser32_be(i)
I               := HMAC-SHA-512( key = parent_chain32, data = data )
child_priv32    := I[0..31]
child_chain32   := I[32..63]
```

Where `ser32_be(i)` is the 32-bit big-endian encoding of `i`. The leading `0x00` byte is required by SLIP-10 to disambiguate the hardened branch.

To traverse a path, repeat this step once per hardened index, threading `(child_priv32, child_chain32)` into the next step as `(parent_priv32, parent_chain32)`.

## 7. MXD canonical derivation path

### 7.1 Path

```
m / 44' / 19800' / account' / 0'
```

Four hardened indices below the master:

| Position | Index (raw) | Index (hardened, hex) | Meaning |
|---|---|---|---|
| 1 | 44 | `0x8000002C` | BIP-44 purpose |
| 2 | 19800 | `0x80004D58` | MXD coin type (provisional, see §7.2) |
| 3 | `account` | `0x80000000 + account` | User-facing account number |
| 4 | 0 | `0x80000000` | External chain (always 0; reserved for future extension) |

There is no fifth `address_index` level in this spec. The fourth-level `0'` is fixed at zero. A future spec extension may permit non-zero values at the fourth level or introduce a fifth level; until then, conformant implementations MUST hold the fourth level at hardened zero.

### 7.2 Coin type 19800

The numeric value `19800` corresponds to the ASCII bytes `"MX"` interpreted as a 16-bit big-endian integer (`0x4D58`).

This value is **provisional** pending registration in `https://github.com/satoshilabs/slips/blob/master/slip-0044.md`. Conformant implementations MUST treat it as the canonical MXD coin type. If the upstream SLIP-44 registration assigns a different number, this spec will be revised under the major-version policy of MXD-00 §"Versioning policy"; in practice this means a successor spec, not a mutation of MXD-02 v1.

The provisional flag is recorded here for transparency. Wallets that ship before SLIP-44 registration completes accept the migration risk described in §14.

### 7.3 Account selection

`account` is a non-negative integer in the range `[0, 2^31 − 1]`. Each distinct value yields an independent keypair and address.

Wallets MAY restrict the user-visible range (typically `[0, 99]` or smaller) for usability. The full range is available for power users and future extensions.

## 8. Public key and address derivation

After traversing the path of §7, the wallet holds a 32-byte private key `priv32`.

```
pub32     := Ed25519_PublicKey( priv32 )                       // RFC 8032 §5.1.5
addr32    := SHA-512( 0x01 ‖ pub32 )[0..31]                    // MXD-01 §4
checksum4 := SHA-512( SHA-512( 0x32 ‖ addr32 ) )[0..3]         // MXD-01 §6 (mainnet version byte)
address   := "mx" ‖ Base58( 0x32 ‖ addr32 ‖ checksum4 )        // MXD-01 §8
```

For testnet deployments, substitute `0x3A` for `0x32` per MXD-01 §5.

## 9. End-to-end worked example

The following example uses a publicly known test mnemonic; values are illustrative and reproducible from any conformant implementation. **All hex values in this section will be filled in by the reference implementation alongside `MXD-02-test-vectors.json`** and replaced in this document upon `Final` status.

```
mnemonic    = "abandon abandon abandon abandon abandon abandon
               abandon abandon abandon abandon abandon about"
passphrase  = ""
account     = 0

NFKD(mnemonic) UTF-8 bytes  = <hex>
salt UTF-8 bytes            = "mnemonic" (8 bytes)

BIP-39 seed (64 bytes)      = <hex>

SLIP-10 master_priv32       = <hex>
SLIP-10 master_chain32      = <hex>

m/44'                       priv32 = <hex>  chain32 = <hex>
m/44'/19800'                priv32 = <hex>  chain32 = <hex>
m/44'/19800'/0'             priv32 = <hex>  chain32 = <hex>
m/44'/19800'/0'/0'          priv32 = <hex>  chain32 = <hex>

pub32                       = <hex>
addr32                      = <hex, 64 hex chars>
checksum4                   = <hex>
address                     = "mx<...~50 chars...>"
```

## 10. Conformance profiles

### 10.1 Thin wallet profile (informative)

A thin wallet (e.g., a MetaMask Snap exposing one address per user) is fully conformant if it implements:

- The English BIP-39 wordlist (12-word entropy).
- The seed derivation of §4.
- The SLIP-10 master and one hardened-derivation chain (§5, §6).
- The single path `m/44'/19800'/0'/0'` (account = 0 only).
- Address derivation per §8 with `algo_id = 0x01` and version byte `0x32` (or `0x3A` for testnet).

It need not implement multiple accounts, the 24-word wordlist, non-English wordlists, or any Dilithium5-related logic.

### 10.2 Full wallet profile

A full wallet additionally supports arbitrary `account` values, 24-word mnemonics, multiple wordlists, and (optionally) Dilithium5 derivation per **MXD-PQ-01**.

A full wallet that defaults to Dilithium5 (and treats Ed25519 as legacy) MAY claim the **PQ-Ready** profile per **MXD-PQ-00**.

## 11. Test vectors

See `MXD-02-test-vectors.json`. The vector set MUST include, at minimum:

- A vector with the standard "abandon × 11 about" 12-word test mnemonic and empty passphrase.
- A vector with a non-empty BIP-39 passphrase.
- A vector with `account = 7` to exercise non-zero account derivation.
- A vector with a 24-word mnemonic.
- A vector demonstrating a non-English wordlist (informative; cross-language portability is explicitly not promised).

Each vector specifies `(mnemonic, passphrase, account)` and expected `(BIP-39 seed, master_priv32, child_priv32_at_path, pub32, addr32, address_mainnet, address_testnet)` as hex strings.

## 12. Security considerations

- **Mnemonic + passphrase is the complete backup.** A user who loses either cannot recover their funds; a user who reveals either to an attacker has lost their funds. This is BIP-39 standard; restated here because the absorption of the legacy "PIN" into `passphrase` may surprise users who treated PIN as a recoverable convenience secret.
- **Different passphrases produce disjoint trees.** A wallet with mnemonic `M` and passphrase `P1` shares no derivable address with the same mnemonic and passphrase `P2 ≠ P1`. There is no "default" passphrase that takes precedence; `""` is itself a passphrase.
- **SLIP-10 hardened-only.** It is computationally infeasible to derive a child public key from a parent public key on the ed25519 path; only the holder of the parent private key can derive children. xpub-style watch-only sharing of an account does not exist for MXD's ed25519 derivation.
- **Account separation is cryptographic, not just label-based.** Two accounts under the same mnemonic share no key material; compromising one private key reveals nothing about another.
- **Provisional coin type risk.** If SLIP-44 registration ultimately assigns a number other than `19800` to MXD, wallets that shipped against the provisional value derive addresses from a path no future canonical wallet will use. The user retains the mnemonic; recovery requires re-deriving along the new canonical path. Users SHOULD NOT be guided to lock long-term holdings into provisional-coin-type addresses without an explicit migration plan.
- **NFKD normalization is mandatory.** Two visually identical mnemonic strings can produce different BIP-39 seeds if their byte sequences differ. NFKD normalization MUST be applied before UTF-8 encoding for both the mnemonic and the passphrase.
- **MXD-02 and MXD-PQ-01 are independent trees from the same mnemonic.** A user with one mnemonic can derive both an Ed25519 wallet (this spec) and a Dilithium5 wallet (MXD-PQ-01) at the same `account` value; the two keypairs share no key material. Backup of the mnemonic recovers both.

## 13. Passphrase strength (security-critical)

The BIP-39 passphrase slot is the **only** brute-force barrier between an attacker who has obtained the user's mnemonic (e.g., via a phished backup, a compromised note-taking app, or a stolen unencrypted hardware-wallet seed) and the user's keys.

The KDF that protects the passphrase is BIP-39's PBKDF2-HMAC-SHA-512 with **2048 iterations**. This is computationally inexpensive by modern standards. A consumer-grade GPU can evaluate the BIP-39 PBKDF2 at a rate sufficient to enumerate:

- A 4-digit numeric PIN (`10^4` candidates) in **milliseconds**.
- A 6-digit numeric PIN (`10^6` candidates) in **seconds to minutes**.
- A common dictionary word (`~10^5` to `~10^6` candidates) in **seconds to minutes**.
- A short alphanumeric passphrase (e.g., 8 characters from a 70-character alphabet, `~70^8 ≈ 6×10^14` candidates) in **months on commodity hardware, hours on a GPU farm**.

This is a **classical** brute-force threat. A quantum adversary is not required. The 2048-iteration count was chosen by BIP-39 in 2013 against then-current commodity CPUs; it has not aged well.

### 13.1 Mandatory wallet behavior

Wallets MUST do all of the following:

1. **NOT** expose the BIP-39 passphrase slot as a "PIN" UI field with numeric-only input or a low character limit, unless the wallet ALSO implements an Argon2id wrapper per §13.3 ahead of the SLIP-10 master step.
2. Display the warning: *"This passphrase is the only protection if your seed phrase is stolen. A short or common passphrase can be brute-forced. Use a long, random, unique passphrase, or use no passphrase at all."* The warning MUST appear when the user is creating or changing the passphrase.
3. NOT silently accept a passphrase shorter than 8 characters without explicit user confirmation.

### 13.2 Recommended user guidance

Wallets SHOULD recommend that users either:

- Use **no passphrase** (empty string) and rely on physical security of the mnemonic backup, OR
- Use a **diceware-style passphrase** of at least 5 random words from a public wordlist (entropy ≥ ~64 bits), which is approximately the minimum that resists offline GPU brute-force at 2048 iterations.

A 4-to-6 character "PIN" provides essentially no protection under the BIP-39 KDF. Users who feel they need a short PIN-style secret SHOULD wait for **MXD-02-EXT** (Argon2id wrapper, reserved per MXD-00) or use a wallet-at-rest encryption layer (future MXD-05) instead of stuffing the secret into the BIP-39 passphrase slot.

### 13.3 Optional MXD-02-EXT path (informative)

A future MXD-02-EXT spec is reserved (see MXD-00) to define an Argon2id-based wrapper that hardens low-entropy passphrases before they reach the BIP-39 KDF. The expected shape:

```
hardened_seed := Argon2id( password = BIP-39 seed, salt = derived_from_mnemonic, ... )
master := SLIP-10_master( hardened_seed )
```

A wallet implementing MXD-02-EXT can safely accept short PIN-style passphrases because the Argon2id memory-hardness defeats commodity GPU brute force. Until MXD-02-EXT is published as a Draft, **wallets MUST NOT pretend** that a 4-digit PIN typed into the BIP-39 passphrase slot offers any meaningful protection.

This warning is independent of MXD's post-quantum stance — it concerns classical adversaries operating today, not future quantum ones.

## 14. Deprecation notice

The legacy MXD wallet derivation, namely:

```
property_key  = SHA-512(SHA-512(passphrase))
salt          = SHA-512(property_key ‖ "MXD_SALT_V1")[0..15]
seed          = Argon2id( property_key ‖ "|" ‖ pin ‖ "|" ‖ salt, salt, ... )
keypair       = Ed25519_KeyGen(seed)
```

is **NOT** part of any MXD specification. It was a pre-standardization implementation. Wallets created under that derivation cannot be imported into MXD-02-conformant wallets without re-keying.

Existing legacy wallets (if any) MUST be migrated to MXD-02 by:

1. The user generating a fresh MXD-02 mnemonic.
2. The user transferring all funds from the legacy address to the MXD-02-derived address via a normal MXD transaction.
3. The user retaining the legacy mnemonic only as a fallback for any forgotten on-chain state, not for new operations.

This spec considers the legacy derivation `Withdrawn`. There is no `Superseded by` relation because the legacy derivation was never published as a numbered spec.

## 15. References

- **BIP-39**: Mnemonic code for generating deterministic keys. `https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki`
- **BIP-44**: Multi-Account Hierarchy for Deterministic Wallets. `https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki`
- **SLIP-10**: Universal private key derivation from master private key. `https://github.com/satoshilabs/slips/blob/master/slip-0010.md`
- **SLIP-44**: Registered coin types for BIP-0044. `https://github.com/satoshilabs/slips/blob/master/slip-0044.md`
- **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA).
- **PBKDF2**: RFC 2898 §5.2.
- **Argon2**: RFC 9106 (referenced for the future MXD-02-EXT wrapper).
- **Unicode NFKD**: Unicode Standard Annex #15.
- **MXD-01**: Address Format.
- **MXD-PQ-01**: Dilithium5 / ML-DSA-87 HD Key Derivation. The PQ analogue of this spec.
- **MXD-PQ-00**: PQ-Ready Wallet Profile.

## 16. Change log

| Date | Version | Change |
|---|---|---|
| 2026-04-26 | 1.0.0 | Initial draft. |
| 2026-04-27 | 1.1.0 | Audit revision F3 cascade: §8 address-derivation formula updated to use `addr32` (MXD-01 §4 v1.1.0). Audit revision F7: new §13 "Passphrase strength" with mandatory wallet behavior, user guidance, and reference to the future MXD-02-EXT Argon2id wrapper. Cross-references to MXD-PQ-00 and MXD-PQ-01 added throughout. |
