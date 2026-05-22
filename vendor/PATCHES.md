# Vendor Patches

## ml-dsa-pqcrystals/ref — seeded keypair internal (MXD-PQ-01 Task 7.2)

The upstream snapshot exposes only `crypto_sign_keypair(pk, sk)`, which calls
`randombytes()` internally to generate entropy; it provides no way to supply a
caller-controlled seed.  FIPS 204 §6.1 defines `ML-DSA.KeyGen(ξ)` as a
deterministic function of a 32-byte seed ξ, which is required for
MXD-PQ-01 HD derivation (leaf keygen must be reproducible from a fixed ξ).

**Files patched:**

- `ref/sign.c`: added `crypto_sign_keypair_internal(pk, sk, seed[SEEDBYTES])`.
  The body is identical to `crypto_sign_keypair` except the first 32 bytes are
  taken from the caller-supplied `seed` instead of `randombytes()`.
  `crypto_sign_keypair` is refactored to call `crypto_sign_keypair_internal`
  after drawing its seed from `randombytes()`, so existing behaviour is
  unchanged.

- `ref/sign.h`: added the `#define crypto_sign_keypair_internal
  DILITHIUM_NAMESPACE(keypair_internal)` macro binding and its prototype, so
  the symbol is correctly namespaced per-mode (e.g.
  `pqcrystals_dilithium5_ref_keypair_internal` when `DILITHIUM_MODE=5`).

- `ref/api.h`: added the `pqcrystals_dilithium5_ref_keypair_internal`
  prototype so callers that include only `api.h` can declare the function
  without pulling in the internal headers.

No algorithm logic was altered.  If this library is updated from upstream,
re-apply these three targeted changes and update this file accordingly.
