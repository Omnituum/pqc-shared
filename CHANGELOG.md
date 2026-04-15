# Changelog — @omnituum/pqc-shared

## 0.4.0 (2026-04-15) — BREAKING: Kyber backend swap, naming reconciliation, deterministic seed keygen

### BREAKING — Kyber backend swap (PQC-03)

The Kyber backend is replaced. Previous releases (0.3.x and earlier) were
backed by `kyber-crystals`, which implements an **earlier draft** of Kyber
(pre-NIST FIPS 203). 0.4.0 is backed by `@noble/post-quantum`'s `ml_kem1024`,
which implements **NIST FIPS 203 ML-KEM-1024 (final, 2024)**.

These two implementations are **NOT wire-compatible**. Empirically verified —
see `tests/interop/historical/kyber-draft-vs-fips203.test.ts.skip` and
`package-docs/GAPS_AND_TASKS.md` (PQC-02 result):

- crystals → noble → crystals: ciphertext decapsulates to a different shared secret.
- noble → crystals → noble: ciphertext decapsulates to a different shared secret.

**Pre-existing draft-Kyber identities, ciphertexts, and stored public keys
produced by 0.3.x cannot be read by 0.4.0.** This is an intentional clean
break. Production migration assumes any historical material lives in an
external archive; no in-tree reader for draft Kyber is retained.

`kyber-crystals` is removed from `dependencies`.

### BREAKING — Algorithm naming corrected (PQC-01)

All references to "ML-KEM-768" are replaced with "ML-KEM-1024". The previous
labels were incorrect — `kyber-crystals` was producing 1568-byte public keys
(NIST Level 5 / ML-KEM-1024 sizes), not 1184-byte keys (Level 3 / 768).
The new noble backend continues to use ML-KEM-1024, so wire-format key
sizes are unchanged from 0.3.x; only the label was wrong.

The canonical suite identifier exported as `KYBER_SUITE` is now
`"ML-KEM-1024-FIPS203"`.

### Added

- `generateKyberKeypairFromSeed(seed: Uint8Array): KyberKeypair` — derive
  a deterministic ML-KEM-1024 keypair from a 64-byte seed (PQC-04). Same
  seed → byte-identical keypair across runtimes (Node, browser). Unblocks
  Loggie SDK CM-01 (Kyber mnemonic recovery).
- `KYBER_SUITE` constant and `KyberSuite` type.

### Deprecated

- `isKyberAvailable()` always returns `true`. The function is retained for
  API stability across the 0.3.x → 0.4.x cut and will be removed in 0.5.x.

### Internal

- Test that proved the cut was necessary, not a silent swap, is preserved
  at `tests/interop/historical/kyber-draft-vs-fips203.test.ts.skip`. It is
  not run in CI (the `.skip` suffix takes it out of the vitest glob, and
  `kyber-crystals` is no longer a dependency for it to import).

---

## 0.3.2 (2026-03-15) — Security fix

### Fixed

**Corrected argument order in Dilithium ML-DSA-65 signing wrappers.**

`dilithiumSign`, `dilithiumSignRaw`, `dilithiumVerify`, and `dilithiumVerifyRaw`
previously passed arguments to `@noble/post-quantum` in reversed order.
The internal implementation now correctly calls:

```
sign(message, secretKey)        // was: sign(secretKey, message)
verify(signature, message, pk)  // was: verify(pk, message, signature)
```

The public API signatures are unchanged — the bug was in the internal delegation
to `@noble/post-quantum/ml-dsa`. All four functions were affected but no
downstream code in the Omnituum workspace called these functions at runtime,
so no existing signatures need to be regenerated.

### Added

- 9 Dilithium regression tests (`tests/crypto/dilithium.test.ts`)
- Includes a direct-verification test that bypasses the wrapper to confirm
  noble receives arguments in the correct order
- vitest added as test runner (`pnpm test` now runs unit tests)

## 0.3.1

Initial tracked release.
