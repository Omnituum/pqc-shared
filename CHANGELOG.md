# Changelog — @omnituum/pqc-shared

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
