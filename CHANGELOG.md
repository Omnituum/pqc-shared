# Changelog — @omnituum/pqc-shared

## 0.7.1 (2026-07-20) — provenance continuity after repository-history sanitation

Maintenance release. **No intended API change**; the published tree is
byte-identical to 0.7.0 at the source level. This version exists to
restore a fully resolvable source/provenance chain: repository history was
sanitized to remove non-source material, which rewrote earlier commit
identities. Immutable npm attestations for versions through 0.7.0 continue
to reference their original commit SHAs, which no longer resolve from the
public refs. 0.7.1 is the first release whose provenance resolves to a
commit reachable from the rewritten history.


## 0.7.0 (2026-07-11) — CM-25/F11: public per-recipient hybrid combiner + X25519 helpers

Additive minor. Normative spec: `SPEC_CM25_F11_COMBINER_EXPORT.md` (repo
root); ratified design record: loggie-sdk's `packages/core/package-docs/specs/SPEC_CM_25.md`.
No breaking changes; `omnituum.hybrid.v2` wire is byte-identical (KAT-proven).

### Added

- **`wrapContentKeyHybrid(contentKey, recipientPub, ctx)` /
  `unwrapContentKeyHybrid(wrap, recipientSec, ctx)`** — misuse-resistant
  per-recipient AND-combined content-key wrap/unwrap. Caller passes a
  content key and structured context (`domain`, `recipientId`, optional
  `aad`); the ephemeral X25519 keypair, both shared secrets, the KEK, and
  all nonces are generated/derived and zeroized internally — no live KEK
  ever crosses the boundary. Fail-closed: every internal failure (ML-KEM
  decapsulation, X25519 ECDH, KEK re-derivation, secretbox
  authentication) surfaces as one opaque `HybridUnwrapError`.
- **`hybridDomain(namespaced)`** — branded `HybridDomain` HKDF salt,
  validated against `owner/profile` (exactly one slash, lowercase ASCII),
  reject-not-normalize.
- **`hybridRecipientId(pub)`** — stable 32-byte recipient identifier,
  SHA-256 over a versioned, length-framed encoding of the recipient's
  canonical key material. Exported so every consumer (loggie-sdk,
  pqc-db) derives the same id rather than each inventing one.
- **`x25519PublicFromSecret(secretKey)`** / **`x25519KeypairFromSecret(secretKey)`**
  (F11) — the two X25519 primitives consumers previously had to reach past
  pqc-shared for (`nacl.scalarMult.base`, `nacl.box.keyPair.fromSecretKey`).
  Verified byte-identical to the raw tweetnacl calls; `x25519KeypairFromSecret`
  is explicitly NOT a substitute for `generateX25519KeypairFromSeed` (which
  hashes its input) — the two are pinned to diverge in tests.
- Error taxonomy: `HybridError`, `InvalidHybridDomainError`,
  `InvalidKeyMaterialError`, `InvalidContentKeyError`, `HybridUnwrapError`.

### Internal (not exported)

- `deriveCombinedKek` — private, parameterized KEK-derivation core shared
  by two profile adapters: the frozen `omnituum.hybrid.v2` profile
  (`hybridEncrypt`/`hybridDecrypt`, textual transcript, unchanged) and the
  new public v3-shaped profile (binary, typed, length-framed transcript).
  Replaces the module-private `combinedKekV2` — deleted, not aliased.
- New `lint:hybrid-kek-boundary` gate: fails if a second hybrid-shaped KEK
  derivation appears anywhere in `src/` outside `crypto/hybrid.ts`.
  Surfaced (and allowlisted, with audit rationale) one pre-existing,
  independently-audited-safe instance: `fs/encrypt.ts`'s `combinedFileKekV2`
  (the `.oqe` v2 file-format's own AND-combiner, shipped in 0.6.0) — a
  convergence candidate for a future minor, not fixed here.

### Verification

- Byte-identity KAT: the real pre-refactor `combinedKekV2` output for a
  fixed tuple was captured before any change and pinned as a permanent
  regression test; all 7 pre-existing `hybrid.test.ts` behavioral tests
  (round-trip, AND-property both directions, transcript splice, tamper,
  version-reject, v1-legacy-read) pass unchanged.
- New frozen vectors match the ratified spec exactly: `V-RID-1`, `V-TX-1`
  (no aad), `V-TX-2` (with aad).
- Full `I-1`..`I-10` invariant matrix (withhold-either-secret both
  directions, recipient/epk/kemCt swap, cross-domain copy, cross-recipient,
  recipientId mismatch, array-position-is-not-identity, opaque error
  across all failure stages) — all pass.
- ESM/CJS build-output parity confirmed byte-identical (no `.browser.ts`
  twins exist in this package — `platform: 'neutral'`, pure-JS deps
  throughout — so Node/browser parity is structural here; that
  bifurcation applies to consumers, not this package).
- Full suite 83/83, `tsc --noEmit` clean, `pnpm build` clean (dist
  surface confirmed to expose exactly the intended public symbols).

### Deferred (explicitly, not skipped)

- loggie-sdk's `scripts/lint-nacl-boundary.allowlist` reduction (rerouting
  `nacl.scalarMult.base`/`nacl.box.keyPair.fromSecretKey` call sites to the
  new F11 exports) cannot land until this minor is published — loggie-sdk
  pins `@omnituum/pqc-shared` via the npm registry, not a workspace link.
- `loggie.hybrid.v3` implementation (the registered multi-recipient wire
  format that will consume `wrapContentKeyHybrid`) has not started.

## 0.6.0 (2026-07-07) — Security: `.oqe` file format v2 + vault integrity fix

Security remediation of the file-encryption (`fs/`) module following the
2026-07-06 audit. **Breaking write-format change** (new files are written as
`.oqe` v2); v1 files remain decryptable (read-only compatibility).

### Fixed (security)

- **AES-GCM nonce reuse (critical).** v1 reused a single IV for both the
  metadata and content sections under the same content key — catastrophic GCM
  nonce reuse that leaked plaintext XOR and enabled tag forgery. v2 uses a
  distinct random IV per section. Regression test asserts `metadataIv !==
  contentIv` for both hybrid and password modes.
- **Weak hybrid key wrapping (high).** v1 hybrid mode wrapped the content key
  independently under X25519 and Kyber, so *either* secret alone decrypted —
  only `min(X25519, ML-KEM)` security. v2 wraps the content key once under an
  AND-combined, transcript-bound KEK `HKDF(ss_mlkem || ss_x25519)` (domain
  `omnituum/fs/hybrid-v2`), matching `crypto/hybrid.ts`. Tests prove neither the
  classical-only nor the post-quantum-only secret can decrypt.
- **Header not authenticated (medium).** The serialized OQE header
  (version/suite/flags/lengths/IVs) is now bound as AES-GCM associated data, so
  algorithm/version downgrade or any header mutation fails authentication.
  Tamper tests cover suite, flags, and content-IV mutation.
- **Fake vault integrity hash (high).** `computeIntegrityHash` used a
  non-cryptographic DJB2 rolling hash while claiming SHA-256. Replaced with real
  SHA-256 (`@noble/hashes`, synchronous). Documented as an *unkeyed* checksum:
  tamper resistance for stored vaults comes from AES-256-GCM, not this value.
- **Crypto-path logging removed.** Deleted primitive-success logs and raw
  caught-exception logging from the file decrypt path and the ML-DSA/ML-KEM
  keygen paths.

### Changed

- New algorithm suite `HYBRID_X25519_MLKEM1024_AES256GCM` (0x03) with an honest
  ML-KEM-1024 label. Legacy suite `0x01` retained for read-only decryption.
- Dependencies pinned to exact versions (was `~`/`^` ranges).

### Added

- Root exports `ENVELOPE_VERSION_V2` (`omnituum.hybrid.v2`) and
  `ENVELOPE_SUITE_V2` (`x25519+mlkem1024`) — previously only the v1
  constants were exported from the package root.

### Fixed (test infrastructure)

- Golden vector suite updated for the v2 write format. The generator was
  cherry-picking v1 field names (`x25519Wrap`/`kyberWrap`), silently dropping
  v2's `ckWrap` and producing an undecryptable envelope vector; the verifier
  still asserted v1 version/suite. Vectors regenerated: envelope is now v2 and
  the vault `integrityHash` is real SHA-256 (was the pre-0.6.0 DJB2 value).
  35/35 golden assertions pass.

### Migration

- No API changes. `encryptFile`/`decryptFile` signatures are unchanged.
- Re-encrypt existing `.oqe` files to gain the v2 guarantees. v1 files still
  decrypt but retain the either-key weakness and (historically) the reused IV.

## 0.4.1 (2026-05-06) — Additive: ML-KEM-1024 size constants exported (PQC-08)

### Added

- `KYBER_PUBLIC_KEY_SIZE` (1568) — ML-KEM-1024 public key size in bytes.
- `KYBER_SECRET_KEY_SIZE` (3168) — ML-KEM-1024 secret key size in bytes.
- `KYBER_CIPHERTEXT_SIZE` (1568) — ML-KEM-1024 ciphertext size in bytes.
- `KYBER_SHARED_SECRET_SIZE` (32) — ML-KEM-1024 shared-secret size in bytes.
- `KYBER_SEED_SIZE` (64) — seed size accepted by `generateKyberKeypairFromSeed`.

These named constants centralize the suite identity at one declaration site so
consumers can validate buffer lengths and allocate without restating magic
literals (`1568` / `3168` / `32` / `64`). Mirrors the precedent set by
`DILITHIUM_PUBLIC_KEY_SIZE` etc. in `./crypto/dilithium`.

### Migration (consumer-side, optional but recommended)

Replace hardcoded ML-KEM byte-size literals in consumer code with the imported
constants. Known sites tracked under PQC-08 acceptance:

- `sdk/loggie-sdk/packages/core/src/crypto/integrity/verify.ts:220-222`
- `sdk/loggie-sdk/packages/core/src/crypto/integrity/verify.browser.ts:214-216`
- `sdk/loggie-sdk/packages/core/src/__tests__/cm-01-mnemonic-recovery-e2e.test.ts:72-73`
- `sdk/loggie-sdk/packages/core/src/crypto/pqc/__tests__/kyber-determinism.test.ts:37-38`

Plus any other `\b(1568|3168)\b` literals surfaced by a workspace-wide grep.

### Coordination

Pairs naturally with PQC-06 (consumer version-pin sweep). Consumers bumping
from `0.3.0` → `^0.4.1` pick up both the FIPS 203 backend (from 0.4.0) and
the size-constant exports in a single bump.

### Internal

- No runtime / wire-format / export-signature changes vs `0.4.0`. Strictly
  additive minor.

---

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
