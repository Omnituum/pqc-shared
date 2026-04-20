# @omnituum/pqc-shared — Gaps and Tasks

**Date:** 2026-04-20 (updated — migrated to GAPS_AND_TASKS Schema v1.0 per DOC_STANDARD; sweep batch 4a-core, 1 / 3. PQC prefix registered in DOC_STANDARD v0.5.1. Prior: 2026-04-15 revised after legacy-preservation requirement dropped.)
**Module:** pqc-shared
**Status:** active
**Owner:** pqc-shared maintainers
**Prefix:** **PQC-##** (registered in DOC_STANDARD v0.5.1 as the canonical shared PQC-primitive layer — downstream modules point at PQC rather than re-tracking shared crypto concerns locally)
**Downstream blocker:** `@loggiecid/core` **CM-01** (Kyber mnemonic recovery) is fail-closed pending PQC-03 / PQC-04.
**Disposition:** 5 PQC-## items. PQC-02 DONE (interop test, historical evidence). PQC-01 / PQC-03 / PQC-04 / PQC-05 open; PQC-03 + PQC-04 coordinated release in `pqc-shared@0.4.0`.

---

## Status Summary

- **Tracked:** 5
- **Complete:** 1
- **Open:** 4

---

## Gaps

- [ ] **PQC-01** — Algorithm name reconciliation (rename `ML-KEM-768` labels to `ML-KEM-1024(-FIPS203)` across source, docs, threat-model, exports contract + SDK re-export sites; no wire-format or code-behavior change)
- [x] **PQC-02** — Cross-library interop test (INTEROP=FAIL recorded 2026-04-15; kept as historical evidence that PQC-03 is a clean cut, not a silent swap)
- [ ] **PQC-03** — Clean cut to noble `ml_kem1024` (remove `kyber-crystals`; rewire `generateKyberKeypair` / `kyberEncapsulate` / `kyberDecapsulate` to `@noble/post-quantum ml_kem1024`; bump 0.3.2 → 0.4.0; coordinated with PQC-04)
- [ ] **PQC-04** — Deterministic seed-keygen export (`generateKyberKeypairFromSeed(seed: Uint8Array): KyberKeypair` backed by `ml_kem1024.keygen(seed)`; unblocks core **CM-01** fail-closed branch; ships with PQC-03 in 0.4.0)
- [ ] **PQC-05** — Post-merge monorepo audit (sweep every `package.json` for `kyber-crystals`; confirm zero non-historical hits after PQC-03 + PQC-04 ship and downstream consumers bump)

---

## Decision (2026-04-15, revised)

Earlier plan considered dual-suite tagging because `kyber-crystals` (draft Kyber) and `@noble/post-quantum` `ml_kem1024` (FIPS 203) were proven non-interoperable by PQC-02. That concern was driven by the need to keep historical identities readable.

**That requirement is withdrawn.** An external archive of the legacy system exists; production does not need to read draft-Kyber identities. The path forward is a **clean cut to FIPS 203 ML-KEM-1024**, no dual-suite, no legacy code path retained in production.

```
PQC-01 (naming) ──┐
                  ├── parallel
PQC-03 (clean-cut swap) ──► PQC-04 (seed keygen) ──► CM-01 unblocks
                  │
PQC-05 (deprecate kyber-crystals + remove from tree)
```

PQC-02 stays as historical record (the test that proved a clean cut was necessary, not a quiet swap). PQC-03b (dual-suite) is **withdrawn**.

---

## Open Gaps

### PQC-01 — Algorithm name reconciliation (P0, naming only)

**Problem.** Every comment, identifier, and constant in the package labels the Kyber suite as **"ML-KEM-768"**, but the underlying material is ML-KEM-1024-sized:

| Field | Current bytes | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| publicKey | **1568** | 1184 | **1568** ✓ |
| secretKey | **3168** | 2400 | **3168** ✓ |
| ciphertext | **1568** | 1088 | **1568** ✓ |

Verified at runtime against `kyber-crystals@^1.0.7` and `@noble/post-quantum@~0.5.4` `ml_kem1024`.

**Why it matters.** The label drives security-posture documentation, threat-model claims (`THREAT_MODEL_SUMMARY.md`), and export contracts (`EXPORTS_CONTRACT.md`). Calling Level-5 material "Level-3" understates security level and misleads downstream packages making suite-selection decisions.

**Scope.**
- `src/crypto/kyber.ts` — top-of-file doc comment (line 5) and section banners.
- `src/crypto/index.ts` — KYBER section header.
- All re-export sites (Loggie SDK `packages/core/src/crypto/pqc/kyber.ts:55` `suite: "ML-KEM-768"` literal in `PqcWrap`).
- `THREAT_MODEL_SUMMARY.md`, `EXPORTS_CONTRACT.md`, `VERSION_AUTHORITY.md`, `README.md`.
- Public type names (`KyberKeypair`, etc.) stay — suite-agnostic. Only the suite-tagging string literal changes.

**Acceptance.**
- No remaining `ML-KEM-768` in source or docs except in the CHANGELOG entry that records this rename.
- Canonical label is now `ML-KEM-1024` (and after PQC-03 specifically, `ML-KEM-1024-FIPS203`).
- No wire-format change. No code-behavior change.

**Out of scope.** Library swap, deterministic keygen.

---

### PQC-02 — Cross-library interop test (DONE, kept as evidence)

**Result recorded:** `INTEROP=FAIL` (see bottom of file). Test file: `tests/interop/kyber-draft-vs-fips203.test.ts`. Test stays in the repo as historical proof that PQC-03 is a clean cut, not a silent swap.

---

### PQC-03 — Clean cut to noble `ml_kem1024` (P0)

**Goal.** Replace `kyber-crystals` with `@noble/post-quantum` `ml_kem1024` everywhere in pqc-shared. No dual-suite, no legacy reader, no shape discriminator.

**Scope.**
- `src/crypto/kyber.ts`:
  - Delete `loadKyber()` and the dynamic `kyber-crystals` import.
  - Rewire `generateKyberKeypair()` to `ml_kem1024.keygen(rand64())` returning the same `KyberKeypairB64` shape.
  - Rewire `kyberEncapsulate(pubKeyB64)` to `ml_kem1024.encapsulate(pk)` (note noble field name `cipherText` → wire `ciphertext`).
  - Rewire `kyberDecapsulate(ctB64, skB64)` to `ml_kem1024.decapsulate(ct, sk)`.
  - `isKyberAvailable()` always returns `true` (noble is always present); keep export for API stability, mark as "always available" in JSDoc.
  - Keep `kyberWrapKey` / `kyberUnwrapKey` unchanged (NaCl secretbox over the shared secret; library-agnostic).
- `package.json`:
  - **Remove** `"kyber-crystals": "^1.0.7"` from dependencies.
  - Keep `"@noble/post-quantum": "~0.5.4"` (already present).
  - Bump `0.3.2 → 0.4.0`.
- `tests/`:
  - Move `tests/interop/kyber-draft-vs-fips203.test.ts` to `tests/interop/historical/` and add a top-of-file note: "Kept as proof of why PQC-03 is a clean cut. Not run in CI." Or simply prefix with `.skip` and leave in place — pick one in implementation.
  - Existing pqc-shared tests run unchanged against the new backend; failures here are diagnostic.
- `CHANGELOG.md`: prominent "BREAKING: Kyber backend swapped from draft `kyber-crystals` to FIPS 203 `@noble/post-quantum` `ml_kem1024`. Pre-existing draft-Kyber identities are NOT readable by this version. Production migration assumes external legacy archive; no in-tree reader retained."

**Acceptance.**
- `kyber-crystals` does not appear in `package.json`, `pnpm-lock.yaml`, or anywhere under `src/`.
- All non-historical pqc-shared tests pass.
- `generateKyberKeypair()` still returns `{publicB64, secretB64}` — the public API of the package is unchanged at the type level. Callers cannot tell the backend changed except by inspecting bytes.
- Loggie SDK consumes the bumped version cleanly (PQC-04 ships in the same coordination window).

**Risk.** Anyone still pointing at `0.3.x` keeps the draft backend; the version bump is the only signal. Communicate the cut in the CHANGELOG and in a one-line release note.

---

### PQC-04 — Deterministic seed-keygen export (P0, ships with PQC-03)

**Goal.** Add the symbol Loggie SDK CM-01 already imports defensively:

```ts
export function generateKyberKeypairFromSeed(
  seed: Uint8Array  // exactly 64 bytes
): { publicKey: Uint8Array; secretKey: Uint8Array };
```

Backed by `ml_kem1024.keygen(seed)`. Verified deterministic at probe time: 64-byte seed → 1568-byte publicKey, 3168-byte secretKey, byte-identical across calls and across Node and browser environments.

**Scope.**
- New named export from `src/crypto/kyber.ts`.
- Added to `src/crypto/index.ts` and the top-level `src/index.ts` barrel.
- Domain-separation tag: pqc-shared **does not** apply its own tag inside this function. The 64-byte seed is passed through to `ml_kem1024.keygen` verbatim. The Loggie SDK applies its own `loggie:kyber-seed:v1` SHA-256 domain separation upstream in `packages/core/src/keys.ts` before calling this. Keeping the domain tag at the SDK layer (not pqc-shared) lets other consumers use raw seeds without an opaque rebinding.
- Unit tests: deterministic across calls, deterministic across Node/browser test envs, rejects non-64-byte seed with a clear error.

**Acceptance.**
- `import { generateKyberKeypairFromSeed } from '@omnituum/pqc-shared'` works.
- Loggie SDK `kyber-determinism.test.ts` activates its determinism cases (currently auto-skipped).
- Loggie SDK CM-01 fail-closed branch becomes unreachable in production.

**Coordination.** PQC-04 lands in the same release as PQC-03. Loggie SDK bumps its `@omnituum/pqc-shared` dependency in a coordinated PR and removes the runtime-supports check from `kyber-determinism.test.ts` (the skip branch becomes dead code).

---

### PQC-05 — Confirm `kyber-crystals` is gone everywhere (P1, post-merge audit)

After PQC-03 ships and downstream packages bump, sweep the monorepo:

- `grep -r "kyber-crystals"` across all `package.json` files in `Loggie_OS_Master/`.
- Any remaining hits are either (a) historical test files (allowed under `tests/interop/historical/`) or (b) downstream consumers that haven't bumped (file an issue per consumer).
- Once zero non-historical hits remain, this gap closes.

**Known consumers to check at audit time:**
- `sdk/loggie-sdk/packages/core` (already swapped indirectly via pqc-shared, but historically imported `kyber-crystals` directly — confirm the direct import paths in `keys.ts:285` and `keys.browser.ts:289` are gone or repointed at pqc-shared).
- `sdk/loggie-sdk/packages/browser-sdk`, `sdk/loggie-sdk/packages/cli`, `sdk/loggie-sdk/packages/sdk-node`, `sdk/loggie-sdk/packages/sdk-browser`, `sdk/loggie-sdk/packages/messaging` — anywhere with PQC code.
- `products/loggie-app`, `sites/loggie-marketing/pilot`, `libs/rf-vision`, `libs/noise-kyber`.

---

## Sequencing summary

```
PQC-01 (naming)   ──► CHANGELOG note, doc-only
PQC-02 (test)     ──► DONE, INTEROP=FAIL recorded
PQC-03 (cut)      ──► remove kyber-crystals, swap to noble
PQC-04 (seed)     ──► add generateKyberKeypairFromSeed
                       ↓
                       Loggie SDK bumps pqc-shared, CM-01 unblocks
PQC-05 (audit)    ──► confirm kyber-crystals removed everywhere
```

PQC-03 + PQC-04 ship together in `pqc-shared@0.4.0`.

## Do-not list (current)

- Do not retain a runtime `kyber-crystals` reader in production code. The cut is clean.
- Do not invent a suite discriminator field in stored shapes — there is only one suite now (FIPS 203 ML-KEM-1024). PQC-03b is withdrawn.
- Do not modify `@loggiecid/core` Kyber paths until pqc-shared `0.4.0` ships. Fail-closed is the contract until then.
- Do not rename public type names (`KyberKeypair`, `KyberKeypairB64`, `KyberEncapsulation`) — they are suite-agnostic.

---

## PQC-02 result (historical evidence)

```
PQC-02-RESULT: INTEROP=FAIL
Date: 2026-04-15
Tested versions: kyber-crystals@^1.0.7, @noble/post-quantum@~0.5.4 (ml_kem1024)
Test file: tests/interop/kyber-draft-vs-fips203.test.ts
Notes: Both single-library baselines pass (4/4 self-roundtrips OK).
       Both cross-library round-trips fail to recover the shared secret —
       crystals→noble→crystals: MISMATCH (no exception, distinct 32-byte SS).
       noble→crystals→noble:    MISMATCH (no exception, distinct 32-byte SS).
       Confirms draft-Kyber-1024 and FIPS 203 ml_kem1024 are NOT wire-compatible.
       Originally would have forced PQC-03b dual-suite. Withdrawn after legacy
       preservation requirement was dropped — clean cut (PQC-03) is the path.
```
