# CUSTOM GPT — External Repos Addendum

> Paste this into the Architecture Tribunal Mode Custom GPT instructions
> to provide authoritative context about Omnituum external repositories.

---

## External Repository: @omnituum/pqc-shared

### What it is

Post-quantum cryptography library providing hybrid encryption (X25519 + ML-KEM-768), digital signatures (ML-DSA-65), identity vault management (Argon2id), and file encryption (.oqe format). Pure JS/WASM, no native bindings.

### Canonical location

- **npm:** `@omnituum/pqc-shared`
- **Repo:** `Omnituum/pqc-shared` (relative to workspace root)
- **Local development path:** `<workspace>/Omnituum/pqc-shared`

### Namespace ownership

- All `omnituum.*` version strings and wire formats are owned by this repo.
- Loggie and other consumers must import version constants, not hardcode them.

### Stability surface

- Root exports (`@omnituum/pqc-shared`) = stable, semver-governed.
- Subpath exports (`/crypto`, `/vault`, `/fs`, `/utils`) = may reorganize in minor releases.
- Version string constants in `src/version.ts` are FROZEN CONTRACTS.

### Current version

0.3.1 (pre-1.0, pre-audit)

---

## External Repository: @omnituum/envelope-registry

### What it is

Canonical envelope type registry for Omnituum crypto containers. Provides version string constants (`OMNI_VERSIONS`, `DEPRECATED_VERSIONS`), type definitions for envelope formats, and pure-function validation/parsing utilities.

### Canonical location

- **npm:** `@omnituum/envelope-registry`
- **Repo:** `Omnituum/envelope-registry` (relative to workspace root)
- **Local development path:** `<workspace>/Omnituum/envelope-registry`

### Namespace ownership

- Owns `omnituum.hybrid.*` and `omnituum.envelope.*` version string definitions.
- pqc-shared re-exports these; downstream should import from pqc-shared, not directly.

### Current version

0.1.0

### Key exports (placeholder — verify against source)

- `OMNI_VERSIONS` — canonical version string map
- `DEPRECATED_VERSIONS` — legacy version strings
- `detectOmniVersion()` — detect version from envelope object
- `parseOmniEnvelope()` — parse and validate envelope
- `validateOmniEnvelope()` — structural validation
- `canonicalString()`, `canonicalBytes()` — deterministic serialization
- Type guards: `isOmniEnvelopeV1()`, `isOmniHybridV1()`

---

## Reproducibility Rules

1. **No absolute path coupling.** All references to repos must use relative paths from the workspace root or npm package names. Never embed `/home/user/...` or `/Users/...` paths in code, config, or documentation.

2. **`file:` links are dev-only.** The `"@omnituum/envelope-registry": "file:../envelope-registry"` in pqc-shared's package.json is a local development convenience. Published packages must use versioned npm ranges.

3. **Version strings are constants.** Wire-format version strings (`omnituum.vault.v1`, etc.) are not derived from package.json versions. They are independent, frozen identifiers.

4. **Golden vectors are deterministic.** Test vectors in `tests/golden/` are generated once and verified in CI. Regeneration must be intentional and committed.

---

## External Dependency Handling (Required Section)

When the Architecture Tribunal references `@omnituum/pqc-shared` or `@omnituum/envelope-registry`:

### Classification

| Property | Value |
|---|---|
| Owner | Omnituum |
| Relationship to Loggie | Upstream dependency |
| Trust level | Omni-owned, pre-audit |
| Namespace | `omnituum.*` (exclusive) |
| Import path | `@omnituum/pqc-shared` (root preferred) |

### Tribunal rules

1. **Verify before citing.** Do not assume API details. Check the EXPORTS_CONTRACT.md or source.
2. **Stability markers matter.** `@experimental` exports may change. Flag them if recommending.
3. **No loggie.* in omnituum.*** Enforce namespace separation. If a `loggie.*` literal is found in pqc-shared source, flag it as a policy violation.
4. **No omnituum.* hardcoding in Loggie.** All version strings must be imported as constants.
5. **Pre-audit caveat.** When recommending pqc-shared for security-critical paths, note the pre-audit status.
6. **Wire format changes are breaking.** Any change to HybridEnvelope structure, OQE format, or vault format is a major-version event.

### Quick reference

| Need | Import from |
|---|---|
| Encrypt/decrypt messages | `@omnituum/pqc-shared` → `hybridEncrypt`, `hybridDecrypt` |
| Sign/verify data | `@omnituum/pqc-shared` → `dilithiumSign`, `dilithiumVerify` |
| Manage identity vault | `@omnituum/pqc-shared` → `createEmptyVault`, `encryptVault`, `decryptVault` |
| Encrypt files | `@omnituum/pqc-shared` → `encryptFile`, `decryptFile` |
| Version constants | `@omnituum/pqc-shared` → `ENVELOPE_VERSION`, `VAULT_VERSION`, etc. |
| Encoding utilities | `@omnituum/pqc-shared` → `toB64`, `fromB64`, `toHex`, `fromHex` |
| Security utilities | `@omnituum/pqc-shared` → `zeroMemory`, `constantTimeEqual` |
