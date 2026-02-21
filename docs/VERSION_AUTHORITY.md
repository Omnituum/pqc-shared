# VERSION AUTHORITY — @omnituum/pqc-shared

> Single source of truth for version string governance.
> Source: src/version.ts as of v0.3.1.

---

## 1. Where Version Strings Live

| Constant | File | Value | Status |
|---|---|---|---|
| `ENVELOPE_VERSION` | `src/version.ts` | From `@omnituum/envelope-registry` → `OMNI_VERSIONS.HYBRID_V1` | FROZEN |
| `ENVELOPE_VERSION_LEGACY` | `src/version.ts` | From `DEPRECATED_VERSIONS.PQC_DEMO_HYBRID_V1` | FROZEN (deprecated) |
| `VAULT_VERSION` | `src/version.ts` | `"omnituum.vault.v1"` | FROZEN |
| `VAULT_ENCRYPTED_VERSION` | `src/version.ts` | `"omnituum.vault.enc.v1"` | FROZEN |
| `VAULT_ENCRYPTED_VERSION_V2` | `src/version.ts` | `"omnituum.vault.enc.v2"` | FROZEN |
| `ENVELOPE_SUITE` | `src/version.ts` | `"x25519+kyber768"` | FROZEN |
| `ENVELOPE_AEAD` | `src/version.ts` | `"xsalsa20poly1305"` | FROZEN |
| `VAULT_KDF` | `src/version.ts` | `"PBKDF2-SHA256"` | FROZEN |
| `VAULT_KDF_V2` | `src/version.ts` | `"Argon2id"` | FROZEN |
| `VAULT_ALGORITHM` | `src/version.ts` | `"AES-256-GCM"` | FROZEN |
| `TUNNEL_VERSION` | `src/tunnel/index.ts` | (see source) | FROZEN |

## 2. Authority Chain

```
@omnituum/envelope-registry   ← Canonical owner of envelope version strings
        ↓
@omnituum/pqc-shared           ← Re-exports + owns vault/KDF version strings
        ↓
Loggie / other consumers       ← Import constants, never hardcode
```

The envelope-registry is the **single source of truth** for `omnituum.hybrid.*` version strings.
The pqc-shared repo is the **single source of truth** for `omnituum.vault.*` and `omnituum.vault.enc.*` strings.

## 3. Rules for Adding New Version Constants

1. **New envelope versions** must be registered in `@omnituum/envelope-registry` first, then re-exported through `src/version.ts`.
2. **New vault versions** are defined directly in `src/version.ts`.
3. Every new version constant must have:
   - A corresponding entry in `SUPPORTED_*_VERSIONS` arrays
   - A guard function (`assert*Version`) or inclusion in existing guards
   - A validator update (`validate*`)
4. Version string format: `omnituum.<domain>.<format>.v<N>` (e.g., `omnituum.vault.enc.v2`).
5. Changing the **value** of a FROZEN constant is a **major** breaking change.
6. Adding a **new** constant to `SUPPORTED_*_VERSIONS` is a **minor** change (new capability, backward compatible).

## 4. Supported Version Arrays

| Array | Purpose | Values |
|---|---|---|
| `SUPPORTED_ENVELOPE_VERSIONS` | Envelope versions this library can read | `[ENVELOPE_VERSION, ENVELOPE_VERSION_LEGACY]` |
| `SUPPORTED_VAULT_VERSIONS` | Decrypted vault versions | `[VAULT_VERSION]` |
| `SUPPORTED_VAULT_ENCRYPTED_VERSIONS` | Encrypted vault versions | `[VAULT_ENCRYPTED_VERSION, VAULT_ENCRYPTED_VERSION_V2]` |

## 5. Version Guards

| Function | Throws | Non-throwing equivalent |
|---|---|---|
| `assertEnvelopeVersion(v)` | `VersionMismatchError` | `isEnvelopeVersionSupported(v)` |
| `assertVaultVersion(v)` | `VersionMismatchError` | `isVaultVersionSupported(v)` |
| `assertVaultEncryptedVersion(v)` | `VersionMismatchError` | `isVaultEncryptedVersionSupported(v)` |

`VersionMismatchError` includes `.type`, `.expected`, and `.received` fields for diagnostics.

## 6. Guidance for Downstream Repos

### Never hardcode version strings

```typescript
// BAD — breaks when pqc-shared changes
const version = 'omnituum.hybrid.v1';

// GOOD — always in sync
import { ENVELOPE_VERSION } from '@omnituum/pqc-shared';
```

### Use guards at deserialization boundaries

```typescript
import { assertEnvelopeVersion } from '@omnituum/pqc-shared';

function processIncoming(envelope: unknown) {
  const env = envelope as { v: string };
  assertEnvelopeVersion(env.v); // throws if unsupported
  // ... proceed
}
```

### Do not import from envelope-registry directly

```typescript
// BAD — bypasses pqc-shared's version governance
import { OMNI_VERSIONS } from '@omnituum/envelope-registry';

// GOOD — use the re-export
import { ENVELOPE_VERSION } from '@omnituum/pqc-shared';
```

## 7. Package Version (npm)

The npm package version (`package.json` → `"version"`) follows semver and is independent of wire-format version strings. The current package version is `0.3.1`. This is a **pre-1.0** package; minor versions may contain API changes until 1.0.
