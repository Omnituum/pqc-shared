# EXPORTS CONTRACT — @omnituum/pqc-shared

> Canonical export surface and subpath policy.
> Source: package.json exports map + src/index.ts as of v0.3.1.

---

## 1. Export Entrypoints

| Subpath | Types | ESM | CJS |
|---|---|---|---|
| `.` (root) | `dist/index.d.ts` | `dist/index.js` | `dist/index.cjs` |
| `./crypto` | `dist/crypto/index.d.ts` | `dist/crypto/index.js` | `dist/crypto/index.cjs` |
| `./vault` | `dist/vault/index.d.ts` | `dist/vault/index.js` | `dist/vault/index.cjs` |
| `./utils` | `dist/utils/index.d.ts` | `dist/utils/index.js` | `dist/utils/index.cjs` |
| `./fs` | `dist/fs/index.d.ts` | `dist/fs/index.js` | `dist/fs/index.cjs` |

## 2. Stability Policy

**Root exports are the stable surface.** All `@stable`-marked symbols re-exported from `src/index.ts` are semver-governed.

**Subpath exports may move.** The `/crypto`, `/vault`, `/fs`, `/utils` subpaths exist for tree-shaking and advanced use. Their internal organization may change in minor releases without constituting a breaking change to the root API.

## 3. Canonical Export Categories (Root)

| Category | Stability | Key exports |
|---|---|---|
| Hybrid Encryption | @stable | `generateHybridIdentity`, `hybridEncrypt`, `hybridDecrypt`, `hybridDecryptToString`, `getPublicKeys`, `getSecretKeys` |
| ML-KEM-768 (Kyber) | @stable | `isKyberAvailable`, `generateKyberKeypair`, `kyberEncapsulate`, `kyberDecapsulate`, `kyberWrapKey`, `kyberUnwrapKey` |
| X25519 | @stable | `generateX25519Keypair`, `generateX25519KeypairFromSeed`, `boxWrapWithX25519`, `boxUnwrapWithX25519`, `x25519SharedSecret`, `deriveKeyFromShared` |
| ML-DSA-65 (Dilithium) | @stable | `generateDilithiumKeypair`, `dilithiumSign`, `dilithiumVerify`, + Raw variants, size constants |
| Vault Management | @stable | `createEmptyVault`, `createIdentity`, `addIdentity`, `encryptVault`, `decryptVault` |
| Vault Migration | @stable | `needsMigration`, `migrateEncryptedVault`, `getVaultKdfInfo`, `isV2Vault` |
| Integrity | @stable | `computeIntegrityHash`, `computeKeyFingerprint` |
| Key Derivation | @stable | `getRecommendedConfig`, `benchmarkKDF`, `kdfDeriveKey`, `generateSalt`, KDF config constants |
| Security Utilities | @stable | `SecureBuffer`, `withSecureData`, `zeroMemory`, `zeroAll`, `constantTimeEqual`, session functions |
| BLAKE3 | @stable | `blake3`, `blake3Hex`, `blake3Mac`, `blake3DeriveKey` |
| ChaCha20-Poly1305 | @stable | `chaCha20Poly1305Encrypt/Decrypt`, `xChaCha20Poly1305Encrypt/Decrypt`, factory functions |
| HKDF | @stable | `hkdfDerive`, `hkdfExtract`, `hkdfExpand` |
| HKDF (Noise) | **@experimental** | `hkdfSplitForNoise`, `hkdfTripleSplitForNoise` |
| NaCl SecretBox | @stable | `secretboxEncrypt/Decrypt`, + String/Raw variants, size constants |
| NaCl Box | @stable | `boxEncrypt`, `boxDecrypt`, size constants |
| Encoding | @stable | `toB64`, `fromB64`, `b64`, `ub64`, `toHex`, `fromHex`, `rand*`, `sha256*`, `hkdfSha256`, `u8`, `assertLen`, `textEncoder`, `textDecoder` |
| Version Constants | @stable | `VAULT_VERSION`, `VAULT_ENCRYPTED_VERSION*`, `ENVELOPE_VERSION`, `ENVELOPE_SUITE`, `ENVELOPE_AEAD`, `VAULT_KDF*`, `VAULT_ALGORITHM`, validators |
| File Encryption | @stable | `encryptFile`, `decryptFile`, `encryptFileWithPassword`, `decryptFileWithPassword` |
| Tunnel | @stable | `createTunnelSession`, `TUNNEL_VERSION`, `TUNNEL_KEY_SIZE`, `TUNNEL_NONCE_SIZE` |

## 4. Guidelines for Downstream Imports

### DO

```typescript
// Import from root — stable, minimal churn
import { hybridEncrypt, ENVELOPE_VERSION } from '@omnituum/pqc-shared';
```

### AVOID

```typescript
// Subpath imports — may reorganize in minor releases
import { hybridEncrypt } from '@omnituum/pqc-shared/crypto';

// Deep dist/ imports — never stable
import { hybridEncrypt } from '@omnituum/pqc-shared/dist/crypto/hybrid';
```

### ACCEPTABLE (advanced tree-shaking)

```typescript
// Subpath imports are fine if you accept the migration risk
import { encryptFile } from '@omnituum/pqc-shared/fs';
```

## 5. Type Exports

All public types are exported alongside their runtime counterparts from the root. Key types:

| Type | Domain |
|---|---|
| `HybridIdentity`, `HybridPublicKeys`, `HybridSecretKeys`, `HybridEnvelope` | Hybrid encryption |
| `KyberKeypair`, `KyberKeypairB64`, `KyberEncapsulation` | Kyber |
| `X25519Keypair`, `X25519KeypairHex`, `ClassicalWrap` | X25519 |
| `DilithiumKeypair`, `DilithiumKeypairB64`, `DilithiumSignature` | Dilithium |
| `OmnituumVault`, `EncryptedVaultFile`, `HybridIdentityRecord` | Vault |
| `MigrationOptions`, `MigrationResult` | Migration |
| `KDFConfig`, `KDFAlgorithm` | Key derivation |
| `SecureSession`, `UnlockReason` | Security |
| `SecretboxPayload`, `BoxPayload` | NaCl |
| `OQEEncryptResult`, `OQEDecryptResult`, `EncryptOptions`, `DecryptOptions` | File encryption |
| `PQCTunnelSession`, `TunnelKeyMaterial` | Tunnel |

## 6. Invariants

1. Every symbol exported from root (`src/index.ts`) is part of the public contract.
2. Removing a root export is a **major** version bump.
3. Subpath entrypoints (`./crypto`, `./vault`, `./fs`, `./utils`) are convenience surfaces; reorganizing them is a **minor** change.
4. `dist/` internal paths are never stable. Zero guarantees.
5. The `@omnituum/envelope-registry` peer is an Omni-internal dependency. Downstream consumers should not import from it directly — use the re-exported constants from pqc-shared.
