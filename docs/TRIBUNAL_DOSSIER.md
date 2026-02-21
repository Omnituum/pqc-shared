# TRIBUNAL DOSSIER — @omnituum/pqc-shared

> Architecture Tribunal reference document.
> Source of truth: README.md + src/index.ts + src/version.ts as of v0.3.1.
> Confidence markers: **Known** / **Likely** / **Unknown**.

---

## 1. Purpose

Post-quantum cryptography library providing hybrid encryption, identity management, digital signatures, vault storage, and file encryption for the Omnituum ecosystem.

**Package:** `@omnituum/pqc-shared`
**Version at time of writing:** 0.3.1
**License:** MIT
**Owner:** Omnituum (namespace: `omnituum.*`)

## 2. Non-Goals

This library does **not** provide:

| Excluded concern | Rationale |
|---|---|
| Custodial services, hosting, key escrow | Out of scope; deployment-layer responsibility |
| User authentication, identity proofing, account recovery | Application-layer responsibility |
| Network transport, relays, message delivery | Transport-layer responsibility |
| Compliance certification (FIPS, SOC2, etc.) | Handled at system + deployment layer |

## 3. Ownership Boundary

### Belongs in pqc-shared

- All `omnituum.*` version strings and wire formats
- Hybrid encryption (X25519 + ML-KEM-768)
- Post-quantum signatures (ML-DSA-65)
- Vault encrypt/decrypt with Argon2id / PBKDF2
- OQE file format
- Cryptographic primitives (BLAKE3, ChaCha20-Poly1305, HKDF, NaCl)
- Security utilities (memory zeroing, constant-time comparison)
- Encoding utilities (base64, hex, random bytes)
- Version guards and envelope validation
- Tunnel session primitives (post-handshake)

### Must NOT be in pqc-shared

- Any `loggie.*` namespaced strings or types
- Application-specific UI, routing, or state management
- Network transport or relay logic
- Key management policies (rotation schedules, backup strategies)
- Authentication flows or session tokens
- Downstream-specific configuration or environment variables

### Location Policy Audit

**Status:** Clean. No `loggie.*` literals found in `src/`. **[Known]**

The `@omnituum/envelope-registry` dependency is referenced via `file:../envelope-registry` in package.json. This is a sibling Omni-owned package providing canonical version strings. **[Known]**

## 4. Public API Surface

### 4.1 Hybrid Encryption (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `generateHybridIdentity(name)` | fn | Create identity with X25519 + Kyber keypairs |
| `hybridEncrypt(plaintext, pubKeys, meta?)` | fn | Encrypt using dual-layer hybrid |
| `hybridDecrypt(envelope, identity)` | fn | Decrypt hybrid envelope → Uint8Array |
| `hybridDecryptToString(envelope, identity)` | fn | Decrypt → UTF-8 string |
| `getPublicKeys(identity)` | fn | Extract public keys |
| `getSecretKeys(identity)` | fn | Extract secret keys |
| `HybridIdentity` | type | Identity record |
| `HybridPublicKeys` | type | Public key bundle |
| `HybridSecretKeys` | type | Secret key bundle |
| `HybridEnvelope` | type | Encrypted envelope |

### 4.2 ML-KEM-768 / Kyber (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `isKyberAvailable()` | fn | Runtime availability check |
| `generateKyberKeypair()` | fn | Generate Kyber keypair |
| `kyberEncapsulate(publicKeyB64)` | fn | KEM encapsulate |
| `kyberDecapsulate(ciphertextB64, secretKeyB64)` | fn | KEM decapsulate |
| `kyberWrapKey(symKey, publicKeyB64)` | fn | Wrap symmetric key |
| `kyberUnwrapKey(wrapped, secretKeyB64)` | fn | Unwrap symmetric key |

### 4.3 X25519 (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `generateX25519Keypair()` | fn | Generate ECDH keypair |
| `generateX25519KeypairFromSeed(seed)` | fn | Deterministic keypair |
| `boxWrapWithX25519(symKey, pubKeyHex)` | fn | Wrap key with ECDH |
| `boxUnwrapWithX25519(wrap, secretKey)` | fn | Unwrap key |
| `x25519SharedSecret(ourSecret, theirPublic)` | fn | Raw scalar mult |
| `deriveKeyFromShared(shared, salt, info)` | fn | HKDF from shared secret |

### 4.4 ML-DSA-65 / Dilithium (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `isDilithiumAvailable()` | fn | Runtime availability check |
| `generateDilithiumKeypair()` | fn | Generate signature keypair |
| `generateDilithiumKeypairFromSeed(seed)` | fn | Deterministic generation |
| `dilithiumSign(message, secretKeyB64)` | fn | Sign → base64 output |
| `dilithiumSignRaw(message, secretKeyB64)` | fn | Sign → Uint8Array output |
| `dilithiumVerify(message, sigB64, pubKeyB64)` | fn | Verify (base64) |
| `dilithiumVerifyRaw(message, sig, pubKey)` | fn | Verify (raw bytes) |
| `DILITHIUM_PUBLIC_KEY_SIZE` | const | 1952 bytes |
| `DILITHIUM_SECRET_KEY_SIZE` | const | 4032 bytes |
| `DILITHIUM_SIGNATURE_SIZE` | const | 3309 bytes |

### 4.5 Vault Management (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `createEmptyVault()` | fn | Initialize empty vault |
| `createIdentity(name)` | fn | Create hybrid identity |
| `addIdentity(vault, identity)` | fn | Add identity to vault |
| `encryptVault(vault, password)` | fn | Encrypt vault (Argon2id) |
| `decryptVault(encryptedVault, password)` | fn | Decrypt vault |

### 4.6 Vault Migration (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `needsMigration(encryptedVault)` | fn | Check if PBKDF2 vault |
| `isV2Vault(encryptedVault)` | fn | Check if Argon2id vault |
| `migrateEncryptedVault(vault, oldPw, newPw)` | fn | Migrate v1→v2 |
| `getVaultKdfInfo(encryptedVault)` | fn | Get KDF metadata |

### 4.7 Key Derivation (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `getRecommendedConfig()` | fn | Optimal KDF config for platform |
| `benchmarkKDF(config, iterations)` | fn | Measure KDF performance |
| `kdfDeriveKey(password, salt, config)` | fn | Derive key from password |
| `generateSalt(length?)` | fn | Generate random salt |
| `KDF_CONFIG_ARGON2ID` | const | 64MB / 3 iter / parallelism 4 |
| `KDF_CONFIG_PBKDF2` | const | 600,000 iterations |

### 4.8 File Encryption (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `encryptFile(data, pubKeys, sender, opts)` | fn | Hybrid file encryption |
| `decryptFile(oqeBytes, identity)` | fn | Decrypt .oqe file |
| `encryptFileWithPassword(data, password, opts)` | fn | Password-based encryption |
| `decryptFileWithPassword(oqeBytes, password)` | fn | Password-based decryption |

### 4.9 Tunnel (`@stable`)

| Export | Kind | Description |
|---|---|---|
| `createTunnelSession(keyMaterial)` | fn | Create post-handshake tunnel |
| `TUNNEL_VERSION` | const | Tunnel wire version |
| `TUNNEL_KEY_SIZE` | const | Key size |
| `TUNNEL_NONCE_SIZE` | const | Nonce size |

### 4.10 Cryptographic Primitives (`@stable` unless noted)

| Export | Kind | Stability |
|---|---|---|
| `blake3`, `blake3Hex`, `blake3Mac`, `blake3DeriveKey` | fn | @stable |
| `chaCha20Poly1305Encrypt/Decrypt` | fn | @stable |
| `xChaCha20Poly1305Encrypt/Decrypt` | fn | @stable |
| `hkdfDerive`, `hkdfExtract`, `hkdfExpand` | fn | @stable |
| `hkdfSplitForNoise`, `hkdfTripleSplitForNoise` | fn | **@experimental** |
| `secretboxEncrypt/Decrypt` | fn | @stable |
| `boxEncrypt/Decrypt` | fn | @stable |

### 4.11 Encoding & Utilities (`@stable`)

| Export | Kind |
|---|---|
| `toB64`, `fromB64`, `b64`, `ub64` | fn |
| `toHex`, `fromHex` | fn |
| `rand32`, `rand24`, `rand12`, `randN` | fn |
| `sha256`, `sha256String` | fn |
| `hkdfSha256` | fn |
| `textEncoder`, `textDecoder` | singleton |
| `u8`, `assertLen` | fn |

### 4.12 Security Utilities (`@stable`)

| Export | Kind |
|---|---|
| `SecureBuffer` | class |
| `withSecureData(factory, callback)` | fn |
| `zeroMemory(buf)` | fn |
| `zeroAll(...bufs)` | fn |
| `constantTimeEqual(a, b)` | fn |
| `createSession`, `unlockSecureSession`, `lockSecureSession`, `isSessionTimedOut` | fn |

### 4.13 Version Constants & Validators (`@stable`)

| Export | Value |
|---|---|
| `VAULT_VERSION` | `"omnituum.vault.v1"` |
| `VAULT_ENCRYPTED_VERSION` | `"omnituum.vault.enc.v1"` |
| `VAULT_ENCRYPTED_VERSION_V2` | `"omnituum.vault.enc.v2"` |
| `ENVELOPE_VERSION` | From `@omnituum/envelope-registry` → `OMNI_VERSIONS.HYBRID_V1` |
| `ENVELOPE_SUITE` | `"x25519+kyber768"` |
| `ENVELOPE_AEAD` | `"xsalsa20poly1305"` |
| `VAULT_KDF` | `"PBKDF2-SHA256"` |
| `VAULT_KDF_V2` | `"Argon2id"` |
| `VAULT_ALGORITHM` | `"AES-256-GCM"` |
| `validateEnvelope(obj)` | fn — structural + version check |
| `validateVault(obj)` | fn — structural + version check |
| `validateEncryptedVault(obj)` | fn — structural + version + KDF check |

## 5. Data Formats

### 5.1 HybridIdentity

| Field | Type | Invariant |
|---|---|---|
| `id` | string | Unique, non-empty |
| `name` | string | Display name |
| `x25519PubHex` | string | 64 hex chars (32 bytes) |
| `x25519SecHex` | string | 64 hex chars (32 bytes) — secret |
| `kyberPubB64` | string | Base64-encoded Kyber public key |
| `kyberSecB64` | string | Base64-encoded Kyber secret key — secret |
| `createdAt` | string | ISO 8601 timestamp |
| `lastRotatedAt` | string? | ISO 8601, present after rotation |
| `rotationCount` | number | ≥ 0, increments on rotation |

### 5.2 HybridEnvelope

| Field | Type | Invariant |
|---|---|---|
| `v` | string | Must be in `SUPPORTED_ENVELOPE_VERSIONS` |
| `suite` | string | Must equal `"x25519+kyber768"` |
| `aead` | string | Must equal `"xsalsa20poly1305"` |
| `x25519Epk` | string | Ephemeral X25519 public key |
| `x25519Wrap` | `{ nonce, wrapped }` | Both base64 strings |
| `kyberKemCt` | string | Kyber KEM ciphertext (base64) |
| `kyberWrap` | `{ nonce, wrapped }` | Both base64 strings |
| `contentNonce` | string | Content encryption nonce (base64) |
| `ciphertext` | string | Encrypted content (base64) |
| `meta` | object | `createdAt` required; `senderName`, `senderId` optional |

**Decryption invariant:** Both X25519 and Kyber key exchanges must succeed. The final content key is derived from both shared secrets. **[Known]**

### 5.3 OQE File Format

```
Magic:   0x4F 0x51 0x45 0x46 ("OQEF")
Version: 0x01
Mode:    0x01 (hybrid) | 0x02 (password)
[Mode-specific key material]
[Encrypted metadata]
[Encrypted file content]
```

**Invariants:**
- Magic bytes must match exactly
- Version byte determines parsing rules
- Mode byte selects key derivation path

### 5.4 Vault Structures

**OmnituumVault (decrypted):**

| Field | Invariant |
|---|---|
| `version` | `"omnituum.vault.v1"` |
| `identities` | Array of HybridIdentity records |
| `settings` | Object (structure varies) |
| `integrityHash` | SHA-256 or BLAKE3 hex string |
| `createdAt` | ISO 8601 |
| `modifiedAt` | ISO 8601 |

**EncryptedVaultFile:**

| Field | V1 | V2 |
|---|---|---|
| `version` | `"omnituum.vault.enc.v1"` | `"omnituum.vault.enc.v2"` |
| `kdf` | `"PBKDF2-SHA256"` | `"Argon2id"` |
| `algorithm` | `"AES-256-GCM"` | `"AES-256-GCM"` |
| `iterations` | 600,000 | 3 |
| `salt` | base64 | base64 |
| `iv` | base64 | base64 |
| `ciphertext` | base64 | base64 |

## 6. Versioning & Stability Policy

| Marker | Meaning |
|---|---|
| `@stable` | Semver-governed. Breaking changes only in major versions. |
| `@experimental` | May change in minor/patch releases. |
| `@internal` | Not public API. Do not depend on. |

**Root exports** (`@omnituum/pqc-shared`) are the stable surface.
**Subpath exports** (`/crypto`, `/vault`, `/fs`, `/utils`) may evolve faster.

**Version string constants** in `src/version.ts` are marked FROZEN CONTRACTS. Changing a version string value is a breaking change. **[Known]**

## 7. Environment Behavior

| Environment | Crypto provider | Notes |
|---|---|---|
| Browser | WebCrypto (`globalThis.crypto`) | Preferred path |
| Node.js 18+ | Node `crypto` module | Fallback when WebCrypto globals unavailable |

`src/runtime/crypto.ts` ensures `globalThis.crypto` exists in Node environments. **[Known]**

**Bundler guidance:** Target web environments. Do not force Node polyfills unless intended.

## 8. Security Posture

| Aspect | Status |
|---|---|
| Audit status | **Pre-audit** |
| Golden test vectors | Present in `tests/golden/` |
| Regression detection | `pnpm test:golden:verify` |
| FIPS compliance | Not claimed |
| PQ algorithms | ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204) — via dependencies |

## 9. Dependencies

| Package | Purpose | Binding |
|---|---|---|
| `@noble/ciphers` ~2.0.0 | ChaCha20-Poly1305 AEAD | Pure JS |
| `@noble/hashes` ~2.0.0 | SHA-256, BLAKE3, HMAC, HKDF | Pure JS |
| `@noble/post-quantum` ~0.5.4 | ML-DSA-65 (Dilithium) | Pure JS |
| `hash-wasm` ^4.11.0 | Argon2id | WebAssembly |
| `kyber-crystals` ^1.0.7 | ML-KEM-768 (Kyber) | Pure JS |
| `tweetnacl` ^1.0.3 | NaCl box/secretbox, X25519 | Pure JS |
| `@omnituum/envelope-registry` (file link) | Canonical version strings | Pure JS |

**Invariant:** No native (C/C++/Rust) bindings. All deps are JS or WASM. **[Known]**

## 10. Downstream Integration Contract (Loggie)

### Import rules

1. **Import from root** (`@omnituum/pqc-shared`) for stable API.
2. Subpath imports (`/crypto`, `/vault`, `/fs`, `/utils`) are for advanced use and may change without major version bump.
3. Never import from `dist/` paths directly.

### Version string rules

1. Never hardcode `omnituum.*` version strings in Loggie source. Import them from pqc-shared.
2. Use `ENVELOPE_VERSION`, `VAULT_VERSION`, etc. constants.
3. Version guards (`assertEnvelopeVersion`, etc.) should be used at deserialization boundaries.

### Namespace rules

1. pqc-shared owns the `omnituum.*` namespace exclusively.
2. Loggie must not define, shadow, or extend `omnituum.*` strings.
3. If Loggie needs its own envelope types, they must use the `loggie.*` namespace.

### Type reuse

1. Import types (`HybridIdentity`, `HybridEnvelope`, etc.) from pqc-shared.
2. Do not re-declare equivalent interfaces in Loggie.

### Security responsibilities

| Concern | Owner |
|---|---|
| Cryptographic correctness | pqc-shared |
| Memory zeroing utilities | pqc-shared (provides `zeroMemory`, `withSecureData`) |
| Calling zeroing at right time | Loggie (downstream) |
| Key storage policy | Loggie |
| Transport security | Loggie |
| Access control | Loggie |
