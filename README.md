# @omnituum/pqc-shared

Post-Quantum Cryptography library for hybrid encryption, identity management, and secure file handling.

## Features

- **Hybrid Encryption** — X25519 + ML-KEM-768 (Kyber) dual-layer security
- **Post-Quantum Signatures** — ML-DSA-65 (Dilithium) via `@noble/post-quantum`
- **Identity Vault** — Encrypted storage with Argon2id key derivation
- **File Encryption** — `.oqe` format with hybrid or password-based modes
- **Cross-Platform** — Works in Node.js and modern browsers; no native bindings

## Installation

```bash
npm install @omnituum/pqc-shared
# or
pnpm add @omnituum/pqc-shared
```

## Supported Environments

`@omnituum/pqc-shared` is designed to run in both Node.js and modern browsers.

- **Node.js:** 18, 20, 22
- **Browsers:** modern Chromium / Firefox / Safari with WebCrypto support

### Cryptographic runtime behavior

- In browsers, the library uses **WebCrypto** (`globalThis.crypto`) when available.
- In Node.js, the library uses **Node built-ins** (e.g. `crypto`) as a fallback when WebCrypto globals are unavailable.

If you bundle for the browser, ensure your bundler targets web environments and does not force Node polyfills unless explicitly intended.

## Non-Goals

This package provides **cryptographic primitives and utilities**. It does **not** provide:

- Custodial services, hosting, or key escrow
- User authentication, identity proofing, or account recovery
- Network transport, relays, or message delivery guarantees
- Compliance certification (audit/compliance is handled at the system + deployment layer)

## Security Status

This repository is **pre-audit**. It includes golden test vectors for regression detection.
If you plan to use this library in high-stakes environments, perform an independent review and validate the threat model for your deployment.

## API Stability

Exports are annotated with stability markers:

- **`@stable`** — Supported and semver-governed. Breaking changes only in major versions.
- **`@experimental`** — May change in minor/patch releases until stabilized.

The public API surface is the root exports (`@omnituum/pqc-shared`). Subpath exports (`/crypto`, `/vault`, `/fs`, `/utils`) may evolve faster and are intended for advanced use cases.

## Quick Start

### Hybrid Encryption

```typescript
import {
  generateHybridIdentity,
  hybridEncrypt,
  hybridDecryptToString,
  getPublicKeys,
} from '@omnituum/pqc-shared';

// Generate identity with X25519 + Kyber keypairs
const alice = await generateHybridIdentity('Alice');
const bob = await generateHybridIdentity('Bob');

// Encrypt message for Bob using his public keys
const bobPublicKeys = getPublicKeys(bob);
const envelope = await hybridEncrypt(
  'Hello, Bob!',
  bobPublicKeys,
  { senderName: alice.name, senderId: alice.id }
);

// Bob decrypts with his secret keys
const plaintext = await hybridDecryptToString(envelope, bob);
console.log(plaintext); // "Hello, Bob!"
```

### Digital Signatures (Dilithium)

```typescript
import {
  generateDilithiumKeypair,
  dilithiumSign,
  dilithiumVerify,
} from '@omnituum/pqc-shared';

const keypair = await generateDilithiumKeypair();
const message = new TextEncoder().encode('Sign this message');

const { signature } = await dilithiumSign(message, keypair.secretB64);
const valid = await dilithiumVerify(message, signature, keypair.publicB64);
console.log(valid); // true
```

### Vault Management

```typescript
import {
  createEmptyVault,
  generateHybridIdentity,
  addIdentity,
  encryptVault,
  decryptVault,
} from '@omnituum/pqc-shared';

// Create and populate vault
let vault = createEmptyVault();
const identity = await generateHybridIdentity('My Identity');
vault = addIdentity(vault, identity);

// Encrypt vault with password (uses Argon2id)
const encrypted = await encryptVault(vault, 'my-password');

// Decrypt vault
const decrypted = await decryptVault(encrypted, 'my-password');
```

### File Encryption

> **Note:** File encryption APIs accept browser `File`/`Blob` objects. For Node.js usage, use `Uint8Array` with the underlying hybrid encryption functions directly.

```typescript
import { encryptFile, decryptFile } from '@omnituum/pqc-shared';

// Encrypt file for recipient (browser)
const result = await encryptFile(fileData, recipientPublicKeys, senderIdentity, {
  filename: 'document.pdf',
  mimeType: 'application/pdf',
});
// result.encrypted contains .oqe file bytes

// Decrypt file
const decrypted = await decryptFile(oqeBytes, recipientIdentity);
console.log(decrypted.metadata.filename); // "document.pdf"
```

---

## API Reference

### Hybrid Encryption

| Function | Description |
|----------|-------------|
| `generateHybridIdentity(name)` | Create identity with X25519 + Kyber keypairs |
| `hybridEncrypt(plaintext, recipientPubKeys, meta?)` | Encrypt using hybrid encryption |
| `hybridDecrypt(envelope, recipientIdentity)` | Decrypt hybrid envelope |
| `hybridDecryptToString(envelope, recipientIdentity)` | Decrypt to UTF-8 string |
| `getPublicKeys(identity)` | Extract public keys from identity |
| `getSecretKeys(identity)` | Extract secret keys from identity |

### ML-KEM-768 (Kyber)

| Function | Description |
|----------|-------------|
| `isKyberAvailable()` | Check if Kyber library is available |
| `generateKyberKeypair()` | Generate Kyber keypair |
| `kyberEncapsulate(publicKeyB64)` | Create shared secret + ciphertext |
| `kyberDecapsulate(ciphertextB64, secretKeyB64)` | Recover shared secret |
| `kyberWrapKey(symKey, publicKeyB64)` | Wrap symmetric key |
| `kyberUnwrapKey(wrapped, secretKeyB64)` | Unwrap symmetric key |

### X25519

| Function | Description |
|----------|-------------|
| `generateX25519Keypair()` | Generate ECDH keypair |
| `generateX25519KeypairFromSeed(seed)` | Deterministic keypair from seed |
| `boxWrapWithX25519(symKey, recipientPubKeyHex)` | Wrap key with ECDH |
| `boxUnwrapWithX25519(wrap, secretKey)` | Unwrap key |
| `x25519SharedSecret(ourSecret, theirPublic)` | Raw scalar multiplication |
| `deriveKeyFromShared(shared, salt, info)` | HKDF derivation |

### Dilithium ML-DSA-65

| Function | Description |
|----------|-------------|
| `isDilithiumAvailable()` | Check if Dilithium library is available |
| `generateDilithiumKeypair()` | Generate signature keypair |
| `generateDilithiumKeypairFromSeed(seed)` | Deterministic generation |
| `dilithiumSign(message, secretKeyB64)` | Sign message (base64 output) |
| `dilithiumSignRaw(message, secretKeyB64)` | Sign message (Uint8Array output) |
| `dilithiumVerify(message, signatureB64, publicKeyB64)` | Verify signature |
| `dilithiumVerifyRaw(message, signature, publicKey)` | Verify with raw bytes |

**Key Sizes:**
- Public Key: 1952 bytes
- Secret Key: 4032 bytes
- Signature: 3309 bytes

### Vault Management

| Function | Description |
|----------|-------------|
| `createEmptyVault()` | Initialize empty vault |
| `createIdentity(name)` | Create new hybrid identity |
| `addIdentity(vault, identity)` | Add identity to vault |
| `removeIdentity(vault, identityId)` | Remove identity from vault |
| `rotateIdentityKeys(identity)` | Rotate all keys for identity |
| `setActiveIdentity(vault, identityId)` | Set default identity |
| `encryptVault(vault, password)` | Encrypt vault (Argon2id) |
| `decryptVault(encryptedVault, password)` | Decrypt vault |
| `exportVault(vault, password)` | Serialize to JSON string |
| `importVault(json, password)` | Deserialize from JSON |

### Vault Migration

| Function | Description |
|----------|-------------|
| `needsMigration(encryptedVault)` | Check if vault uses PBKDF2 |
| `isV2Vault(encryptedVault)` | Check if vault uses Argon2id |
| `migrateEncryptedVault(vault, oldPw, newPw)` | Migrate PBKDF2 → Argon2id |
| `getVaultKdfInfo(encryptedVault)` | Get KDF metadata |

### Key Derivation

| Function | Description |
|----------|-------------|
| `getRecommendedConfig()` | Get optimal KDF config for platform |
| `benchmarkKDF(config, iterations)` | Measure KDF performance |
| `kdfDeriveKey(password, salt, config)` | Derive key from password |
| `generateSalt(length?)` | Generate random salt |

**KDF Configurations:**
- `KDF_CONFIG_ARGON2ID` — Memory: 64MB, Time: 3, Parallelism: 4
- `KDF_CONFIG_PBKDF2` — 600,000 iterations (OWASP 2023)

### File Encryption

| Function | Description |
|----------|-------------|
| `encryptFile(data, recipientPubKeys, sender, opts)` | Hybrid file encryption |
| `decryptFile(oqeBytes, recipientIdentity)` | Decrypt .oqe file |
| `encryptFileWithPassword(data, password, opts)` | Password-based encryption |
| `decryptFileWithPassword(oqeBytes, password)` | Password-based decryption |

### Cryptographic Primitives

#### BLAKE3
```typescript
import { blake3, blake3Hex, blake3Mac, blake3DeriveKey } from '@omnituum/pqc-shared';

blake3(data);                      // 32-byte hash
blake3Hex(data);                   // Hex string
blake3Mac(key, data);              // Keyed MAC
blake3DeriveKey(ikm, 'context');   // Key derivation
```

#### ChaCha20-Poly1305
```typescript
import {
  chaCha20Poly1305Encrypt,
  chaCha20Poly1305Decrypt,
  xChaCha20Poly1305Encrypt,
  xChaCha20Poly1305Decrypt,
} from '@omnituum/pqc-shared';

// 12-byte nonce
const ciphertext = chaCha20Poly1305Encrypt(key, nonce12, plaintext, aad?);
const plaintext = chaCha20Poly1305Decrypt(key, nonce12, ciphertext, aad?);

// 24-byte nonce (extended)
const ciphertext = xChaCha20Poly1305Encrypt(key, nonce24, plaintext, aad?);
const plaintext = xChaCha20Poly1305Decrypt(key, nonce24, ciphertext, aad?);
```

#### HKDF
```typescript
import { hkdfDerive, hkdfExtract, hkdfExpand } from '@omnituum/pqc-shared';

const key = hkdfDerive(ikm, salt, info, 32);    // Full HKDF
const prk = hkdfExtract(ikm, salt);             // Extract phase
const okm = hkdfExpand(prk, info, 32);          // Expand phase
```

#### NaCl SecretBox
```typescript
import {
  secretboxEncrypt,
  secretboxDecrypt,
  SECRETBOX_KEY_SIZE,    // 32
  SECRETBOX_NONCE_SIZE,  // 24
} from '@omnituum/pqc-shared';

const { nonce, ciphertext } = secretboxEncrypt(key, plaintext);
const plaintext = secretboxDecrypt(key, nonce, ciphertext);
```

### Security Utilities

```typescript
import {
  SecureBuffer,
  zeroMemory,
  zeroAll,
  withSecureData,
  constantTimeEqual,
} from '@omnituum/pqc-shared';

// Memory cleanup
zeroMemory(sensitiveArray);
zeroAll(array1, array2, array3);

// Secure data handling
const result = withSecureData(
  () => getSensitiveKey(),
  (key) => doOperation(key)
); // Key is zeroed after callback

// Timing-safe comparison
if (constantTimeEqual(hash1, hash2)) { ... }
```

### Encoding Utilities

```typescript
import { toB64, fromB64, toHex, fromHex, rand32 } from '@omnituum/pqc-shared';

toB64(bytes);      // Uint8Array → base64 string
fromB64(str);      // base64 string → Uint8Array
toHex(bytes);      // Uint8Array → hex string
fromHex(str);      // hex string → Uint8Array

rand32();          // 32 random bytes
rand24();          // 24 random bytes
rand12();          // 12 random bytes
randN(n);          // n random bytes
```

---

## Data Formats

### HybridIdentity

```typescript
interface HybridIdentity {
  id: string;                 // Unique identifier
  name: string;               // Display name
  x25519PubHex: string;       // X25519 public key (hex)
  x25519SecHex: string;       // X25519 secret key (hex)
  kyberPubB64: string;        // Kyber public key (base64)
  kyberSecB64: string;        // Kyber secret key (base64)
  createdAt: string;          // ISO timestamp
  lastRotatedAt?: string;     // Key rotation timestamp
  rotationCount: number;      // Rotation counter
}
```

### HybridEnvelope

```typescript
interface HybridEnvelope {
  v: string;                  // "omnituum.hybrid.v1"
  suite: string;              // "x25519+kyber768"
  aead: string;               // "xsalsa20poly1305"
  x25519Epk: string;          // Ephemeral X25519 public key
  x25519Wrap: { nonce: string; wrapped: string };
  kyberKemCt: string;         // Kyber KEM ciphertext
  kyberWrap: { nonce: string; wrapped: string };
  contentNonce: string;       // Content encryption nonce
  ciphertext: string;         // Encrypted content
  meta: {
    createdAt: string;
    senderName?: string;
    senderId?: string;
  };
}
```

### OQE File Format

The `.oqe` (Omnituum Quantum Encrypted) format:

```
┌─────────────────────────────────────┐
│ Magic: 0x4F 0x51 0x45 0x46 ("OQEF") │
│ Version: 0x01                        │
│ Mode: 0x01 (hybrid) | 0x02 (password)│
├─────────────────────────────────────┤
│ [Mode-specific key material]         │
│ [Encrypted metadata]                 │
│ [Encrypted file content]             │
└─────────────────────────────────────┘
```

---

## Version Constants

```typescript
import {
  VAULT_VERSION,              // "omnituum.vault.v1"
  VAULT_ENCRYPTED_VERSION,    // "omnituum.vault.enc.v1" (PBKDF2)
  VAULT_ENCRYPTED_VERSION_V2, // "omnituum.vault.enc.v2" (Argon2id)
  ENVELOPE_VERSION,           // "omnituum.hybrid.v1"
  ENVELOPE_SUITE,             // "x25519+kyber768"
  ENVELOPE_AEAD,              // "xsalsa20poly1305"
} from '@omnituum/pqc-shared';
```

---

## Module Imports

The package supports tree-shaking via subpath exports:

```typescript
// Full library
import { ... } from '@omnituum/pqc-shared';

// Crypto only
import { ... } from '@omnituum/pqc-shared/crypto';

// Vault only
import { ... } from '@omnituum/pqc-shared/vault';

// File system / encryption
import { ... } from '@omnituum/pqc-shared/fs';

// Utilities
import { ... } from '@omnituum/pqc-shared/utils';
```

---

## Security Considerations

### Post-Quantum Security

This library implements post-quantum algorithms based on NIST standards:

- **ML-KEM-768** (FIPS 203) — Key encapsulation mechanism, via `kyber-crystals`
- **ML-DSA-65** (FIPS 204) — Digital signatures, via `@noble/post-quantum`

Hybrid encryption combines classical (X25519, RFC 7748) and post-quantum (ML-KEM) algorithms. Both must decrypt successfully, providing defense-in-depth.

> **Note:** This library is pre-audit. "Implements" means we use these algorithms via dependencies; it does not imply FIPS certification or compliance program participation.

### Key Derivation

| Version | KDF | Parameters |
|---------|-----|------------|
| V1 | PBKDF2-SHA256 | 600,000 iterations |
| V2 | Argon2id | 64MB memory, 3 iterations, parallelism 4 |

New implementations should use Argon2id (V2). Use `migrateEncryptedVault()` to upgrade legacy vaults.

### Memory Hygiene

Always zero sensitive data after use:

```typescript
import { zeroMemory, withSecureData } from '@omnituum/pqc-shared';

// Manual cleanup
const key = deriveKey(...);
try {
  // use key
} finally {
  zeroMemory(key);
}

// Automatic cleanup
withSecureData(
  () => deriveKey(...),
  (key) => encrypt(key, data)
);
```

### Timing Attacks

Use `constantTimeEqual()` for comparing secrets:

```typescript
import { constantTimeEqual } from '@omnituum/pqc-shared';

// Bad: variable-time comparison
if (hash1 === hash2) { ... }

// Good: constant-time comparison
if (constantTimeEqual(hash1, hash2)) { ... }
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/ciphers` | ChaCha20-Poly1305 AEAD |
| `@noble/hashes` | SHA-256, BLAKE3, HMAC, HKDF |
| `@noble/post-quantum` | ML-DSA-65 (Dilithium) signatures |
| `hash-wasm` | Argon2id (WebAssembly) |
| `kyber-crystals` | ML-KEM-768 (Kyber) |
| `tweetnacl` | NaCl box/secretbox, X25519 |

All dependencies are pure JavaScript/WebAssembly with no native bindings.

---

## Development

```bash
# Build
pnpm build

# Watch mode
pnpm dev

# Type check
pnpm typecheck

# Run golden tests
pnpm test:golden
```

### Golden Tests

Test vectors in `tests/golden/` provide reproducible cryptographic test cases:

```bash
# Generate new test vectors (run once)
pnpm test:golden:generate

# Verify test vectors (CI/pre-audit)
pnpm test:golden:verify
```

---

## License

MIT
