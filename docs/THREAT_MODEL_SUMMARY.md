# THREAT MODEL SUMMARY — @omnituum/pqc-shared

> Security assumptions and operational guidance.
> Confidence markers: **Known** / **Likely** / **Unknown**.

---

## 1. Threat Model Scope

This library provides **cryptographic primitives**. It does not implement a complete security system. The threat model covers the cryptographic operations themselves, not the application context in which they are used.

## 2. Hybrid Encryption Assumptions

### What it protects against

| Threat | Mitigation | Confidence |
|---|---|---|
| Classical key compromise alone | Kyber layer still protects content | **Known** |
| Quantum attack on X25519 alone | Kyber (ML-KEM-768, NIST Level 3) provides PQ security | **Known** |
| Future quantum attack on archived ciphertext | Hybrid defense-in-depth: both layers must be broken | **Known** |
| Passive eavesdropping | Ephemeral X25519 + Kyber KEM per message | **Known** |

### What it does NOT protect against

| Threat | Reason |
|---|---|
| Compromise of both classical AND quantum keys | Both layers broken = plaintext recovered |
| Compromised recipient private keys | No forward secrecy at the library level; application must manage key rotation |
| Man-in-the-middle (active) | Library provides no authentication of public keys; application must verify identity |
| Side-channel attacks on JS runtime | JavaScript/WASM cannot guarantee constant-time execution on all platforms |
| Memory disclosure (Spectre, Meltdown, cold boot) | `zeroMemory` is best-effort; GC and JIT may retain copies |
| Malicious dependency supply chain | Dependencies are pure JS/WASM but not vendored |
| Denial of service via large inputs | No input size limits enforced at library level |

## 3. Vault Encryption Assumptions

### V2 (Argon2id) — Recommended

| Parameter | Value | Purpose |
|---|---|---|
| Memory | 64 MB | Resist GPU/ASIC attacks |
| Time | 3 iterations | Increase cost |
| Parallelism | 4 | Utilize multi-core |
| Algorithm | AES-256-GCM | Symmetric encryption of vault blob |

### V1 (PBKDF2-SHA256) — Legacy

| Parameter | Value | Note |
|---|---|---|
| Iterations | 600,000 | OWASP 2023 recommendation |
| Algorithm | AES-256-GCM | Same symmetric layer as V2 |

**Migration path:** `migrateEncryptedVault()` upgrades V1 → V2. **[Known]**

### Vault threats NOT covered

| Threat | Reason |
|---|---|
| Weak passwords | Library cannot enforce password policy |
| Offline brute force with unlimited resources | Argon2id increases cost but cannot prevent it |
| Compromised runtime environment | If attacker controls the JS engine, all bets are off |
| Vault file integrity without password | Integrity is verified during decryption, not at rest |

## 4. Digital Signatures (ML-DSA-65)

| Property | Status | Confidence |
|---|---|---|
| Post-quantum security | NIST Level 3 (FIPS 204) via `@noble/post-quantum` | **Known** |
| Deterministic generation from seed | Supported via `generateDilithiumKeypairFromSeed` | **Known** |
| Non-repudiation | Provided if private key is secured | **Known** |
| Implementation correctness | Depends on `@noble/post-quantum`; pre-audit | **Likely** |

## 5. OQE File Format

| Property | Status | Confidence |
|---|---|---|
| Magic byte validation | `"OQEF"` prefix checked on parse | **Known** |
| Version byte checked | Yes | **Known** |
| Mode byte determines key material path | hybrid (0x01) or password (0x02) | **Known** |
| Metadata encrypted | Yes, alongside content | **Likely** |
| Authenticated encryption | Via underlying AEAD (xsalsa20poly1305 or AES-256-GCM) | **Known** |

## 6. Operational Guidance

### Key Handling

1. **Zero sensitive buffers** after use: call `zeroMemory(buf)` or use `withSecureData()`.
2. **Do not log** secret keys, shared secrets, or decrypted vault contents.
3. **Rotate keys** periodically using `rotateIdentityKeys()`. The library tracks `rotationCount` and `lastRotatedAt`.
4. **Store vault files** encrypted. Never write decrypted vault JSON to disk.

### Memory Zeroing Limitations

- `zeroMemory` overwrites `Uint8Array` contents with zeros. **[Known]**
- JavaScript GC may have already copied the buffer. Zeroing is best-effort. **[Known]**
- JIT compilers may optimize away zeroing operations. **[Likely]**
- `withSecureData` provides scoped cleanup but shares the same GC limitations. **[Known]**

### Timing Attack Mitigation

- Use `constantTimeEqual()` for all secret comparisons. **[Known]**
- JS runtimes do not guarantee constant-time execution. Mitigated but not eliminated. **[Known]**
- The `@noble/*` dependencies implement their own constant-time protections. **[Likely]**

### Nonce Management

- Hybrid encryption generates fresh ephemeral keys per message; nonce reuse risk is low. **[Known]**
- For direct ChaCha20-Poly1305 usage, callers must ensure unique nonces per key.
- `xChaCha20Poly1305` (24-byte nonce) is preferred for random nonce generation to minimize collision probability.
- `rand12()`, `rand24()`, `rand32()` use the platform CSPRNG. **[Known]**

## 7. Dependency Risk

| Package | Risk level | Notes |
|---|---|---|
| `@noble/*` | Low | Well-audited, widely used, pure JS |
| `tweetnacl` | Low | Mature, audited, pure JS |
| `hash-wasm` | Medium | WASM binary; verify integrity of WASM blobs |
| `kyber-crystals` | Medium | Less mature than noble; pure JS |

## 8. Audit Status

**Pre-audit.** No formal third-party security audit has been performed. Golden test vectors exist for regression detection but do not constitute a security review.

Recommendation: Before production use in high-stakes environments, commission an independent audit covering:
- Correct usage of underlying primitives
- Key material lifecycle
- Nonce/IV management
- WASM binary integrity (hash-wasm)
- Side-channel exposure in the JS/WASM boundary
