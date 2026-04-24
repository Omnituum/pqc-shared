# @omnituum/pqc-shared — Use Cases (Plain Language)

**Date:** 2026-04-23 (added 2026-04-24 under DO-24 — DO-27 scaffold oversight; file authored 2026-04-23 without Date header)

## What is this?

A library that lets your app encrypt, sign, and store data in a way that resists attacks from future quantum computers. It combines today's proven math (X25519, ChaCha20-Poly1305) with tomorrow's quantum-resistant math (ML-KEM-768) so you're safe against both current adversaries and "harvest now, decrypt later" attacks.

---

## Who is this for?

### Apps that send sensitive messages

You're building a messaging app, a credential vault, or a field-ops tool. You need to encrypt payloads so that only the intended recipient can read them — and you need those payloads to still be safe in 10 years when quantum computers arrive. This library gives you one function call (`hybridEncrypt`) that produces ciphertext protected by both classical and post-quantum algorithms.

### Servers that issue encrypted files

You're building a system that hands encrypted files to users — medical records, legal discovery, regulated telemetry. You want the file format to outlive whichever crypto algorithm the industry mandates next. The `fs` subpath encrypts files with a format that can rotate primitives without breaking past files.

### Libraries that need a vault

You're writing another library (a BLE layer, a web transport, a Python backend) that needs to persist secret keys between sessions. The `vault` subpath stores keys encrypted at rest with a password-derived key, portable across platforms.

---

## What you get

- **One import.** `generateHybridIdentity`, `hybridEncrypt`, `hybridDecrypt` — three functions cover most needs.
- **Stable root API.** Subpaths (`/crypto`, `/vault`, `/fs`) may reorganize in minor versions; the root is semver-frozen.
- **No crypto choices.** The library picks the primitives; you don't have to understand ML-KEM vs X25519 to use it safely.
- **Auditable surface.** Every export is listed in `reference/EXPORTS_CONTRACT.md` with stability markers.

---

## What it is NOT

- **Not a transport.** It encrypts payloads; how those payloads travel (HTTPS, BLE, IPFS) is another library's job.
- **Not a key-management service.** It generates keys and ciphertexts; where you store the private keys is up to you (use the `vault` subpath or bring your own).
- **Not experimental.** ML-KEM-768 is NIST-standardized (FIPS 203, 2024). This is production crypto, not research code.
