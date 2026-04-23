# @omnituum/pqc-shared — Overview

**Date:** 2026-04-23
**Package:** `@omnituum/pqc-shared`
**Version:** 0.4.0
**Layer:** Foundation (shared PQC primitives)
**Status:** stable

---

## What This Is

The canonical shared PQC-primitive layer for the Omnituum + LoggieCID workspace. Ships hybrid ML-KEM-768 (Kyber) + X25519 + ChaCha20-Poly1305 encryption, Kyber wrap/unwrap, file encryption, and vault utilities as a single library consumable by every downstream PQC-dependent module.

Canonical details: surface contract in `reference/EXPORTS_CONTRACT.md`; threat model summary in `reference/THREAT_MODEL_SUMMARY.md`; version policy in `reference/VERSION_AUTHORITY.md`.

## Where It Sits

- Depends on: `@noble/ciphers`, `@noble/hashes`, `@noble/curves`, WASM bindings for ML-KEM.
- Consumed by: `@omnituum/pqc-ble`, `@omnituum/pqc-vault`, `@omnituum/pqc-web`, `@omnituum/envelope-registry`, `@loggiecid/noise-kyber`, `@loggiecid/core`, `@loggiecid/sdk-*`, `@darkwire/*`, `@omnituum/secure-intake-*`.

Downstream modules reference PQC primitives via cross-module pointers (**PQC-##**) rather than re-tracking shared crypto concerns locally per DOC_STANDARD § Module-Scoped ID Grammar § Pointer-Only Rule.

## Prefix

**PQC-##** — registered in DOC_STANDARD v0.5.1. Tracked work lives in `GAPS_AND_TASKS.md`.
