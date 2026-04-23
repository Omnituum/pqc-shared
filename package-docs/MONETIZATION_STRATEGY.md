# @omnituum/pqc-shared — Monetization Strategy

**Date:** 2026-04-23
**Module:** pqc-shared
**Disposition:** Foundation library. Not a direct revenue surface; enables monetizable downstreams.

---

## Positioning

`@omnituum/pqc-shared` is foundation-layer infrastructure. It has no end-user surface of its own; it is consumed by every Omnituum and LoggieCID module that needs post-quantum-safe encryption, signing, or key management. Revenue accrues at the downstream boundary, not here.

## Value Captured Downstream

The library's economic value is the aggregate of what its consumers can charge for, multiplied by the share those consumers would fail to deliver without it.

Direct downstreams that monetize on top of this crypto:

| Consumer | Revenue surface | PQC dependency |
|---|---|---|
| `@omnituum/pqc-vault` | Paid vault tiers + enterprise deployments | Hybrid encryption for vault-at-rest + key rotation |
| `@omnituum/pqc-web` | Paid web-encryption middleware + SaaS offering | Hybrid encryption for request bodies + sessions |
| `@omnituum/secure-intake-*` | Per-form usage + enterprise seat pricing | Envelope encryption for intake payloads |
| `@darkwire/*` | End-user subscriptions + premium features | Hybrid encryption for darkwire messaging |
| `@loggiecid/core` | SDK license + support contracts | Underlying crypto for encrypted-message flow |
| `@loggiecid/noise-kyber` | Research / defense-sector licensing | Kyber primitives for noise handshake |

## Commercial Posture

- **License:** Private workspace library; no public release planned. Consumers are workspace-internal modules with private dependencies.
- **Pricing:** N/A at this layer. Any future external licensing would price on the consumer's revenue contribution, not on this library's LOC or surface.
- **Support:** Support contracts for consumers include coverage of this layer — breakage here blocks every downstream.

## Non-Goals

- **Not a standalone SaaS.** No hosted crypto API, no key-as-a-service offering.
- **Not open-source.** Publishing to npm public would invite forking pressure on the root export surface, which consumers rely on as semver-stable.

## Strategic Importance

Scored 10/10 in `MODULE_INDEX.json`. Any replacement would require re-auditing every downstream's crypto posture — a single change here is load-bearing across 8+ modules.
