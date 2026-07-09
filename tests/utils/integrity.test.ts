/**
 * Vault integrity-hash tests — 2026-07-06 fs remediation.
 *
 * The previous implementation used a non-cryptographic DJB2 rolling hash while
 * claiming SHA-256. These tests pin that the value is now a real SHA-256 digest
 * and that it actually changes when the identity records change (tamper-evident
 * as a checksum — note it is unkeyed, so it is not authentication).
 */

import { describe, it, expect } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { computeIntegrityHash, verifyIntegrity } from '../../src/utils/integrity';
import { toHex } from '../../src/crypto/primitives';
import type { HybridIdentityRecord } from '../../src/vault/types';

function rec(over: Partial<HybridIdentityRecord> = {}): HybridIdentityRecord {
  return {
    id: 'id-1',
    name: 'Alice',
    x25519PubHex: '0xaabbcc',
    kyberPubB64: 'a2V5',
    x25519SecHex: '0xdeadbeef',
    kyberSecB64: 'c2Vj',
    createdAt: '2026-01-01T00:00:00.000Z',
    rotationCount: 0,
    ...over,
  } as HybridIdentityRecord;
}

describe('computeIntegrityHash', () => {
  it('produces a 64-hex-char SHA-256 digest', () => {
    const h = computeIntegrityHash([rec()]);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('matches an independent SHA-256 of the canonical serialization', () => {
    const canonical = [{
      id: 'id-1', name: 'Alice', x25519PubHex: '0xaabbcc',
      kyberPubB64: 'a2V5', createdAt: '2026-01-01T00:00:00.000Z', rotationCount: 0,
    }];
    const expected = toHex(sha256(new TextEncoder().encode(JSON.stringify(canonical))));
    expect(computeIntegrityHash([rec()])).toBe(expected);
  });

  it('is deterministic', () => {
    expect(computeIntegrityHash([rec()])).toBe(computeIntegrityHash([rec()]));
  });

  it('changes when a public field changes (tamper-evident)', () => {
    const base = computeIntegrityHash([rec()]);
    expect(computeIntegrityHash([rec({ x25519PubHex: '0xaabbcd' })])).not.toBe(base);
    expect(computeIntegrityHash([rec({ name: 'Bob' })])).not.toBe(base);
    expect(computeIntegrityHash([rec({ rotationCount: 1 })])).not.toBe(base);
  });

  it('is not the old 16-char DJB2 output', () => {
    const h = computeIntegrityHash([rec()]);
    expect(h.length).toBe(64);
  });
});

describe('verifyIntegrity', () => {
  it('accepts a matching hash and rejects a mutated set', async () => {
    const identities = [rec()];
    const hash = computeIntegrityHash(identities);
    expect(await verifyIntegrity(identities, hash)).toBe(true);
    expect(await verifyIntegrity([rec({ name: 'Mallory' })], hash)).toBe(false);
  });
});
