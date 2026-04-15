// tests/crypto/kyber.test.ts
/**
 * Kyber (ML-KEM-1024 / FIPS 203) — backend swap and deterministic seed keygen.
 * Covers PQC-03 (clean cut to noble) and PQC-04 (generateKyberKeypairFromSeed).
 */

import { describe, it, expect } from 'vitest';
import {
  generateKyberKeypair,
  generateKyberKeypairFromSeed,
  kyberEncapsulate,
  kyberDecapsulate,
  kyberWrapKey,
  kyberUnwrapKey,
  isKyberAvailable,
  KYBER_SUITE,
} from '../../src/crypto/kyber';
import { ub64 } from '../../src/crypto/primitives';

describe('Kyber ML-KEM-1024 (FIPS 203)', () => {
  it('canonical suite identifier is ML-KEM-1024-FIPS203', () => {
    expect(KYBER_SUITE).toBe('ML-KEM-1024-FIPS203');
  });

  it('isKyberAvailable always resolves true', async () => {
    await expect(isKyberAvailable()).resolves.toBe(true);
  });

  it('generateKyberKeypair returns FIPS-203-sized material', async () => {
    const kp = await generateKyberKeypair();
    expect(kp).not.toBeNull();
    expect(ub64(kp!.publicB64).length).toBe(1568);
    expect(ub64(kp!.secretB64).length).toBe(3168);
  });

  it('encapsulate → decapsulate recovers the shared secret', async () => {
    const kp = await generateKyberKeypair();
    const enc = await kyberEncapsulate(kp!.publicB64);
    expect(enc.ciphertext.length).toBe(1568);
    expect(enc.sharedSecret.length).toBe(32);
    const ss = await kyberDecapsulate(
      btoa(String.fromCharCode(...enc.ciphertext)),
      kp!.secretB64,
    );
    expect(ss).toEqual(enc.sharedSecret);
  });

  it('kyberWrapKey / kyberUnwrapKey round-trips a 32-byte message key', () => {
    const ss = new Uint8Array(32).fill(11);
    const msgKey = new Uint8Array(32).fill(7);
    const w = kyberWrapKey(ss, msgKey);
    const out = kyberUnwrapKey(ss, w.nonce, w.wrapped);
    expect(out).toEqual(msgKey);
  });
});

describe('PQC-04 generateKyberKeypairFromSeed', () => {
  const SEED = new Uint8Array(64).map((_, i) => (i * 7 + 13) & 0xff);

  it('rejects seeds that are not 64 bytes', () => {
    expect(() => generateKyberKeypairFromSeed(new Uint8Array(32))).toThrow(/64 bytes/);
    expect(() => generateKyberKeypairFromSeed(new Uint8Array(65))).toThrow(/64 bytes/);
  });

  it('produces byte-identical keypairs for the same seed', () => {
    const a = generateKyberKeypairFromSeed(SEED);
    const b = generateKyberKeypairFromSeed(SEED);
    expect(a.publicKey).toEqual(b.publicKey);
    expect(a.secretKey).toEqual(b.secretKey);
  });

  it('produces FIPS-203-sized material', () => {
    const kp = generateKyberKeypairFromSeed(SEED);
    expect(kp.publicKey.length).toBe(1568);
    expect(kp.secretKey.length).toBe(3168);
  });

  it('different seeds produce different keypairs', () => {
    const a = generateKyberKeypairFromSeed(SEED);
    const b = generateKyberKeypairFromSeed(new Uint8Array(64).fill(1));
    expect(a.publicKey).not.toEqual(b.publicKey);
  });

  it('keypair derived from seed encapsulates and decapsulates correctly', async () => {
    const kp = generateKyberKeypairFromSeed(SEED);
    const pkB64 = btoa(String.fromCharCode(...kp.publicKey));
    const skB64 = btoa(String.fromCharCode(...kp.secretKey));
    const enc = await kyberEncapsulate(pkB64);
    const ctB64 = btoa(String.fromCharCode(...enc.ciphertext));
    const ss = await kyberDecapsulate(ctB64, skB64);
    expect(ss).toEqual(enc.sharedSecret);
  });
});
