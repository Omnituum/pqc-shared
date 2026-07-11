/**
 * F11 — X25519 public-from-secret + raw keypair-from-secret.
 *
 * Filed during the PQC-07 NaCl-boundary audit: consumers needed
 * `nacl.scalarMult.base` (ephemeral pubkey derivation) and
 * `nacl.box.keyPair.fromSecretKey` (raw keypair recovery) but pqc-shared
 * didn't wrap either, so those two tweetnacl calls stayed on the boundary
 * allowlist. These tests pin byte-identity against the raw tweetnacl
 * primitives directly (not just internal consistency) so the export is
 * provably a drop-in replacement.
 */

import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import {
  x25519PublicFromSecret,
  x25519KeypairFromSecret,
  generateX25519KeypairFromSeed,
} from '../../src/crypto/x25519';

describe('x25519PublicFromSecret', () => {
  it('matches nacl.scalarMult.base exactly', () => {
    const sk = new Uint8Array(32).map((_, i) => (i * 17 + 3) & 0xff);
    const expected = nacl.scalarMult.base(sk);
    const actual = x25519PublicFromSecret(sk);
    expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
  });

  it('matches nacl.box.keyPair.fromSecretKey().publicKey exactly', () => {
    const sk = new Uint8Array(32).fill(9);
    const expected = nacl.box.keyPair.fromSecretKey(sk).publicKey;
    const actual = x25519PublicFromSecret(sk);
    expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
  });

  it('rejects a secret key of the wrong length', () => {
    expect(() => x25519PublicFromSecret(new Uint8Array(16))).toThrow();
  });
});

describe('x25519KeypairFromSecret', () => {
  it('echoes the secret key back unchanged (no hashing/normalization)', () => {
    const sk = new Uint8Array(32).map((_, i) => (i * 11 + 5) & 0xff);
    const kp = x25519KeypairFromSecret(sk);
    expect(Buffer.from(kp.secretKey).equals(Buffer.from(sk))).toBe(true);
  });

  it('matches nacl.box.keyPair.fromSecretKey exactly', () => {
    const sk = new Uint8Array(32).map((_, i) => (i * 3 + 1) & 0xff);
    const expected = nacl.box.keyPair.fromSecretKey(sk);
    const actual = x25519KeypairFromSecret(sk);
    expect(Buffer.from(actual.publicKey).equals(Buffer.from(expected.publicKey))).toBe(true);
    expect(Buffer.from(actual.secretKey).equals(Buffer.from(expected.secretKey))).toBe(true);
  });

  it('is NOT the same as generateX25519KeypairFromSeed (that hashes the seed)', async () => {
    const seed = new Uint8Array(32).fill(42);
    const viaRaw = x25519KeypairFromSecret(seed);
    const viaSeed = generateX25519KeypairFromSeed(seed);
    expect(Buffer.from(viaRaw.secretKey).equals(Buffer.from(viaSeed.secretKey))).toBe(false);
    expect(Buffer.from(viaRaw.publicKey).equals(Buffer.from(viaSeed.publicKey))).toBe(false);
  });
});
