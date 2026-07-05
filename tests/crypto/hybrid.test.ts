/**
 * Hybrid envelope tests — v2 AND-combiner (2026-07-05 security audit fix).
 *
 * v1 wrapped the content key independently under X25519 and Kyber, so
 * EITHER secret alone decrypted — min(X25519, ML-KEM) security. v2 wraps
 * once under HKDF(ss_mlkem || ss_x25519) with transcript binding, so both
 * primitives must be broken. These tests pin the AND property (the entire
 * point of the fix) plus v1 read compatibility.
 */

import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import {
  generateHybridIdentity,
  getPublicKeys,
  getSecretKeys,
  hybridEncrypt,
  hybridDecrypt,
  hybridDecryptToString,
  type HybridEnvelopeV1,
  type HybridEnvelopeV2,
} from '../../src/crypto/hybrid';
import { kyberEncapsulate } from '../../src/crypto/kyber';
import {
  rand24,
  rand32,
  b64,
  ub64,
  toHex,
  fromHex,
  hkdfSha256,
  u8,
  textEncoder,
} from '../../src/crypto/primitives';

async function makeIdentity() {
  const identity = await generateHybridIdentity('hybrid-test');
  if (!identity) throw new Error('identity generation failed');
  return identity;
}

/** Reimplementation of the v1 (independent-wraps) writer, for read-compat tests. */
async function encryptV1(plaintext: string, pub: { x25519PubHex: string; kyberPubB64: string }): Promise<HybridEnvelopeV1> {
  const hkdf = (ikm: Uint8Array, salt: string, info: string) =>
    hkdfSha256(ikm, { salt: u8(salt), info: u8(info), length: 32 });

  const CK = rand32();
  const contentNonce = rand24();
  const ciphertext = nacl.secretbox(textEncoder.encode(plaintext), contentNonce, CK);

  const eph = nacl.box.keyPair();
  const xShared = nacl.scalarMult(eph.secretKey, fromHex(pub.x25519PubHex));
  const xKek = hkdf(xShared, 'omnituum/x25519', 'wrap-ck');
  const xNonce = rand24();
  const xWrapped = nacl.secretbox(CK, xNonce, xKek);

  const kem = await kyberEncapsulate(pub.kyberPubB64);
  const kKek = hkdf(kem.sharedSecret, 'omnituum/kyber', 'wrap-ck');
  const kNonce = rand24();
  const kWrapped = nacl.secretbox(CK, kNonce, kKek);

  return {
    v: 'omnituum.hybrid.v1',
    suite: 'x25519+kyber768',
    aead: 'xsalsa20poly1305',
    x25519Epk: toHex(eph.publicKey),
    x25519Wrap: { nonce: b64(xNonce), wrapped: b64(xWrapped) },
    kyberKemCt: b64(kem.ciphertext),
    kyberWrap: { nonce: b64(kNonce), wrapped: b64(kWrapped) },
    contentNonce: b64(contentNonce),
    ciphertext: b64(ciphertext),
    meta: { createdAt: new Date().toISOString() },
  };
}

describe('hybrid v2 (AND-combined KEK)', () => {
  it('round-trips and emits the v2 wire format', async () => {
    const id = await makeIdentity();
    const envelope = await hybridEncrypt('phi-value-123', getPublicKeys(id));

    expect(envelope.v).toBe('omnituum.hybrid.v2');
    expect(envelope.suite).toBe('x25519+mlkem1024');
    expect(envelope.ckWrap.wrapped).toBeTruthy();
    expect((envelope as unknown as Record<string, unknown>).x25519Wrap).toBeUndefined();
    expect((envelope as unknown as Record<string, unknown>).kyberWrap).toBeUndefined();

    const pt = await hybridDecryptToString(envelope, getSecretKeys(id));
    expect(pt).toBe('phi-value-123');
  });

  it('AND property: the correct X25519 secret plus a wrong Kyber secret fails', async () => {
    const id = await makeIdentity();
    const other = await makeIdentity();
    const envelope = await hybridEncrypt('secret', getPublicKeys(id));

    // v1's defect was exactly this scenario succeeding via the classical wrap.
    await expect(
      hybridDecrypt(envelope, { x25519SecHex: id.x25519SecHex, kyberSecB64: other.kyberSecB64 })
    ).rejects.toThrow();
  });

  it('AND property: the correct Kyber secret plus a wrong X25519 secret fails', async () => {
    const id = await makeIdentity();
    const other = await makeIdentity();
    const envelope = await hybridEncrypt('secret', getPublicKeys(id));

    await expect(
      hybridDecrypt(envelope, { x25519SecHex: other.x25519SecHex, kyberSecB64: id.kyberSecB64 })
    ).rejects.toThrow();
  });

  it('transcript binding: splicing another envelope\'s KEM ciphertext fails', async () => {
    const id = await makeIdentity();
    const a = await hybridEncrypt('message-a', getPublicKeys(id));
    const b = await hybridEncrypt('message-b', getPublicKeys(id));

    const spliced: HybridEnvelopeV2 = { ...a, kyberKemCt: b.kyberKemCt };
    await expect(hybridDecrypt(spliced, getSecretKeys(id))).rejects.toThrow();
  });

  it('rejects tampered content ciphertext', async () => {
    const id = await makeIdentity();
    const envelope = await hybridEncrypt('integrity', getPublicKeys(id));

    const bytes = ub64(envelope.ciphertext);
    bytes[0] ^= 0xff;
    const tampered = { ...envelope, ciphertext: b64(bytes) };
    await expect(hybridDecrypt(tampered, getSecretKeys(id))).rejects.toThrow('Content authentication failed');
  });

  it('rejects unknown envelope versions', async () => {
    const id = await makeIdentity();
    const envelope = await hybridEncrypt('x', getPublicKeys(id));
    const bogus = { ...envelope, v: 'omnituum.hybrid.v99' } as unknown as HybridEnvelopeV2;
    await expect(hybridDecrypt(bogus, getSecretKeys(id))).rejects.toThrow('Version mismatch');
  });
});

describe('hybrid v1 (read-only legacy)', () => {
  it('still decrypts envelopes written in the v1 format', async () => {
    const id = await makeIdentity();
    const v1Envelope = await encryptV1('pre-v2 data', getPublicKeys(id));
    const pt = await hybridDecryptToString(v1Envelope, getSecretKeys(id));
    expect(pt).toBe('pre-v2 data');
  });
});
