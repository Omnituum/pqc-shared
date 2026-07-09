/**
 * OQE v2 file-format security tests — 2026-07-06 fs remediation.
 *
 * Pins the properties the v2 format was introduced to guarantee:
 *  1. Distinct AES-GCM IVs for metadata vs. content (no GCM nonce reuse).
 *  2. Hybrid mode uses an AND-combined KEK — NEITHER the classical secret nor
 *     the post-quantum secret alone can decrypt.
 *  3. The header (version/suite/flags/IVs) is AEAD-bound: mutating it fails auth.
 *  4. Round-trip correctness for hybrid and password modes.
 */

import { describe, it, expect } from 'vitest';
import { generateHybridIdentity } from '../../src/crypto/hybrid';
import { generateKyberKeypair } from '../../src/crypto/kyber';
import { generateX25519Keypair } from '../../src/crypto/x25519';
import { encryptFile } from '../../src/fs/encrypt';
import { decryptFile } from '../../src/fs/decrypt';
import { parseOQEHeader, parseOQEFile } from '../../src/fs/format';
import {
  OQE_FORMAT_VERSION_V2,
  ALGORITHM_SUITES,
} from '../../src/fs/types';

const enc = new TextEncoder();

async function makeIdentity() {
  const id = await generateHybridIdentity('oqe-v2-test');
  if (!id) throw new Error('identity generation failed');
  return id;
}

function pub(id: { x25519PubHex: string; kyberPubB64: string }) {
  return { x25519PubHex: id.x25519PubHex, kyberPubB64: id.kyberPubB64 };
}
function sec(id: { x25519SecHex: string; kyberSecB64: string }) {
  return { x25519SecHex: id.x25519SecHex, kyberSecB64: id.kyberSecB64 };
}

describe('OQE v2 — nonce reuse regression', () => {
  it('hybrid: metadata IV !== content IV', async () => {
    const id = await makeIdentity();
    const { data } = await encryptFile(
      { data: enc.encode('secret file body'), filename: 'a.txt' },
      { mode: 'hybrid', recipientPublicKeys: pub(id) }
    );
    const header = parseOQEHeader(data);
    expect(header.version).toBe(OQE_FORMAT_VERSION_V2);
    expect(header.contentIv).toBeDefined();
    expect(Buffer.from(header.iv)).not.toEqual(Buffer.from(header.contentIv!));
  });

  it('password: metadata IV !== content IV', async () => {
    const { data } = await encryptFile(
      { data: enc.encode('secret file body'), filename: 'a.txt' },
      { mode: 'password', password: 'correct horse battery staple' }
    );
    const header = parseOQEHeader(data);
    expect(header.version).toBe(OQE_FORMAT_VERSION_V2);
    expect(header.contentIv).toBeDefined();
    expect(Buffer.from(header.iv)).not.toEqual(Buffer.from(header.contentIv!));
  });
});

describe('OQE v2 — round trip', () => {
  it('hybrid encrypts and decrypts with both secrets', async () => {
    const id = await makeIdentity();
    const body = enc.encode('the quick brown fox');
    const { data } = await encryptFile(
      { data: body, filename: 'fox.txt' },
      { mode: 'hybrid', recipientPublicKeys: pub(id) }
    );
    const out = await decryptFile(data, { mode: 'hybrid', recipientSecretKeys: sec(id) });
    expect(new Uint8Array(out.data)).toEqual(body);
    expect(out.filename).toBe('fox.txt');
  });

  it('uses the ML-KEM-1024 AND-combined suite id', async () => {
    const id = await makeIdentity();
    const { data } = await encryptFile(
      { data: enc.encode('x'), filename: 'x' },
      { mode: 'hybrid', recipientPublicKeys: pub(id) }
    );
    const { header } = parseOQEFile(data);
    expect(header.algorithmSuite).toBe(ALGORITHM_SUITES.HYBRID_X25519_MLKEM1024_AES256GCM);
  });

  it('password encrypts and decrypts', async () => {
    const body = enc.encode('classified');
    const { data } = await encryptFile(
      { data: body, filename: 'c.txt' },
      { mode: 'password', password: 'pw-123456' }
    );
    const out = await decryptFile(data, { mode: 'password', password: 'pw-123456' });
    expect(new Uint8Array(out.data)).toEqual(body);
  });
});

describe('OQE v2 — hybrid AND property (both secrets required)', () => {
  it('post-quantum secret alone CANNOT decrypt (wrong X25519 secret)', async () => {
    const id = await makeIdentity();
    const attacker = generateX25519Keypair(); // wrong classical secret
    const { data } = await encryptFile(
      { data: enc.encode('needs both'), filename: 'b.txt' },
      { mode: 'hybrid', recipientPublicKeys: pub(id) }
    );
    await expect(
      decryptFile(data, {
        mode: 'hybrid',
        recipientSecretKeys: { x25519SecHex: attacker.secretHex, kyberSecB64: id.kyberSecB64 },
      })
    ).rejects.toThrow();
  });

  it('classical secret alone CANNOT decrypt (wrong ML-KEM secret)', async () => {
    const id = await makeIdentity();
    const attackerKyber = await generateKyberKeypair(); // wrong PQ secret
    if (!attackerKyber) throw new Error('kyber keygen failed');
    const { data } = await encryptFile(
      { data: enc.encode('needs both'), filename: 'b.txt' },
      { mode: 'hybrid', recipientPublicKeys: pub(id) }
    );
    await expect(
      decryptFile(data, {
        mode: 'hybrid',
        recipientSecretKeys: { x25519SecHex: id.x25519SecHex, kyberSecB64: attackerKyber.secretB64 },
      })
    ).rejects.toThrow();
  });
});

describe('OQE v2 — header is AEAD-bound (tamper detection)', () => {
  async function encryptedBytes() {
    const id = await makeIdentity();
    const { data } = await encryptFile(
      { data: enc.encode('tamper target'), filename: 't.txt' },
      { mode: 'hybrid', recipientPublicKeys: pub(id) }
    );
    return { data, id };
  }

  it('flipping the suite byte fails decryption', async () => {
    const { data, id } = await encryptedBytes();
    const tampered = data.slice();
    tampered[5] ^= 0xff; // offset 5 = algorithm suite
    await expect(
      decryptFile(tampered, { mode: 'hybrid', recipientSecretKeys: sec(id) })
    ).rejects.toThrow();
  });

  it('flipping a flags byte fails authentication', async () => {
    const { data, id } = await encryptedBytes();
    const tampered = data.slice();
    tampered[6] ^= 0x01; // offset 6 = flags (bound as AAD)
    await expect(
      decryptFile(tampered, { mode: 'hybrid', recipientSecretKeys: sec(id) })
    ).rejects.toThrow();
  });

  it('flipping a content-IV byte fails authentication', async () => {
    const { data, id } = await encryptedBytes();
    const tampered = data.slice();
    tampered[30] ^= 0xff; // offset 30 = first byte of content IV (v2)
    await expect(
      decryptFile(tampered, { mode: 'hybrid', recipientSecretKeys: sec(id) })
    ).rejects.toThrow();
  });
});
