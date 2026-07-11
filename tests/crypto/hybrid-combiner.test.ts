/**
 * CM-25 / F11 — new public hybrid content-key combiner.
 *
 * Covers: frozen encoding vectors (V-RID-1, V-TX-1, V-TX-2 — design-level,
 * pure encoding/hash), the crypto-backed vectors produced during this
 * implementation step (V-WRAP-1, V-DOMAIN-1), and the I-1..I-10 invariant
 * matrix from SPEC_CM25_F11_COMBINER_EXPORT.md §7.
 *
 * `buildHybridTranscriptV1` is imported directly (file-level export, not
 * in any public barrel — see hybrid-kek-core.test.ts for why that's safe)
 * to verify the frozen transcript bytes independently of the full
 * wrap/unwrap round-trip.
 */

import { describe, it, expect } from 'vitest';
import {
  wrapContentKeyHybrid,
  unwrapContentKeyHybrid,
  hybridDomain,
  hybridRecipientId,
  buildHybridTranscriptV1,
  HybridUnwrapError,
  InvalidHybridDomainError,
  InvalidKeyMaterialError,
  InvalidContentKeyError,
  type HybridRecipientPub,
} from '../../src/crypto/hybrid';
import { generateHybridIdentity, getPublicKeys, getSecretKeys } from '../../src/crypto/hybrid';
import { sha256 } from '../../src/crypto/primitives';

// ── Deterministic fillers matching the design-record vectors exactly ───────
const x25519PubRaw = new Uint8Array(32).map((_, i) => i & 0xff);
const kyberPubRaw = new Uint8Array(1568).map((_, i) => (3 * i + 7) & 0xff);
const epkRaw = new Uint8Array(32).map((_, i) => (5 * i + 1) & 0xff);
const kemRaw = new Uint8Array(1568).map((_, i) => (7 * i + 3) & 0xff);

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

describe('V-RID-1 — hybridRecipientId frozen vector', () => {
  it('matches the design-record frozen digest', () => {
    const pub: HybridRecipientPub = {
      x25519PubHex: '0x' + toHex(x25519PubRaw),
      kyberPubB64: Buffer.from(kyberPubRaw).toString('base64'),
    };
    const rid = hybridRecipientId(pub);
    expect(toHex(rid)).toBe('8fe406405490b6c1280e7fddecb6b5f81e170496584594366feb1e95ffb60453');
  });

  it('rejects malformed X25519 public key length', () => {
    expect(() =>
      hybridRecipientId({ x25519PubHex: '0x' + toHex(x25519PubRaw.slice(0, 31)), kyberPubB64: Buffer.from(kyberPubRaw).toString('base64') })
    ).toThrow(InvalidKeyMaterialError);
  });

  it('rejects malformed ML-KEM public key length', () => {
    expect(() =>
      hybridRecipientId({ x25519PubHex: '0x' + toHex(x25519PubRaw), kyberPubB64: Buffer.from(kyberPubRaw.slice(0, 100)).toString('base64') })
    ).toThrow(InvalidKeyMaterialError);
  });
});

describe('V-TX-1 / V-TX-2 — buildHybridTranscriptV1 frozen vectors', () => {
  it('V-TX-1 (no aad) matches the design-record frozen digest', () => {
    const rid = hybridRecipientId({
      x25519PubHex: '0x' + toHex(x25519PubRaw),
      kyberPubB64: Buffer.from(kyberPubRaw).toString('base64'),
    });
    const info = buildHybridTranscriptV1(epkRaw, kemRaw, rid);
    expect(info.length).toBe(1679);
    expect(toHex(sha256(info))).toBe(
      '930e94660ef4119cad7e9b9459a92d7415c03de803f832ed77a3a23dcf3ad9c1'
    );
  });

  it('V-TX-2 (with aad) matches the design-record frozen digest', () => {
    const rid = hybridRecipientId({
      x25519PubHex: '0x' + toHex(x25519PubRaw),
      kyberPubB64: Buffer.from(kyberPubRaw).toString('base64'),
    });
    const aad = Buffer.from('thread:abc|sender:cid123|content-sha256:deadbeef', 'ascii');
    const aadHash = sha256(aad);
    expect(toHex(aadHash)).toBe('b08d3d87679118c23038e50be0e77e445d768d6f00ef44d7bc0519e57dd73223');
    const info = buildHybridTranscriptV1(epkRaw, kemRaw, rid, aadHash);
    expect(info.length).toBe(1711);
    expect(toHex(sha256(info))).toBe(
      '3ea417da526106df3edbc72315c85467682d79c30d2ff574265db1cb0aaa6e51'
    );
  });
});

describe('V-DOMAIN-1 — hybridDomain accept/reject table', () => {
  it.each([
    'loggie/hybrid-v3',
    'a/b',
    'x.y/z-1',
  ])('accepts %s', (v) => {
    expect(() => hybridDomain(v)).not.toThrow();
  });

  it.each([
    '',
    'noslash',
    'a/b/c',
    'A/b',
    '/b',
    'a/',
    'a//b',
    'a_b/c',
  ])('rejects %s', (v) => {
    expect(() => hybridDomain(v)).toThrow(InvalidHybridDomainError);
  });
});

async function makeIdentity() {
  const identity = await generateHybridIdentity('combiner-test');
  if (!identity) throw new Error('identity generation failed');
  return identity;
}

describe('V-WRAP-1 — wrapContentKeyHybrid / unwrapContentKeyHybrid round-trip', () => {
  it('round-trips with a fixed content key, domain, and recipientId', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const CK = new Uint8Array(32).map((_, i) => (i * 3 + 1) & 0xff);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);

    const wrap = await wrapContentKeyHybrid(CK, pub, { domain, recipientId });
    expect(wrap.x25519Epk).toBeTruthy();
    expect(wrap.mlKemCiphertext).toBeTruthy();
    expect(wrap.ckWrap.wrapped).toBeTruthy();

    const recovered = await unwrapContentKeyHybrid(wrap, sec, { domain, recipientId });
    expect(Buffer.from(recovered).equals(Buffer.from(CK))).toBe(true);
  });

  it('binds aad: same wrap fails to open under a different aad', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const CK = new Uint8Array(32).fill(7);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const aad = Buffer.from('thread:abc', 'ascii');

    const wrap = await wrapContentKeyHybrid(CK, pub, { domain, recipientId, aad });
    await expect(
      unwrapContentKeyHybrid(wrap, sec, { domain, recipientId, aad: Buffer.from('thread:xyz', 'ascii') })
    ).rejects.toThrow(HybridUnwrapError);
    await expect(
      unwrapContentKeyHybrid(wrap, sec, { domain, recipientId })
    ).rejects.toThrow(HybridUnwrapError);
    const recovered = await unwrapContentKeyHybrid(wrap, sec, { domain, recipientId, aad });
    expect(Buffer.from(recovered).equals(Buffer.from(CK))).toBe(true);
  });

  it('rejects a content key of the wrong length', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    await expect(
      wrapContentKeyHybrid(new Uint8Array(16), pub, { domain, recipientId })
    ).rejects.toThrow(InvalidContentKeyError);
  });
});

describe('I-1..I-10 invariant matrix (SPEC_CM25_F11_COMBINER_EXPORT.md §7)', () => {
  it('I-1: withholding the ML-KEM secret (valid X25519 secret) fails', async () => {
    const id = await makeIdentity();
    const other = await makeIdentity();
    const pub = getPublicKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const CK = new Uint8Array(32).fill(1);
    const wrap = await wrapContentKeyHybrid(CK, pub, { domain, recipientId });
    await expect(
      unwrapContentKeyHybrid(wrap, { x25519SecHex: getSecretKeys(id).x25519SecHex, kyberSecB64: getSecretKeys(other).kyberSecB64 }, { domain, recipientId })
    ).rejects.toThrow(HybridUnwrapError);
  });

  it('I-2: withholding the X25519 secret (valid ML-KEM secret) fails', async () => {
    const id = await makeIdentity();
    const other = await makeIdentity();
    const pub = getPublicKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const CK = new Uint8Array(32).fill(2);
    const wrap = await wrapContentKeyHybrid(CK, pub, { domain, recipientId });
    await expect(
      unwrapContentKeyHybrid(wrap, { x25519SecHex: getSecretKeys(other).x25519SecHex, kyberSecB64: getSecretKeys(id).kyberSecB64 }, { domain, recipientId })
    ).rejects.toThrow(HybridUnwrapError);
  });

  it('I-3: corrupting the ML-KEM ciphertext (swap from another wrap) fails', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const a = await wrapContentKeyHybrid(new Uint8Array(32).fill(3), pub, { domain, recipientId });
    const b = await wrapContentKeyHybrid(new Uint8Array(32).fill(4), pub, { domain, recipientId });
    const spliced = { ...a, mlKemCiphertext: b.mlKemCiphertext };
    await expect(unwrapContentKeyHybrid(spliced, sec, { domain, recipientId })).rejects.toThrow(HybridUnwrapError);
  });

  it('I-4: corrupting the X25519 ephemeral pubkey (swap from another wrap) fails', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const a = await wrapContentKeyHybrid(new Uint8Array(32).fill(5), pub, { domain, recipientId });
    const b = await wrapContentKeyHybrid(new Uint8Array(32).fill(6), pub, { domain, recipientId });
    const spliced = { ...a, x25519Epk: b.x25519Epk };
    await expect(unwrapContentKeyHybrid(spliced, sec, { domain, recipientId })).rejects.toThrow(HybridUnwrapError);
  });

  it('I-5: copying a wrap into a different domain context fails', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const recipientId = hybridRecipientId(pub);
    const wrap = await wrapContentKeyHybrid(new Uint8Array(32).fill(7), pub, {
      domain: hybridDomain('loggie/hybrid-v3'),
      recipientId,
    });
    await expect(
      unwrapContentKeyHybrid(wrap, sec, { domain: hybridDomain('omnituum/other-profile'), recipientId })
    ).rejects.toThrow(HybridUnwrapError);
  });

  it('I-6: recipient A wrap cannot be unwrapped by recipient B secrets', async () => {
    const a = await makeIdentity();
    const b = await makeIdentity();
    const pubA = getPublicKeys(a);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pubA);
    const wrap = await wrapContentKeyHybrid(new Uint8Array(32).fill(8), pubA, { domain, recipientId });
    await expect(unwrapContentKeyHybrid(wrap, getSecretKeys(b), { domain, recipientId })).rejects.toThrow(HybridUnwrapError);
  });

  it('I-7: mismatched recipientId in ctx fails even with correct key material', async () => {
    const id = await makeIdentity();
    const other = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const wrap = await wrapContentKeyHybrid(new Uint8Array(32).fill(9), pub, {
      domain,
      recipientId: hybridRecipientId(pub),
    });
    await expect(
      unwrapContentKeyHybrid(wrap, sec, { domain, recipientId: hybridRecipientId(getPublicKeys(other)) })
    ).rejects.toThrow(HybridUnwrapError);
  });

  it('I-8: relocating a valid wrap object (simulated array-position move) still opens for its true recipient', async () => {
    const id = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const wraps = [
      await wrapContentKeyHybrid(new Uint8Array(32).fill(10), pub, { domain, recipientId }),
      await wrapContentKeyHybrid(new Uint8Array(32).fill(11), pub, { domain, recipientId }),
    ];
    // "Relocate" wraps[1] to index 0 — position carries no identity; it
    // still opens under its own recipient's secrets and recovers its own CK.
    const relocated = wraps[1];
    const recovered = await unwrapContentKeyHybrid(relocated, sec, { domain, recipientId });
    expect(recovered[0]).toBe(11);
  });

  it('I-10: unwrap error is opaque — same error type/message across distinct failure stages', async () => {
    const id = await makeIdentity();
    const other = await makeIdentity();
    const pub = getPublicKeys(id);
    const sec = getSecretKeys(id);
    const domain = hybridDomain('loggie/hybrid-v3');
    const recipientId = hybridRecipientId(pub);
    const wrap = await wrapContentKeyHybrid(new Uint8Array(32).fill(12), pub, { domain, recipientId });

    const failures: unknown[] = [];
    // Stage: wrong ML-KEM secret
    try {
      await unwrapContentKeyHybrid(wrap, { ...sec, kyberSecB64: getSecretKeys(other).kyberSecB64 }, { domain, recipientId });
    } catch (e) { failures.push(e); }
    // Stage: wrong X25519 secret
    try {
      await unwrapContentKeyHybrid(wrap, { ...sec, x25519SecHex: getSecretKeys(other).x25519SecHex }, { domain, recipientId });
    } catch (e) { failures.push(e); }
    // Stage: wrong recipientId (KEK re-derivation mismatch)
    try {
      await unwrapContentKeyHybrid(wrap, sec, { domain, recipientId: hybridRecipientId(getPublicKeys(other)) });
    } catch (e) { failures.push(e); }
    // Stage: corrupted ckWrap (secretbox auth failure)
    try {
      const bad = { ...wrap, ckWrap: { ...wrap.ckWrap, wrapped: Buffer.from('not-valid-base64-wrapped-bytes').toString('base64') } };
      await unwrapContentKeyHybrid(bad, sec, { domain, recipientId });
    } catch (e) { failures.push(e); }

    expect(failures).toHaveLength(4);
    for (const f of failures) {
      expect(f).toBeInstanceOf(HybridUnwrapError);
      expect((f as Error).message).toBe('Could not unwrap content key — combined-KEK authentication failed');
    }
  });
});
