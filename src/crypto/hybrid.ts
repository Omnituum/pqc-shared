/**
 * Omnituum PQC Shared - Hybrid Encryption
 *
 * Post-quantum secure hybrid encryption combining:
 * - X25519 ECDH (classical, proven security)
 * - ML-KEM-1024 (post-quantum, FIPS 203, NIST Level 5)
 *
 * v2 (current write format): the content key is wrapped once, under a KEK
 * derived from BOTH shared secrets (HKDF(ss_mlkem || ss_x25519) with
 * transcript binding) — both key exchanges must succeed to decrypt, so
 * breaking either primitive alone is insufficient.
 *
 * v1 (read-only legacy): wrapped the key independently under each
 * primitive; either secret alone sufficed. Kept only for decrypting
 * existing envelopes — see the 2026-07-05 security audit.
 */

import nacl from 'tweetnacl';
import {
  rand32,
  rand24,
  b64,
  ub64,
  toHex,
  fromHex,
  hkdfSha256,
  sha256,
  textEncoder,
  textDecoder,
  u8,
} from './primitives';
import { generateX25519Keypair, x25519SharedSecret } from './x25519';
import {
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate,
  isKyberAvailable,
  KYBER_PUBLIC_KEY_SIZE,
} from './kyber';
import {
  ENVELOPE_VERSION_V2,
  ENVELOPE_SUITE_V2,
  ENVELOPE_AEAD,
  assertEnvelopeVersion,
} from '../version';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface HybridIdentity {
  /** Unique identifier */
  id: string;
  /** Display name */
  name: string;
  /** X25519 public key (hex) */
  x25519PubHex: string;
  /** X25519 secret key (hex) - keep private! */
  x25519SecHex: string;
  /** Kyber public key (base64) */
  kyberPubB64: string;
  /** Kyber secret key (base64) - keep private! */
  kyberSecB64: string;
  /** Creation timestamp */
  createdAt: string;
  /** Last rotation timestamp */
  lastRotatedAt?: string;
  /** Key rotation count */
  rotationCount: number;
}

export interface HybridPublicKeys {
  /** X25519 public key (hex) */
  x25519PubHex: string;
  /** Kyber public key (base64) */
  kyberPubB64: string;
}

export interface HybridSecretKeys {
  /** X25519 secret key (hex) */
  x25519SecHex: string;
  /** Kyber secret key (base64) */
  kyberSecB64: string;
}

/**
 * HybridEnvelopeV1 -- OmniHybridV1 from the registry with
 * app-semantic meta fields (senderName, senderId).
 * The Omni registry type defines only the crypto-relevant surface.
 *
 * Intentionally a type alias (not interface extends) to discourage
 * further field additions here. New app-semantic fields belong in
 * product-level types, not in the shared crypto layer.
 *
 * READ-ONLY LEGACY: v1 wraps the content key independently under X25519
 * and Kyber, so either secret alone unwraps it — min(X25519, ML-KEM)
 * security. hybridEncrypt no longer produces this shape; hybridDecrypt
 * still reads it.
 */
import type { OmniHybridV1 } from '@omnituum/envelope-registry';
export type HybridEnvelopeV1 = Omit<OmniHybridV1, 'meta'> & {
  meta: OmniHybridV1['meta'] & {
    senderName?: string;
    senderId?: string;
  };
};

/**
 * HybridEnvelopeV2 -- OmniHybridV2 from the registry with app-semantic meta
 * fields (senderName, senderId), same pattern as HybridEnvelopeV1. Single
 * wrap of the content key under an AND-combined KEK:
 * HKDF-SHA256(ss_mlkem || ss_x25519) with the envelope's own KEM values
 * bound into the info string. Both primitives must be broken to unwrap.
 */
import type { OmniHybridV2 } from '@omnituum/envelope-registry';
export type HybridEnvelopeV2 = Omit<OmniHybridV2, 'meta'> & {
  meta: OmniHybridV2['meta'] & {
    senderName?: string;
    senderId?: string;
  };
};

/** Any hybrid envelope this module can decrypt. */
export type HybridEnvelope = HybridEnvelopeV1 | HybridEnvelopeV2;

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function hkdfFlex(ikm: Uint8Array, salt: string, info: string): Uint8Array {
  return hkdfSha256(ikm, { salt: u8(salt), info: u8(info), length: 32 });
}

function generateId(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ═══════════════════════════════════════════════════════════════════════════
// IDENTITY GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a new hybrid identity with both X25519 and Kyber keys.
 */
export async function generateHybridIdentity(name: string): Promise<HybridIdentity | null> {
  // Generate X25519 keypair
  const x25519 = generateX25519Keypair();

  // Generate Kyber keypair
  const kyber = await generateKyberKeypair();
  if (!kyber) {
    // Backend unavailable; caller handles the null return.
    return null;
  }

  return {
    id: generateId(),
    name,
    x25519PubHex: x25519.publicHex,
    x25519SecHex: x25519.secretHex,
    kyberPubB64: kyber.publicB64,
    kyberSecB64: kyber.secretB64,
    createdAt: new Date().toISOString(),
    rotationCount: 0,
  };
}

/**
 * Rotate keys for an existing identity.
 */
export async function rotateHybridIdentity(identity: HybridIdentity): Promise<HybridIdentity | null> {
  // Generate new X25519 keypair
  const x25519 = generateX25519Keypair();

  // Generate new Kyber keypair
  const kyber = await generateKyberKeypair();
  if (!kyber) {
    return null;
  }

  return {
    ...identity,
    x25519PubHex: x25519.publicHex,
    x25519SecHex: x25519.secretHex,
    kyberPubB64: kyber.publicB64,
    kyberSecB64: kyber.secretB64,
    lastRotatedAt: new Date().toISOString(),
    rotationCount: identity.rotationCount + 1,
  };
}

/**
 * Extract public keys from identity.
 */
export function getPublicKeys(identity: HybridIdentity): HybridPublicKeys {
  return {
    x25519PubHex: identity.x25519PubHex,
    kyberPubB64: identity.kyberPubB64,
  };
}

/**
 * Extract secret keys from identity.
 */
export function getSecretKeys(identity: HybridIdentity): HybridSecretKeys {
  return {
    x25519SecHex: identity.x25519SecHex,
    kyberSecB64: identity.kyberSecB64,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// PRIVATE KEK CORE (CM-25 / F11) — the ONLY hybrid-KEK derivation code in
// this package. Never exported (see SPEC_CM25_F11_COMBINER_EXPORT.md §4).
// Two profile adapters call this: the FROZEN omnituum profile below
// (byte-identical to the pre-refactor combinedKekV2 — see the golden KAT
// in tests/crypto/hybrid-kek-core.test.ts) and the public v3 profile
// (wrapContentKeyHybrid/unwrapContentKeyHybrid, further down this file).
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Derive an AND-combined KEK from both shared secrets. ikm = ss_mlkem ||
 * ss_x25519 (fixed order, unchanged from the original combinedKekV2).
 * `salt`/`info` are profile-specific raw bytes supplied by the calling
 * adapter — this function has no opinion on which profile it serves.
 */
export function deriveCombinedKek(
  ssMlkem: Uint8Array,
  ssX25519: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array
): Uint8Array {
  const ikm = new Uint8Array(ssMlkem.length + ssX25519.length);
  ikm.set(ssMlkem, 0);
  ikm.set(ssX25519, ssMlkem.length);
  try {
    return hkdfSha256(ikm, { salt, info, length: 32 });
  } finally {
    ikm.fill(0);
  }
}

// ── omnituum profile adapter (FROZEN — reproduces combinedKekV2 exactly) ──
const OMNITUUM_HYBRID_SALT = u8('omnituum/hybrid-v2');
function omnituumHybridInfo(x25519EpkHex: string, kyberKemCtB64: string): Uint8Array {
  return u8(`wrap-ck|${x25519EpkHex}|${kyberKemCtB64}`);
}

/**
 * Encrypt a message using hybrid X25519 + ML-KEM-1024 encryption (v2).
 *
 * The content key is wrapped exactly once, under a KEK derived from both
 * shared secrets together — breaking either primitive alone is insufficient
 * to unwrap. (v1 wrapped the key independently under each primitive, which
 * reduced security to min(X25519, ML-KEM); v1 is now read-only legacy.)
 *
 * @param plaintext - Message to encrypt (string or bytes)
 * @param recipientPublicKeys - Recipient's public keys
 * @param sender - Optional sender identity for metadata
 */
export async function hybridEncrypt(
  plaintext: string | Uint8Array,
  recipientPublicKeys: HybridPublicKeys,
  sender?: { name?: string; id?: string }
): Promise<HybridEnvelopeV2> {
  const pt = typeof plaintext === 'string' ? textEncoder.encode(plaintext) : plaintext;

  // 1. Generate random content key (32 bytes)
  const CK = rand32();

  try {
    // 2. Encrypt content with content key
    const contentNonce = rand24();
    const ciphertext = nacl.secretbox(pt, contentNonce, CK);

    // 3. X25519 ECDH shared secret (ephemeral)
    const x25519EphKp = nacl.box.keyPair();
    const recipientX25519Pk = fromHex(recipientPublicKeys.x25519PubHex);
    const x25519Shared = nacl.scalarMult(x25519EphKp.secretKey, recipientX25519Pk);
    const x25519EpkHex = toHex(x25519EphKp.publicKey);

    // 4. ML-KEM-1024 shared secret
    const kyberResult = await kyberEncapsulate(recipientPublicKeys.kyberPubB64);
    const kyberKemCtB64 = b64(kyberResult.ciphertext);

    // 5. Single wrap under the AND-combined KEK
    const kek = deriveCombinedKek(
      kyberResult.sharedSecret,
      x25519Shared,
      OMNITUUM_HYBRID_SALT,
      omnituumHybridInfo(x25519EpkHex, kyberKemCtB64)
    );
    const ckWrapNonce = rand24();
    const ckWrapped = nacl.secretbox(CK, ckWrapNonce, kek);
    kek.fill(0);
    x25519Shared.fill(0);
    kyberResult.sharedSecret.fill(0);
    x25519EphKp.secretKey.fill(0);

    return {
      v: ENVELOPE_VERSION_V2,
      suite: ENVELOPE_SUITE_V2,
      aead: ENVELOPE_AEAD,
      x25519Epk: x25519EpkHex,
      kyberKemCt: kyberKemCtB64,
      ckWrap: {
        nonce: b64(ckWrapNonce),
        wrapped: b64(ckWrapped),
      },
      contentNonce: b64(contentNonce),
      ciphertext: b64(ciphertext),
      meta: {
        createdAt: new Date().toISOString(),
        senderName: sender?.name,
        senderId: sender?.id,
      },
    };
  } finally {
    CK.fill(0);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/** Unwrap the content key from a v2 envelope — requires BOTH secrets. */
async function unwrapCkV2(
  envelope: HybridEnvelopeV2,
  secretKeys: HybridSecretKeys
): Promise<Uint8Array> {
  // ML-KEM decapsulation (post-quantum half). Failure here is fatal — there
  // is deliberately no classical fallback path in v2.
  const kyberShared = await kyberDecapsulate(envelope.kyberKemCt, secretKeys.kyberSecB64);

  // X25519 ECDH (classical half)
  const ephPk = fromHex(envelope.x25519Epk);
  const sk = fromHex(secretKeys.x25519SecHex);
  const x25519Shared = nacl.scalarMult(sk, ephPk);

  const kek = deriveCombinedKek(
    kyberShared,
    x25519Shared,
    OMNITUUM_HYBRID_SALT,
    omnituumHybridInfo(envelope.x25519Epk, envelope.kyberKemCt)
  );
  kyberShared.fill(0);
  x25519Shared.fill(0);

  const CK = nacl.secretbox.open(ub64(envelope.ckWrap.wrapped), ub64(envelope.ckWrap.nonce), kek);
  kek.fill(0);
  if (!CK) {
    throw new Error('Could not unwrap content key — combined-KEK authentication failed');
  }
  return CK;
}

/**
 * Unwrap the content key from a v1 (or pqc-demo) envelope.
 *
 * LEGACY READ PATH: v1 wrapped the key independently under each primitive,
 * so either secret alone suffices — this is exactly the defect v2 fixes.
 * Kept only so envelopes written before v2 remain readable; re-encrypt to
 * v2 where the post-quantum guarantee matters.
 */
async function unwrapCkV1(
  envelope: HybridEnvelopeV1,
  secretKeys: HybridSecretKeys,
  saltPrefix: string
): Promise<Uint8Array> {
  let CK: Uint8Array | null = null;

  try {
    const kyberShared = await kyberDecapsulate(envelope.kyberKemCt, secretKeys.kyberSecB64);
    const kyberKek = hkdfFlex(kyberShared, `${saltPrefix}/kyber`, 'wrap-ck');
    CK = nacl.secretbox.open(
      ub64(envelope.kyberWrap.wrapped),
      ub64(envelope.kyberWrap.nonce),
      kyberKek
    );
  } catch {
    // Fall through to the X25519 wrap.
  }

  if (!CK) {
    try {
      const ephPk = fromHex(envelope.x25519Epk);
      const sk = fromHex(secretKeys.x25519SecHex);
      const x25519Shared = nacl.scalarMult(sk, ephPk);
      const x25519Kek = hkdfFlex(x25519Shared, `${saltPrefix}/x25519`, 'wrap-ck');
      CK = nacl.secretbox.open(
        ub64(envelope.x25519Wrap.wrapped),
        ub64(envelope.x25519Wrap.nonce),
        x25519Kek
      );
    } catch {
      // Handled below.
    }
  }

  if (!CK) {
    throw new Error('Could not unwrap content key with either algorithm');
  }
  return CK;
}

/**
 * Decrypt a hybrid envelope (v2, v1, or legacy pqc-demo).
 *
 * v2: the content key is unwrapped from a single AND-combined KEK — both
 * ML-KEM and X25519 secrets are required, and any failure is fatal.
 * v1/legacy: read-only compatibility path (either secret suffices — the
 * defect v2 exists to fix).
 *
 * @param envelope - Encrypted envelope
 * @param secretKeys - Recipient's secret keys
 * @returns Decrypted plaintext as bytes
 */
export async function hybridDecrypt(
  envelope: HybridEnvelope,
  secretKeys: HybridSecretKeys
): Promise<Uint8Array> {
  // Validate envelope version (throws VersionMismatchError if unsupported)
  const version = envelope.v as string;
  assertEnvelopeVersion(version);

  const CK =
    version === ENVELOPE_VERSION_V2
      ? await unwrapCkV2(envelope as HybridEnvelopeV2, secretKeys)
      : await unwrapCkV1(
          envelope as HybridEnvelopeV1,
          secretKeys,
          version === 'pqc-demo.hybrid.v1' ? 'pqc-demo' : 'omnituum'
        );

  // Decrypt content
  const pt = nacl.secretbox.open(
    ub64(envelope.ciphertext),
    ub64(envelope.contentNonce),
    CK
  );
  CK.fill(0);

  if (!pt) {
    throw new Error('Content authentication failed');
  }

  return pt;
}

/**
 * Decrypt and decode as UTF-8 string.
 */
export async function hybridDecryptToString(
  envelope: HybridEnvelope,
  secretKeys: HybridSecretKeys
): Promise<string> {
  const pt = await hybridDecrypt(envelope, secretKeys);
  return textDecoder.decode(pt);
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export { isKyberAvailable };

// ═══════════════════════════════════════════════════════════════════════════
// CM-25 / F11 — PUBLIC HYBRID CONTENT-KEY COMBINER
//
// Per SPEC_CM25_F11_COMBINER_EXPORT.md. Callers pass a content key and get
// back wire pieces; the KEK, both raw shared secrets, the ephemeral X25519
// secret, and all nonces stay inside this module. Domain + recipientId are
// MANDATORY structured context — callers never construct HKDF info bytes.
// ═══════════════════════════════════════════════════════════════════════════

// ── Error taxonomy (spec §1) ────────────────────────────────────────────────

export class HybridError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HybridError';
  }
}

export class InvalidHybridDomainError extends HybridError {
  constructor(namespaced: string) {
    super(`Invalid hybrid domain: "${namespaced}" (expected "owner/profile", lowercase ASCII, exactly one slash)`);
    this.name = 'InvalidHybridDomainError';
  }
}

export class InvalidKeyMaterialError extends HybridError {
  constructor(detail: string) {
    super(`Invalid hybrid key material: ${detail}`);
    this.name = 'InvalidKeyMaterialError';
  }
}

export class InvalidContentKeyError extends HybridError {
  constructor(length: number) {
    super(`Invalid content key: expected 32 bytes, got ${length}`);
    this.name = 'InvalidContentKeyError';
  }
}

/**
 * Opaque unwrap failure. Deliberately does NOT distinguish which stage
 * failed (ML-KEM decapsulation, X25519 ECDH, KEK derivation, or secretbox
 * authentication) — spec §1/§9.3: an oracle that reveals the failing stage
 * is a misuse-resistance regression.
 */
export class HybridUnwrapError extends HybridError {
  constructor() {
    super('Could not unwrap content key — combined-KEK authentication failed');
    this.name = 'HybridUnwrapError';
  }
}

// ── Branded domain-separation tag (spec §1) ─────────────────────────────────

export type HybridDomain = string & { readonly __hybridDomain: unique symbol };

const HYBRID_DOMAIN_RE = /^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9.-]*$/;

/**
 * Construct a validated HybridDomain. Throws InvalidHybridDomainError unless
 * `namespaced` matches EXACTLY /^[a-z0-9][a-z0-9.-]*\/[a-z0-9][a-z0-9.-]*$/
 * — exactly one slash, each side lowercase ASCII starting alphanumeric.
 * Rejects non-canonical input; does NOT lowercase or normalize
 * (design-owner sign-off spec §9.4).
 */
export function hybridDomain(namespaced: string): HybridDomain {
  if (!HYBRID_DOMAIN_RE.test(namespaced)) {
    throw new InvalidHybridDomainError(namespaced);
  }
  return namespaced as HybridDomain;
}

// ── Stable recipient identity (spec §1/§2) ──────────────────────────────────

export interface HybridRecipientPub {
  x25519PubHex: string;
  kyberPubB64: string;
}

export interface HybridRecipientSec {
  x25519SecHex: string;
  kyberSecB64: string;
}

/** Frozen label for hybridRecipientId — spec §2/§10.2. 31 bytes. */
const RID_LABEL = u8('omnituum/hybrid-recipient-id/v1');

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Canonical, stable recipient identifier — 32 bytes, SHA-256 over a
 * length-framed, domain-separated encoding of the recipient's public key
 * material. Exported so every consumer (loggie, pqc-db) derives the SAME
 * id; MUST NOT be re-implemented downstream. Throws InvalidKeyMaterialError
 * on malformed key material (wrong X25519 length, wrong ML-KEM-1024
 * public-key length). Spec §2/§10.2: recipientId = SHA256(RID_LABEL ||
 * u32be(32) || x25519PubRaw || u32be(1568) || kyberPubRaw), X25519 first.
 */
export function hybridRecipientId(pub: HybridRecipientPub): Uint8Array {
  const x = fromHex(pub.x25519PubHex);
  if (x.length !== 32) {
    throw new InvalidKeyMaterialError(`x25519PubHex must decode to 32 bytes, got ${x.length}`);
  }
  const k = ub64(pub.kyberPubB64);
  if (k.length !== KYBER_PUBLIC_KEY_SIZE) {
    throw new InvalidKeyMaterialError(
      `kyberPubB64 must decode to ${KYBER_PUBLIC_KEY_SIZE} bytes (ML-KEM-1024), got ${k.length}`
    );
  }
  const msg = concatBytes(RID_LABEL, u32be(x.length), x, u32be(k.length), k);
  return sha256(msg);
}

// ── Structured wrap context (spec §1/§3) ────────────────────────────────────

export interface HybridWrapContext {
  /** MANDATORY. HKDF salt / domain separation. */
  domain: HybridDomain;
  /** MANDATORY. Stable recipient id — NOT array position. */
  recipientId: Uint8Array;
  /** OPTIONAL. Outer-protocol PRE-WRAP transcript bytes. MUST be computable
   *  before any wrap exists (spec §3.3 circularity caveat). */
  aad?: Uint8Array;
}

export interface HybridCkWrap {
  x25519Epk: string;
  mlKemCiphertext: string;
  ckWrap: { nonce: string; wrapped: string };
}

// ── Private binary transcript builder (spec §3.2/§10.3) ─────────────────────

/** Frozen label for the v3/public-primitive transcript. 22 bytes. */
const TX_LABEL = u8('omnituum/hybrid-kek/v1');

const TX_TAG_LABEL = 0x00;
const TX_TAG_EPK = 0x01;
const TX_TAG_KEM_CT = 0x02;
const TX_TAG_RECIPIENT_ID = 0x03;
const TX_TAG_AAD_HASH = 0x04;

function transcriptField(tag: number, value: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([tag]), u32be(value.length), value);
}

/**
 * Build the binary, typed, length-framed HKDF info transcript for the v3
 * / public-primitive profile. Five fixed-order, always-present fields
 * (spec §3.2) — the AAD field is present with length 0 when `aadHash` is
 * omitted. Values are RAW bytes, never their hex/base64 wire encoding.
 * This is the ONLY place `info` is constructed for this profile — callers
 * never build it themselves.
 */
export function buildHybridTranscriptV1(
  epkRaw: Uint8Array,
  kemRaw: Uint8Array,
  recipientId: Uint8Array,
  aadHash?: Uint8Array
): Uint8Array {
  return concatBytes(
    transcriptField(TX_TAG_LABEL, TX_LABEL),
    transcriptField(TX_TAG_EPK, epkRaw),
    transcriptField(TX_TAG_KEM_CT, kemRaw),
    transcriptField(TX_TAG_RECIPIENT_ID, recipientId),
    transcriptField(TX_TAG_AAD_HASH, aadHash ?? new Uint8Array(0))
  );
}

// ── The public primitive (spec §1) ──────────────────────────────────────────

/**
 * Wrap a caller-owned 32-byte content key for ONE recipient under an
 * AND-combined KEK. Ephemeral X25519 keypair, both shared secrets, the
 * KEK, and all nonces are generated/derived and zeroized INTERNALLY.
 * Throws InvalidKeyMaterialError on malformed pub material,
 * InvalidContentKeyError if contentKey.length !== 32. Does NOT retain or
 * zeroize contentKey — the caller owns it (e.g. loggie reuses one CK
 * across N recipients).
 */
export async function wrapContentKeyHybrid(
  contentKey: Uint8Array,
  recipientPub: HybridRecipientPub,
  ctx: HybridWrapContext
): Promise<HybridCkWrap> {
  if (contentKey.length !== 32) {
    throw new InvalidContentKeyError(contentKey.length);
  }
  const recipientX25519Pk = fromHex(recipientPub.x25519PubHex);
  if (recipientX25519Pk.length !== 32) {
    throw new InvalidKeyMaterialError(
      `x25519PubHex must decode to 32 bytes, got ${recipientX25519Pk.length}`
    );
  }

  const x25519EphKp = nacl.box.keyPair();
  const x25519Shared = x25519SharedSecret(x25519EphKp.secretKey, recipientX25519Pk);
  const x25519EpkHex = toHex(x25519EphKp.publicKey);

  try {
    const kyberResult = await kyberEncapsulate(recipientPub.kyberPubB64);
    const kyberKemCtB64 = b64(kyberResult.ciphertext);

    const aadHash = ctx.aad ? sha256(ctx.aad) : undefined;
    const info = buildHybridTranscriptV1(
      x25519EphKp.publicKey,
      kyberResult.ciphertext,
      ctx.recipientId,
      aadHash
    );
    const kek = deriveCombinedKek(kyberResult.sharedSecret, x25519Shared, u8(ctx.domain), info);
    kyberResult.sharedSecret.fill(0);

    try {
      const nonce = rand24();
      const wrapped = nacl.secretbox(contentKey, nonce, kek);
      return {
        x25519Epk: x25519EpkHex,
        mlKemCiphertext: kyberKemCtB64,
        ckWrap: { nonce: b64(nonce), wrapped: b64(wrapped) },
      };
    } finally {
      kek.fill(0);
    }
  } finally {
    x25519Shared.fill(0);
    x25519EphKp.secretKey.fill(0);
  }
}

/**
 * Unwrap for ONE recipient. Requires BOTH secrets; ANY failure throws
 * HybridUnwrapError — no classical fallback, no OR path, no
 * try-one-then-the-other. `ctx` must carry the same domain + recipientId
 * (+ aad) used at wrap or KEK re-derivation fails closed. Returns a fresh
 * Uint8Array the CALLER must zeroize.
 */
export async function unwrapContentKeyHybrid(
  wrap: HybridCkWrap,
  recipientSec: HybridRecipientSec,
  ctx: HybridWrapContext
): Promise<Uint8Array> {
  let kyberShared: Uint8Array | undefined;
  let x25519Shared: Uint8Array | undefined;
  let kek: Uint8Array | undefined;
  try {
    kyberShared = await kyberDecapsulate(wrap.mlKemCiphertext, recipientSec.kyberSecB64);

    const ephPk = fromHex(wrap.x25519Epk);
    const sk = fromHex(recipientSec.x25519SecHex);
    x25519Shared = x25519SharedSecret(sk, ephPk);

    const aadHash = ctx.aad ? sha256(ctx.aad) : undefined;
    const kemRaw = ub64(wrap.mlKemCiphertext);
    const info = buildHybridTranscriptV1(ephPk, kemRaw, ctx.recipientId, aadHash);
    kek = deriveCombinedKek(kyberShared, x25519Shared, u8(ctx.domain), info);

    const CK = nacl.secretbox.open(ub64(wrap.ckWrap.wrapped), ub64(wrap.ckWrap.nonce), kek);
    if (!CK) {
      throw new HybridUnwrapError();
    }
    return CK;
  } catch {
    // Opaque by design (spec §1/§9.3): every internal failure — ML-KEM
    // decapsulation, X25519 ECDH, KEK derivation, or secretbox
    // authentication — surfaces as the same HybridUnwrapError. No
    // console.warn, no stage-distinguishing public cause.
    throw new HybridUnwrapError();
  } finally {
    kyberShared?.fill(0);
    x25519Shared?.fill(0);
    kek?.fill(0);
  }
}
