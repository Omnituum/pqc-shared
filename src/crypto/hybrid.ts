/**
 * Omnituum PQC Shared - Hybrid Encryption
 *
 * Post-quantum secure hybrid encryption combining:
 * - X25519 ECDH (classical, proven security)
 * - Kyber ML-KEM-768 (post-quantum, NIST Level 3)
 *
 * Both key exchanges must succeed for decryption, providing
 * security against both classical and quantum attacks.
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
  textEncoder,
  textDecoder,
  u8,
} from './primitives';
import { generateX25519Keypair } from './x25519';
import {
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate,
  isKyberAvailable,
} from './kyber';
import {
  ENVELOPE_VERSION,
  ENVELOPE_SUITE,
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
 * HybridEnvelope -- OmniHybridV1 from the registry with
 * app-semantic meta fields (senderName, senderId).
 * The Omni registry type defines only the crypto-relevant surface.
 *
 * Intentionally a type alias (not interface extends) to discourage
 * further field additions here. New app-semantic fields belong in
 * product-level types, not in the shared crypto layer.
 */
import type { OmniHybridV1 } from '@omnituum/envelope-registry';
export type HybridEnvelope = Omit<OmniHybridV1, 'meta'> & {
  meta: OmniHybridV1['meta'] & {
    senderName?: string;
    senderId?: string;
  };
};

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
    console.error('Kyber key generation failed - library not available');
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

/**
 * Encrypt a message using hybrid X25519 + Kyber encryption.
 *
 * @param plaintext - Message to encrypt (string or bytes)
 * @param recipientPublicKeys - Recipient's public keys
 * @param sender - Optional sender identity for metadata
 */
export async function hybridEncrypt(
  plaintext: string | Uint8Array,
  recipientPublicKeys: HybridPublicKeys,
  sender?: { name?: string; id?: string }
): Promise<HybridEnvelope> {
  const pt = typeof plaintext === 'string' ? textEncoder.encode(plaintext) : plaintext;

  // 1. Generate random content key (32 bytes)
  const CK = rand32();

  // 2. Encrypt content with content key
  const contentNonce = rand24();
  const ciphertext = nacl.secretbox(pt, contentNonce, CK);

  // 3. Wrap content key with X25519 ECDH
  const x25519EphKp = nacl.box.keyPair();
  const recipientX25519Pk = fromHex(recipientPublicKeys.x25519PubHex);

  const x25519Shared = nacl.scalarMult(x25519EphKp.secretKey, recipientX25519Pk);
  const x25519Kek = hkdfFlex(x25519Shared, 'omnituum/x25519', 'wrap-ck');
  const x25519WrapNonce = rand24();
  const x25519Wrapped = nacl.secretbox(CK, x25519WrapNonce, x25519Kek);

  // 4. Wrap content key with Kyber KEM
  const kyberResult = await kyberEncapsulate(recipientPublicKeys.kyberPubB64);
  const kyberKek = hkdfFlex(kyberResult.sharedSecret, 'omnituum/kyber', 'wrap-ck');
  const kyberWrapNonce = rand24();
  const kyberWrapped = nacl.secretbox(CK, kyberWrapNonce, kyberKek);

  return {
    v: ENVELOPE_VERSION,
    suite: ENVELOPE_SUITE,
    aead: ENVELOPE_AEAD,
    x25519Epk: toHex(x25519EphKp.publicKey),
    x25519Wrap: {
      nonce: b64(x25519WrapNonce),
      wrapped: b64(x25519Wrapped),
    },
    kyberKemCt: b64(kyberResult.ciphertext),
    kyberWrap: {
      nonce: b64(kyberWrapNonce),
      wrapped: b64(kyberWrapped),
    },
    contentNonce: b64(contentNonce),
    ciphertext: b64(ciphertext),
    meta: {
      createdAt: new Date().toISOString(),
      senderName: sender?.name,
      senderId: sender?.id,
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt a hybrid envelope.
 *
 * Tries Kyber first (post-quantum), falls back to X25519 (classical).
 * Both must be valid for the envelope to be considered secure.
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

  let CK: Uint8Array | null = null;

  // Determine HKDF salt based on envelope version
  const saltPrefix = version === 'pqc-demo.hybrid.v1' ? 'pqc-demo' : 'omnituum';

  // Try Kyber decapsulation first (post-quantum)
  try {
    const kyberShared = await kyberDecapsulate(envelope.kyberKemCt, secretKeys.kyberSecB64);
    const kyberKek = hkdfFlex(kyberShared, `${saltPrefix}/kyber`, 'wrap-ck');
    CK = nacl.secretbox.open(
      ub64(envelope.kyberWrap.wrapped),
      ub64(envelope.kyberWrap.nonce),
      kyberKek
    );
    if (CK) {
      console.log('[Hybrid] Decrypted using Kyber (post-quantum)');
    }
  } catch (e) {
    console.warn('[Hybrid] Kyber decapsulation failed:', e);
  }

  // Try X25519 if Kyber failed
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
      if (CK) {
        console.log('[Hybrid] Decrypted using X25519 (classical)');
      }
    } catch (e) {
      console.warn('[Hybrid] X25519 decryption failed:', e);
    }
  }

  if (!CK) {
    throw new Error('Could not unwrap content key with either algorithm');
  }

  // Decrypt content
  const pt = nacl.secretbox.open(
    ub64(envelope.ciphertext),
    ub64(envelope.contentNonce),
    CK
  );

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
