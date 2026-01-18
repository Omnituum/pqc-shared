/**
 * Omnituum PQC Shared - Kyber ML-KEM-768
 *
 * Browser-compatible Kyber operations using kyber-crystals.
 * NIST Level 3 security - quantum-resistant.
 */

import { b64, ub64, sha256 } from './primitives';
import nacl from 'tweetnacl';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface KyberKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface KyberKeypairB64 {
  publicB64: string;
  secretB64: string;
}

export interface KyberEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

// ═══════════════════════════════════════════════════════════════════════════
// KYBER LIBRARY LOADING
// ═══════════════════════════════════════════════════════════════════════════

let kyberModule: any = null;

async function loadKyber(): Promise<any> {
  if (kyberModule) return kyberModule;

  try {
    const m = await import('kyber-crystals');
    const k = (m as any).default ?? m;
    kyberModule = k.kyber ?? k;
    return kyberModule;
  } catch (e) {
    console.warn('[Kyber] Failed to load kyber-crystals:', e);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AVAILABILITY CHECK
// ═══════════════════════════════════════════════════════════════════════════

export async function isKyberAvailable(): Promise<boolean> {
  const mod = await loadKyber();
  return mod !== null;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a Kyber ML-KEM-768 keypair.
 */
export async function generateKyberKeypair(): Promise<KyberKeypairB64 | null> {
  try {
    const mod = await loadKyber();
    if (!mod) return null;

    if (mod?.ready?.then) {
      await mod.ready;
    }

    const fn = mod?.keypair ?? mod?.keyPair ?? mod?.generateKeyPair ?? null;
    if (typeof fn !== 'function') {
      console.warn('[Kyber] No keypair function found');
      return null;
    }

    const kp = await fn.call(mod);
    const pub = kp?.publicKey ?? kp?.public ?? kp?.pk;
    const priv = kp?.privateKey ?? kp?.secretKey ?? kp?.secret ?? kp?.sk;

    if (!pub || !priv) {
      console.warn('[Kyber] Invalid keypair result');
      return null;
    }

    return {
      publicB64: b64(new Uint8Array(pub)),
      secretB64: b64(new Uint8Array(priv)),
    };
  } catch (e) {
    console.warn('[Kyber] Key generation failed:', e);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCAPSULATION / DECAPSULATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encapsulate a shared secret using Kyber ML-KEM-768.
 */
export async function kyberEncapsulate(pubKeyB64: string): Promise<KyberEncapsulation> {
  const kyber = await loadKyber();
  if (!kyber?.encrypt) {
    throw new Error('Kyber encrypt not available');
  }

  const pk = ub64(pubKeyB64);
  const r: any = await kyber.encrypt(pk);

  // Normalize ciphertext
  const ctRaw =
    r?.ciphertext ?? r?.cyphertext ?? r?.ct ??
    r?.bytes?.ciphertext ?? r?.bytes?.cyphertext ?? r?.bytes?.ct ??
    (Array.isArray(r) ? r[0] : undefined);

  // Normalize shared secret
  const ssRaw =
    r?.key ?? r?.sharedSecret ?? r?.secret ??
    r?.bytes?.key ?? r?.bytes?.sharedSecret ??
    (Array.isArray(r) ? r[1] : undefined);

  if (!ctRaw || !ssRaw) {
    throw new Error('Kyber encapsulate failed: missing ciphertext or shared secret');
  }

  return {
    ciphertext: new Uint8Array(ctRaw),
    sharedSecret: new Uint8Array(ssRaw),
  };
}

/**
 * Decapsulate a shared secret using Kyber ML-KEM-768.
 */
export async function kyberDecapsulate(
  kemCiphertextB64: string,
  secretKeyB64: string
): Promise<Uint8Array> {
  const kyber = await loadKyber();
  if (!kyber?.decrypt && !kyber?.decapsulate) {
    throw new Error('Kyber decrypt/decapsulate not available');
  }

  const ct = ub64(kemCiphertextB64);
  const sk = ub64(secretKeyB64);

  const r: any = kyber.decrypt
    ? await kyber.decrypt(ct, sk)
    : await kyber.decapsulate(ct, sk);

  const key = (r && (r.key ?? r.sharedSecret)) ? (r.key ?? r.sharedSecret) : r;
  return new Uint8Array(key);
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY WRAPPING HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Wrap a message key using Kyber shared secret.
 */
export function kyberWrapKey(sharedSecret: Uint8Array, msgKey32: Uint8Array): {
  nonce: string;
  wrapped: string;
} {
  if (msgKey32.length !== 32) {
    throw new Error('Message key must be 32 bytes');
  }

  const kek = sha256(sharedSecret); // Derive KEK from shared secret
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(24));
  const wrapped = nacl.secretbox(msgKey32, nonce, kek);

  return {
    nonce: b64(nonce),
    wrapped: b64(wrapped),
  };
}

/**
 * Unwrap a message key using Kyber shared secret.
 */
export function kyberUnwrapKey(
  sharedSecret: Uint8Array,
  nonceB64: string,
  wrappedB64: string
): Uint8Array | null {
  const kek = sha256(sharedSecret);
  const nonce = ub64(nonceB64);
  const wrapped = ub64(wrappedB64);

  return nacl.secretbox.open(wrapped, nonce, kek) || null;
}
