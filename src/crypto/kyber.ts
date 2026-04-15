/**
 * Omnituum PQC Shared — Kyber (ML-KEM-1024, FIPS 203)
 *
 * Backend: @noble/post-quantum `ml_kem1024`. NIST FIPS 203 (final, 2024).
 *
 * Wire-format note: previous releases (<= 0.3.x) of this package were backed by
 * `kyber-crystals`, which implements an earlier draft of Kyber and is NOT
 * interoperable with FIPS 203 — see `tests/interop/historical/` and
 * `package-docs/GAPS_AND_TASKS.md` (PQC-02 result). 0.4.0 is an intentional
 * clean break: legacy draft-Kyber material cannot be read by this version.
 *
 * Sizes (ML-KEM-1024):
 *   publicKey  1568 bytes
 *   secretKey  3168 bytes
 *   ciphertext 1568 bytes
 *   sharedSecret 32 bytes
 *
 * Suite tag for new material: "ML-KEM-1024-FIPS203".
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { b64, ub64, sha256, randN } from './primitives';
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

/** Canonical suite identifier for new material produced by this package. */
export const KYBER_SUITE = 'ML-KEM-1024-FIPS203' as const;
export type KyberSuite = typeof KYBER_SUITE;

// ═══════════════════════════════════════════════════════════════════════════
// AVAILABILITY
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @deprecated Always returns true. Retained for API stability across the
 * 0.3.x → 0.4.x cut. The noble backend is statically imported and always
 * present; there is no runtime feature-detection path.
 */
export async function isKyberAvailable(): Promise<boolean> {
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a fresh ML-KEM-1024 keypair using a cryptographically random seed.
 */
export async function generateKyberKeypair(): Promise<KyberKeypairB64 | null> {
  const seed = randN(64);
  const kp = ml_kem1024.keygen(seed);
  return {
    publicB64: b64(kp.publicKey),
    secretB64: b64(kp.secretKey),
  };
}

/**
 * Derive a deterministic ML-KEM-1024 keypair from a 64-byte seed.
 * Same seed → byte-identical keypair, across runtimes (Node, browser).
 *
 * The seed is passed verbatim to the FIPS 203 keygen. Callers that need
 * domain separation between Kyber and other key types must apply it
 * upstream (e.g. via SHA-256 with a domain tag) before calling.
 */
export function generateKyberKeypairFromSeed(seed: Uint8Array): KyberKeypair {
  if (seed.length !== 64) {
    throw new Error('Kyber seed must be 64 bytes');
  }
  const kp = ml_kem1024.keygen(seed);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCAPSULATION / DECAPSULATION
// ═══════════════════════════════════════════════════════════════════════════

export async function kyberEncapsulate(pubKeyB64: string): Promise<KyberEncapsulation> {
  const pk = ub64(pubKeyB64);
  const enc = ml_kem1024.encapsulate(pk);
  return {
    ciphertext: enc.cipherText,
    sharedSecret: enc.sharedSecret,
  };
}

export async function kyberDecapsulate(
  kemCiphertextB64: string,
  secretKeyB64: string,
): Promise<Uint8Array> {
  const ct = ub64(kemCiphertextB64);
  const sk = ub64(secretKeyB64);
  return ml_kem1024.decapsulate(ct, sk);
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY WRAPPING (library-agnostic; NaCl secretbox over derived KEK)
// ═══════════════════════════════════════════════════════════════════════════

export function kyberWrapKey(
  sharedSecret: Uint8Array,
  msgKey32: Uint8Array,
): { nonce: string; wrapped: string } {
  if (msgKey32.length !== 32) {
    throw new Error('Message key must be 32 bytes');
  }
  const kek = sha256(sharedSecret);
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(24));
  const wrapped = nacl.secretbox(msgKey32, nonce, kek);
  return { nonce: b64(nonce), wrapped: b64(wrapped) };
}

export function kyberUnwrapKey(
  sharedSecret: Uint8Array,
  nonceB64: string,
  wrappedB64: string,
): Uint8Array | null {
  const kek = sha256(sharedSecret);
  const nonce = ub64(nonceB64);
  const wrapped = ub64(wrappedB64);
  return nacl.secretbox.open(wrapped, nonce, kek) || null;
}
