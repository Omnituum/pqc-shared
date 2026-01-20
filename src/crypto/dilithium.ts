/**
 * Omnituum PQC Shared - Dilithium ML-DSA-65 Signatures
 *
 * Post-quantum digital signatures using ML-DSA-65 (formerly CRYSTALS-Dilithium).
 * NIST Level 3 security - quantum-resistant.
 *
 * Uses @noble/post-quantum for browser-compatible implementation.
 */

import { toB64, fromB64, sha256, randN } from './primitives';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface DilithiumKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface DilithiumKeypairB64 {
  publicB64: string;
  secretB64: string;
}

export interface DilithiumSignature {
  /** Signature (base64) */
  signature: string;
  /** Algorithm identifier */
  algorithm: 'ML-DSA-65';
}

// ═══════════════════════════════════════════════════════════════════════════
// LIBRARY LOADING
// ═══════════════════════════════════════════════════════════════════════════

let dilithiumModule: any = null;

async function loadDilithium(): Promise<any> {
  if (dilithiumModule) return dilithiumModule;

  try {
    // @noble/post-quantum provides ml-dsa
    const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
    dilithiumModule = ml_dsa65;
    return dilithiumModule;
  } catch (e) {
    console.warn('[Dilithium] Failed to load @noble/post-quantum:', e);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AVAILABILITY CHECK
// ═══════════════════════════════════════════════════════════════════════════

export async function isDilithiumAvailable(): Promise<boolean> {
  const mod = await loadDilithium();
  return mod !== null;
}

// ═══════════════════════════════════════════════════════════════════════════
// KEY GENERATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a Dilithium ML-DSA-65 keypair.
 *
 * @returns Keypair with base64-encoded keys, or null if unavailable
 */
export async function generateDilithiumKeypair(): Promise<DilithiumKeypairB64 | null> {
  try {
    const mod = await loadDilithium();
    if (!mod) return null;

    // Generate random seed
    const seed = randN(32);

    // Generate keypair from seed for determinism
    const kp = mod.keygen(seed);

    return {
      publicB64: toB64(kp.publicKey),
      secretB64: toB64(kp.secretKey),
    };
  } catch (e) {
    console.warn('[Dilithium] Key generation failed:', e);
    return null;
  }
}

/**
 * Generate a deterministic Dilithium keypair from a seed.
 *
 * @param seed - 32-byte seed
 * @returns Keypair
 */
export async function generateDilithiumKeypairFromSeed(
  seed: Uint8Array
): Promise<DilithiumKeypair> {
  const mod = await loadDilithium();
  if (!mod) {
    throw new Error('Dilithium library not available');
  }

  if (seed.length !== 32) {
    throw new Error('Dilithium seed must be 32 bytes');
  }

  // Hash seed for uniformity
  const uniformSeed = sha256(seed);
  const kp = mod.keygen(uniformSeed);

  return {
    publicKey: kp.publicKey,
    secretKey: kp.secretKey,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// SIGNING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Sign a message using Dilithium ML-DSA-65.
 *
 * @param message - Message to sign (Uint8Array or string)
 * @param secretKeyB64 - Secret key (base64)
 * @returns Signature object
 */
export async function dilithiumSign(
  message: Uint8Array | string,
  secretKeyB64: string
): Promise<DilithiumSignature> {
  const mod = await loadDilithium();
  if (!mod) {
    throw new Error('Dilithium library not available');
  }

  const sk = fromB64(secretKeyB64);
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;

  const signature = mod.sign(sk, msg);

  return {
    signature: toB64(signature),
    algorithm: 'ML-DSA-65',
  };
}

/**
 * Sign raw bytes (returns raw signature).
 */
export async function dilithiumSignRaw(
  message: Uint8Array,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  const mod = await loadDilithium();
  if (!mod) {
    throw new Error('Dilithium library not available');
  }

  return mod.sign(secretKey, message);
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Verify a Dilithium signature.
 *
 * @param message - Original message
 * @param signatureB64 - Signature (base64)
 * @param publicKeyB64 - Public key (base64)
 * @returns true if signature is valid
 */
export async function dilithiumVerify(
  message: Uint8Array | string,
  signatureB64: string,
  publicKeyB64: string
): Promise<boolean> {
  const mod = await loadDilithium();
  if (!mod) {
    throw new Error('Dilithium library not available');
  }

  const pk = fromB64(publicKeyB64);
  const sig = fromB64(signatureB64);
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;

  try {
    return mod.verify(pk, msg, sig);
  } catch {
    return false;
  }
}

/**
 * Verify raw signature bytes.
 */
export async function dilithiumVerifyRaw(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  const mod = await loadDilithium();
  if (!mod) {
    throw new Error('Dilithium library not available');
  }

  try {
    return mod.verify(publicKey, message, signature);
  } catch {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** ML-DSA-65 public key size */
export const DILITHIUM_PUBLIC_KEY_SIZE = 1952;

/** ML-DSA-65 secret key size */
export const DILITHIUM_SECRET_KEY_SIZE = 4032;

/** ML-DSA-65 signature size */
export const DILITHIUM_SIGNATURE_SIZE = 3309;

/** Algorithm identifier */
export const DILITHIUM_ALGORITHM = 'ML-DSA-65';
