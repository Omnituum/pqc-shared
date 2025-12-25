/**
 * Omnituum PQC Shared - ChaCha20-Poly1305 Primitives
 *
 * AEAD ciphers for authenticated encryption:
 * - ChaCha20-Poly1305: Standard AEAD (12-byte nonce)
 * - XChaCha20-Poly1305: Extended nonce variant (24-byte nonce)
 *
 * Used in Noise protocols and general-purpose encryption.
 */

import { chacha20poly1305, xchacha20poly1305 } from '@noble/ciphers/chacha';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface ChaChaPayload {
  /** Nonce (12 bytes for standard, 24 bytes for xchacha) */
  nonce: Uint8Array;
  /** Ciphertext with Poly1305 tag (16 bytes appended) */
  ciphertext: Uint8Array;
}

// ═══════════════════════════════════════════════════════════════════════════
// CHACHA20-POLY1305 (12-byte nonce)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt using ChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce (must be unique per key)
 * @param plaintext - Data to encrypt
 * @param aad - Optional additional authenticated data
 * @returns Ciphertext with Poly1305 tag appended
 */
export function chaCha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
  }
  if (nonce.length !== 12) {
    throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes');
  }

  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt using ChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param ciphertext - Ciphertext with Poly1305 tag
 * @param aad - Optional additional authenticated data
 * @returns Plaintext, or null if authentication fails
 */
export function chaCha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Uint8Array | null {
  if (key.length !== 32) {
    throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
  }
  if (nonce.length !== 12) {
    throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes');
  }

  try {
    const cipher = chacha20poly1305(key, nonce, aad);
    return cipher.decrypt(ciphertext);
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// XCHACHA20-POLY1305 (24-byte nonce)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt using XChaCha20-Poly1305 (extended 24-byte nonce).
 *
 * XChaCha20-Poly1305 is preferred for most applications because:
 * - 24-byte nonce can be safely generated randomly
 * - No nonce collision risk with ~2^80 messages per key
 *
 * @param key - 32-byte encryption key
 * @param nonce - 24-byte nonce (can be random)
 * @param plaintext - Data to encrypt
 * @param aad - Optional additional authenticated data
 * @returns Ciphertext with Poly1305 tag appended
 */
export function xChaCha20Poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== 32) {
    throw new Error('XChaCha20-Poly1305 key must be 32 bytes');
  }
  if (nonce.length !== 24) {
    throw new Error('XChaCha20-Poly1305 nonce must be 24 bytes');
  }

  const cipher = xchacha20poly1305(key, nonce, aad);
  return cipher.encrypt(plaintext);
}

/**
 * Decrypt using XChaCha20-Poly1305.
 *
 * @param key - 32-byte encryption key
 * @param nonce - 24-byte nonce
 * @param ciphertext - Ciphertext with Poly1305 tag
 * @param aad - Optional additional authenticated data
 * @returns Plaintext, or null if authentication fails
 */
export function xChaCha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array
): Uint8Array | null {
  if (key.length !== 32) {
    throw new Error('XChaCha20-Poly1305 key must be 32 bytes');
  }
  if (nonce.length !== 24) {
    throw new Error('XChaCha20-Poly1305 nonce must be 24 bytes');
  }

  try {
    const cipher = xchacha20poly1305(key, nonce, aad);
    return cipher.decrypt(ciphertext);
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTIONS (for Noise protocol compatibility)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Create an XChaCha20-Poly1305 cipher instance.
 * Compatible with @noble/ciphers API used in noise-kyber.
 *
 * @param key - 32-byte encryption key
 * @param nonce - 24-byte nonce
 * @param aad - Optional additional authenticated data
 * @returns Cipher with encrypt/decrypt methods
 */
export function createXChaCha20Poly1305(
  key: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array
) {
  if (key.length !== 32) {
    throw new Error('XChaCha20-Poly1305 key must be 32 bytes');
  }
  if (nonce.length !== 24) {
    throw new Error('XChaCha20-Poly1305 nonce must be 24 bytes');
  }
  return xchacha20poly1305(key, nonce, aad);
}

/**
 * Create a ChaCha20-Poly1305 cipher instance.
 *
 * @param key - 32-byte encryption key
 * @param nonce - 12-byte nonce
 * @param aad - Optional additional authenticated data
 * @returns Cipher with encrypt/decrypt methods
 */
export function createChaCha20Poly1305(
  key: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array
) {
  if (key.length !== 32) {
    throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
  }
  if (nonce.length !== 12) {
    throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes');
  }
  return chacha20poly1305(key, nonce, aad);
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** ChaCha20-Poly1305 key size (32 bytes) */
export const CHACHA20_KEY_SIZE = 32;

/** ChaCha20-Poly1305 nonce size (12 bytes) */
export const CHACHA20_NONCE_SIZE = 12;

/** XChaCha20-Poly1305 nonce size (24 bytes) */
export const XCHACHA20_NONCE_SIZE = 24;

/** Poly1305 tag size (16 bytes) */
export const POLY1305_TAG_SIZE = 16;
