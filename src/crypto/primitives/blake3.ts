/**
 * Omnituum PQC Shared - BLAKE3 Hash Primitive
 *
 * BLAKE3 is a cryptographic hash function that provides:
 * - Fast performance (faster than SHA-256, SHA-3)
 * - 256-bit security (collision resistance)
 * - Variable output length (default 32 bytes)
 *
 * Used in Noise protocols for transcript hashing.
 */

import { blake3 as nobleBlake3 } from '@noble/hashes/blake3';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface Blake3Options {
  /** Output length in bytes (default: 32) */
  outputLength?: number;
  /** Optional key for keyed hashing (32 bytes) */
  key?: Uint8Array;
  /** Optional context string for domain separation */
  context?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// BLAKE3 HASH
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Compute BLAKE3 hash of input data.
 *
 * @param data - Data to hash (Uint8Array or string)
 * @param options - Optional configuration
 * @returns BLAKE3 hash (default 32 bytes)
 *
 * @example
 * ```ts
 * // Simple hash
 * const hash = blake3(new Uint8Array([1, 2, 3]));
 *
 * // Hash with context (domain separation)
 * const hash = blake3(data, { context: 'MyApp v1.0 signing' });
 *
 * // Keyed hash (requires 32-byte key)
 * const hash = blake3(data, { key: keyBytes });
 *
 * // Variable output length
 * const hash = blake3(data, { outputLength: 64 });
 * ```
 */
export function blake3(
  data: Uint8Array | string,
  options?: Blake3Options
): Uint8Array {
  const input = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;

  // @noble/hashes blake3 supports key and context options
  const opts: { dkLen?: number; key?: Uint8Array; context?: Uint8Array } = {};

  if (options?.outputLength) {
    opts.dkLen = options.outputLength;
  }

  if (options?.key) {
    if (options.key.length !== 32) {
      throw new Error('BLAKE3 key must be exactly 32 bytes');
    }
    opts.key = options.key;
  }

  if (options?.context) {
    opts.context = new TextEncoder().encode(options.context);
  }

  return nobleBlake3(input, opts);
}

/**
 * Compute BLAKE3 hash and return as hex string.
 */
export function blake3Hex(
  data: Uint8Array | string,
  options?: Blake3Options
): string {
  const hash = blake3(data, options);
  return Array.from(hash)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Create a keyed BLAKE3 hash (MAC).
 *
 * @param key - 32-byte key
 * @param data - Data to hash
 * @returns BLAKE3-MAC (32 bytes by default)
 */
export function blake3Mac(
  key: Uint8Array,
  data: Uint8Array,
  outputLength = 32
): Uint8Array {
  if (key.length !== 32) {
    throw new Error('BLAKE3 MAC key must be exactly 32 bytes');
  }
  return blake3(data, { key, outputLength });
}

/**
 * Derive a key from a context and key material using BLAKE3.
 * This uses BLAKE3's built-in KDF mode.
 *
 * @param context - Domain separation string
 * @param keyMaterial - Input key material
 * @param outputLength - Desired output length (default 32)
 * @returns Derived key
 */
export function blake3DeriveKey(
  context: string,
  keyMaterial: Uint8Array,
  outputLength = 32
): Uint8Array {
  return blake3(keyMaterial, { context, outputLength });
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** Default BLAKE3 output length (32 bytes = 256 bits) */
export const BLAKE3_OUTPUT_LENGTH = 32;

/** BLAKE3 key length for keyed mode (32 bytes) */
export const BLAKE3_KEY_LENGTH = 32;

/** BLAKE3 block size (64 bytes) */
export const BLAKE3_BLOCK_SIZE = 64;
