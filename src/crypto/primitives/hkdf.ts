/**
 * Omnituum PQC Shared - HKDF (HMAC-based Key Derivation Function)
 *
 * HKDF is a NIST-approved key derivation function (RFC 5869).
 * Supports SHA-256 (default) and SHA-512 hash functions.
 *
 * Two-step process:
 * 1. Extract: Derive a pseudorandom key from input keying material
 * 2. Expand: Generate output keying material from the PRK
 *
 * Used in Noise protocols for key derivation.
 */

import { hkdf, extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type HkdfHash = 'sha256' | 'sha512';

export interface HkdfOptions {
  /** Hash function to use (default: 'sha256') */
  hash?: HkdfHash;
  /** Context info for domain separation */
  info?: Uint8Array | string;
  /** Salt (defaults to zeroes if not provided) */
  salt?: Uint8Array;
}

// ═══════════════════════════════════════════════════════════════════════════
// HKDF FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Derive keys using HKDF (Extract + Expand).
 *
 * @param ikm - Input keying material
 * @param outputLength - Desired output length in bytes
 * @param options - Optional salt, info, and hash selection
 * @returns Derived key material
 *
 * @example
 * ```ts
 * // Basic key derivation
 * const key = hkdfDerive(sharedSecret, 32);
 *
 * // With domain separation
 * const key = hkdfDerive(sharedSecret, 32, {
 *   info: 'MyApp v1.0 encryption key'
 * });
 *
 * // With salt
 * const key = hkdfDerive(sharedSecret, 32, {
 *   salt: randomSalt,
 *   info: 'session key'
 * });
 * ```
 */
export function hkdfDerive(
  ikm: Uint8Array,
  outputLength: number,
  options?: HkdfOptions
): Uint8Array {
  const hashFn = getHashFunction(options?.hash ?? 'sha256');
  const info = normalizeInfo(options?.info);
  const salt = options?.salt;

  return hkdf(hashFn, ikm, salt, info, outputLength);
}

/**
 * HKDF-Extract: Derive a pseudorandom key from input keying material.
 *
 * @param ikm - Input keying material
 * @param salt - Optional salt (defaults to zeroes)
 * @param hash - Hash function ('sha256' or 'sha512')
 * @returns Pseudorandom key (32 bytes for SHA-256, 64 for SHA-512)
 */
export function hkdfExtract(
  ikm: Uint8Array,
  salt?: Uint8Array,
  hash: HkdfHash = 'sha256'
): Uint8Array {
  const hashFn = getHashFunction(hash);
  return extract(hashFn, ikm, salt);
}

/**
 * HKDF-Expand: Expand a pseudorandom key into output keying material.
 *
 * @param prk - Pseudorandom key (from hkdfExtract)
 * @param info - Context info for domain separation
 * @param outputLength - Desired output length in bytes
 * @param hash - Hash function ('sha256' or 'sha512')
 * @returns Output keying material
 */
export function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array | string | undefined,
  outputLength: number,
  hash: HkdfHash = 'sha256'
): Uint8Array {
  const hashFn = getHashFunction(hash);
  return expand(hashFn, prk, normalizeInfo(info), outputLength);
}

// ═══════════════════════════════════════════════════════════════════════════
// NOISE PROTOCOL HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * HKDF for Noise protocol key derivation.
 * Splits output into chaining key and output key.
 *
 * @param chainingKey - Current chaining key (salt)
 * @param inputKeyMaterial - New key material to mix in
 * @returns [newChainingKey, outputKey] - both 32 bytes
 */
export function hkdfSplitForNoise(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array
): [Uint8Array, Uint8Array] {
  const prk = hkdfExtract(inputKeyMaterial, chainingKey, 'sha256');
  const output = hkdfExpand(prk, undefined, 64, 'sha256');

  return [
    output.slice(0, 32),  // New chaining key
    output.slice(32, 64), // Output key
  ];
}

/**
 * HKDF for Noise protocol with three outputs.
 * Used when deriving transport keys at the end of handshake.
 *
 * @param chainingKey - Current chaining key
 * @param inputKeyMaterial - Key material to mix
 * @returns [ck, k1, k2] - chaining key and two output keys
 */
export function hkdfTripleSplitForNoise(
  chainingKey: Uint8Array,
  inputKeyMaterial: Uint8Array
): [Uint8Array, Uint8Array, Uint8Array] {
  const prk = hkdfExtract(inputKeyMaterial, chainingKey, 'sha256');
  const output = hkdfExpand(prk, undefined, 96, 'sha256');

  return [
    output.slice(0, 32),   // New chaining key
    output.slice(32, 64),  // Output key 1
    output.slice(64, 96),  // Output key 2
  ];
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

function getHashFunction(hash: HkdfHash) {
  switch (hash) {
    case 'sha256':
      return sha256;
    case 'sha512':
      return sha512;
    default:
      throw new Error(`Unsupported HKDF hash: ${hash}`);
  }
}

function normalizeInfo(info: Uint8Array | string | undefined): Uint8Array {
  if (!info) return new Uint8Array(0);
  if (typeof info === 'string') return new TextEncoder().encode(info);
  return info;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** HKDF-SHA256 output size (32 bytes) */
export const HKDF_SHA256_OUTPUT_SIZE = 32;

/** HKDF-SHA512 output size (64 bytes) */
export const HKDF_SHA512_OUTPUT_SIZE = 64;

/** Maximum HKDF output length for SHA-256 (255 * 32 = 8160 bytes) */
export const HKDF_SHA256_MAX_OUTPUT = 255 * 32;

/** Maximum HKDF output length for SHA-512 (255 * 64 = 16320 bytes) */
export const HKDF_SHA512_MAX_OUTPUT = 255 * 64;
