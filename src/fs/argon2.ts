/**
 * Omnituum FS - Argon2id Key Derivation
 *
 * Memory-hard password hashing using Argon2id (winner of PHC).
 * Uses hash-wasm for browser-compatible WASM implementation.
 *
 * Security: OWASP 2024 recommended parameters.
 */

import { argon2id } from 'hash-wasm';
import { randN } from '../crypto/primitives';
import {
  Argon2idParams,
  DEFAULT_ARGON2ID_PARAMS,
  MIN_ARGON2ID_PARAMS,
} from './types';

// ═══════════════════════════════════════════════════════════════════════════
// ARGON2ID KEY DERIVATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Derive an encryption key from a password using Argon2id.
 *
 * @param password - User password
 * @param salt - 32-byte random salt (generate with generateArgon2Salt())
 * @param params - Argon2id parameters (uses OWASP defaults if not specified)
 * @returns 32-byte derived key suitable for AES-256
 */
export async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array,
  params: Argon2idParams = DEFAULT_ARGON2ID_PARAMS
): Promise<Uint8Array> {
  if (salt.length !== params.saltLength) {
    throw new Error(`Salt must be ${params.saltLength} bytes, got ${salt.length}`);
  }

  const hash = await argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.timeCost,
    memorySize: params.memoryCost,
    hashLength: params.hashLength,
    outputType: 'binary',
  });

  return new Uint8Array(hash);
}

/**
 * Generate a random salt for Argon2id.
 *
 * @param length - Salt length in bytes (default: 32)
 * @returns Random salt
 */
export function generateArgon2Salt(length: number = 32): Uint8Array {
  return randN(length);
}

/**
 * Verify a password against a stored hash.
 * Useful for vault unlocking or file password verification.
 *
 * @param password - Password to verify
 * @param salt - Original salt used
 * @param expectedKey - Expected derived key
 * @param params - Argon2id parameters
 * @returns true if password is correct
 */
export async function verifyPassword(
  password: string,
  salt: Uint8Array,
  expectedKey: Uint8Array,
  params: Argon2idParams = DEFAULT_ARGON2ID_PARAMS
): Promise<boolean> {
  const derivedKey = await deriveKeyFromPassword(password, salt, params);

  // Constant-time comparison to prevent timing attacks
  if (derivedKey.length !== expectedKey.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < derivedKey.length; i++) {
    result |= derivedKey[i] ^ expectedKey[i];
  }

  return result === 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// PARAMETER ESTIMATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Estimate Argon2id parameters based on available memory and target time.
 * Useful for adapting to low-memory environments.
 *
 * @param targetTimeMs - Target key derivation time in milliseconds
 * @param availableMemoryMB - Available memory in megabytes
 * @returns Estimated Argon2id parameters
 */
export function estimateArgon2Params(
  targetTimeMs: number = 1000,
  availableMemoryMB: number = 64
): Argon2idParams {
  // Start with minimum parameters
  const params = { ...MIN_ARGON2ID_PARAMS };

  // Scale memory based on availability (cap at 64MB for browser compatibility)
  const maxMemoryKB = Math.min(availableMemoryMB * 1024, 65536);
  params.memoryCost = Math.max(MIN_ARGON2ID_PARAMS.memoryCost, maxMemoryKB);

  // Use 4 parallelism for modern multi-core CPUs
  params.parallelism = Math.min(4, navigator.hardwareConcurrency || 1);

  // Estimate time cost (rough heuristic: 1 iteration ≈ 300ms at 64MB)
  const estimatedIterations = Math.max(2, Math.floor(targetTimeMs / 300));
  params.timeCost = Math.min(estimatedIterations, 10); // Cap at 10 iterations

  return params;
}

/**
 * Benchmark Argon2id on current device.
 * Returns the time in milliseconds for one derivation.
 *
 * @param params - Parameters to benchmark
 * @returns Time in milliseconds
 */
export async function benchmarkArgon2(
  params: Argon2idParams = DEFAULT_ARGON2ID_PARAMS
): Promise<number> {
  const testPassword = 'benchmark-test-password';
  const testSalt = generateArgon2Salt(params.saltLength);

  const start = performance.now();
  await deriveKeyFromPassword(testPassword, testSalt, params);
  const end = performance.now();

  return end - start;
}

// ═══════════════════════════════════════════════════════════════════════════
// AVAILABILITY CHECK
// ═══════════════════════════════════════════════════════════════════════════

let _argon2Available: boolean | null = null;

/**
 * Check if Argon2id is available in current environment.
 * Caches result after first check.
 */
export async function isArgon2Available(): Promise<boolean> {
  if (_argon2Available !== null) {
    return _argon2Available;
  }

  try {
    // Quick test with minimal parameters
    await argon2id({
      password: 'test',
      salt: new Uint8Array(16),
      parallelism: 1,
      iterations: 1,
      memorySize: 1024, // 1 MB
      hashLength: 32,
      outputType: 'binary',
    });
    _argon2Available = true;
  } catch {
    _argon2Available = false;
  }

  return _argon2Available;
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export { DEFAULT_ARGON2ID_PARAMS, MIN_ARGON2ID_PARAMS };
