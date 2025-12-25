/**
 * Omnituum PQC Shared - Unified Key Derivation
 *
 * Single source of truth for password-based key derivation.
 * Supports both legacy PBKDF2 (for backwards compatibility) and
 * Argon2id (recommended for new implementations).
 *
 * Security Levels:
 * - PBKDF2-SHA256: 600K iterations (OWASP 2023)
 * - Argon2id: 64MB memory, 3 iterations, 4 parallelism (OWASP 2024)
 */

import { argon2id } from 'hash-wasm';
import { randN } from '../crypto/primitives';

// ═══════════════════════════════════════════════════════════════════════════
// KDF TYPES
// ═══════════════════════════════════════════════════════════════════════════

export type KDFAlgorithm = 'PBKDF2-SHA256' | 'Argon2id';

export interface KDFConfig {
  algorithm: KDFAlgorithm;
  // PBKDF2 params
  pbkdf2Iterations?: number;
  // Argon2id params
  argon2MemoryCost?: number; // KiB
  argon2TimeCost?: number;
  argon2Parallelism?: number;
  // Common
  saltLength: number;
  hashLength: number;
}

export interface KDFResult {
  key: Uint8Array;
  salt: Uint8Array;
  algorithm: KDFAlgorithm;
  params: Record<string, number>;
}

// ═══════════════════════════════════════════════════════════════════════════
// DEFAULT CONFIGURATIONS
// ═══════════════════════════════════════════════════════════════════════════

/** Legacy PBKDF2 config (for existing vaults) */
export const KDF_CONFIG_PBKDF2: KDFConfig = {
  algorithm: 'PBKDF2-SHA256',
  pbkdf2Iterations: 600000, // OWASP 2023
  saltLength: 32,
  hashLength: 32,
};

/** Modern Argon2id config (recommended for new vaults) */
export const KDF_CONFIG_ARGON2ID: KDFConfig = {
  algorithm: 'Argon2id',
  argon2MemoryCost: 65536, // 64 MB
  argon2TimeCost: 3,
  argon2Parallelism: 4,
  saltLength: 32,
  hashLength: 32,
};

/** Low-memory Argon2id config (for constrained environments) */
export const KDF_CONFIG_ARGON2ID_LOW_MEMORY: KDFConfig = {
  algorithm: 'Argon2id',
  argon2MemoryCost: 19456, // 19 MB
  argon2TimeCost: 2,
  argon2Parallelism: 1,
  saltLength: 32,
  hashLength: 32,
};

/** Current default - can be changed for migration */
export const KDF_CONFIG_DEFAULT = KDF_CONFIG_PBKDF2;

// ═══════════════════════════════════════════════════════════════════════════
// PBKDF2 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

const textEncoder = new TextEncoder();

async function derivePBKDF2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  hashLength: number
): Promise<Uint8Array> {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const saltBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(saltBuffer).set(salt);

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    hashLength * 8
  );

  return new Uint8Array(bits);
}

// ═══════════════════════════════════════════════════════════════════════════
// ARGON2ID IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════

async function deriveArgon2id(
  password: string,
  salt: Uint8Array,
  memoryCost: number,
  timeCost: number,
  parallelism: number,
  hashLength: number
): Promise<Uint8Array> {
  const hash = await argon2id({
    password,
    salt,
    parallelism,
    iterations: timeCost,
    memorySize: memoryCost,
    hashLength,
    outputType: 'binary',
  });

  return new Uint8Array(hash);
}

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED API
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a cryptographically secure salt.
 */
export function generateSalt(length: number = 32): Uint8Array {
  return randN(length);
}

/**
 * Derive a key from a password using the specified KDF configuration.
 *
 * @param password - User password
 * @param salt - Random salt (use generateSalt())
 * @param config - KDF configuration
 * @returns Derived key as Uint8Array
 */
export async function kdfDeriveKey(
  password: string,
  salt: Uint8Array,
  config: KDFConfig = KDF_CONFIG_DEFAULT
): Promise<Uint8Array> {
  if (salt.length !== config.saltLength) {
    throw new Error(`Salt must be ${config.saltLength} bytes, got ${salt.length}`);
  }

  if (config.algorithm === 'PBKDF2-SHA256') {
    return derivePBKDF2(
      password,
      salt,
      config.pbkdf2Iterations ?? 600000,
      config.hashLength
    );
  } else if (config.algorithm === 'Argon2id') {
    return deriveArgon2id(
      password,
      salt,
      config.argon2MemoryCost ?? 65536,
      config.argon2TimeCost ?? 3,
      config.argon2Parallelism ?? 4,
      config.hashLength
    );
  } else {
    throw new Error(`Unsupported KDF algorithm: ${config.algorithm}`);
  }
}

/**
 * Derive a key and return full result with params.
 * Useful for storing KDF metadata alongside encrypted data.
 */
export async function kdfDeriveKeyWithParams(
  password: string,
  config: KDFConfig = KDF_CONFIG_DEFAULT
): Promise<KDFResult> {
  const salt = generateSalt(config.saltLength);
  const key = await kdfDeriveKey(password, salt, config);

  const params: Record<string, number> = {};

  if (config.algorithm === 'PBKDF2-SHA256') {
    params.iterations = config.pbkdf2Iterations ?? 600000;
  } else if (config.algorithm === 'Argon2id') {
    params.memoryCost = config.argon2MemoryCost ?? 65536;
    params.timeCost = config.argon2TimeCost ?? 3;
    params.parallelism = config.argon2Parallelism ?? 4;
  }

  return {
    key,
    salt,
    algorithm: config.algorithm,
    params,
  };
}

/**
 * Reconstruct KDF config from stored parameters.
 */
export function configFromParams(
  algorithm: KDFAlgorithm,
  params: Record<string, number>
): KDFConfig {
  if (algorithm === 'PBKDF2-SHA256') {
    return {
      algorithm,
      pbkdf2Iterations: params.iterations,
      saltLength: 32,
      hashLength: 32,
    };
  } else if (algorithm === 'Argon2id') {
    return {
      algorithm,
      argon2MemoryCost: params.memoryCost,
      argon2TimeCost: params.timeCost,
      argon2Parallelism: params.parallelism,
      saltLength: 32,
      hashLength: 32,
    };
  } else {
    throw new Error(`Unsupported KDF algorithm: ${algorithm}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// AVAILABILITY CHECKS
// ═══════════════════════════════════════════════════════════════════════════

let _argon2Available: boolean | null = null;

/**
 * Check if Argon2id is available in current environment.
 */
export async function isArgon2idAvailable(): Promise<boolean> {
  if (_argon2Available !== null) {
    return _argon2Available;
  }

  try {
    await argon2id({
      password: 'test',
      salt: new Uint8Array(16),
      parallelism: 1,
      iterations: 1,
      memorySize: 1024,
      hashLength: 32,
      outputType: 'binary',
    });
    _argon2Available = true;
  } catch {
    _argon2Available = false;
  }

  return _argon2Available;
}

/**
 * Check if PBKDF2 is available (always true in Web Crypto environments).
 */
export function isPBKDF2Available(): boolean {
  return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
}

/**
 * Get the recommended KDF config based on environment capabilities.
 */
export async function getRecommendedConfig(): Promise<KDFConfig> {
  if (await isArgon2idAvailable()) {
    return KDF_CONFIG_ARGON2ID;
  }
  return KDF_CONFIG_PBKDF2;
}

// ═══════════════════════════════════════════════════════════════════════════
// BENCHMARKING
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Benchmark a KDF configuration.
 * @returns Time in milliseconds
 */
export async function benchmarkKDF(config: KDFConfig = KDF_CONFIG_DEFAULT): Promise<number> {
  const salt = generateSalt(config.saltLength);
  const testPassword = 'benchmark-test-password';

  const start = performance.now();
  await kdfDeriveKey(testPassword, salt, config);
  const end = performance.now();

  return end - start;
}
