/**
 * Omnituum PQC Shared - Vault Encryption
 *
 * Password-based encryption using PBKDF2 or Argon2id + AES-256-GCM.
 * All operations use the Web Crypto API for browser compatibility.
 */

import type { OmnituumVault, EncryptedVaultFile, EncryptedVaultFileV1, EncryptedVaultFileV2 } from './types';
import { PBKDF2_ITERATIONS } from './types';
import { toB64 } from '../crypto/primitives';
import {
  VAULT_ENCRYPTED_VERSION,
  VAULT_ENCRYPTED_VERSION_V2,
  VAULT_KDF,
  VAULT_KDF_V2,
  VAULT_ALGORITHM,
} from '../version';
import { kdfDeriveKey, KDF_CONFIG_ARGON2ID } from '../kdf';

// ═══════════════════════════════════════════════════════════════════════════
// TEXT ENCODING
// ═══════════════════════════════════════════════════════════════════════════

const textEncoder = new TextEncoder();

// ═══════════════════════════════════════════════════════════════════════════
// KEY DERIVATION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Derive an AES-256 key from a password using PBKDF2-SHA256.
 *
 * @param password - User password
 * @param salt - 32-byte salt
 * @param iterations - PBKDF2 iterations (default: 600,000)
 * @returns CryptoKey for AES-GCM
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number = PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  // Import password as raw key material
  const passwordKey = await globalThis.crypto.subtle.importKey(
    'raw',
    textEncoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  // Derive AES-256-GCM key
  // Create a clean ArrayBuffer to ensure type compatibility
  const saltArrayBuffer = new ArrayBuffer(salt.length);
  new Uint8Array(saltArrayBuffer).set(salt);
  return globalThis.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltArrayBuffer,
      iterations,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false, // not extractable
    ['encrypt', 'decrypt']
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// VAULT ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a vault with a password.
 *
 * Uses PBKDF2-SHA256 for key derivation and AES-256-GCM for encryption.
 * The salt and IV are randomly generated and included in the output.
 *
 * @param vault - Vault to encrypt
 * @param password - User password
 * @returns Encrypted vault file structure
 */
export async function encryptVault(
  vault: OmnituumVault,
  password: string
): Promise<EncryptedVaultFile> {
  // Generate random salt (32 bytes) and IV (12 bytes for GCM)
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

  // Derive encryption key
  const key = await deriveKey(password, salt);

  // Serialize vault to JSON
  const plaintext = textEncoder.encode(JSON.stringify(vault));

  // Encrypt with AES-256-GCM
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  return {
    version: VAULT_ENCRYPTED_VERSION,
    kdf: VAULT_KDF,
    iterations: PBKDF2_ITERATIONS,
    salt: toB64(salt),
    iv: toB64(iv),
    ciphertext: toB64(new Uint8Array(ciphertext)),
    algorithm: VAULT_ALGORITHM,
  };
}

/**
 * Encrypt vault to a downloadable blob.
 *
 * @param vault - Vault to encrypt
 * @param password - User password
 * @returns Blob for download
 */
export async function encryptVaultToBlob(
  vault: OmnituumVault,
  password: string
): Promise<Blob> {
  const encrypted = await encryptVault(vault, password);
  const json = JSON.stringify(encrypted, null, 2);
  return new Blob([json], { type: 'application/json' });
}

/**
 * Encrypt vault to a data URL for download.
 *
 * @param vault - Vault to encrypt
 * @param password - User password
 * @returns Data URL
 */
export async function encryptVaultToDataURL(
  vault: OmnituumVault,
  password: string
): Promise<string> {
  const encrypted = await encryptVault(vault, password);
  const json = JSON.stringify(encrypted, null, 2);
  return 'data:application/json;charset=utf-8,' + encodeURIComponent(json);
}

// ═══════════════════════════════════════════════════════════════════════════
// V2 ENCRYPTION (ARGON2ID)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt a vault with a password using Argon2id (v2 format).
 *
 * Uses Argon2id for key derivation (64MB memory, 3 iterations) and AES-256-GCM.
 * This is the recommended format for new vaults.
 *
 * @param vault - Vault to encrypt
 * @param password - User password
 * @returns Encrypted vault file structure (v2)
 */
export async function encryptVaultV2(
  vault: OmnituumVault,
  password: string
): Promise<EncryptedVaultFileV2> {
  // Generate random salt (32 bytes) and IV (12 bytes for GCM)
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

  // Derive key using Argon2id
  const keyBytes = await kdfDeriveKey(password, salt, KDF_CONFIG_ARGON2ID);

  // Create ArrayBuffer from key bytes for importKey compatibility
  const keyBuffer = new ArrayBuffer(keyBytes.length);
  new Uint8Array(keyBuffer).set(keyBytes);

  // Import key for AES-GCM
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Serialize vault to JSON
  const plaintext = textEncoder.encode(JSON.stringify(vault));

  // Encrypt with AES-256-GCM
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );

  return {
    version: VAULT_ENCRYPTED_VERSION_V2,
    kdf: VAULT_KDF_V2,
    memoryCost: KDF_CONFIG_ARGON2ID.argon2MemoryCost!,
    timeCost: KDF_CONFIG_ARGON2ID.argon2TimeCost!,
    parallelism: KDF_CONFIG_ARGON2ID.argon2Parallelism!,
    salt: toB64(salt),
    iv: toB64(iv),
    ciphertext: toB64(new Uint8Array(ciphertext)),
    algorithm: VAULT_ALGORITHM,
  };
}
