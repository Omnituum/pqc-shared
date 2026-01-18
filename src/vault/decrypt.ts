/**
 * Omnituum PQC Shared - Vault Decryption
 *
 * Password-based decryption using PBKDF2 or Argon2id + AES-256-GCM.
 * Includes integrity verification.
 */

import type { OmnituumVault, EncryptedVaultFile, EncryptedVaultFileV2 } from './types';
import { deriveKey } from './encrypt';
import { fromB64 } from '../crypto/primitives';
import {
  assertVaultEncryptedVersion,
  assertVaultVersion,
  VAULT_VERSION,
  VAULT_ENCRYPTED_VERSION,
  VAULT_ENCRYPTED_VERSION_V2,
  VAULT_KDF,
  VAULT_ALGORITHM,
} from '../version';
import { kdfDeriveKey, configFromParams } from '../kdf';

// ═══════════════════════════════════════════════════════════════════════════
// TEXT ENCODING
// ═══════════════════════════════════════════════════════════════════════════

const textDecoder = new TextDecoder();

// ═══════════════════════════════════════════════════════════════════════════
// VAULT DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt an encrypted vault file with a password.
 * Supports both v1 (PBKDF2) and v2 (Argon2id) formats.
 *
 * @param encryptedFile - Encrypted vault file structure
 * @param password - User password
 * @returns Decrypted vault
 * @throws Error if decryption fails (wrong password or corrupted data)
 */
export async function decryptVault(
  encryptedFile: EncryptedVaultFile,
  password: string
): Promise<OmnituumVault> {
  // Validate encrypted file version (throws VersionMismatchError if unsupported)
  assertVaultEncryptedVersion(encryptedFile.version);

  // Decode base64 values
  const salt = fromB64(encryptedFile.salt);
  const iv = fromB64(encryptedFile.iv);
  const ciphertext = fromB64(encryptedFile.ciphertext);

  // Derive decryption key based on version
  let key: CryptoKey;

  if (encryptedFile.version === VAULT_ENCRYPTED_VERSION_V2) {
    // V2: Argon2id
    const v2File = encryptedFile as EncryptedVaultFileV2;
    const kdfConfig = configFromParams('Argon2id', {
      memoryCost: v2File.memoryCost,
      timeCost: v2File.timeCost,
      parallelism: v2File.parallelism,
    });
    const keyBytes = await kdfDeriveKey(password, salt, kdfConfig);
    // Create ArrayBuffer for importKey compatibility
    const keyBuffer = new ArrayBuffer(keyBytes.length);
    new Uint8Array(keyBuffer).set(keyBytes);
    key = await globalThis.crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  } else {
    // V1: PBKDF2
    key = await deriveKey(password, salt, (encryptedFile as any).iterations);
  }

  try {
    // Create clean ArrayBuffers to ensure type compatibility
    const ivArrayBuffer = new ArrayBuffer(iv.length);
    new Uint8Array(ivArrayBuffer).set(iv);
    const ciphertextArrayBuffer = new ArrayBuffer(ciphertext.length);
    new Uint8Array(ciphertextArrayBuffer).set(ciphertext);

    // Decrypt with AES-256-GCM
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivArrayBuffer },
      key,
      ciphertextArrayBuffer
    );

    // Parse JSON
    const json = textDecoder.decode(plaintext);
    const vault = JSON.parse(json) as OmnituumVault;

    // Validate vault version (throws VersionMismatchError if unsupported)
    assertVaultVersion(vault.version);

    // Validate structure
    if (!Array.isArray(vault.identities)) {
      throw new Error('Invalid vault structure: missing identities array');
    }

    return vault;
  } catch (error) {
    // AES-GCM will throw if authentication fails (wrong password)
    if (error instanceof DOMException && error.name === 'OperationError') {
      throw new Error('Incorrect password or corrupted vault');
    }
    throw error;
  }
}

/**
 * Decrypt a vault from a JSON string.
 *
 * @param json - Encrypted vault JSON string
 * @param password - User password
 * @returns Decrypted vault
 */
export async function decryptVaultFromJson(
  json: string,
  password: string
): Promise<OmnituumVault> {
  const encryptedFile = JSON.parse(json) as EncryptedVaultFile;
  return decryptVault(encryptedFile, password);
}

/**
 * Decrypt a vault from a File object.
 *
 * @param file - File object (from file input)
 * @param password - User password
 * @returns Decrypted vault
 */
export async function decryptVaultFromFile(
  file: File,
  password: string
): Promise<OmnituumVault> {
  const text = await file.text();
  return decryptVaultFromJson(text, password);
}

/**
 * Validate an encrypted vault file without decrypting.
 *
 * @param json - JSON string to validate
 * @returns true if valid encrypted vault file structure
 */
export function isValidEncryptedVaultFile(json: string): boolean {
  try {
    const parsed = JSON.parse(json);
    return (
      parsed.version === VAULT_ENCRYPTED_VERSION &&
      parsed.kdf === VAULT_KDF &&
      typeof parsed.iterations === 'number' &&
      typeof parsed.salt === 'string' &&
      typeof parsed.iv === 'string' &&
      typeof parsed.ciphertext === 'string' &&
      parsed.algorithm === VAULT_ALGORITHM
    );
  } catch {
    return false;
  }
}
