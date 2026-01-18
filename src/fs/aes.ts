/**
 * Omnituum FS - AES-256-GCM Encryption
 *
 * File encryption using AES-256-GCM via Web Crypto API.
 * Provides authenticated encryption with associated data (AEAD).
 */

import { rand12 } from '../crypto/primitives';

// Helper to safely extract ArrayBuffer from Uint8Array (handles SharedArrayBuffer)
function toArrayBuffer(arr: Uint8Array): ArrayBuffer {
  // If buffer is SharedArrayBuffer or view is offset, copy to new ArrayBuffer
  if (arr.buffer instanceof SharedArrayBuffer || arr.byteOffset !== 0 || arr.byteLength !== arr.buffer.byteLength) {
    const copy = new ArrayBuffer(arr.byteLength);
    new Uint8Array(copy).set(arr);
    return copy;
  }
  return arr.buffer as ArrayBuffer;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** AES-256 key size in bytes */
export const AES_KEY_SIZE = 32;

/** AES-GCM IV size in bytes (96 bits recommended by NIST) */
export const AES_GCM_IV_SIZE = 12;

/** AES-GCM auth tag size in bytes (128 bits) */
export const AES_GCM_TAG_SIZE = 16;

// ═══════════════════════════════════════════════════════════════════════════
// KEY IMPORT
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Import a raw 256-bit key for AES-GCM operations.
 *
 * @param keyBytes - 32-byte raw key material
 * @returns CryptoKey suitable for AES-GCM encryption/decryption
 */
export async function importAesKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  if (keyBytes.length !== AES_KEY_SIZE) {
    throw new Error(`AES key must be ${AES_KEY_SIZE} bytes, got ${keyBytes.length}`);
  }

  return globalThis.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes),
    { name: 'AES-GCM', length: 256 },
    false, // not extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate a random 256-bit AES key.
 *
 * @returns CryptoKey for AES-GCM
 */
export async function generateAesKey(): Promise<CryptoKey> {
  return globalThis.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable for wrapping
    ['encrypt', 'decrypt']
  );
}

/**
 * Export a CryptoKey to raw bytes.
 *
 * @param key - CryptoKey to export
 * @returns 32-byte raw key
 */
export async function exportAesKey(key: CryptoKey): Promise<Uint8Array> {
  const exported = await globalThis.crypto.subtle.exportKey('raw', key);
  return new Uint8Array(exported);
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt data using AES-256-GCM.
 *
 * @param plaintext - Data to encrypt
 * @param key - AES-256 key (CryptoKey or 32-byte Uint8Array)
 * @param iv - Optional 12-byte IV (generated if not provided)
 * @param additionalData - Optional additional authenticated data (AAD)
 * @returns Object containing IV and ciphertext (with auth tag appended)
 */
export async function aesEncrypt(
  plaintext: Uint8Array,
  key: CryptoKey | Uint8Array,
  iv?: Uint8Array,
  additionalData?: Uint8Array
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  // Import key if raw bytes provided
  const cryptoKey = key instanceof CryptoKey ? key : await importAesKey(key);

  // Generate IV if not provided
  const ivBytes = iv ?? rand12();

  if (ivBytes.length !== AES_GCM_IV_SIZE) {
    throw new Error(`IV must be ${AES_GCM_IV_SIZE} bytes, got ${ivBytes.length}`);
  }

  // Encrypt with AES-GCM (convert Uint8Arrays to ArrayBuffer for Web Crypto compatibility)
  const encrypted = await globalThis.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(ivBytes),
      additionalData: additionalData ? toArrayBuffer(additionalData) : undefined,
      tagLength: 128, // 16 bytes
    },
    cryptoKey,
    toArrayBuffer(plaintext)
  );

  return {
    iv: ivBytes,
    ciphertext: new Uint8Array(encrypted), // Includes auth tag
  };
}

/**
 * Encrypt data and return combined IV + ciphertext.
 * Convenience method for simple encryption.
 *
 * @param plaintext - Data to encrypt
 * @param key - AES-256 key
 * @param additionalData - Optional AAD
 * @returns Combined bytes: [IV (12 bytes)] [ciphertext + tag]
 */
export async function aesEncryptCombined(
  plaintext: Uint8Array,
  key: CryptoKey | Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const { iv, ciphertext } = await aesEncrypt(plaintext, key, undefined, additionalData);

  // Combine IV + ciphertext
  const combined = new Uint8Array(iv.length + ciphertext.length);
  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);

  return combined;
}

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt data using AES-256-GCM.
 *
 * @param ciphertext - Encrypted data (with auth tag appended)
 * @param key - AES-256 key (CryptoKey or 32-byte Uint8Array)
 * @param iv - 12-byte IV used for encryption
 * @param additionalData - Optional additional authenticated data (must match encryption)
 * @returns Decrypted plaintext
 * @throws Error if authentication fails (wrong key or tampered data)
 */
export async function aesDecrypt(
  ciphertext: Uint8Array,
  key: CryptoKey | Uint8Array,
  iv: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  // Import key if raw bytes provided
  const cryptoKey = key instanceof CryptoKey ? key : await importAesKey(key);

  if (iv.length !== AES_GCM_IV_SIZE) {
    throw new Error(`IV must be ${AES_GCM_IV_SIZE} bytes, got ${iv.length}`);
  }

  try {
    // Convert Uint8Arrays to ArrayBuffer for Web Crypto compatibility
    const decrypted = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(iv),
        additionalData: additionalData ? toArrayBuffer(additionalData) : undefined,
        tagLength: 128,
      },
      cryptoKey,
      toArrayBuffer(ciphertext)
    );

    return new Uint8Array(decrypted);
  } catch (error) {
    // Web Crypto throws a generic error for auth failures
    throw new Error('Decryption failed: authentication tag mismatch (wrong key or corrupted data)');
  }
}

/**
 * Decrypt combined IV + ciphertext.
 * Convenience method for simple decryption.
 *
 * @param combined - Combined bytes: [IV (12 bytes)] [ciphertext + tag]
 * @param key - AES-256 key
 * @param additionalData - Optional AAD
 * @returns Decrypted plaintext
 */
export async function aesDecryptCombined(
  combined: Uint8Array,
  key: CryptoKey | Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  if (combined.length < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
    throw new Error(`Combined data too short: need at least ${AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE} bytes`);
  }

  const iv = combined.slice(0, AES_GCM_IV_SIZE);
  const ciphertext = combined.slice(AES_GCM_IV_SIZE);

  return aesDecrypt(ciphertext, key, iv, additionalData);
}

// ═══════════════════════════════════════════════════════════════════════════
// STREAMING ENCRYPTION (for large files)
// ═══════════════════════════════════════════════════════════════════════════

/** Chunk size for streaming operations (1 MB) */
export const STREAM_CHUNK_SIZE = 1024 * 1024;

/**
 * Encrypt large data in chunks.
 * Each chunk is encrypted with a unique IV derived from base IV + counter.
 *
 * Note: For files < 100MB, use regular aesEncrypt for simplicity.
 * This is primarily for very large files where memory is a concern.
 *
 * @param plaintext - Data to encrypt
 * @param key - AES-256 key
 * @param onProgress - Optional progress callback
 * @returns Encrypted data with format: [chunk count (4 bytes)] [IV] [chunks...]
 */
export async function aesEncryptStreaming(
  plaintext: Uint8Array,
  key: CryptoKey | Uint8Array,
  onProgress?: (percent: number) => void
): Promise<Uint8Array> {
  const cryptoKey = key instanceof CryptoKey ? key : await importAesKey(key);

  const chunks: Uint8Array[] = [];
  const totalChunks = Math.ceil(plaintext.length / STREAM_CHUNK_SIZE);

  // Store chunk count (4 bytes, big-endian)
  const header = new Uint8Array(4);
  new DataView(header.buffer).setUint32(0, totalChunks, false);
  chunks.push(header);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * STREAM_CHUNK_SIZE;
    const end = Math.min(start + STREAM_CHUNK_SIZE, plaintext.length);
    const chunk = plaintext.slice(start, end);

    // Encrypt chunk (IV is generated fresh for each chunk)
    const { iv, ciphertext } = await aesEncrypt(chunk, cryptoKey);

    // Store: [IV (12 bytes)] [ciphertext length (4 bytes)] [ciphertext]
    const chunkData = new Uint8Array(12 + 4 + ciphertext.length);
    chunkData.set(iv, 0);
    new DataView(chunkData.buffer).setUint32(12, ciphertext.length, false);
    chunkData.set(ciphertext, 16);
    chunks.push(chunkData);

    if (onProgress) {
      onProgress(Math.round(((i + 1) / totalChunks) * 100));
    }
  }

  // Combine all chunks
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

/**
 * Decrypt large data encrypted with aesEncryptStreaming.
 *
 * @param encrypted - Encrypted data from aesEncryptStreaming
 * @param key - AES-256 key
 * @param onProgress - Optional progress callback
 * @returns Decrypted plaintext
 */
export async function aesDecryptStreaming(
  encrypted: Uint8Array,
  key: CryptoKey | Uint8Array,
  onProgress?: (percent: number) => void
): Promise<Uint8Array> {
  const cryptoKey = key instanceof CryptoKey ? key : await importAesKey(key);

  // Read chunk count
  const totalChunks = new DataView(encrypted.buffer, encrypted.byteOffset).getUint32(0, false);
  const chunks: Uint8Array[] = [];

  let offset = 4; // Skip header

  for (let i = 0; i < totalChunks; i++) {
    // Read IV
    const iv = encrypted.slice(offset, offset + 12);
    offset += 12;

    // Read ciphertext length
    const ctLength = new DataView(encrypted.buffer, encrypted.byteOffset + offset).getUint32(0, false);
    offset += 4;

    // Read ciphertext
    const ciphertext = encrypted.slice(offset, offset + ctLength);
    offset += ctLength;

    // Decrypt chunk
    const plaintext = await aesDecrypt(ciphertext, cryptoKey, iv);
    chunks.push(plaintext);

    if (onProgress) {
      onProgress(Math.round(((i + 1) / totalChunks) * 100));
    }
  }

  // Combine all chunks
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLength);
  let resultOffset = 0;
  for (const chunk of chunks) {
    result.set(chunk, resultOffset);
    resultOffset += chunk.length;
  }

  return result;
}
