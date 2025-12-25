/**
 * Omnituum PQC Shared - NaCl Secretbox Operations
 *
 * Symmetric encryption using XSalsa20-Poly1305 (NaCl secretbox).
 * 32-byte key, 24-byte nonce, authenticated encryption.
 */

import nacl from 'tweetnacl';
import { rand24, toB64, fromB64, assertLen } from './primitives';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════

export interface SecretboxPayload {
  /** Scheme identifier for format detection */
  scheme: 'nacl.secretbox';
  /** Nonce (base64, 24 bytes) */
  nonce: string;
  /** Ciphertext (base64, includes auth tag) */
  ciphertext: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Encrypt data using NaCl secretbox (XSalsa20-Poly1305).
 *
 * @param key - 32-byte symmetric key
 * @param plaintext - Data to encrypt
 * @param nonce - Optional 24-byte nonce (generated if not provided)
 * @returns Encrypted payload with nonce and ciphertext
 */
export function secretboxEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce?: Uint8Array
): SecretboxPayload {
  assertLen('secretbox key', key, 32);

  const n = nonce ?? rand24();
  assertLen('nonce', n, 24);

  const ciphertext = nacl.secretbox(plaintext, n, key);

  return {
    scheme: 'nacl.secretbox' as const,
    nonce: toB64(n),
    ciphertext: toB64(ciphertext),
  };
}

/**
 * Encrypt a string using NaCl secretbox.
 */
export function secretboxEncryptString(
  key: Uint8Array,
  plaintext: string,
  nonce?: Uint8Array
): SecretboxPayload {
  return secretboxEncrypt(key, new TextEncoder().encode(plaintext), nonce);
}

// ═══════════════════════════════════════════════════════════════════════════
// DECRYPTION
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Decrypt data using NaCl secretbox.
 *
 * @param key - 32-byte symmetric key
 * @param payload - Encrypted payload from secretboxEncrypt
 * @returns Decrypted data, or null if authentication fails
 */
export function secretboxDecrypt(
  key: Uint8Array,
  payload: SecretboxPayload
): Uint8Array | null {
  if (payload.scheme !== 'nacl.secretbox') {
    return null;
  }
  assertLen('secretbox key', key, 32);

  const nonce = fromB64(payload.nonce);
  const ciphertext = fromB64(payload.ciphertext);

  return nacl.secretbox.open(ciphertext, nonce, key) || null;
}

/**
 * Decrypt to a string using NaCl secretbox.
 */
export function secretboxDecryptString(
  key: Uint8Array,
  payload: SecretboxPayload
): string | null {
  const result = secretboxDecrypt(key, payload);
  if (!result) return null;
  return new TextDecoder().decode(result);
}

// ═══════════════════════════════════════════════════════════════════════════
// RAW OPERATIONS (for low-level use)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Raw secretbox encryption (returns raw bytes).
 */
export function secretboxRaw(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  assertLen('secretbox key', key, 32);
  assertLen('nonce', nonce, 24);
  return nacl.secretbox(plaintext, nonce, key);
}

/**
 * Raw secretbox decryption (returns raw bytes).
 */
export function secretboxOpenRaw(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array
): Uint8Array | null {
  assertLen('secretbox key', key, 32);
  assertLen('nonce', nonce, 24);
  return nacl.secretbox.open(ciphertext, nonce, key) || null;
}

// ═══════════════════════════════════════════════════════════════════════════
// BOX OPERATIONS (authenticated public-key encryption)
// ═══════════════════════════════════════════════════════════════════════════

export interface BoxPayload {
  /** Nonce (base64, 24 bytes) */
  nonce: string;
  /** Ciphertext (base64) */
  ciphertext: string;
}

/**
 * Encrypt data using NaCl box (X25519 + XSalsa20-Poly1305).
 *
 * @param plaintext - Data to encrypt
 * @param nonce - 24-byte nonce
 * @param recipientPubKey - Recipient's X25519 public key (32 bytes)
 * @param senderSecKey - Sender's X25519 secret key (32 bytes)
 * @returns Encrypted ciphertext
 */
export function boxEncrypt(
  plaintext: Uint8Array,
  nonce: Uint8Array,
  recipientPubKey: Uint8Array,
  senderSecKey: Uint8Array
): Uint8Array {
  assertLen('nonce', nonce, 24);
  assertLen('recipient pubKey', recipientPubKey, 32);
  assertLen('sender secKey', senderSecKey, 32);
  return nacl.box(plaintext, nonce, recipientPubKey, senderSecKey);
}

/**
 * Decrypt data using NaCl box.
 *
 * @param ciphertext - Encrypted data
 * @param nonce - 24-byte nonce
 * @param senderPubKey - Sender's X25519 public key (32 bytes)
 * @param recipientSecKey - Recipient's X25519 secret key (32 bytes)
 * @returns Decrypted data, or null if authentication fails
 */
export function boxDecrypt(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  senderPubKey: Uint8Array,
  recipientSecKey: Uint8Array
): Uint8Array | null {
  assertLen('nonce', nonce, 24);
  assertLen('sender pubKey', senderPubKey, 32);
  assertLen('recipient secKey', recipientSecKey, 32);
  return nacl.box.open(ciphertext, nonce, senderPubKey, recipientSecKey) || null;
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

/** NaCl secretbox key size (32 bytes) */
export const SECRETBOX_KEY_SIZE = nacl.secretbox.keyLength;

/** NaCl secretbox nonce size (24 bytes) */
export const SECRETBOX_NONCE_SIZE = nacl.secretbox.nonceLength;

/** NaCl secretbox overhead (16 bytes auth tag) */
export const SECRETBOX_OVERHEAD = nacl.secretbox.overheadLength;

/** NaCl box key size (32 bytes) */
export const BOX_KEY_SIZE = nacl.box.publicKeyLength;

/** NaCl box nonce size (24 bytes) */
export const BOX_NONCE_SIZE = nacl.box.nonceLength;
