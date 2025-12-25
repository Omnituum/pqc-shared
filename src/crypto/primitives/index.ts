/**
 * Omnituum PQC Shared - Cryptographic Primitives
 *
 * Low-level cryptographic building blocks for higher-level protocols.
 * These are exported for use in noise-kyber and other protocol implementations.
 *
 * PRIMITIVES (use directly):
 * - BLAKE3: Fast hash function for transcripts
 * - ChaCha20-Poly1305: AEAD encryption (12-byte nonce)
 * - XChaCha20-Poly1305: AEAD encryption (24-byte nonce, safer)
 * - HKDF: Key derivation function (NIST-approved)
 */

// BLAKE3 hash function
export {
  blake3,
  blake3Hex,
  blake3Mac,
  blake3DeriveKey,
  BLAKE3_OUTPUT_LENGTH,
  BLAKE3_KEY_LENGTH,
  BLAKE3_BLOCK_SIZE,
  type Blake3Options,
} from './blake3';

// ChaCha20-Poly1305 AEAD
export {
  chaCha20Poly1305Encrypt,
  chaCha20Poly1305Decrypt,
  xChaCha20Poly1305Encrypt,
  xChaCha20Poly1305Decrypt,
  createChaCha20Poly1305,
  createXChaCha20Poly1305,
  CHACHA20_KEY_SIZE,
  CHACHA20_NONCE_SIZE,
  XCHACHA20_NONCE_SIZE,
  POLY1305_TAG_SIZE,
  type ChaChaPayload,
} from './chacha';

// HKDF key derivation
export {
  hkdfDerive,
  hkdfExtract,
  hkdfExpand,
  hkdfSplitForNoise,
  hkdfTripleSplitForNoise,
  HKDF_SHA256_OUTPUT_SIZE,
  HKDF_SHA512_OUTPUT_SIZE,
  HKDF_SHA256_MAX_OUTPUT,
  HKDF_SHA512_MAX_OUTPUT,
  type HkdfHash,
  type HkdfOptions,
} from './hkdf';
