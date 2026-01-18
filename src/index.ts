// Ensure globalThis.crypto exists in Node environments
import './runtime/crypto';

/**
 * Omnituum PQC Shared
 *
 * Unified cryptographic and vault utilities for PQC applications.
 * Combines X25519 (classical) + Kyber ML-KEM-768 (post-quantum) encryption.
 *
 * FROZEN CONTRACTS - see pqc-docs/specs/ for format specifications.
 *
 * ## API Stability
 *
 * Exports are annotated with stability markers:
 * - `@stable` — Supported and semver-governed. Breaking changes only in major versions.
 * - `@experimental` — May change in minor/patch releases until stabilized.
 * - `@internal` — Not part of the public API surface; do not depend on these.
 *
 * @example
 * ```ts
 * // Hybrid Encryption
 * import { generateHybridIdentity, hybridEncrypt, hybridDecryptToString } from '@omnituum/pqc-shared';
 *
 * // Vault Management
 * import { createEmptyVault, createIdentity, encryptVault, decryptVault } from '@omnituum/pqc-shared';
 *
 * // Vault Migration
 * import { needsMigration, migrateEncryptedVault } from '@omnituum/pqc-shared';
 * ```
 */

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID ENCRYPTION (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Hybrid X25519 + Kyber-768 encryption primitives.
 * The core post-quantum encryption interface.
 */
export {
  generateHybridIdentity,
  hybridEncrypt,
  hybridDecrypt,
  hybridDecryptToString,
  getPublicKeys,
  getSecretKeys,
} from './crypto/hybrid';

export type {
  HybridIdentity,
  HybridPublicKeys,
  HybridSecretKeys,
  HybridEnvelope,
} from './crypto/hybrid';

// ═══════════════════════════════════════════════════════════════════════════
// KYBER (ML-KEM-768) (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Kyber ML-KEM-768 post-quantum KEM primitives.
 */
export {
  isKyberAvailable,
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate,
  kyberWrapKey,
  kyberUnwrapKey,
} from './crypto/kyber';

export type {
  KyberKeypair,
  KyberKeypairB64,
  KyberEncapsulation,
} from './crypto/kyber';

// ═══════════════════════════════════════════════════════════════════════════
// X25519 (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable X25519 ECDH key exchange and wrapping.
 */
export {
  generateX25519Keypair,
  generateX25519KeypairFromSeed,
  boxWrapWithX25519,
  boxUnwrapWithX25519,
  x25519SharedSecret,
  deriveKeyFromShared,
} from './crypto/x25519';

export type {
  X25519Keypair,
  X25519KeypairHex,
  ClassicalWrap,
} from './crypto/x25519';

// ═══════════════════════════════════════════════════════════════════════════
// DILITHIUM (ML-DSA-65) (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Dilithium ML-DSA-65 post-quantum digital signatures.
 */
export {
  isDilithiumAvailable,
  generateDilithiumKeypair,
  generateDilithiumKeypairFromSeed,
  dilithiumSign,
  dilithiumSignRaw,
  dilithiumVerify,
  dilithiumVerifyRaw,
  DILITHIUM_PUBLIC_KEY_SIZE,
  DILITHIUM_SECRET_KEY_SIZE,
  DILITHIUM_SIGNATURE_SIZE,
  DILITHIUM_ALGORITHM,
} from './crypto/dilithium';

export type {
  DilithiumKeypair,
  DilithiumKeypairB64,
  DilithiumSignature,
} from './crypto/dilithium';

// ═══════════════════════════════════════════════════════════════════════════
// VAULT MANAGEMENT (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Vault creation, encryption, and decryption.
 * Core vault operations for identity management.
 */
export {
  createEmptyVault,
  createIdentity,
  addIdentity,
  encryptVault,
  decryptVault,
} from './vault';

export type {
  OmnituumVault,
  EncryptedVaultFile,
  HybridIdentityRecord,
} from './vault';

// ═══════════════════════════════════════════════════════════════════════════
// VAULT MIGRATION (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Migration from PBKDF2 (v1) to Argon2id (v2) vaults.
 */
export {
  needsMigration,
  migrateEncryptedVault,
  getVaultKdfInfo,
  isV2Vault,
} from './vault';

export type {
  MigrationOptions,
  MigrationResult,
} from './vault';

// ═══════════════════════════════════════════════════════════════════════════
// INTEGRITY UTILITIES (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Integrity hashing and key fingerprinting.
 */
export {
  computeIntegrityHash,
  computeKeyFingerprint,
} from './utils';

// ═══════════════════════════════════════════════════════════════════════════
// KEY DERIVATION (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Password-based key derivation (PBKDF2 and Argon2id).
 */
export {
  getRecommendedConfig,
  benchmarkKDF,
  kdfDeriveKey,
  generateSalt,
  KDF_CONFIG_ARGON2ID,
  KDF_CONFIG_PBKDF2,
} from './kdf';

export type {
  KDFConfig,
  KDFAlgorithm,
} from './kdf';

// ═══════════════════════════════════════════════════════════════════════════
// SECURITY UTILITIES (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Memory hygiene, secure sessions, and sensitive data handling.
 */
export {
  SecureBuffer,
  withSecureData,
  zeroMemory,
  zeroAll,
  constantTimeEqual,
  createSession,
  unlockSecureSession,
  lockSecureSession,
  isSessionTimedOut,
} from './security';

export type {
  SecureSession,
  UnlockReason,
} from './security';

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES - BLAKE3 (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable BLAKE3 hash function for transcripts and commitments.
 */
export {
  blake3,
  blake3Hex,
  blake3Mac,
  blake3DeriveKey,
  BLAKE3_OUTPUT_LENGTH,
} from './crypto/primitives/blake3';

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES - CHACHA20-POLY1305 (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable AEAD encryption primitives (ChaCha20-Poly1305, XChaCha20-Poly1305).
 */
export {
  chaCha20Poly1305Encrypt,
  chaCha20Poly1305Decrypt,
  xChaCha20Poly1305Encrypt,
  xChaCha20Poly1305Decrypt,
  createXChaCha20Poly1305,
  createChaCha20Poly1305,
  CHACHA20_KEY_SIZE,
  XCHACHA20_NONCE_SIZE,
  POLY1305_TAG_SIZE,
} from './crypto/primitives/chacha';

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES - HKDF (@stable for basic, @experimental for Noise helpers)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable HKDF key derivation (RFC 5869).
 */
export {
  hkdfDerive,
  hkdfExtract,
  hkdfExpand,
} from './crypto/primitives/hkdf';

/**
 * @experimental Noise protocol HKDF helpers.
 * These may change as Noise integration evolves.
 */
export {
  hkdfSplitForNoise,
  hkdfTripleSplitForNoise,
} from './crypto/primitives/hkdf';

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES - ENCODING (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Encoding utilities (Base64, Hex).
 */
export {
  // Text encoding
  textEncoder,
  textDecoder,

  // Base64
  toB64,
  fromB64,
  b64,
  ub64,

  // Hex
  toHex,
  fromHex,

  // Validation
  assertLen,

  // Randomness
  rand32,
  rand24,
  rand12,
  randN,

  // Hashing
  sha256,
  sha256String,

  // Key derivation
  hkdfSha256,

  // Utility
  u8,
} from './crypto/primitives';

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES - NACL SECRETBOX (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable NaCl secretbox symmetric encryption.
 */
export {
  secretboxEncrypt,
  secretboxDecrypt,
  secretboxEncryptString,
  secretboxDecryptString,
  secretboxRaw,
  secretboxOpenRaw,
  SECRETBOX_KEY_SIZE,
  SECRETBOX_NONCE_SIZE,
  SECRETBOX_OVERHEAD,
} from './crypto/nacl';

export type { SecretboxPayload } from './crypto/nacl';

/**
 * @stable NaCl box authenticated public-key encryption.
 */
export {
  boxEncrypt,
  boxDecrypt,
  BOX_KEY_SIZE,
  BOX_NONCE_SIZE,
} from './crypto/nacl';

export type { BoxPayload } from './crypto/nacl';

// ═══════════════════════════════════════════════════════════════════════════
// VERSION CONSTANTS (@stable)
// ═══════════════════════════════════════════════════════════════════════════

export {
  VAULT_VERSION,
  VAULT_ENCRYPTED_VERSION,
  VAULT_ENCRYPTED_VERSION_V2,
  ENVELOPE_VERSION,
  ENVELOPE_SUITE,
  ENVELOPE_AEAD,
  VAULT_KDF,
  VAULT_KDF_V2,
  VAULT_ALGORITHM,
  validateVault,
  validateEnvelope,
  validateEncryptedVault,
} from './version';

// ═══════════════════════════════════════════════════════════════════════════
// FILE ENCRYPTION (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Omnituum FS - file encryption with hybrid PQC.
 */
export {
  encryptFile,
  decryptFile,
  encryptFileWithPassword,
  decryptFileWithPassword,
} from './fs';

export type {
  OQEEncryptResult,
  OQEDecryptResult,
  EncryptOptions,
  DecryptOptions,
} from './fs';

// ═══════════════════════════════════════════════════════════════════════════
// TUNNEL (@stable)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @stable Post-handshake encrypted tunnel.
 * Handshake-agnostic: accepts key material from any protocol.
 */
export {
  createTunnelSession,
  TUNNEL_VERSION,
  TUNNEL_KEY_SIZE,
  TUNNEL_NONCE_SIZE,
} from './tunnel';

export type {
  PQCTunnelSession,
  TunnelKeyMaterial,
} from './tunnel';
