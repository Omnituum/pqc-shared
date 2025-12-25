/**
 * Omnituum PQC Shared - Crypto Exports
 *
 * Unified cryptographic primitives for both Loggie and Omnituum.
 * Browser-compatible, no Node.js dependencies.
 */

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════

export {
  textEncoder,
  textDecoder,
  toB64,
  fromB64,
  toHex,
  fromHex,
  b64,
  ub64,
  assertLen,
  rand32,
  rand24,
  rand12,
  randN,
  sha256,
  sha256String,
  hkdfSha256,
  u8,
} from './primitives';

// ═══════════════════════════════════════════════════════════════════════════
// NaCl SECRETBOX / BOX
// ═══════════════════════════════════════════════════════════════════════════

export type { SecretboxPayload, BoxPayload } from './nacl';

export {
  secretboxEncrypt,
  secretboxEncryptString,
  secretboxDecrypt,
  secretboxDecryptString,
  secretboxRaw,
  secretboxOpenRaw,
  boxEncrypt,
  boxDecrypt,
  SECRETBOX_KEY_SIZE,
  SECRETBOX_NONCE_SIZE,
  SECRETBOX_OVERHEAD,
  BOX_KEY_SIZE,
  BOX_NONCE_SIZE,
} from './nacl';

// ═══════════════════════════════════════════════════════════════════════════
// X25519 (Classical ECDH)
// ═══════════════════════════════════════════════════════════════════════════

export type {
  X25519Keypair,
  X25519KeypairHex,
  ClassicalWrap,
} from './x25519';

export {
  generateX25519Keypair,
  generateX25519KeypairFromSeed,
  boxWrapWithX25519,
  boxUnwrapWithX25519,
  x25519SharedSecret,
  deriveKeyFromShared,
} from './x25519';

// ═══════════════════════════════════════════════════════════════════════════
// KYBER ML-KEM-768 (Post-Quantum KEM)
// ═══════════════════════════════════════════════════════════════════════════

export type {
  KyberKeypair,
  KyberKeypairB64,
  KyberEncapsulation,
} from './kyber';

export {
  isKyberAvailable,
  generateKyberKeypair,
  kyberEncapsulate,
  kyberDecapsulate,
  kyberWrapKey,
  kyberUnwrapKey,
} from './kyber';

// ═══════════════════════════════════════════════════════════════════════════
// DILITHIUM ML-DSA-65 (Post-Quantum Signatures)
// ═══════════════════════════════════════════════════════════════════════════

export type {
  DilithiumKeypair,
  DilithiumKeypairB64,
  DilithiumSignature,
} from './dilithium';

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
} from './dilithium';

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID ENCRYPTION (X25519 + Kyber768)
// ═══════════════════════════════════════════════════════════════════════════

export type {
  HybridIdentity,
  HybridPublicKeys,
  HybridSecretKeys,
  HybridEnvelope,
} from './hybrid';

export {
  generateHybridIdentity,
  rotateHybridIdentity,
  getPublicKeys,
  getSecretKeys,
  hybridEncrypt,
  hybridDecrypt,
  hybridDecryptToString,
} from './hybrid';

// ═══════════════════════════════════════════════════════════════════════════
// PRIMITIVES (for protocol implementations like noise-kyber)
// ═══════════════════════════════════════════════════════════════════════════

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
} from './primitives/blake3';

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
} from './primitives/chacha';

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
} from './primitives/hkdf';
